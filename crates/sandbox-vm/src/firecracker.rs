use sandbox_launcher_linux::{
    LauncherEvent, LauncherStatus, VmmLaunchSpec, file_identity, read_launcher_event,
    read_launcher_status, send_launcher_terminate, send_vmm_launch_spec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub launcher_executable: PathBuf,
    pub firecracker_executable: PathBuf,
    pub firecracker_sha256: String,
    pub state_directory: PathBuf,
    pub kernel_image: PathBuf,
    pub rootfs_image: PathBuf,
    /// Immutable distribution/workload root. The trusted bootstrap rootfs is
    /// always separate and remains the only source of the supervisor.
    pub workload_image: PathBuf,
    pub workspace_image: PathBuf,
    /// Protected guest replay and control state. This disk is never mounted in
    /// the workload root and is independently bounded from writable workload
    /// storage.
    pub control_image: PathBuf,
    pub authentication_image: PathBuf,
    pub owner_token: String,
    pub guest_cid: u32,
    pub guest_port: u32,
    pub vcpu_count: u8,
    pub memory_mib: u32,
}

pub struct FirecrackerProcess {
    child: Child,
    control: UnixStream,
    diagnostics: Vec<JoinHandle<()>>,
    pub vsock_path: PathBuf,
    pub api_socket_path: PathBuf,
    final_status: Option<sandbox_launcher_linux::LauncherFinalStatus>,
}

impl FirecrackerProcess {
    pub fn spawn(config: &FirecrackerConfig) -> Result<Self, FirecrackerError> {
        validate_config(config)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&config.state_directory)?;
        let vm_state = config.state_directory.join("vm-state");
        fs::DirBuilder::new().mode(0o700).create(&vm_state)?;
        let vsock_path = vm_state.join("guest.vsock");
        let api_socket_path = vm_state.join("firecracker.socket");
        let config_path = vm_state.join("firecracker.json");
        let drives = vec![
            Drive {
                drive_id: "bootstrap".into(),
                path_on_host: "/vm/bootstrap".into(),
                is_root_device: true,
                is_read_only: true,
            },
            Drive {
                drive_id: "workload".into(),
                path_on_host: "/vm/workload".into(),
                is_root_device: false,
                is_read_only: true,
            },
            Drive {
                drive_id: "workload-state".into(),
                path_on_host: "/vm/workload-state".into(),
                is_root_device: false,
                is_read_only: false,
            },
            Drive {
                drive_id: "control-state".into(),
                path_on_host: "/vm/control-state".into(),
                is_root_device: false,
                is_read_only: false,
            },
            Drive {
                drive_id: "auth".into(),
                path_on_host: "/vm/auth".into(),
                is_root_device: false,
                is_read_only: true,
            },
        ];
        let firecracker_json = FirecrackerJson {
            boot_source: BootSource {
                kernel_image_path: "/vm/kernel".into(),
                boot_args:
                    "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/sbin/sandbox-guest"
                        .into(),
            },
            drives,
            machine_config: MachineConfig {
                vcpu_count: config.vcpu_count,
                mem_size_mib: config.memory_mib,
                smt: false,
                track_dirty_pages: true,
            },
            vsock: Vsock {
                guest_cid: config.guest_cid,
                uds_path: "/vm/state/guest.vsock".into(),
            },
        };
        let mut config_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config_path)?;
        config_file.write_all(
            &serde_json::to_vec(&firecracker_json)
                .map_err(|error| FirecrackerError::Invalid(error.to_string()))?,
        )?;
        config_file.sync_all()?;

        let mut files = Vec::new();
        let kernel_fd_index = add_file(&mut files, &config.kernel_image)?;
        let bootstrap_fd_index = add_file(&mut files, &config.rootfs_image)?;
        let workload_fd_index = add_file(&mut files, &config.workload_image)?;
        let workload_state_fd_index = add_file(&mut files, &config.workspace_image)?;
        let control_state_fd_index = add_file(&mut files, &config.control_image)?;
        let authentication_fd_index = add_file(&mut files, &config.authentication_image)?;
        let configuration_fd_index = add_file(&mut files, &config_path)?;

        let mut firecracker = File::open(&config.firecracker_executable)?;
        let actual_digest = hash_reader(&mut firecracker)?;
        if actual_digest != config.firecracker_sha256 {
            return Err(FirecrackerError::Invalid(
                "Firecracker digest mismatch".into(),
            ));
        }
        let executable_identity = file_identity(firecracker.as_raw_fd())?;
        let firecracker_fd_index = files.len();
        files.push(firecracker);
        let state_directory_fd_index = files.len();
        let cwd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&vm_state)?;
        let cwd_identity = file_identity(cwd.as_raw_fd())?;
        files.push(cwd);
        let namespace_launcher_fd_index = files.len();
        files.push(sandbox_launcher_linux::NamespaceLauncher::open()?.file);
        let kvm_fd_index = add_file(&mut files, Path::new("/dev/kvm"))?;
        let spec = VmmLaunchSpec {
            namespace_launcher_fd_index,
            firecracker_fd_index,
            firecracker_identity: executable_identity,
            firecracker_sha256: actual_digest,
            kernel_fd_index,
            bootstrap_fd_index,
            workload_fd_index,
            workload_state_fd_index,
            control_state_fd_index,
            authentication_fd_index,
            configuration_fd_index,
            state_directory_fd_index,
            state_directory_identity: cwd_identity,
            kvm_fd_index,
            open_files_limit: 1024,
            file_size_limit: 16 * 1024 * 1024 * 1024,
            termination_grace_ms: 1_000,
        };
        let (mut control, launcher_control) = UnixStream::pair()?;
        let launcher_input: OwnedFd = launcher_control.into();
        let child = Command::new(&config.launcher_executable)
            .arg("--linux-vmm-launcher")
            .env_clear()
            .env("TMPDIR", &config.state_directory)
            .env("SANDBOX_VM_OWNER_TOKEN", &config.owner_token)
            .stdin(Stdio::from(launcher_input))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut guard = ChildLaunchGuard::new(child);
        let setup = (|| -> Result<(), FirecrackerError> {
            send_vmm_launch_spec(&mut control, &spec, &files)?;
            drop(files);
            control.set_read_timeout(Some(Duration::from_secs(30)))?;
            match read_launcher_status(&mut control)? {
                LauncherStatus::Started(_) => {}
                LauncherStatus::SetupError(error) => {
                    return Err(FirecrackerError::Setup(format!(
                        "{}: {}",
                        error.code, error.message
                    )));
                }
            }
            control.set_read_timeout(None)?;
            Ok(())
        })();
        if let Err(error) = setup {
            let failures = guard.cleanup();
            return if failures.is_empty() {
                Err(error)
            } else {
                Err(FirecrackerError::Setup(format!(
                    "{error}; launcher cleanup failed: {}",
                    failures.join("; ")
                )))
            };
        }
        let mut child = guard.handoff();
        let diagnostics = [
            (
                child
                    .stdout
                    .take()
                    .map(|value| Box::new(value) as Box<dyn Read + Send>),
                vm_state.join("console.log"),
            ),
            (
                child
                    .stderr
                    .take()
                    .map(|value| Box::new(value) as Box<dyn Read + Send>),
                vm_state.join("vmm.log"),
            ),
        ]
        .into_iter()
        .filter_map(|(input, path)| input.map(|input| drain_diagnostic(input, path)))
        .collect();
        Ok(Self {
            child,
            control,
            diagnostics,
            vsock_path,
            api_socket_path,
            final_status: None,
        })
    }

    pub fn terminate(&mut self) -> Result<(), FirecrackerError> {
        send_launcher_terminate(&mut self.control)?;
        Ok(())
    }

    /// Pause vCPUs through the private Firecracker API and wait for the API's
    /// committed response. This retains the VMM and guest memory.
    pub fn pause(&self) -> Result<(), FirecrackerError> {
        self.patch_vm_state("Paused")
    }

    /// Resume a VM previously paused through the same private API socket.
    pub fn resume(&self) -> Result<(), FirecrackerError> {
        self.patch_vm_state("Resumed")
    }

    fn patch_vm_state(&self, state: &str) -> Result<(), FirecrackerError> {
        let body = serde_json::to_vec(&serde_json::json!({ "state": state }))
            .map_err(|error| FirecrackerError::Invalid(error.to_string()))?;
        let mut connection = UnixStream::connect(&self.api_socket_path)?;
        connection.set_read_timeout(Some(Duration::from_secs(10)))?;
        connection.set_write_timeout(Some(Duration::from_secs(10)))?;
        write!(
            connection,
            "PATCH /vm HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        connection.write_all(&body)?;
        connection.flush()?;
        let mut response = Vec::new();
        connection.take(64 * 1024 + 1).read_to_end(&mut response)?;
        if response.len() > 64 * 1024 {
            return Err(FirecrackerError::Setup(
                "Firecracker API response exceeds 64 KiB".into(),
            ));
        }
        let Some(line_end) = response.windows(2).position(|value| value == b"\r\n") else {
            return Err(FirecrackerError::Setup(
                "Firecracker API response has no status line".into(),
            ));
        };
        let status = std::str::from_utf8(&response[..line_end])
            .map_err(|_| FirecrackerError::Setup("Firecracker API status is not UTF-8".into()))?;
        if status != "HTTP/1.1 204 No Content" && status != "HTTP/1.0 204 No Content" {
            return Err(FirecrackerError::Setup(format!(
                "Firecracker API rejected VM state change: {status}"
            )));
        }
        Ok(())
    }

    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    pub fn has_exited(&mut self) -> Result<bool, FirecrackerError> {
        Ok(self.child.try_wait()?.is_some())
    }

    pub fn wait(
        &mut self,
    ) -> Result<&sandbox_launcher_linux::LauncherFinalStatus, FirecrackerError> {
        if self.final_status.is_none() {
            self.control
                .set_read_timeout(Some(Duration::from_secs(5)))?;
            loop {
                match read_launcher_event(&mut self.control)? {
                    LauncherEvent::Final(status) => {
                        self.final_status = Some(status);
                        break;
                    }
                    LauncherEvent::RuntimeError(error) => {
                        return Err(FirecrackerError::Setup(format!(
                            "{}: {}",
                            error.code, error.message
                        )));
                    }
                    LauncherEvent::StdinCredit(_) => {}
                }
            }
            let _ = self.child.wait()?;
            self.finish_diagnostics();
        }
        self.final_status
            .as_ref()
            .ok_or_else(|| FirecrackerError::Setup("missing VMM final status".into()))
    }

    fn finish_diagnostics(&mut self) {
        for thread in self.diagnostics.drain(..) {
            let _ = thread.join();
        }
    }
}

struct ChildLaunchGuard {
    child: Option<Child>,
}

impl ChildLaunchGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn handoff(&mut self) -> Child {
        self.child.take().expect("launch guard owns its child")
    }

    fn cleanup(&mut self) -> Vec<String> {
        let Some(mut child) = self.child.take() else {
            return Vec::new();
        };
        let mut failures = Vec::new();
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = child.kill()
                    && error.kind() != io::ErrorKind::InvalidInput
                {
                    failures.push(format!("kill: {error}"));
                }
            }
            Err(error) => failures.push(format!("status: {error}")),
        }
        if let Err(error) = child.wait() {
            failures.push(format!("wait: {error}"));
        }
        for (label, stream) in [
            (
                "stdout",
                child
                    .stdout
                    .take()
                    .map(|value| Box::new(value) as Box<dyn Read>),
            ),
            (
                "stderr",
                child
                    .stderr
                    .take()
                    .map(|value| Box::new(value) as Box<dyn Read>),
            ),
        ] {
            if let Some(stream) = stream {
                let mut bytes = Vec::new();
                if stream.take(16 * 1024 + 1).read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
                    failures.push(format!(
                        "{label}: {}",
                        String::from_utf8_lossy(&bytes[..bytes.len().min(16 * 1024)])
                    ));
                }
            }
        }
        failures
    }
}

impl Drop for ChildLaunchGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl Drop for FirecrackerProcess {
    fn drop(&mut self) {
        if self.final_status.is_none() {
            let _ = send_launcher_terminate(&mut self.control);
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.finish_diagnostics();
    }
}

fn drain_diagnostic(mut input: Box<dyn Read + Send>, path: PathBuf) -> JoinHandle<()> {
    std::thread::spawn(move || {
        const RETAINED: u64 = 8 * 1024 * 1024;
        let Ok(mut output) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        else {
            let _ = io::copy(&mut input, &mut io::sink());
            return;
        };
        let mut retained = (&mut input).take(RETAINED);
        let _ = io::copy(&mut retained, &mut output);
        let _ = output.sync_all();
        let _ = io::copy(&mut input, &mut io::sink());
    })
}

#[derive(Debug)]
pub enum FirecrackerError {
    Io(io::Error),
    Invalid(String),
    Setup(String),
}

impl Display for FirecrackerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Firecracker I/O error: {error}"),
            Self::Invalid(message) => {
                write!(formatter, "invalid Firecracker configuration: {message}")
            }
            Self::Setup(message) => write!(formatter, "Firecracker setup failed: {message}"),
        }
    }
}

impl std::error::Error for FirecrackerError {}

impl From<io::Error> for FirecrackerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn validate_config(config: &FirecrackerConfig) -> Result<(), FirecrackerError> {
    if config.guest_cid < 3
        || config.guest_port < 1024
        || config.vcpu_count == 0
        || config.vcpu_count > 32
        || config.memory_mib < 128
        || config.memory_mib > 65_536
        || config.owner_token.len() != 64
        || !config
            .owner_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || config.state_directory.exists()
    {
        return Err(FirecrackerError::Invalid(
            "invalid VM resources or state path".into(),
        ));
    }
    for path in [
        &config.launcher_executable,
        &config.firecracker_executable,
        &config.kernel_image,
        &config.rootfs_image,
        &config.workload_image,
        &config.workspace_image,
        &config.control_image,
        &config.authentication_image,
    ] {
        if !path.is_absolute() || !path.is_file() {
            return Err(FirecrackerError::Invalid(format!(
                "missing VM input {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn add_file(files: &mut Vec<File>, path: &Path) -> io::Result<usize> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() && !metadata.is_file() {
        let identity = file_identity(file.as_raw_fd())?;
        if path != Path::new("/dev/kvm") || identity.mode & libc::S_IFMT != libc::S_IFCHR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMM mount source has an unsupported object type",
            ));
        }
    }
    let index = files.len();
    files.push(file);
    Ok(index)
}

fn hash_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Serialize, Deserialize)]
struct FirecrackerJson {
    #[serde(rename = "boot-source")]
    boot_source: BootSource,
    drives: Vec<Drive>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
    vsock: Vsock,
}

#[derive(Serialize, Deserialize)]
struct BootSource {
    kernel_image_path: String,
    boot_args: String,
}

#[derive(Serialize, Deserialize)]
struct Drive {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Serialize, Deserialize)]
struct MachineConfig {
    vcpu_count: u8,
    mem_size_mib: u32,
    smt: bool,
    track_dirty_pages: bool,
}

#[derive(Serialize, Deserialize)]
struct Vsock {
    guest_cid: u32,
    uds_path: String,
}
