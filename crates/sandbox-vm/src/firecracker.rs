use sandbox_launcher_linux::{
    LaunchSpec, LauncherEvent, LauncherStatus, MountSpec, PreparedCwd, file_identity,
    read_launcher_event, read_launcher_status, send_launch_spec, send_launcher_terminate,
};
use sandbox_policy::{NormalizedMask, ResourceLimits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub launcher_executable: PathBuf,
    pub firecracker_executable: PathBuf,
    pub firecracker_sha256: String,
    pub state_directory: PathBuf,
    pub kernel_image: PathBuf,
    pub rootfs_image: PathBuf,
    pub workspace_image: PathBuf,
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
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    pub vsock_path: PathBuf,
    pub api_socket_path: PathBuf,
    final_status: Option<sandbox_launcher_linux::LauncherFinalStatus>,
}

impl FirecrackerProcess {
    pub fn spawn(config: &FirecrackerConfig) -> Result<Self, FirecrackerError> {
        validate_config(config)?;
        fs::create_dir(&config.state_directory)?;
        let root_directory = config.state_directory.join("root");
        let vm_state = config.state_directory.join("vm-state");
        fs::create_dir(&vm_state)?;
        let vsock_path = vm_state.join("guest.vsock");
        let api_socket_path = vm_state.join("firecracker.socket");
        let config_path = vm_state.join("firecracker.json");
        let firecracker_json = FirecrackerJson {
            boot_source: BootSource {
                kernel_image_path: "/vm/kernel".into(),
                boot_args:
                    "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/sbin/sandbox-guest"
                        .into(),
            },
            drives: vec![
                Drive {
                    drive_id: "rootfs".into(),
                    path_on_host: "/vm/rootfs".into(),
                    is_root_device: true,
                    is_read_only: true,
                },
                Drive {
                    drive_id: "workspace".into(),
                    path_on_host: "/vm/workspace".into(),
                    is_root_device: false,
                    is_read_only: false,
                },
                Drive {
                    drive_id: "auth".into(),
                    path_on_host: "/vm/auth".into(),
                    is_root_device: false,
                    is_read_only: true,
                },
            ],
            machine_config: MachineConfig {
                vcpu_count: config.vcpu_count,
                mem_size_mib: config.memory_mib,
                smt: false,
                track_dirty_pages: false,
            },
            vsock: Vsock {
                guest_cid: config.guest_cid,
                uds_path: "/vm/state/guest.vsock".into(),
            },
        };
        fs::write(
            &config_path,
            serde_json::to_vec(&firecracker_json)
                .map_err(|error| FirecrackerError::Invalid(error.to_string()))?,
        )?;

        let mut files = Vec::new();
        let mut mounts = Vec::new();
        for (path, target, read_only, executable) in [
            (&config.kernel_image, "/vm/kernel", true, false),
            (&config.rootfs_image, "/vm/rootfs", true, false),
            (&config.workspace_image, "/vm/workspace", false, false),
            (&config.authentication_image, "/vm/auth", true, false),
            (&config_path, "/vm/state/firecracker.json", true, false),
        ] {
            add_mount(&mut files, &mut mounts, path, target, read_only, executable)?;
        }
        add_mount(
            &mut files,
            &mut mounts,
            &vm_state,
            "/vm/state",
            false,
            false,
        )?;
        add_mount(
            &mut files,
            &mut mounts,
            Path::new("/dev/kvm"),
            "/dev/kvm",
            false,
            true,
        )?;

        let mut firecracker = File::open(&config.firecracker_executable)?;
        let actual_digest = hash_reader(&mut firecracker)?;
        if actual_digest != config.firecracker_sha256 {
            return Err(FirecrackerError::Invalid(
                "Firecracker digest mismatch".into(),
            ));
        }
        let executable_identity = file_identity(firecracker.as_raw_fd())?;
        let executable_fd_index = files.len();
        files.push(firecracker);
        let cwd_index = files.len();
        let cwd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&vm_state)?;
        let cwd_identity = file_identity(cwd.as_raw_fd())?;
        files.push(cwd);
        let spec = LaunchSpec {
            root_path: root_directory.to_string_lossy().into_owned(),
            mounts,
            masks: Vec::<NormalizedMask>::new(),
            private_home_enabled: false,
            private_home_size_bytes: 1024 * 1024,
            private_home_executable: false,
            temporary_size_bytes: 64 * 1024 * 1024,
            temporary_executable: false,
            executable_fd_index,
            executable_identity,
            executable_content_sha256: actual_digest,
            executable_snapshot_path: "/.sandbox-runtime/firecracker".into(),
            cwd: PreparedCwd::Bound {
                fd_index: cwd_index,
                identity: cwd_identity,
                target_path: "/vm/state".into(),
            },
            executable: "/.sandbox-runtime/firecracker".into(),
            args: vec![
                "--enable-pci".into(),
                "--api-sock".into(),
                "/vm/state/firecracker.socket".into(),
                "--config-file".into(),
                "/vm/state/firecracker.json".into(),
            ],
            environment: BTreeMap::new(),
            resources: ResourceLimits {
                wall_time_ms: 24 * 60 * 60 * 1000,
                cpu_time_ms: None,
                memory_bytes: u64::from(config.memory_mib + 256) * 1024 * 1024,
                max_processes: u64::from(config.vcpu_count) + 32,
                max_open_files_per_process: Some(1024),
                max_single_file_bytes: Some(16 * 1024 * 1024 * 1024),
                max_output_bytes: 64 * 1024 * 1024,
                termination_grace_ms: 1_000,
            },
            network_mode: "none".into(),
        };
        let (mut control, launcher_control) = UnixStream::pair()?;
        let launcher_input: OwnedFd = launcher_control.into();
        let child = Command::new(&config.launcher_executable)
            .arg("--linux-launcher")
            .env_clear()
            .env("TMPDIR", &config.state_directory)
            .env("SANDBOX_VM_OWNER_TOKEN", &config.owner_token)
            .stdin(Stdio::from(launcher_input))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut guard = ChildLaunchGuard::new(child);
        let setup = (|| -> Result<(), FirecrackerError> {
            send_launch_spec(&mut control, &spec, &files)?;
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
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Ok(Self {
            child,
            control,
            stdout,
            stderr,
            vsock_path,
            api_socket_path,
            final_status: None,
        })
    }

    pub fn terminate(&mut self) -> Result<(), FirecrackerError> {
        send_launcher_terminate(&mut self.control)?;
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
        }
        self.final_status
            .as_ref()
            .ok_or_else(|| FirecrackerError::Setup("missing VMM final status".into()))
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
    }
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
        &config.workspace_image,
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

fn add_mount(
    files: &mut Vec<File>,
    mounts: &mut Vec<MountSpec>,
    path: &Path,
    target: &str,
    read_only: bool,
    executable: bool,
) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() && !metadata.is_file() {
        let identity = file_identity(file.as_raw_fd())?;
        if target != "/dev/kvm" || identity.mode & libc::S_IFMT != libc::S_IFCHR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMM mount source has an unsupported object type",
            ));
        }
    }
    let index = files.len();
    files.push(file);
    mounts.push(MountSpec {
        fd_index: index,
        target_path: target.into(),
        kind: if metadata.is_dir() {
            "directory"
        } else {
            "file"
        }
        .into(),
        read_only,
        executable,
    });
    Ok(())
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
