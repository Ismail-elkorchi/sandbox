use crate::launcher::{
    LauncherEvent, LauncherEventReader, LauncherStatus, VmmLaunchSpec, file_identity,
    read_launcher_status, send_launcher_terminate, send_vmm_launch_spec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const API_HEADER_LIMIT: usize = 64 * 1024;
const API_BODY_LIMIT: usize = 1024 * 1024;
const API_TIMEOUT: Duration = Duration::from_secs(10);
const OBSERVATION_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct FirecrackerRestore {
    pub snapshot_state: PathBuf,
    pub snapshot_memory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirecrackerSnapshot {
    pub snapshot_state: PathBuf,
    pub snapshot_memory: PathBuf,
    pub state_bytes: u64,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub launcher_executable: PathBuf,
    pub firecracker_executable: PathBuf,
    pub firecracker_sha256: String,
    pub state_directory: PathBuf,
    pub kernel_image: PathBuf,
    /// Exclusively attached, host-owned writable Linux system disk.
    pub system_disk: PathBuf,
    /// The storage owner's exclusive slot lease, transferred into the actual
    /// VMM. Never unlock a duplicate while a native attachment still exists.
    pub storage_lease: std::sync::Arc<File>,
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
    final_status: Option<crate::launcher::LauncherFinalStatus>,
    event_reader: LauncherEventReader,
    termination_requested: bool,
}

impl FirecrackerProcess {
    pub fn spawn(config: &FirecrackerConfig) -> Result<Self, FirecrackerError> {
        Self::spawn_inner(config, None)
    }

    /// Start a fresh VMM, load exactly the supplied Firecracker state and
    /// memory files, and leave the machine paused. A restore failure tears down
    /// the new VMM and is never substituted with a cold boot.
    pub fn spawn_restore(
        config: &FirecrackerConfig,
        restore: &FirecrackerRestore,
    ) -> Result<Self, FirecrackerError> {
        for path in [&restore.snapshot_state, &restore.snapshot_memory] {
            if !path.is_absolute() || !path.is_file() {
                return Err(FirecrackerError::Invalid(format!(
                    "missing snapshot input {}",
                    path.display()
                )));
            }
        }
        Self::spawn_inner(config, Some(restore))
    }

    fn spawn_inner(
        config: &FirecrackerConfig,
        restore: Option<&FirecrackerRestore>,
    ) -> Result<Self, FirecrackerError> {
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
                drive_id: "system".into(),
                path_on_host: "/vm/system".into(),
                is_root_device: true,
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
                boot_args: crate::linux_boot_arguments("ttyS0", "/dev/vda"),
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
        let system_fd_index = add_file(&mut files, &config.system_disk)?;
        let storage_lease_fd_index = files.len();
        let storage_lease_identity = file_identity(config.storage_lease.as_raw_fd())?;
        files.push(config.storage_lease.try_clone()?);
        let authentication_fd_index = add_file(&mut files, &config.authentication_image)?;
        let configuration_fd_index = add_file(&mut files, &config_path)?;
        let snapshot_state_fd_index = restore
            .map(|value| add_file(&mut files, &value.snapshot_state))
            .transpose()?;
        let snapshot_memory_fd_index = restore
            .map(|value| add_file(&mut files, &value.snapshot_memory))
            .transpose()?;

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
        files.push(crate::launcher::NamespaceLauncher::open()?.file);
        let kvm_fd_index = add_file(&mut files, Path::new("/dev/kvm"))?;
        let spec = VmmLaunchSpec {
            namespace_launcher_fd_index,
            firecracker_fd_index,
            firecracker_identity: executable_identity,
            firecracker_sha256: actual_digest,
            kernel_fd_index,
            system_fd_index,
            storage_lease_fd_index,
            storage_lease_identity,
            authentication_fd_index,
            configuration_fd_index,
            snapshot_state_fd_index,
            snapshot_memory_fd_index,
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
        let mut process = Self {
            child,
            control,
            diagnostics,
            vsock_path,
            api_socket_path,
            final_status: None,
            event_reader: LauncherEventReader::default(),
            termination_requested: false,
        };
        if restore.is_some() {
            process.wait_for_api()?;
            let body = serde_json::to_vec(&serde_json::json!({
                "snapshot_path": "/vm/snapshot-state",
                "mem_backend": {
                    "backend_type": "File",
                    "backend_path": "/vm/snapshot-memory"
                },
                "track_dirty_pages": true,
                "resume_vm": false,
                "vsock_override": { "uds_path": "/vm/state/guest.vsock" },
                "clock_realtime": true
            }))
            .map_err(|error| FirecrackerError::Invalid(error.to_string()))?;
            process.api_request("PUT", "/snapshot/load", &body, 204)?;
        }
        process.wait_for_power(if restore.is_some() {
            "Paused"
        } else {
            "Running"
        })?;
        Ok(process)
    }

    pub fn terminate(&mut self) -> Result<(), FirecrackerError> {
        if !self.termination_requested {
            send_launcher_terminate(&mut self.control)?;
            self.termination_requested = true;
        }
        Ok(())
    }

    #[must_use]
    pub fn termination_requested(&self) -> bool {
        self.termination_requested
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

    /// Create a full snapshot while the VM is paused. Files are produced in
    /// the already confined private state directory and synchronized before
    /// their paths are returned to the guardian.
    pub fn create_full_snapshot(
        &self,
        identity: &str,
    ) -> Result<FirecrackerSnapshot, FirecrackerError> {
        if identity.is_empty()
            || identity.len() > 128
            || !identity
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
        {
            return Err(FirecrackerError::Invalid(
                "snapshot identity is malformed".into(),
            ));
        }
        let state_name = format!("snapshot-{identity}.vmstate");
        let memory_name = format!("snapshot-{identity}.memory");
        let body = serde_json::to_vec(&serde_json::json!({
            "snapshot_type": "Full",
            "snapshot_path": format!("/vm/state/{state_name}"),
            "mem_file_path": format!("/vm/state/{memory_name}")
        }))
        .map_err(|error| FirecrackerError::Invalid(error.to_string()))?;
        self.api_request("PUT", "/snapshot/create", &body, 204)?;
        let directory = self
            .api_socket_path
            .parent()
            .ok_or_else(|| FirecrackerError::Invalid("API socket has no parent".into()))?;
        let snapshot_state = directory.join(state_name);
        let snapshot_memory = directory.join(memory_name);
        let state = sync_regular_file(&snapshot_state)?;
        let memory = sync_regular_file(&snapshot_memory)?;
        File::open(directory)?.sync_all()?;
        Ok(FirecrackerSnapshot {
            snapshot_state,
            snapshot_memory,
            state_bytes: state,
            memory_bytes: memory,
        })
    }

    fn patch_vm_state(&self, state: &str) -> Result<(), FirecrackerError> {
        let body = serde_json::to_vec(&serde_json::json!({ "state": state }))
            .map_err(|error| FirecrackerError::Invalid(error.to_string()))?;
        self.api_request("PATCH", "/vm", &body, 204).map(drop)
    }

    fn wait_for_api(&self) -> Result<(), FirecrackerError> {
        let deadline = Instant::now() + API_TIMEOUT;
        loop {
            match self.api_connection(deadline) {
                Ok(_) => return Ok(()),
                Err(error) if Instant::now() < deadline => {
                    if !matches!(
                        &error,
                        FirecrackerError::Io(value)
                            if matches!(
                                value.kind(),
                                io::ErrorKind::NotFound
                                    | io::ErrorKind::ConnectionRefused
                                    | io::ErrorKind::WouldBlock
                            )
                    ) {
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn wait_for_power(&mut self, expected: &str) -> Result<(), FirecrackerError> {
        let deadline = Instant::now() + API_TIMEOUT;
        loop {
            if self.has_exited()? || Instant::now() >= deadline {
                return Err(FirecrackerError::Setup(
                    "native machine did not reach its startup postcondition".into(),
                ));
            }
            match self.api_request_until("GET", "/", &[], 200, deadline) {
                Ok(bytes) => {
                    let instance = decode_instance(&bytes)?;
                    if instance.state == expected {
                        return Ok(());
                    }
                    if instance.state != "Not started" {
                        return Err(FirecrackerError::Invalid(
                            "native startup reached an unexpected power state".into(),
                        ));
                    }
                }
                Err(FirecrackerError::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn api_connection(&self, deadline: Instant) -> Result<UnixStream, FirecrackerError> {
        // Persistent Machine roots can exceed AF_UNIX's 108-byte pathname
        // bound. Resolve the already-owned state directory through a short
        // proc-fd path rather than requiring callers to choose a short root.
        let api_directory =
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(self.api_socket_path.parent().ok_or_else(|| {
                    FirecrackerError::Invalid("API socket has no parent".into())
                })?)?;
        let short_api_path = PathBuf::from(format!(
            "/proc/self/fd/{}/firecracker.socket",
            api_directory.as_raw_fd()
        ));
        Ok(sandsurf_native::unix_io::connect_socket(
            &short_api_path,
            deadline,
        )?)
    }

    fn api_request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        expected_status: u16,
    ) -> Result<Vec<u8>, FirecrackerError> {
        self.api_request_until(
            method,
            path,
            body,
            expected_status,
            Instant::now() + API_TIMEOUT,
        )
    }

    fn api_request_until(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        expected_status: u16,
        deadline: Instant,
    ) -> Result<Vec<u8>, FirecrackerError> {
        if !matches!(method, "GET" | "PUT" | "PATCH")
            || !path.starts_with('/')
            || path.bytes().any(|value| value.is_ascii_control())
            || body.len() > API_BODY_LIMIT
        {
            return Err(FirecrackerError::Invalid(
                "Firecracker API request is malformed".into(),
            ));
        }
        let mut stream = self.api_connection(deadline)?;
        let mut connection = sandsurf_native::unix_io::DeadlineIo {
            stream: &mut stream,
            deadline: Some(deadline),
        };
        write!(
            connection,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        connection.write_all(body)?;
        connection.flush()?;
        read_api_response(BufReader::with_capacity(4096, connection), expected_status)
    }

    #[must_use]
    pub fn execution_id(&self) -> u32 {
        self.child.id()
    }

    pub fn has_exited(&mut self) -> Result<bool, FirecrackerError> {
        Ok(self.child.try_wait()?.is_some())
    }

    pub fn observe_power(&mut self) -> Result<crate::NativePowerObservation, FirecrackerError> {
        if self.has_exited()? {
            let status = self.wait()?;
            if !status.tree_reaped || !status.cleanup_failures.is_empty() {
                return Err(FirecrackerError::Setup(
                    "native exit containment is unconfirmed".into(),
                ));
            }
            let evidence = serde_json::to_vec(status)
                .map_err(|error| FirecrackerError::Invalid(error.to_string()))?;
            return Ok(crate::NativePowerObservation {
                state: if status.exit_code == Some(0) {
                    sandsurf_protocol::MachineState::Stopped
                } else {
                    sandsurf_protocol::MachineState::Failed
                },
                evidence_digest: sandsurf_protocol::bytes_digest(&evidence),
            });
        }
        let bytes =
            self.api_request_until("GET", "/", &[], 200, Instant::now() + OBSERVATION_TIMEOUT)?;
        parse_instance_power(&bytes)
    }

    pub fn wait(&mut self) -> Result<&crate::launcher::LauncherFinalStatus, FirecrackerError> {
        if self.final_status.is_none() {
            match self
                .event_reader
                .read(&mut self.control, Duration::from_secs(30))?
            {
                LauncherEvent::Final(status) => self.final_status = Some(status),
                LauncherEvent::RuntimeError(error) => {
                    return Err(FirecrackerError::Setup(format!(
                        "{}: {}",
                        error.code, error.message
                    )));
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

#[derive(Deserialize)]
struct InstanceInfo {
    state: String,
}

fn decode_instance(bytes: &[u8]) -> Result<InstanceInfo, FirecrackerError> {
    serde_json::from_slice(bytes).map_err(|error| FirecrackerError::Invalid(error.to_string()))
}

fn parse_instance_power(bytes: &[u8]) -> Result<crate::NativePowerObservation, FirecrackerError> {
    let instance = decode_instance(bytes)?;
    let state = match instance.state.as_str() {
        "Running" => sandsurf_protocol::MachineState::Running,
        "Paused" => sandsurf_protocol::MachineState::Paused,
        // Not started is not proof of a terminated, previously running VM.
        _ => {
            return Err(FirecrackerError::Invalid(
                "native power state is indeterminate".into(),
            ));
        }
    };
    Ok(crate::NativePowerObservation {
        state,
        evidence_digest: sandsurf_protocol::bytes_digest(bytes),
    })
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

/// Bounded native-control decoding. The caller supplies the transport's single
/// absolute deadline; buffering does not admit unbounded lines or chunked data.
pub fn read_api_response(
    mut reader: impl BufRead,
    expected_status: u16,
) -> Result<Vec<u8>, FirecrackerError> {
    let mut response = Vec::new();
    loop {
        let remaining = API_HEADER_LIMIT - response.len();
        let count = (&mut reader)
            .take(remaining as u64)
            .read_until(b'\n', &mut response)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete native API headers",
            )
            .into());
        }
        if count < 2 || !response.ends_with(b"\r\n") {
            return Err(FirecrackerError::Setup(
                "native API requires CRLF-delimited headers".into(),
            ));
        }
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() == API_HEADER_LIMIT {
            return Err(FirecrackerError::Setup(
                "native API headers exceed 64 KiB".into(),
            ));
        }
    }
    let mut lines = response[..response.len() - 4].split(|byte| *byte == b'\n');
    let status = lines
        .next()
        .ok_or_else(|| FirecrackerError::Setup("native API status missing".into()))?;
    let status = status.strip_suffix(b"\r").unwrap_or(status);
    if status
        .iter()
        .any(|byte| (*byte < 32 && *byte != b'\t') || *byte >= 127)
    {
        return Err(FirecrackerError::Setup(
            "native API status contains invalid bytes".into(),
        ));
    }
    let status = std::str::from_utf8(status)
        .map_err(|_| FirecrackerError::Setup("native API status is not UTF-8".into()))?;
    let mut status_fields = status.split_ascii_whitespace();
    let protocol = status_fields.next();
    let code = status_fields
        .next()
        .filter(|code| code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..=599).contains(code));
    if protocol != Some("HTTP/1.1") || code.is_none() {
        return Err(FirecrackerError::Setup(
            "native API status line is invalid".into(),
        ));
    }
    let mut content_length = None;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| FirecrackerError::Setup("native API header is invalid".into()))?;
        let (name, value) = (&line[..separator], &line[separator + 1..]);
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
            || value
                .iter()
                .any(|byte| (*byte < 32 && *byte != b'\t') || *byte == 127)
        {
            return Err(FirecrackerError::Setup(
                "native API header contains invalid bytes".into(),
            ));
        }
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(FirecrackerError::Setup(
                "native API transfer encoding is unsupported".into(),
            ));
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(FirecrackerError::Setup(
                    "native API content length is duplicated".into(),
                ));
            }
            let digits = std::str::from_utf8(value)
                .map_err(|_| {
                    FirecrackerError::Setup("native API content length is invalid".into())
                })?
                .trim();
            let length = (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| digits.parse::<usize>().ok())
                .flatten()
                .filter(|length| *length <= API_BODY_LIMIT)
                .ok_or_else(|| {
                    FirecrackerError::Setup(
                        "native API body exceeds 1 MiB or has invalid length".into(),
                    )
                })?;
            content_length = Some(length);
        }
    }
    let length = match (code, content_length) {
        (Some(204), None | Some(0)) => 0,
        (Some(204), _) => {
            return Err(FirecrackerError::Setup(
                "native API 204 response carries a body".into(),
            ));
        }
        (_, Some(length)) => length,
        _ => {
            return Err(FirecrackerError::Setup(
                "native API response length missing".into(),
            ));
        }
    };
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    if code != Some(expected_status) {
        return Err(FirecrackerError::Setup(format!(
            "native API rejected request: {}: {}",
            status.trim(),
            String::from_utf8_lossy(&body[..body.len().min(4096)])
        )));
    }
    Ok(body)
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
        &config.system_disk,
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

fn sync_regular_file(path: &Path) -> Result<u64, FirecrackerError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(FirecrackerError::Setup(
            "Firecracker produced an empty or non-regular snapshot artifact".into(),
        ));
    }
    file.sync_all()?;
    Ok(metadata.len())
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

#[cfg(test)]
mod control_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn instance_power_is_native_evidence_and_indeterminate_states_are_not_shutdown() {
        for (wire, state) in [
            ("Running", sandsurf_protocol::MachineState::Running),
            ("Paused", sandsurf_protocol::MachineState::Paused),
        ] {
            let bytes = format!(
                "{{\"state\":\"{wire}\",\"id\":\"anonymous-instance\",\"vmm_version\":\"qualified-by-caller\"}}"
            );
            let observation = parse_instance_power(bytes.as_bytes()).unwrap();
            assert_eq!(observation.state, state);
            assert_eq!(
                observation.evidence_digest,
                sandsurf_protocol::bytes_digest(bytes.as_bytes())
            );
        }
        for bytes in [
            b"{}".as_slice(),
            br#"{"state":"Not started"}"#,
            br#"{"state":"Stopped"}"#,
            br#"{"state":"Running","state":"Paused"}"#,
        ] {
            assert!(parse_instance_power(bytes).is_err());
        }
    }

    #[test]
    fn native_http_response_is_binary_exact_strict_and_bounded() {
        let body = b"\0\xff\x80\x01";
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".to_vec();
        response.extend_from_slice(body);
        assert_eq!(
            read_api_response(Cursor::new(&response), 200).unwrap(),
            body
        );
        assert!(read_api_response(Cursor::new(&response), 204).is_err());
        assert!(
            read_api_response(Cursor::new(b"HTTP/1.1 204 No Content\r\n\r\n"), 204)
                .unwrap()
                .is_empty()
        );
        for malformed in [
            &b"HTTP/1.1 200 OK\nContent-Length: 0\n\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc"[..],
            &b"HTTP/1.1 200 OK\r\n\r\n"[..],
            &b"HTTP/1.1 200 \0\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 000 OK\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n"[..],
        ] {
            assert!(
                read_api_response(Cursor::new(malformed), 200).is_err(),
                "{malformed:?}"
            );
        }
        let mut oversized = b"HTTP/1.1 200 OK\r\nX-Header: ".to_vec();
        oversized.resize(API_HEADER_LIMIT + 4096, b'x');
        let mut cursor = Cursor::new(&oversized);
        assert!(read_api_response(&mut cursor, 200).is_err());
        assert_eq!(
            cursor.position(),
            API_HEADER_LIMIT as u64,
            "do not read past the header allocation bound"
        );
    }

    #[test]
    fn slow_native_response_has_one_operation_deadline() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let writer = std::thread::spawn(move || {
            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" {
                if server.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let start = Instant::now();
        let transport = sandsurf_native::unix_io::DeadlineIo {
            stream: &mut client,
            deadline: Some(start + Duration::from_millis(100)),
        };
        assert!(
            matches!(read_api_response(BufReader::new(transport), 200), Err(FirecrackerError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(client);
        writer.join().unwrap();
    }
}
