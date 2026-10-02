//! The Darwin privileged boundary launches only installed, fixed Sandsurf
//! workers. It applies limits to its own unreaped children, never supplied PIDs.
//! Grants, Linux state and machine lifecycle remain outside this boundary.
#[cfg(any(target_os = "macos", test))]
use crate::process_budget::ProcessBudget;
use std::io;

#[cfg(any(target_os = "macos", test))]
const HEADER_BYTES: usize = 32;
#[cfg(any(target_os = "macos", test))]
const MAGIC: [u8; 8] = *b"SSBUD001";
#[cfg(target_os = "macos")]
const READY: [u8; 8] = *b"SSRDY001";
#[cfg(target_os = "macos")]
const APPLIED: [u8; 8] = *b"SSACK001";
#[cfg(target_os = "macos")]
const TERMINATE: [u8; 8] = *b"SSTERM01";
#[cfg(target_os = "macos")]
const MEASURE: [u8; 8] = *b"SSUSG001";
pub const BROKER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub const BROKER_CPU_MICROS: u64 = 10000;

/// Native child termination reported by its retained privileged parent. The
/// broker dying without this evidence does not establish that its worker died.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExit {
    Exited(i32),
    Signaled(i32),
}

/// Includes both the retained privileged owner and its original worker. No
/// guest observation, PID adoption, or sum of unrelated per-process peaks.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerUsage {
    pub owner_start_ticks: u64,
    pub worker_start_ticks: u64,
    pub cpu_micros: u64,
    pub memory_current: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
}

#[cfg(any(target_os = "macos", test))]
impl WorkerUsage {
    fn encode(value: Option<Self>) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..8].copy_from_slice(b"SSUSAGE1");
        if let Some(value) = value {
            bytes[8] = 1;
            for (offset, value) in [
                value.owner_start_ticks,
                value.worker_start_ticks,
                value.cpu_micros,
                value.memory_current,
                value.io_read_bytes,
                value.io_write_bytes,
            ]
            .into_iter()
            .enumerate()
            {
                bytes[16 + offset * 8..24 + offset * 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    fn decode(bytes: &[u8; 64]) -> io::Result<Self> {
        if &bytes[..8] != b"SSUSAGE1" || bytes[9..16] != [0; 7] {
            return Err(invalid("invalid native usage envelope"));
        }
        if bytes[8] == 0 && bytes[16..] == [0; 48] {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native usage is unavailable",
            ));
        }
        if bytes[8] != 1 {
            return Err(invalid("invalid native usage discriminant"));
        }
        let value = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let usage = Self {
            owner_start_ticks: value(16),
            worker_start_ticks: value(24),
            cpu_micros: value(32),
            memory_current: value(40),
            io_read_bytes: value(48),
            io_write_bytes: value(56),
        };
        if usage.owner_start_ticks == 0 || usage.worker_start_ticks == 0 {
            return Err(invalid("native usage lacks original process lifetimes"));
        }
        Ok(usage)
    }
}

#[cfg(any(target_os = "macos", test))]
impl WorkerExit {
    fn encode(self) -> io::Result<[u8; 16]> {
        let (kind, value) = match self {
            Self::Exited(value) if (0..=255).contains(&value) => (1, value),
            Self::Signaled(value) if (1..=64).contains(&value) => (2, value),
            _ => return Err(invalid("invalid native worker exit")),
        };
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(b"SSEXIT01");
        bytes[8] = kind;
        bytes[12..].copy_from_slice(&value.to_le_bytes());
        Ok(bytes)
    }
    fn decode(bytes: &[u8; 16]) -> io::Result<Self> {
        if &bytes[..8] != b"SSEXIT01" || bytes[9..12] != [0; 3] {
            return Err(invalid("invalid native exit evidence envelope"));
        }
        let value = i32::from_le_bytes(bytes[12..].try_into().unwrap());
        let exit = match bytes[8] {
            1 => Self::Exited(value),
            2 => Self::Signaled(value),
            _ => return Err(invalid("invalid native exit evidence discriminant")),
        };
        exit.encode()?;
        Ok(exit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerKind {
    Api,
    Supervisor,
    Images,
    Guardian,
    VirtualMachine,
}

impl WorkerKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Supervisor => "supervisor",
            Self::Images => "images",
            Self::Guardian => "guardian",
            Self::VirtualMachine => "virtual-machine",
        }
    }

    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "api" => Ok(Self::Api),
            "supervisor" => Ok(Self::Supervisor),
            "images" => Ok(Self::Images),
            "guardian" => Ok(Self::Guardian),
            "virtual-machine" => Ok(Self::VirtualMachine),
            _ => Err(invalid("unknown installed worker role")),
        }
    }

    pub fn host_mode(self) -> Option<&'static str> {
        match self {
            Self::Api => Some("serve"),
            Self::Supervisor => Some("supervise"),
            Self::Images => Some("image-worker"),
            Self::Guardian => Some("guardian"),
            Self::VirtualMachine => None,
        }
    }

    pub fn durable(self) -> bool {
        self != Self::VirtualMachine
    }
}

#[cfg(any(target_os = "macos", test))]
fn argument_bounds(kind: WorkerKind) -> (usize, usize) {
    match kind {
        WorkerKind::VirtualMachine => (128, 64 * 1024),
        _ => (16, 16 * 1024),
    }
}

/// Split an admitted envelope, never add a second allowance outside it. The
/// broker and worker are exactly two processes; their CPU and footprint caps
/// sum to the caller's envelope. The owner installs both ledgers after exec.
pub fn worker_budget(
    envelope: crate::process_budget::ProcessBudget,
) -> io::Result<crate::process_budget::ProcessBudget> {
    let worker = crate::process_budget::ProcessBudget {
        cpu_quota_micros: envelope
            .cpu_quota_micros
            .checked_sub(BROKER_CPU_MICROS)
            .ok_or_else(|| invalid("CPU envelope cannot contain the native owner"))?,
        memory_bytes: envelope
            .memory_bytes
            .checked_sub(BROKER_MEMORY_BYTES)
            .ok_or_else(|| invalid("memory envelope cannot contain the native owner"))?,
        processes: 1,
    };
    envelope.validate()?;
    worker.validate()?;
    if envelope.processes != 2
        || !worker.cpu_quota_micros.is_multiple_of(1000)
        || worker.cpu_quota_micros > 255000
        || !worker.memory_bytes.is_multiple_of(1024 * 1024)
        || worker.memory_bytes > i32::MAX as u64 * 1024 * 1024
    {
        return Err(invalid("native owner/worker envelope is not representable"));
    }
    Ok(worker)
}

#[cfg(any(target_os = "macos", test))]
fn encode(budget: ProcessBudget) -> io::Result<[u8; HEADER_BYTES]> {
    validate(budget)?;
    let mut bytes = [0; HEADER_BYTES];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..16].copy_from_slice(&budget.cpu_quota_micros.to_le_bytes());
    bytes[16..24].copy_from_slice(&budget.memory_bytes.to_le_bytes());
    bytes[24..28].copy_from_slice(&budget.processes.to_le_bytes());
    Ok(bytes)
}

#[cfg(any(target_os = "macos", test))]
fn decode(bytes: &[u8; HEADER_BYTES]) -> io::Result<ProcessBudget> {
    if bytes[..8] != MAGIC || bytes[28..] != [0; 4] {
        return Err(invalid("invalid native broker budget envelope"));
    }
    let budget = ProcessBudget {
        cpu_quota_micros: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        memory_bytes: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        processes: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
    };
    validate(budget)?;
    Ok(budget)
}

#[cfg(any(target_os = "macos", test))]
fn validate(budget: ProcessBudget) -> io::Result<()> {
    budget.validate()?;
    if budget.processes != 1
        || !budget.memory_bytes.is_multiple_of(1024 * 1024)
        || budget.memory_bytes > i32::MAX as u64 * 1024 * 1024
        || !budget.cpu_quota_micros.is_multiple_of(1000)
        || budget.cpu_quota_micros > 255000
    {
        return Err(invalid(
            "budget is not representable by an owned Darwin worker",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(target_os = "macos")]
pub mod macos {
    static APPLIED_BUDGET: std::sync::OnceLock<super::ProcessBudget> = std::sync::OnceLock::new();
    type UsageReply = std::sync::mpsc::SyncSender<io::Result<WorkerUsage>>;
    static USAGE_REQUESTS: std::sync::OnceLock<std::sync::mpsc::SyncSender<UsageReply>> =
        std::sync::OnceLock::new();

    /// Query through the root-owned gate. Its sole reader also watches owner
    /// death; concurrent queries cannot steal lifecycle bytes from that reader.
    pub fn current_worker_usage() -> io::Result<WorkerUsage> {
        let requests = USAGE_REQUESTS
            .get()
            .ok_or_else(|| invalid("native worker gate unavailable"))?;
        let (reply, result) = std::sync::mpsc::sync_channel(1);
        requests
            .try_send(reply)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "native usage query is busy"))?;
        result
            .recv_timeout(HANDSHAKE_TIMEOUT)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native usage query timed out"))?
    }

    /// Observation sealed by the root-owned entry gate, not an environment
    /// variable or guest assertion. It cannot authorize a different envelope.
    pub fn current_worker_budget() -> Option<super::ProcessBudget> {
        APPLIED_BUDGET.get().copied()
    }

    pub fn receive_image_lease(path: &std::path::Path) -> std::io::Result<std::fs::File> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let expected =
            super::worker_budget(crate::service_pool::ServicePool::Images.process_budget())?;
        if current_worker_budget() != Some(expected) {
            return Err(super::invalid(
                "image worker has no verified native allowance",
            ));
        }
        // SAFETY: fstat validates the fixed explicitly transferred slot before
        // this one entrypoint takes ownership; no ambient descriptor is adopted.
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(5, &mut metadata) } != 0
            || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(super::invalid("missing inherited image custody"));
        }
        // SAFETY: the installed broker transfers this one reference into slot 5.
        let file = unsafe { std::fs::File::from_raw_fd(5) };
        crate::storage::verify_transferred_lease(&file, path)?;
        // SAFETY: stop incidental inheritance; an appliance launch must transfer
        // this held description explicitly, never reacquire its pathname.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(file)
    }
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::Duration;

    const INSTALLATION: &str = "/usr/local/libexec/sandsurf";
    const BROKER: &str = "/usr/local/libexec/sandsurf/sandsurf-resource-broker";
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

    fn credential(stream: &UnixStream) -> io::Result<libc::uid_t> {
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: stream is retained; both outputs have the public uid/gid ABI.
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }

    fn timed(stream: &UnixStream) -> io::Result<()> {
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
    }

    /// Holds the original native lease. Dropping it requests containment, not
    /// Linux shutdown; client disconnection must not drop a guardian's lease.
    pub struct OwnedWorker {
        broker: Option<Child>,
        lease: UnixStream,
        worker_pid: u32,
        kind: WorkerKind,
        exit: Option<WorkerExit>,
    }

    impl OwnedWorker {
        pub fn process_id(&self) -> u32 {
            self.worker_pid
        }

        pub fn usage(&mut self) -> io::Result<WorkerUsage> {
            if self.try_wait()?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native worker exited",
                ));
            }
            self.lease.write_all(&MEASURE)?;
            let mut bytes = [0; 8];
            self.lease.read_exact(&mut bytes)?;
            if &bytes == b"SSEXIT01" {
                let mut exit = [0; 16];
                exit[..8].copy_from_slice(&bytes);
                self.lease.read_exact(&mut exit[8..])?;
                self.exit = Some(WorkerExit::decode(&exit)?);
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native worker exited during measurement",
                ));
            }
            let mut usage = [0; 64];
            usage[..8].copy_from_slice(&bytes);
            self.lease.read_exact(&mut usage[8..])?;
            WorkerUsage::decode(&usage)
        }

        pub fn wait(&mut self) -> io::Result<WorkerExit> {
            self.broker
                .as_mut()
                .ok_or_else(|| invalid("native owner detached"))?
                .wait()?;
            self.read_exit()
        }

        pub fn try_wait(&mut self) -> io::Result<Option<WorkerExit>> {
            if self
                .broker
                .as_mut()
                .ok_or_else(|| invalid("native owner detached"))?
                .try_wait()?
                .is_none()
            {
                return Ok(None);
            }
            self.read_exit().map(Some)
        }

        fn read_exit(&mut self) -> io::Result<WorkerExit> {
            if let Some(exit) = self.exit {
                return Ok(exit);
            }
            let mut bytes = [0; 16];
            self.lease.read_exact(&mut bytes)?;
            let exit = WorkerExit::decode(&bytes)?;
            self.exit = Some(exit);
            Ok(exit)
        }

        pub fn terminate(&mut self) -> io::Result<()> {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            self.lease.write_all(&TERMINATE)?;
            self.wait().map(|_| ())
        }
    }

    impl Drop for OwnedWorker {
        fn drop(&mut self) {
            if !self.kind.durable() {
                let _ = self.lease.shutdown(std::net::Shutdown::Both);
                let _ = self.wait();
            } else {
                // A durable service owns its lifetime, not this client handle.
                // Reap if this client survives; parent exit is handled by the OS.
                let _ = self.lease.shutdown(std::net::Shutdown::Both);
                if let Some(mut child) = self.broker.take() {
                    let _ = std::thread::Builder::new()
                        .name("native-service-reaper".into())
                        .spawn(move || {
                            let _ = child.wait();
                        });
                }
            }
        }
    }

    fn inherited_socket(fd: i32) -> io::Result<UnixStream> {
        let mut kind = 0;
        let mut bytes = std::mem::size_of_val(&kind) as libc::socklen_t;
        // SAFETY: the scalar descriptor may be invalid; getsockopt checks it
        // before writing to the exact socket-type ABI output and length slot.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut kind).cast(),
                &mut bytes,
            )
        } != 0
            || bytes as usize != std::mem::size_of_val(&kind)
            || kind != libc::SOCK_STREAM
        {
            return Err(io::Error::other(
                "native entry requires an inherited stream socket",
            ));
        }
        // SAFETY: a valid open stream is established above. This entrypoint
        // takes sole ownership of the fixed inherited descriptor exactly once.
        Ok(unsafe { UnixStream::from_raw_fd(fd) })
    }

    /// Resolve only the operator's immutable installation. This never installs
    /// a setuid file, changes privileges on disk, or executes an SDK-selected
    /// binary as root. Operator installation is an explicit prerequisite.
    fn protected_installed(name: &str, setuid: bool) -> io::Result<PathBuf> {
        let path = Path::new(INSTALLATION).join(name);
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || (metadata.mode() & 0o4000 != 0) != setuid
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker installation is not root-owned and immutable",
            ));
        }
        crate::macos::require_protected_ancestor_acl(&path)?;
        for parent in path.parent().into_iter().flat_map(Path::ancestors) {
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            crate::macos::require_protected_ancestor_acl(parent)?;
        }
        Ok(path)
    }

    pub fn virtual_machine_executable() -> io::Result<PathBuf> {
        protected_installed(
            if cfg!(target_arch = "aarch64") {
                "sandsurf-qemu-arm64"
            } else {
                "sandsurf-qemu-x64"
            },
            false,
        )
    }

    /// Launch one fixed installed worker. Arguments are bounded and passed to
    /// the worker only after credentials have been irreversibly dropped. The
    /// privileged broker does not open configuration, machine disks or secrets.
    pub fn launch(
        kind: WorkerKind,
        budget: ProcessBudget,
        arguments: &[OsString],
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> io::Result<OwnedWorker> {
        if matches!(kind, WorkerKind::VirtualMachine | WorkerKind::Images) {
            return Err(invalid(
                "this worker role requires transferred storage custody",
            ));
        }
        launch_inner(kind, budget, arguments, None, stdin, stdout, stderr)
    }

    /// One admitted image slot is acquired before fork and follows the worker,
    /// including when the API or original supervisor disconnects.
    pub fn launch_images(
        arguments: &[OsString],
        custody: Arc<fs::File>,
    ) -> io::Result<OwnedWorker> {
        launch_inner(
            WorkerKind::Images,
            crate::service_pool::ServicePool::Images.process_budget(),
            arguments,
            Some(custody),
            Stdio::null(),
            Stdio::null(),
            Stdio::null(),
        )
    }

    /// The native worker and its unreaped parent keep the original open file
    /// description. Guardian death cannot release a VM's disk lease early.
    pub fn launch_vm(
        budget: ProcessBudget,
        arguments: &[OsString],
        custody: Arc<fs::File>,
        stderr: Stdio,
    ) -> io::Result<OwnedWorker> {
        launch_inner(
            WorkerKind::VirtualMachine,
            budget,
            arguments,
            Some(custody),
            Stdio::null(),
            Stdio::null(),
            stderr,
        )
    }

    fn launch_inner(
        kind: WorkerKind,
        budget: ProcessBudget,
        arguments: &[OsString],
        custody: Option<Arc<fs::File>>,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> io::Result<OwnedWorker> {
        validate_arguments(kind, arguments)?;
        let applied = worker_budget(budget)?;
        protected_installed("sandsurf-resource-broker", true)?;
        let (mut lease, peer) = UnixStream::pair()?;
        timed(&lease)?;
        // Move both sources above the fixed descriptor slots before fork.
        // Otherwise dup2 of one source could overwrite the other source.
        let duplicate = |fd| -> io::Result<OwnedFd> {
            // SAFETY: a retained source FD, owned CLOEXEC duplicate and scalar bound.
            let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 16) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful fcntl returned one newly owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        };
        let source = duplicate(peer.as_raw_fd())?;
        let storage = custody
            .as_ref()
            .map(|file| duplicate(file.as_raw_fd()))
            .transpose()?;
        let fd = source.as_raw_fd();
        let storage_fd = storage.as_ref().map(AsRawFd::as_raw_fd);
        let mut command = Command::new(BROKER);
        command
            .env_clear()
            .args([
                kind.name(),
                &budget.cpu_quota_micros.to_string(),
                &budget.memory_bytes.to_string(),
            ])
            .args(arguments)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr);
        // SAFETY: the closure invokes only async-signal-safe descriptor calls;
        // peer is retained until spawn and this is a newly forked child.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(3);
                if let Some(fd) = storage_fd {
                    if libc::dup2(fd, 5) < 0 || libc::fcntl(5, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else {
                    libc::close(5);
                }
                Ok(())
            });
        }
        let mut broker = command.spawn()?;
        drop(peer);
        let receipt = (|| {
            let mut bytes = [0; 4];
            lease.read_exact(&mut bytes)?;
            let pid = u32::from_le_bytes(bytes);
            if pid == 0 || pid == broker.id() {
                return Err(invalid("invalid owned-worker identity"));
            }
            let mut readback = [0; HEADER_BYTES];
            lease.read_exact(&mut readback)?;
            if decode(&readback)? != applied {
                return Err(invalid("broker applied a different worker allowance"));
            }
            if crate::socket_io::peer_process(&socket2::Socket::from(OwnedFd::from(
                lease.try_clone()?,
            )))? != broker.id()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "worker receipt was not sent by the retained broker",
                ));
            }
            Ok(pid)
        })();
        match receipt {
            Ok(worker_pid) => Ok(OwnedWorker {
                broker: Some(broker),
                lease,
                worker_pid,
                kind,
                exit: None,
            }),
            Err(error) => {
                let _ = lease.write_all(&TERMINATE);
                let _ = lease.shutdown(std::net::Shutdown::Both);
                let _ = broker.wait();
                Err(error)
            }
        }
    }

    fn validate_arguments(kind: WorkerKind, arguments: &[OsString]) -> io::Result<()> {
        let (maximum_count, maximum_bytes) = argument_bounds(kind);
        if arguments.len() > maximum_count
            || arguments
                .iter()
                .map(|value| value.as_encoded_bytes().len())
                .sum::<usize>()
                > maximum_bytes
            || arguments.iter().any(|value| {
                value.as_encoded_bytes().len() > 4096 || value.as_encoded_bytes().contains(&0)
            })
        {
            return Err(invalid(
                "worker arguments exceed the bounded launch envelope",
            ));
        }
        Ok(())
    }

    /// The single-threaded elevated entrypoint discards all caller descriptors
    /// except stdio and the original owner lease. Enumerate actual open FDs,
    /// not RLIMIT_NOFILE: a caller may lower that limit after opening high FDs.
    fn discard_inherited_descriptors() -> io::Result<()> {
        let mut entries = [libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        }; 16384];
        // SAFETY: fixed initialized native FD-list output for this process.
        let count = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                std::mem::size_of_val(&entries) as i32,
            )
        };
        if count <= 0
            || count as usize >= std::mem::size_of_val(&entries)
            || !(count as usize).is_multiple_of(std::mem::size_of::<libc::proc_fdinfo>())
        {
            return Err(io::Error::other(
                "inherited descriptor inventory is incomplete",
            ));
        }
        for entry in &entries[..count as usize / std::mem::size_of::<libc::proc_fdinfo>()] {
            let fd = entry.proc_fd;
            if fd < 0 {
                return Err(io::Error::other("invalid native descriptor inventory"));
            }
            if fd >= 3 && fd != 4 && fd != 5 {
                // SAFETY: the single-threaded broker exclusively owns each
                // enumerated descriptor; no concurrent code can reuse an FD.
                if unsafe { libc::close(fd) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    /// Called at entry in the final executable, before starting worker threads,
    /// touching any guest input, or creating a hardware partition. FD 3 is a
    /// private broker-created socket, not an environment-variable attestation.
    pub fn enter_worker() -> io::Result<ProcessBudget> {
        let mut socket = inherited_socket(3)?;
        // SAFETY: the adopted live socket must never leak to subsequently
        // launched broker/worker executables, even when dup2 was a no-op.
        if unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if credential(&socket)? != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // SAFETY: this scalar credential query must show privileges were dropped.
        if unsafe { libc::geteuid() } == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        timed(&socket)?;
        socket.write_all(&READY)?;
        let mut bytes = [0; HEADER_BYTES];
        socket.read_exact(&mut bytes)?;
        // SAFETY: getppid is a scalar parent-identity query. The elevated owner
        // must still be alive and must have written this gate's budget itself.
        let parent = unsafe { libc::getppid() };
        if parent <= 1
            || crate::socket_io::peer_process(&socket2::Socket::from(OwnedFd::from(
                socket.try_clone()?,
            )))? != parent as u32
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let budget = decode(&bytes)?;
        socket.write_all(&APPLIED)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        socket.set_write_timeout(None)?;
        // A dead privileged owner closes this socket. The fixed installed
        // worker contains itself even if no orderly broker cleanup can run.
        let (requests, receiver) = std::sync::mpsc::sync_channel::<UsageReply>(1);
        USAGE_REQUESTS
            .set(requests)
            .map_err(|_| invalid("native usage gate was already consumed"))?;
        std::thread::Builder::new()
            .name("native-owner-lease".into())
            .spawn(move || {
                let mut byte = [0];
                loop {
                    if let Ok(reply) = receiver.try_recv() {
                        socket
                            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
                            .unwrap_or_else(|_| std::process::exit(70));
                        let mut bytes = [0; 64];
                        if socket
                            .write_all(&MEASURE)
                            .and_then(|()| socket.read_exact(&mut bytes))
                            .is_err()
                        {
                            std::process::exit(70);
                        }
                        let _ = reply.send(WorkerUsage::decode(&bytes));
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .unwrap_or_else(|_| std::process::exit(70));
                    }
                    match socket.read(&mut byte) {
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::Interrupted
                                    | io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue;
                        }
                        _ => std::process::exit(70),
                    }
                }
            })?;
        APPLIED_BUDGET
            .set(budget)
            .map_err(|_| invalid("native entry gate was already consumed"))?;
        Ok(budget)
    }

    /// Entrypoint of the separately operator-installed setuid broker. No request
    /// names a PID or an executable. All parsing is bounded before spawning.
    pub fn run() -> io::Result<i32> {
        // SAFETY: only scalar credential queries; real UID identifies the caller.
        let (uid, gid, privileged) = unsafe { (libc::getuid(), libc::getgid(), libc::geteuid()) };
        if uid == 0 || privileged != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        discard_inherited_descriptors()?;
        crate::process_budget::macos::install_broker_current()?;
        let mut owner = inherited_socket(4)?;
        if credential(&owner)? != uid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        timed(&owner)?;
        let mut args = std::env::args_os().skip(1);
        let kind = WorkerKind::parse(
            &args
                .next()
                .and_then(|v| v.into_string().ok())
                .ok_or_else(|| invalid("missing worker role"))?,
        )?;
        let number = |value: Option<OsString>| -> io::Result<u64> {
            value
                .and_then(|v| v.into_string().ok())
                .filter(|v| v.len() <= 20)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| invalid("invalid worker allowance"))
        };
        let budget = ProcessBudget {
            cpu_quota_micros: number(args.next())?,
            memory_bytes: number(args.next())?,
            processes: 2,
        };
        let budget = worker_budget(budget)?;
        let args: Vec<_> = args.take(argument_bounds(kind).0 + 1).collect();
        validate_arguments(kind, &args)?;
        if matches!(kind, WorkerKind::VirtualMachine | WorkerKind::Images) {
            // SAFETY: initialized native stat output for the inherited lease,
            // never a host pathname opened with elevated credentials.
            let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: fstat checks the scalar FD before bounded output write.
            if unsafe { libc::fstat(5, &mut metadata) } != 0
                || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                || metadata.st_uid != uid
                || metadata.st_nlink != 1
                || metadata.st_mode & 0o077 != 0
            {
                return Err(invalid(
                    "native worker has no private transferred storage lease",
                ));
            }
        } else {
            // SAFETY: the single-threaded broker discards any caller-selected
            // storage descriptor; ordinary service workers inherit no custody.
            unsafe { libc::close(5) };
        }
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        };
        let program = protected_installed(
            &match kind {
                WorkerKind::VirtualMachine => format!("sandsurf-qemu-{arch}"),
                _ => format!("sandsurf-host-macos-{arch}"),
            },
            false,
        )?;
        let (mut gate, peer) = UnixStream::pair()?;
        timed(&gate)?;
        let fd = peer.as_raw_fd();
        let mut command = Command::new(program);
        command
            .env_clear()
            .arg("--broker-worker")
            .arg(kind.name())
            .args(&args);
        // SAFETY: a fresh child calls only async-signal-safe credential/FD
        // operations before exec. No user data is opened with root credentials.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(4);
                if fd != 3 {
                    libc::close(fd);
                }
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = BrokerChild(command.spawn()?);
        drop(peer);
        let mut ready = [0; 8];
        gate.read_exact(&mut ready)?;
        if ready != READY {
            return Err(invalid("installed worker did not enter the native gate"));
        }
        // Crucially after exec, before releasing the worker to initialize VM or
        // service code. The child has not been reaped, so PID reuse is impossible.
        crate::process_budget::macos::install_owned(&child.0, budget)?;
        gate.write_all(&encode(budget)?)?;
        gate.read_exact(&mut ready)?;
        if ready != APPLIED {
            return Err(invalid(
                "installed worker did not acknowledge the native gate",
            ));
        }
        owner.write_all(&child.0.id().to_le_bytes())?;
        owner.write_all(&encode(budget)?)?;
        // Fixed, bounded privileged supervisor; no privileged worker threads or
        // guest parsers. Closing the original owner lease contains its own child.
        owner.set_read_timeout(Some(Duration::from_millis(100)))?;
        owner.set_write_timeout(Some(Duration::from_secs(1)))?;
        gate.set_read_timeout(Some(Duration::from_millis(100)))?;
        gate.set_write_timeout(Some(Duration::from_secs(1)))?;
        let deadline = if kind == WorkerKind::Images {
            Some(std::time::Instant::now() + Duration::from_secs(300))
        } else {
            None
        };
        let mut connected = true;
        let mut commands = [[0; 8]; 2];
        let mut filled = [0; 2];
        loop {
            if let Some(status) = child.0.try_wait()? {
                send_exit(&mut owner, status);
                return Ok(status.code().unwrap_or(1));
            }
            if deadline.is_some_and(|value| std::time::Instant::now() >= value) {
                child.0.kill()?;
                let status = child.0.wait()?;
                send_exit(&mut owner, status);
                return Ok(1);
            }
            let mut sockets = [
                libc::pollfd {
                    fd: if connected { owner.as_raw_fd() } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if kind == WorkerKind::VirtualMachine {
                        -1
                    } else {
                        gate.as_raw_fd()
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: two fixed, retained stream descriptors and exact writable
            // poll records. No request can supply another target or descriptor.
            let ready = unsafe { libc::poll(sockets.as_mut_ptr(), 2, 100) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            for index in 0..2 {
                if sockets[index].revents == 0 {
                    continue;
                }
                let stream = if index == 0 { &mut owner } else { &mut gate };
                match stream.read(&mut commands[index][filled[index]..]) {
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Ok(0) if index == 0 && kind.durable() && filled[index] == 0 => {
                        connected = false;
                    }
                    Ok(count) if count != 0 => {
                        filled[index] += count;
                        if filled[index] < 8 {
                            continue;
                        }
                        filled[index] = 0;
                        if commands[index] == MEASURE {
                            // An unavailable observation never becomes a power
                            // decision. A child exiting during the query returns
                            // an absent measurement, then ordinary exit evidence.
                            if let Err(error) =
                                stream.write_all(&WorkerUsage::encode(measure_owned(&child.0).ok()))
                            {
                                if index == 0 && kind.durable() {
                                    connected = false;
                                } else {
                                    return Err(error);
                                }
                            }
                        } else if index == 0 && commands[index] == TERMINATE {
                            child.0.kill()?;
                            let status = child.0.wait()?;
                            send_exit(&mut owner, status);
                            return Ok(0);
                        } else {
                            return Err(invalid("invalid native owner command"));
                        }
                    }
                    _ => {
                        child.0.kill()?;
                        let status = child.0.wait()?;
                        send_exit(&mut owner, status);
                        return Ok(0);
                    }
                }
            }
        }
    }

    fn measure_owned(child: &Child) -> io::Result<WorkerUsage> {
        let owner = crate::process_budget::macos::current_usage()?;
        let worker = crate::process_budget::macos::owned_usage(child)?;
        let sum = |a: u64, b: u64| {
            a.checked_add(b)
                .ok_or_else(|| io::Error::other("native measurement overflow"))
        };
        Ok(WorkerUsage {
            owner_start_ticks: owner.start_ticks,
            worker_start_ticks: worker.start_ticks,
            cpu_micros: sum(owner.cpu_micros, worker.cpu_micros)?,
            memory_current: sum(owner.physical_footprint, worker.physical_footprint)?,
            io_read_bytes: sum(owner.io_read_bytes, worker.io_read_bytes)?,
            io_write_bytes: sum(owner.io_write_bytes, worker.io_write_bytes)?,
        })
    }

    fn send_exit(owner: &mut UnixStream, status: std::process::ExitStatus) {
        let exit = if let Some(code) = status.code() {
            WorkerExit::Exited(code)
        } else if let Some(signal) = status.signal() {
            WorkerExit::Signaled(signal)
        } else {
            return;
        };
        if let Ok(bytes) = exit.encode() {
            let _ = owner.write_all(&bytes);
        }
    }

    struct BrokerChild(Child);
    impl Drop for BrokerChild {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn usage_is_fixed_bounded_and_distinguishes_absence_from_zero() {
        let value = WorkerUsage {
            owner_start_ticks: 1,
            worker_start_ticks: 2,
            cpu_micros: 0,
            memory_current: 0,
            io_read_bytes: u64::MAX,
            io_write_bytes: 0,
        };
        let encoded = WorkerUsage::encode(Some(value));
        assert_eq!(encoded.len(), 64);
        assert_eq!(WorkerUsage::decode(&encoded).unwrap(), value);
        assert_eq!(
            WorkerUsage::decode(&WorkerUsage::encode(None))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        for offset in [0, 7, 8, 9, 15] {
            let mut corrupted = encoded;
            corrupted[offset] ^= 128;
            assert!(WorkerUsage::decode(&corrupted).is_err());
        }
        let mut absent = WorkerUsage::encode(None);
        absent[16] = 1;
        assert_eq!(
            WorkerUsage::decode(&absent).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(
            WorkerUsage::decode(&WorkerUsage::encode(Some(WorkerUsage {
                worker_start_ticks: 0,
                ..value
            })))
            .is_err()
        );
    }
    #[test]
    fn virtual_hardware_has_a_bounded_larger_launch_envelope_than_host_modes() {
        assert_eq!(argument_bounds(WorkerKind::VirtualMachine), (128, 65536));
        for kind in [
            WorkerKind::Api,
            WorkerKind::Supervisor,
            WorkerKind::Images,
            WorkerKind::Guardian,
        ] {
            assert_eq!(argument_bounds(kind), (16, 16384));
        }
    }
    #[test]
    fn broker_loss_or_invalid_receipts_cannot_be_read_as_clean_worker_exit() {
        for exit in [
            WorkerExit::Exited(0),
            WorkerExit::Exited(70),
            WorkerExit::Signaled(9),
        ] {
            assert_eq!(WorkerExit::decode(&exit.encode().unwrap()).unwrap(), exit);
        }
        for exit in [
            WorkerExit::Exited(-1),
            WorkerExit::Exited(256),
            WorkerExit::Signaled(0),
            WorkerExit::Signaled(65),
        ] {
            assert!(exit.encode().is_err());
        }
        let original = WorkerExit::Exited(0).encode().unwrap();
        for offset in [0, 7, 8, 9, 11] {
            let mut forged = original;
            forged[offset] ^= 8;
            assert!(WorkerExit::decode(&forged).is_err());
        }
        assert!(WorkerExit::decode(&[0; 16]).is_err());
    }
    #[test]
    fn owner_and_worker_limits_sum_to_one_envelope_and_never_create_authority() {
        let envelope = ProcessBudget {
            cpu_quota_micros: 100000,
            memory_bytes: 512 * 1024 * 1024,
            processes: 2,
        };
        let worker = worker_budget(envelope).unwrap();
        assert_eq!(
            worker.cpu_quota_micros + BROKER_CPU_MICROS,
            envelope.cpu_quota_micros
        );
        assert_eq!(
            worker.memory_bytes + BROKER_MEMORY_BYTES,
            envelope.memory_bytes
        );
        assert_eq!(worker.processes + 1, envelope.processes);
        for bad in [
            ProcessBudget {
                processes: 1,
                ..envelope
            },
            ProcessBudget {
                cpu_quota_micros: BROKER_CPU_MICROS,
                ..envelope
            },
            ProcessBudget {
                memory_bytes: BROKER_MEMORY_BYTES,
                ..envelope
            },
            ProcessBudget {
                cpu_quota_micros: 100010,
                ..envelope
            },
        ] {
            assert!(worker_budget(bad).is_err());
        }
        assert!(WorkerKind::Guardian.durable());
        assert!(WorkerKind::Api.durable());
        assert!(WorkerKind::Images.durable());
        assert!(!WorkerKind::VirtualMachine.durable());
    }
    #[test]
    fn broker_vocabulary_has_no_adoption_or_general_execution() {
        for value in ["adopt", "set-pid", "/bin/sh", "shell", "fork", ""] {
            assert!(WorkerKind::parse(value).is_err());
        }
        for kind in [
            WorkerKind::Api,
            WorkerKind::Supervisor,
            WorkerKind::Images,
            WorkerKind::Guardian,
            WorkerKind::VirtualMachine,
        ] {
            assert_eq!(WorkerKind::parse(kind.name()).unwrap(), kind);
        }
    }
    #[test]
    fn native_budget_wire_is_fixed_and_has_no_legacy_decoder() {
        let budget = ProcessBudget {
            cpu_quota_micros: 25000,
            memory_bytes: 128 * 1024 * 1024,
            processes: 1,
        };
        let bytes = encode(budget).unwrap();
        assert_eq!(decode(&bytes).unwrap(), budget);
        for offset in [0, 7, 28, 31] {
            let mut forged = bytes;
            forged[offset] ^= 1;
            assert!(decode(&forged).is_err());
        }
        for invalid in [
            ProcessBudget {
                processes: 2,
                ..budget
            },
            ProcessBudget {
                memory_bytes: budget.memory_bytes + 1,
                ..budget
            },
            ProcessBudget {
                cpu_quota_micros: 25001,
                ..budget
            },
            ProcessBudget {
                cpu_quota_micros: 256000,
                ..budget
            },
        ] {
            assert!(encode(invalid).is_err());
        }
    }
}
