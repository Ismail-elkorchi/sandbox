#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]

mod namespace;

pub use namespace::{NamespaceLauncher, isolated_main, namespace_probe_main};

use sandbox_policy::{NormalizedMask, NormalizedSyntheticDirectory, ResourceLimits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::{self, MaybeUninit};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

const MAX_INTERNAL_MESSAGE: usize = 1024 * 1024;
const INTERNAL_STDIN: u8 = 2;
const INTERNAL_CLOSE_STDIN: u8 = 3;
const INTERNAL_TERMINATE: u8 = 4;
const INTERNAL_STARTED: u8 = 101;
const INTERNAL_SETUP_ERROR: u8 = 102;
const INTERNAL_EXIT: u8 = 103;
const INTERNAL_STDIN_CREDIT: u8 = 104;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchSpec {
    pub launcher_fd_index: usize,
    pub mounts: Vec<MountSpec>,
    pub masks: Vec<NormalizedMask>,
    pub private_home: Option<NormalizedSyntheticDirectory>,
    pub temporary: Option<NormalizedSyntheticDirectory>,
    pub executable_fd_index: usize,
    pub executable_identity: FileIdentity,
    pub executable_content_sha256: String,
    pub executable_snapshot_path: String,
    pub cwd: PreparedCwd,
    pub executable: String,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub resources: ResourceLimits,
    pub termination_grace_ms: u64,
    pub network_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MountSpec {
    pub fd_index: usize,
    pub target_path: String,
    pub kind: String,
    pub read_only: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PreparedCwd {
    Bound {
        fd_index: usize,
        identity: FileIdentity,
        target_path: String,
    },
    Synthetic {
        target_path: String,
        identity_nonce: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LauncherStarted {
    pub host_pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LauncherSetupError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LauncherFinalStatus {
    pub raw_wait_status: i32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub core_dumped: bool,
    pub cleanup_failures: Vec<String>,
    pub tree_reaped: bool,
}

#[derive(Debug)]
pub enum LauncherEvent {
    Final(LauncherFinalStatus),
    StdinCredit(u64),
    RuntimeError(LauncherSetupError),
}

#[derive(Debug)]
pub enum LauncherStatus {
    Started(LauncherStarted),
    SetupError(LauncherSetupError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelProbeResult {
    pub mechanisms: BTreeMap<String, ProbeOutcome>,
    pub landlock_abi: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutcome {
    pub state: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_error: Option<ProbeOsError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOsError {
    pub code: u32,
    pub name: String,
}

pub fn probe_main() -> i32 {
    let result = run_kernel_probe();
    match serde_json::to_string(&result) {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            eprintln!("probe serialization failed: {error}");
            1
        }
    }
}

fn run_kernel_probe() -> KernelProbeResult {
    let mut mechanisms = BTreeMap::new();
    let mut landlock_version = 0;
    let namespace = namespace::probe(false);
    let network = namespace::probe(true);
    mechanisms.insert("namespace-launcher".into(), namespace);
    mechanisms.insert("network-namespace".into(), network);
    match probe_landlock_enforcement() {
        Ok(abi) => {
            landlock_version = abi;
            mechanisms.insert(
                "landlock".into(),
                available(
                    "landlock_restrict_self",
                    &format!("ABI {abi}; allowed read succeeded and denied read returned EACCES"),
                ),
            );
        }
        Err(error) => {
            mechanisms.insert(
                "landlock".into(),
                probe_outcome("landlock_restrict_self", Err(error)),
            );
        }
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS accepts scalar arguments and monotonically restricts this probe process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        mechanisms.insert(
            "seccomp".into(),
            unavailable("prctl(PR_SET_NO_NEW_PRIVS)", &io::Error::last_os_error()),
        );
    } else {
        match apply_seccomp() {
            Ok(()) => {
                // SAFETY: PR_GET_SECCOMP has no pointer arguments and returns the active mode.
                let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
                mechanisms.insert(
                    "seccomp".into(),
                    if mode == 2 {
                        available(
                            "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)",
                            "filter mode is active",
                        )
                    } else {
                        ProbeOutcome {
                            state: "error".into(),
                            operation: "prctl(PR_GET_SECCOMP)".into(),
                            os_error: None,
                            detail: Some(format!("unexpected seccomp mode {mode}")),
                        }
                    },
                );
            }
            Err(error) => {
                mechanisms.insert(
                    "seccomp".into(),
                    probe_outcome("install seccomp filter", Err(error)),
                );
            }
        }
    }
    KernelProbeResult {
        mechanisms,
        landlock_abi: landlock_version,
    }
}

fn available(operation: &str, detail: &str) -> ProbeOutcome {
    ProbeOutcome {
        state: "available".into(),
        operation: operation.into(),
        os_error: None,
        detail: Some(detail.chars().take(1024).collect()),
    }
}

fn unavailable(operation: &str, error: &io::Error) -> ProbeOutcome {
    ProbeOutcome {
        state: "unavailable".into(),
        operation: operation.into(),
        os_error: error.raw_os_error().and_then(|code| {
            u32::try_from(code).ok().map(|code| ProbeOsError {
                code,
                name: format!("{:?}", error.kind()),
            })
        }),
        detail: Some(error.to_string().chars().take(1024).collect()),
    }
}

fn probe_outcome(operation: &str, result: io::Result<()>) -> ProbeOutcome {
    match result {
        Ok(()) => available(operation, "operation succeeded"),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) || matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL)
            ) =>
        {
            unavailable(operation, &error)
        }
        Err(error) => ProbeOutcome {
            state: "error".into(),
            operation: operation.into(),
            os_error: error.raw_os_error().and_then(|code| {
                u32::try_from(code).ok().map(|code| ProbeOsError {
                    code,
                    name: format!("{:?}", error.kind()),
                })
            }),
            detail: Some(error.to_string().chars().take(1024).collect()),
        },
    }
}

fn probe_landlock_enforcement() -> io::Result<u32> {
    let abi = landlock_abi()?;
    if abi < 3 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Landlock ABI {abi} lacks truncate mediation"),
        ));
    }
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let handled = LL_READ_FILE;
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled,
        handled_access_net: 0,
        scoped: 0,
    };
    // SAFETY: attr is initialized and the exact C layout size is passed.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: create_ruleset returned a new owned descriptor.
    let ruleset = unsafe { File::from_raw_fd(ruleset_fd as RawFd) };
    add_landlock_rule(&ruleset, &executable, LL_READ_FILE)?;
    // SAFETY: no_new_privs takes scalar arguments and monotonically restricts this process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ruleset is a live Landlock ruleset and flags must be zero.
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    File::open(executable)?;
    match File::open("/proc/self/status") {
        Err(error) if error.raw_os_error() == Some(libc::EACCES) => Ok(abi),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other(
            "Landlock denied-read check unexpectedly succeeded",
        )),
    }
}

pub fn send_launch_spec(
    stream: &mut UnixStream,
    spec: &LaunchSpec,
    files: &[File],
) -> io::Result<()> {
    let payload = serde_json::to_vec(spec).map_err(invalid_data)?;
    if payload.len() > MAX_INTERNAL_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher request is too large",
        ));
    }
    send_fds(
        stream.as_raw_fd(),
        u32::try_from(payload.len()).map_err(invalid_data)?,
        files,
    )?;
    stream.write_all(&payload)
}

pub fn send_launcher_stdin(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    write_internal(stream, INTERNAL_STDIN, payload)
}

pub fn send_launcher_close_stdin(stream: &mut UnixStream) -> io::Result<()> {
    write_internal(stream, INTERNAL_CLOSE_STDIN, &[])
}

pub fn send_launcher_terminate(stream: &mut UnixStream) -> io::Result<()> {
    write_internal(stream, INTERNAL_TERMINATE, &[])
}

pub fn read_launcher_status(stream: &mut UnixStream) -> io::Result<LauncherStatus> {
    let (kind, payload) = read_internal(stream)?;
    match kind {
        INTERNAL_STARTED => serde_json::from_slice(&payload)
            .map(LauncherStatus::Started)
            .map_err(invalid_data),
        INTERNAL_SETUP_ERROR => serde_json::from_slice(&payload)
            .map(LauncherStatus::SetupError)
            .map_err(invalid_data),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown launcher status",
        )),
    }
}

pub fn read_launcher_event(stream: &mut UnixStream) -> io::Result<LauncherEvent> {
    let (kind, payload) = read_internal(stream)?;
    match kind {
        INTERNAL_EXIT => serde_json::from_slice(&payload)
            .map(LauncherEvent::Final)
            .map_err(invalid_data),
        INTERNAL_STDIN_CREDIT if payload.len() == 8 => {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&payload);
            Ok(LauncherEvent::StdinCredit(u64::from_be_bytes(bytes)))
        }
        INTERNAL_SETUP_ERROR => serde_json::from_slice(&payload)
            .map(LauncherEvent::RuntimeError)
            .map_err(invalid_data),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown launcher event",
        )),
    }
}

pub fn receive_managed_listener_fds(stream: &UnixStream) -> io::Result<Vec<File>> {
    let (count, files) = receive_fds(stream.as_raw_fd())?;
    if count != 4 || files.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed network listener bundle must contain four descriptors",
        ));
    }
    Ok(files)
}

/// Retain a process identity independently of numeric PID reuse.
pub fn open_pidfd(pid: u32) -> io::Result<File> {
    // SAFETY: pidfd_open takes scalar arguments and returns an owned process descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful syscall returned a new descriptor, transferred once to File.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

/// Receive the gated target's pidfd in the host PID namespace. The target cannot
/// execute or fork until the supervisor admits it to the requested resource scope.
pub fn receive_target_pid(stream: &UnixStream) -> io::Result<u32> {
    let (count, files) = receive_fds(stream.as_raw_fd())?;
    if count != 1 || files.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected one target pidfd",
        ));
    }
    let information = fs::read_to_string(format!("/proc/self/fdinfo/{}", files[0].as_raw_fd()))?;
    information
        .lines()
        .find_map(|line| line.strip_prefix("Pid:")?.trim().parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "target pidfd has no live host process",
            )
        })
}

pub fn admit_target(stream: &mut UnixStream) -> io::Result<()> {
    stream.write_all(&[1])
}

pub fn launcher_main() -> i32 {
    // Keep an independent failure channel because run_launcher owns and may close descriptor 0.
    // SAFETY: fd 0 is the trusted Unix socket in launcher mode; F_DUPFD_CLOEXEC creates an owned duplicate.
    let failure_fd = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
    match run_launcher() {
        Ok(code) => code,
        Err(error) => {
            let failure = LauncherSetupError {
                code: "setup.launcher".into(),
                message: bounded_error(&error),
            };
            let payload = serde_json::to_vec(&failure).unwrap_or_else(|_| b"{}".to_vec());
            if failure_fd >= 0 {
                // SAFETY: fcntl returned an independent owned Unix-domain descriptor.
                let mut control = unsafe { UnixStream::from_raw_fd(failure_fd) };
                let _ = write_internal(&mut control, INTERNAL_SETUP_ERROR, &payload);
            }
            125
        }
    }
}

fn run_launcher() -> io::Result<i32> {
    bind_lifetime_to_parent()?;
    // Ownership of fd 0 transfers from the process standard-input slot to this UnixStream.
    // SAFETY: launcher mode exclusively transfers ownership of its Unix-domain stdin descriptor here.
    let mut control = unsafe { UnixStream::from_raw_fd(0) };
    let (length, files) = receive_fds(control.as_raw_fd())?;
    if length as usize > MAX_INTERNAL_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher request exceeds limit",
        ));
    }
    let mut payload = vec![0_u8; length as usize];
    control.read_exact(&mut payload)?;
    let spec: LaunchSpec = serde_json::from_slice(&payload).map_err(invalid_data)?;
    validate_spec(&spec, files.len())?;

    namespace::launch(&spec, &files)
}

fn namespace_init(
    control: &mut UnixStream,
    spec: &LaunchSpec,
    files: Vec<File>,
) -> io::Result<i32> {
    let managed_environment = if spec.network_mode == "managed" {
        setup_managed_listeners(control)?
    } else {
        BTreeMap::new()
    };
    let (stdin_read, stdin_write) = pipe_cloexec()?;
    let (exec_status_read, mut exec_status_write) = pipe_cloexec()?;
    let gate = if spec.resources.memory.is_some() || spec.resources.process_count.is_some() {
        Some(pipe_cloexec()?)
    } else {
        None
    };
    // SAFETY: namespace init remains single-threaded, and the child immediately performs bounded setup then exec/_exit.
    let target_pid = unsafe { libc::fork() };
    if target_pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if target_pid == 0 {
        drop(stdin_write);
        drop(exec_status_read);
        if let Some((mut read, write)) = gate {
            drop(write);
            let mut admitted = [0];
            if read.read_exact(&mut admitted).is_err() || admitted != [1] {
                // SAFETY: this post-fork child has not executed target code; failed admission terminates it.
                unsafe { libc::_exit(125) };
            }
        }
        // SAFETY: setpgid(0, 0) affects only the calling child and uses no pointers.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            let error = context("create target process group", io::Error::last_os_error());
            let _ = exec_status_write.write_all(error.to_string().as_bytes());
            // SAFETY: setup failed in the post-fork child; _exit prevents duplicated cleanup.
            unsafe { libc::_exit(125) };
        }
        if let Err(error) = target_exec(stdin_read.as_raw_fd(), spec, &files, &managed_environment)
        {
            let error = context("target exec setup", error);
            let _ = exec_status_write.write_all(error.to_string().as_bytes());
            // SAFETY: setup failed in the post-fork child; _exit prevents duplicated cleanup.
            unsafe { libc::_exit(125) };
        }
        unreachable!();
    }
    drop(files);
    drop(stdin_read);
    drop(exec_status_write);
    if let Some((read, mut write)) = gate {
        drop(read);
        // SAFETY: target_pid is this process's live, gated child; pidfd_open takes scalar arguments.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target_pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pidfd_open returned a new owned descriptor, transferred once to File.
        let target = unsafe { File::from_raw_fd(fd as RawFd) };
        send_fds(control.as_raw_fd(), 1, &[target])?;
        let mut admitted = [0];
        control.read_exact(&mut admitted)?;
        if admitted != [1] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid resource admission",
            ));
        }
        write.write_all(&admitted)?;
    }
    let mut setup_error = Vec::new();
    exec_status_read.take(4097).read_to_end(&mut setup_error)?;
    if !setup_error.is_empty() {
        let failure = LauncherSetupError {
            code: "setup.target_exec".into(),
            message: String::from_utf8_lossy(&setup_error[..setup_error.len().min(4096)])
                .into_owned(),
        };
        write_internal(
            control,
            INTERNAL_SETUP_ERROR,
            &serde_json::to_vec(&failure).map_err(invalid_data)?,
        )?;
        let mut status = 0;
        // SAFETY: status is writable and target_pid is the child created above.
        let _ = unsafe { libc::waitpid(target_pid, &mut status, 0) };
        return Ok(125);
    }
    let started = LauncherStarted {
        host_pid: u32::try_from(target_pid).unwrap_or(0),
    };
    write_internal(
        control,
        INTERNAL_STARTED,
        &serde_json::to_vec(&started).map_err(invalid_data)?,
    )?;
    let final_status =
        supervise_namespace(control, stdin_write, target_pid, spec.termination_grace_ms)?;
    write_internal(
        control,
        INTERNAL_EXIT,
        &serde_json::to_vec(&final_status).map_err(invalid_data)?,
    )?;
    Ok(status_to_exit(final_status.raw_wait_status))
}

fn target_exec(
    stdin_fd: RawFd,
    spec: &LaunchSpec,
    files: &[File],
    managed_environment: &BTreeMap<String, String>,
) -> io::Result<()> {
    // SAFETY: stdin_fd is an owned live pipe descriptor; dup2 atomically replaces descriptor 0.
    if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0 {
        return Err(context("install target stdin", io::Error::last_os_error()));
    }
    let cwd_target = match &spec.cwd {
        PreparedCwd::Bound {
            fd_index,
            identity,
            target_path,
        } => {
            let prepared = files.get(*fd_index).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cwd descriptor index is invalid",
                )
            })?;
            let target = PathBuf::from(target_path);
            let opened = open_path(&target, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
                .map_err(|error| context("open mounted working directory", error))?;
            if file_identity(opened.as_raw_fd())? != *identity
                || file_identity(prepared.as_raw_fd())? != *identity
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "working directory identity changed",
                ));
            }
            (target_path.clone(), Some(opened))
        }
        PreparedCwd::Synthetic { target_path, .. } => (target_path.clone(), None),
    };

    let executable = files.get(spec.executable_fd_index).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "executable descriptor index is invalid",
        )
    })?;
    if file_identity(executable.as_raw_fd())? != spec.executable_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable identity changed",
        ));
    }
    if sha256_file(executable)? != spec.executable_content_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "prepared executable snapshot digest changed",
        ));
    }
    let mounted_executable = open_path(
        Path::new(&spec.executable_snapshot_path),
        libc::O_RDONLY | libc::O_CLOEXEC,
    )?;
    if sha256_file(&mounted_executable)? != spec.executable_content_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mounted executable snapshot digest changed",
        ));
    }

    let cwd = CString::new(cwd_target.0).map_err(invalid_data)?;
    // SAFETY: cwd is a valid CString validated and identity-checked inside the new root.
    if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
        return Err(context(
            "select prepared working directory",
            io::Error::last_os_error(),
        ));
    }
    drop(cwd_target.1);

    drop_capabilities().map_err(|error| context("drop capabilities", error))?;
    // SAFETY: PR_SET_NO_NEW_PRIVS takes scalar arguments and only restricts this process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(context("set no_new_privs", io::Error::last_os_error()));
    }
    apply_landlock(spec).map_err(|error| context("install Landlock ruleset", error))?;
    apply_seccomp().map_err(|error| context("install seccomp filter", error))?;

    prepare_descriptors_for_exec().map_err(|error| context("close ambient descriptors", error))?;

    let executable_name = CString::new(spec.executable.as_bytes()).map_err(invalid_data)?;
    let mut arguments = Vec::with_capacity(spec.args.len() + 1);
    arguments.push(executable_name);
    for argument in &spec.args {
        arguments.push(CString::new(argument.as_bytes()).map_err(invalid_data)?);
    }
    let argument_pointers = c_string_pointers(&arguments);
    let mut environment_values = spec.environment.clone();
    environment_values.extend(managed_environment.clone());
    let environment: Vec<CString> = environment_values
        .iter()
        .map(|(name, value)| CString::new(format!("{name}={value}")).map_err(invalid_data))
        .collect::<io::Result<_>>()?;
    let environment_pointers = c_string_pointers(&environment);
    let launch_path =
        CString::new(spec.executable_snapshot_path.as_bytes()).map_err(invalid_data)?;
    apply_rlimits(&spec.resources).map_err(|error| context("apply target rlimits", error))?;
    // SAFETY: launch_path names the read-only bind mount of the sealed snapshot, and argv/envp are live NUL-terminated arrays.
    let result = unsafe {
        libc::execve(
            launch_path.as_ptr(),
            argument_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    } as libc::c_long;
    if result != 0 {
        return Err(context(
            "execve prepared executable snapshot mount",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn setup_managed_listeners(control: &mut UnixStream) -> io::Result<BTreeMap<String, String>> {
    let http = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let socks = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let dns_udp = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 53))?;
    let dns_tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 53))?;
    let http_port = http.local_addr()?.port();
    let socks_port = socks.local_addr()?.port();
    let listeners = vec![
        // SAFETY: each into_raw_fd transfers one distinct socket descriptor exactly once.
        unsafe { File::from_raw_fd(http.into_raw_fd()) },
        // SAFETY: each into_raw_fd transfers one distinct socket descriptor exactly once.
        unsafe { File::from_raw_fd(socks.into_raw_fd()) },
        // SAFETY: each into_raw_fd transfers one distinct socket descriptor exactly once.
        unsafe { File::from_raw_fd(dns_udp.into_raw_fd()) },
        // SAFETY: each into_raw_fd transfers one distinct socket descriptor exactly once.
        unsafe { File::from_raw_fd(dns_tcp.into_raw_fd()) },
    ];
    send_fds(control.as_raw_fd(), listeners.len() as u32, &listeners)?;
    Ok(BTreeMap::from([
        ("HTTP_PROXY".into(), format!("http://127.0.0.1:{http_port}")),
        (
            "HTTPS_PROXY".into(),
            format!("http://127.0.0.1:{http_port}"),
        ),
        (
            "ALL_PROXY".into(),
            format!("socks5h://127.0.0.1:{socks_port}"),
        ),
        ("NO_PROXY".into(), String::new()),
    ]))
}

fn supervise_namespace(
    control: &mut UnixStream,
    stdin_write: File,
    target_pid: libc::pid_t,
    termination_grace_ms: u64,
) -> io::Result<LauncherFinalStatus> {
    let mut target_status = None;
    let mut terminating_at: Option<Instant> = None;
    let mut stdin_open = true;
    let mut stdin_close_requested = false;
    let mut stdin_queue = Vec::new();
    let mut stdin_offset = 0_usize;
    let mut decoder = InternalDecoder::default();
    control.set_nonblocking(true)?;
    set_nonblocking(stdin_write.as_raw_fd(), true)?;
    let mut stdin_write = Some(stdin_write);
    loop {
        reap_children(target_pid, &mut target_status)?;
        if let Some(status) = target_status {
            let mut cleanup_failures = Vec::new();
            if let Err(error) = kill_all_children() {
                cleanup_failures.push(format!("kill descendants: {error}"));
            }
            let tree_reaped = match reap_until_empty() {
                Ok(()) => true,
                Err(error) => {
                    cleanup_failures.push(format!("reap descendants: {error}"));
                    false
                }
            };
            return Ok(final_status(status, cleanup_failures, tree_reaped));
        }
        if let Some(started) = terminating_at
            && started.elapsed() >= Duration::from_millis(termination_grace_ms)
        {
            signal_process_group(target_pid, libc::SIGKILL)?;
        }
        match decoder.read_available(control) {
            Ok(messages) => {
                for (kind, payload) in messages {
                    match kind {
                        INTERNAL_STDIN if stdin_open && !stdin_close_requested => {
                            if stdin_queue.len().saturating_sub(stdin_offset) + payload.len()
                                > sandbox_protocol_credit_limit()
                            {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "stdin queue exceeded granted credit",
                                ));
                            }
                            if stdin_offset == stdin_queue.len() {
                                stdin_queue.clear();
                                stdin_offset = 0;
                            }
                            stdin_queue.extend_from_slice(&payload);
                        }
                        INTERNAL_CLOSE_STDIN => stdin_close_requested = true,
                        INTERNAL_TERMINATE => {
                            if terminating_at.is_none() {
                                signal_process_group(target_pid, libc::SIGTERM)?;
                                terminating_at = Some(Instant::now());
                            }
                        }
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unknown launcher control message",
                            ));
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                signal_process_group(target_pid, libc::SIGKILL)?;
                terminating_at = Some(Instant::now() - Duration::from_millis(termination_grace_ms));
            }
            Err(error) => return Err(error),
        }
        if stdin_open && stdin_offset < stdin_queue.len() {
            let Some(writer) = stdin_write.as_mut() else {
                stdin_open = false;
                continue;
            };
            match writer.write(&stdin_queue[stdin_offset..]) {
                Ok(0) => stdin_open = false,
                Ok(count) => {
                    stdin_offset += count;
                    write_internal(
                        control,
                        INTERNAL_STDIN_CREDIT,
                        &(count as u64).to_be_bytes(),
                    )?;
                    if stdin_offset == stdin_queue.len() {
                        stdin_queue.clear();
                        stdin_offset = 0;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => stdin_open = false,
            }
        }
        if !stdin_open {
            stdin_queue.clear();
            stdin_write.take();
        } else if stdin_close_requested && stdin_queue.is_empty() {
            stdin_open = false;
            stdin_write.take();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn bind_lifetime_to_parent() -> io::Result<()> {
    // SAFETY: getppid has no arguments or memory-safety preconditions.
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "launcher has no live supervisor parent",
        ));
    }
    // SAFETY: PR_SET_PDEATHSIG takes scalar values and establishes a monotonic lifecycle restriction.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getppid has no arguments or memory-safety preconditions.
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "supervisor changed while binding launcher lifetime",
        ));
    }
    Ok(())
}

fn final_status(
    status: i32,
    cleanup_failures: Vec<String>,
    tree_reaped: bool,
) -> LauncherFinalStatus {
    LauncherFinalStatus {
        raw_wait_status: status,
        exit_code: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
        signal: libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)),
        core_dumped: libc::WIFSIGNALED(status) && libc::WCOREDUMP(status),
        cleanup_failures,
        tree_reaped,
    }
}

fn sandbox_protocol_credit_limit() -> usize {
    1024 * 1024
}

fn validate_spec(spec: &LaunchSpec, descriptor_count: usize) -> io::Result<()> {
    if spec.launcher_fd_index >= descriptor_count
        || spec.executable_fd_index >= descriptor_count
        || spec
            .mounts
            .iter()
            .any(|mount| mount.fd_index >= descriptor_count)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher descriptor index is outside the received set",
        ));
    }
    if spec.args.len() > 65_536 || spec.environment.len() > 65_536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher vector count exceeds limit",
        ));
    }
    if !matches!(
        spec.network_mode.as_str(),
        "none" | "managed" | "unrestricted"
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid network mode",
        ));
    }
    for mount in &spec.mounts {
        validate_target(&mount.target_path)?;
        if mount.kind != "file" && mount.kind != "directory" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mount object kind",
            ));
        }
    }
    validate_target(&spec.executable_snapshot_path)?;
    if !spec
        .executable_snapshot_path
        .starts_with("/.sandbox-runtime/")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "executable snapshot path is outside the reserved runtime namespace",
        ));
    }
    Ok(())
}

fn apply_rlimits(limits: &ResourceLimits) -> io::Result<()> {
    set_rlimit(libc::RLIMIT_NOFILE, limits.open_files.value)?;
    set_rlimit(libc::RLIMIT_FSIZE, limits.single_file_size.value)?;
    if let Some(cpu_time) = &limits.cpu_time {
        let soft = cpu_time.value.div_ceil(1000);
        set_rlimit_pair(libc::RLIMIT_CPU, soft, soft.saturating_add(1))?;
    }
    Ok(())
}

#[cfg(not(target_env = "musl"))]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(target_env = "musl")]
type RlimitResource = libc::c_int;

fn set_rlimit(resource: RlimitResource, value: u64) -> io::Result<()> {
    set_rlimit_pair(resource, value, value)
}

fn set_rlimit_pair(resource: RlimitResource, soft: u64, hard: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: resource is one of the fixed RLIMIT constants and limit points to an initialized rlimit.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn drop_capabilities() -> io::Result<()> {
    for capability in 0..64 {
        // SAFETY: PR_CAPBSET_READ takes a scalar capability number and no pointers.
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        if present == 0 {
            continue;
        }
        if present < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(error);
        }
        // SAFETY: PR_CAPBSET_DROP monotonically removes this supported capability.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: header and both capability data words are initialized with the kernel's v3 ABI layout.
    let result = unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LL_EXECUTE: u64 = 1 << 0;
const LL_WRITE_FILE: u64 = 1 << 1;
const LL_READ_FILE: u64 = 1 << 2;
const LL_READ_DIR: u64 = 1 << 3;
const LL_REMOVE_DIR: u64 = 1 << 4;
const LL_REMOVE_FILE: u64 = 1 << 5;
const LL_MAKE_CHAR: u64 = 1 << 6;
const LL_MAKE_DIR: u64 = 1 << 7;
const LL_MAKE_REG: u64 = 1 << 8;
const LL_MAKE_SOCK: u64 = 1 << 9;
const LL_MAKE_FIFO: u64 = 1 << 10;
const LL_MAKE_BLOCK: u64 = 1 << 11;
const LL_MAKE_SYM: u64 = 1 << 12;
const LL_REFER: u64 = 1 << 13;
const LL_TRUNCATE: u64 = 1 << 14;
const LL_IOCTL_DEV: u64 = 1 << 15;
const LL_READ: u64 = LL_READ_FILE | LL_READ_DIR;
const LL_WRITE: u64 = LL_WRITE_FILE
    | LL_REMOVE_DIR
    | LL_REMOVE_FILE
    | LL_MAKE_CHAR
    | LL_MAKE_DIR
    | LL_MAKE_REG
    | LL_MAKE_SOCK
    | LL_MAKE_FIFO
    | LL_MAKE_BLOCK
    | LL_MAKE_SYM
    | LL_REFER
    | LL_TRUNCATE
    | LL_IOCTL_DEV;

fn landlock_abi() -> io::Result<u32> {
    // SAFETY: a null attribute with size zero is the documented Landlock ABI version query.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<LandlockRulesetAttr>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(result).map_err(invalid_data)
}

fn apply_landlock(spec: &LaunchSpec) -> io::Result<()> {
    let abi = landlock_abi()?;
    let mut handled = LL_EXECUTE
        | LL_WRITE_FILE
        | LL_READ_FILE
        | LL_READ_DIR
        | LL_REMOVE_DIR
        | LL_REMOVE_FILE
        | LL_MAKE_CHAR
        | LL_MAKE_DIR
        | LL_MAKE_REG
        | LL_MAKE_SOCK
        | LL_MAKE_FIFO
        | LL_MAKE_BLOCK
        | LL_MAKE_SYM;
    if abi >= 2 {
        handled |= LL_REFER;
    }
    if abi >= 3 {
        handled |= LL_TRUNCATE;
    }
    if abi >= 5 {
        handled |= LL_IOCTL_DEV;
    }
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled,
        handled_access_net: 0,
        scoped: 0,
    };
    // SAFETY: attr is initialized and its exact C layout size is passed to the Landlock syscall.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };
    if ruleset_fd < 0 {
        return Err(context(
            "create Landlock ruleset",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: a successful create_ruleset returns a new descriptor transferred exactly once to File.
    let ruleset = unsafe { File::from_raw_fd(ruleset_fd as RawFd) };

    for mount in &spec.mounts {
        let mut access = if mount.kind == "file" {
            LL_READ_FILE
        } else {
            LL_READ
        };
        if mount.executable {
            access |= LL_EXECUTE;
        }
        if !mount.read_only {
            access |= if mount.kind == "file" {
                LL_WRITE_FILE | LL_TRUNCATE | LL_IOCTL_DEV
            } else {
                LL_WRITE
            };
        }
        add_landlock_rule(&ruleset, Path::new(&mount.target_path), access & handled)
            .map_err(|error| context(&format!("add Landlock rule {}", mount.target_path), error))?;
    }
    if let Some(private_home) = &spec.private_home {
        let access = LL_READ
            | LL_WRITE
            | if private_home.executable {
                LL_EXECUTE
            } else {
                0
            };
        add_landlock_rule(
            &ruleset,
            Path::new(&private_home.target_path),
            access & handled,
        )
        .map_err(|error| context("add Landlock rule private home", error))?;
    }
    if let Some(temporary) = &spec.temporary {
        let temp_access = LL_READ | LL_WRITE | if temporary.executable { LL_EXECUTE } else { 0 };
        add_landlock_rule(
            &ruleset,
            Path::new(&temporary.target_path),
            temp_access & handled,
        )
        .map_err(|error| context("add Landlock rule temporary directory", error))?;
    }
    add_landlock_rule(&ruleset, Path::new("/dev"), (LL_READ | LL_WRITE) & handled)
        .map_err(|error| context("add Landlock rule /dev", error))?;
    add_landlock_rule(&ruleset, Path::new("/proc"), (LL_READ | LL_WRITE) & handled)
        .map_err(|error| context("add Landlock rule /proc", error))?;
    add_landlock_rule(&ruleset, Path::new("/etc"), LL_READ & handled)
        .map_err(|error| context("add Landlock rule /etc", error))?;
    add_landlock_rule(
        &ruleset,
        Path::new(&spec.executable_snapshot_path),
        (LL_READ_FILE | LL_EXECUTE) & handled,
    )
    .map_err(|error| context("add Landlock rule executable snapshot", error))?;

    // SAFETY: ruleset is a live Landlock ruleset descriptor and flags zero is required by the negotiated ABI.
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } != 0 {
        return Err(context(
            "restrict self with Landlock",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn add_landlock_rule(ruleset: &File, path: &Path, access: u64) -> io::Result<()> {
    if access == 0 {
        return Ok(());
    }
    let parent = open_path(path, libc::O_PATH | libc::O_CLOEXEC)?;
    let attr = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: attr references a live O_PATH descriptor and matches the C path-beneath layout.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &attr,
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

fn apply_seccomp() -> io::Result<()> {
    let architecture = if cfg!(target_arch = "x86_64") {
        AUDIT_ARCH_X86_64
    } else {
        AUDIT_ARCH_AARCH64
    };
    let blocked = blocked_syscalls();
    let mut filters = Vec::with_capacity(blocked.len() * 2 + 10);
    filters.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 4));
    filters.push(jump(
        (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        architecture,
        1,
        0,
    ));
    filters.push(stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        SECCOMP_RET_KILL_PROCESS,
    ));
    filters.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0));
    let namespace_flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWCGROUP;
    filters.push(jump(
        (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        libc::SYS_clone as u32,
        0,
        4,
    ));
    filters.push(stmt(
        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        16,
    ));
    filters.push(jump(
        (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
        namespace_flags as u32,
        0,
        1,
    ));
    filters.push(stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        SECCOMP_RET_ERRNO | libc::EPERM as u32,
    ));
    filters.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0));
    for syscall in blocked {
        filters.push(jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            syscall as u32,
            0,
            1,
        ));
        let errno = if syscall == libc::SYS_clone3 {
            libc::ENOSYS
        } else {
            libc::EPERM
        };
        filters.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            SECCOMP_RET_ERRNO | errno as u32,
        ));
    }
    filters.push(stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        SECCOMP_RET_ALLOW,
    ));
    let program = libc::sock_fprog {
        len: u16::try_from(filters.len()).map_err(invalid_data)?,
        filter: filters.as_mut_ptr(),
    };
    // SAFETY: program references a live, validated BPF array for the duration of PR_SET_SECCOMP.
    let result = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn blocked_syscalls() -> Vec<libc::c_long> {
    vec![
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_bpf,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_ptrace,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_perf_event_open,
        libc::SYS_clone3,
    ]
}

const fn stmt(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt,
        jf,
        k: value,
    }
}

fn prepare_descriptors_for_exec() -> io::Result<()> {
    // SAFETY: close_range with CLOEXEC only marks descriptors above standard I/O;
    // the qualified Linux kernel supports it and no pointers are passed.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn c_string_pointers(values: &[CString]) -> Vec<*const libc::c_char> {
    let mut pointers: Vec<_> = values.iter().map(|value| value.as_ptr()).collect();
    pointers.push(ptr::null());
    pointers
}

fn pipe_cloexec() -> io::Result<(File, File)> {
    let mut fds = [0; 2];
    // SAFETY: fds points to two writable integers and O_CLOEXEC is a valid pipe2 flag.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two distinct owned descriptors, each transferred exactly once.
    let read = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: pipe2 returned two distinct owned descriptors, each transferred exactly once.
    let write = unsafe { File::from_raw_fd(fds[1]) };
    Ok((read, write))
}

fn open_path(path: &Path, flags: libc::c_int) -> io::Result<File> {
    let path = path_cstring(path)?;
    // SAFETY: path is NUL-terminated and flags are supplied by the launcher's fixed call sites.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful open returns a new descriptor transferred exactly once to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub fn file_identity(fd: RawFd) -> io::Result<FileIdentity> {
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat points to writable storage and fd is required by callers to be live.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized every field of libc::stat.
    let stat = unsafe { stat.assume_init() };
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
    })
}

/// Attempts to retain an exclusive advisory lease for the lifetime of `file`.
/// `Ok(false)` means another process currently owns the lease.
pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    // SAFETY: `file` owns a live descriptor and flock retains no pointer.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Sends SIGKILL to an exact positive PID. `Ok(false)` means it no longer exists.
pub fn kill_process(pid: u32) -> io::Result<bool> {
    let pid = i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process ID"))?;
    // SAFETY: a validated positive PID cannot select a process group.
    if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(error)
    }
}

fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(invalid_data)
}

fn sha256_file(file: &File) -> io::Result<String> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_target(path: &str) -> io::Result<()> {
    if !path.starts_with('/')
        || path.contains('\0')
        || path.split('/').any(|part| part == ".." || part == ".")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid target path",
        ));
    }
    Ok(())
}

fn component_count(path: &str) -> usize {
    Path::new(path).components().count()
}

fn reap_children(target_pid: libc::pid_t, target_status: &mut Option<i32>) -> io::Result<()> {
    loop {
        let mut status = 0;
        // SAFETY: status is writable; -1 intentionally selects any namespace child without blocking.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid == 0 {
            return Ok(());
        }
        if pid < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            return Err(error);
        }
        if pid == target_pid {
            *target_status = Some(status);
        }
    }
}

fn reap_until_empty() -> io::Result<()> {
    loop {
        let mut status = 0;
        // SAFETY: status is writable; -1 intentionally reaps any remaining namespace child.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

fn kill_all_children() -> io::Result<()> {
    // SAFETY: PID -1 inside the private PID namespace targets all signalable target descendants.
    let result = unsafe { libc::kill(-1, libc::SIGKILL) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn signal_process_group(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: pid is the direct target child; this idempotently establishes its private process group.
    let _ = unsafe { libc::setpgid(pid, pid) };
    // SAFETY: negative pid intentionally addresses only the target's private process group.
    let result = unsafe { libc::kill(-pid, signal) };
    if result != 0 {
        // SAFETY: pid is the direct target child and signal is a fixed termination signal.
        let fallback = unsafe { libc::kill(pid, signal) };
        if fallback != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn status_to_exit(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        125
    }
}

#[derive(Default)]
struct InternalDecoder {
    buffer: Vec<u8>,
}

impl InternalDecoder {
    fn read_available(&mut self, stream: &mut UnixStream) -> io::Result<Vec<(u8, Vec<u8>)>> {
        let mut chunk = [0_u8; 64 * 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        if self.buffer.is_empty() {
                            "launcher control channel closed"
                        } else {
                            "launcher control channel ended with a partial frame"
                        },
                    ));
                }
                Ok(count) => {
                    self.buffer.extend_from_slice(&chunk[..count]);
                    if self.buffer.len() > MAX_INTERNAL_MESSAGE + 5 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "internal decoder buffer exceeded its bound",
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        let mut messages = Vec::new();
        loop {
            if self.buffer.len() < 5 {
                break;
            }
            let length = u32::from_be_bytes([
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
                self.buffer[4],
            ]) as usize;
            if length > MAX_INTERNAL_MESSAGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "internal message too large",
                ));
            }
            if self.buffer.len() < 5 + length {
                break;
            }
            let kind = self.buffer[0];
            let payload = self.buffer[5..5 + length].to_vec();
            self.buffer.drain(..5 + length);
            messages.push((kind, payload));
        }
        Ok(messages)
    }
}

fn write_internal(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_INTERNAL_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "internal message too large",
        ));
    }
    let length = u32::try_from(payload.len()).map_err(invalid_data)?;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(kind);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

fn read_internal(stream: &mut UnixStream) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > MAX_INTERNAL_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "internal message too large",
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((header[0], payload))
}

fn set_nonblocking(fd: RawFd, enabled: bool) -> io::Result<()> {
    // SAFETY: F_GETFL reads scalar descriptor flags from a live descriptor.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if enabled {
        current | libc::O_NONBLOCK
    } else {
        current & !libc::O_NONBLOCK
    };
    // SAFETY: F_SETFL updates only status flags on the same live descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn send_fds(socket: RawFd, length: u32, files: &[File]) -> io::Result<()> {
    if files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher needs authority descriptors",
        ));
    }
    let mut bytes = length.to_be_bytes();
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let descriptor_bytes = files
        .len()
        .checked_mul(mem::size_of::<RawFd>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "descriptor count overflow"))?;
    let control_length = cmsg_space(descriptor_bytes);
    let mut control = vec![0_u8; control_length];
    // SAFETY: all-zero msghdr is a valid starting state before explicitly setting its active fields.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_field_length(control.len())?;
    let cmsg = message.msg_control.cast::<libc::cmsghdr>();
    // SAFETY: control has CMSG_SPACE bytes, cmsg points into it, and data has room for every descriptor.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = control_field_length(cmsg_len(descriptor_bytes))
            .expect("bounded descriptor control length");
        let data = cmsg
            .cast::<u8>()
            .add(cmsg_align(mem::size_of::<libc::cmsghdr>()))
            .cast::<RawFd>();
        for (index, file) in files.iter().enumerate() {
            *data.add(index) = file.as_raw_fd();
        }
    }
    // SAFETY: message references live header/control buffers for the duration of sendmsg.
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent != bytes.len() as isize {
        return Err(if sent < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::new(io::ErrorKind::WriteZero, "partial descriptor message")
        });
    }
    Ok(())
}

fn receive_fds(socket: RawFd) -> io::Result<(u32, Vec<File>)> {
    let mut bytes = [0_u8; 4];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let maximum_fds = 4096_usize;
    let mut control = vec![0_u8; cmsg_space(maximum_fds * mem::size_of::<RawFd>())];
    // SAFETY: all-zero msghdr is a valid starting state before explicitly setting its active fields.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_field_length(control.len())?;
    // SAFETY: message points to writable header/control buffers sized above; recvmsg initializes received control data.
    let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received != bytes.len() as isize {
        return Err(if received < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::new(io::ErrorKind::UnexpectedEof, "partial descriptor message")
        });
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor message truncated",
        ));
    }
    let header = message.msg_control.cast::<libc::cmsghdr>();
    // SAFETY: after the null check, header points into the initialized control buffer returned by recvmsg.
    if header.is_null()
        || unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
        // SAFETY: the same validated cmsghdr pointer remains live for this adjacent field read.
        || unsafe { (*header).cmsg_type } != libc::SCM_RIGHTS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "launcher descriptors missing",
        ));
    }
    // SAFETY: header was checked non-null and lies within the recvmsg control buffer.
    let header_len = control_field_to_usize(unsafe { (*header).cmsg_len })?;
    let base_len = cmsg_align(mem::size_of::<libc::cmsghdr>());
    if header_len < base_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid descriptor control length",
        ));
    }
    let count = (header_len - base_len) / mem::size_of::<RawFd>();
    // SAFETY: validated cmsg_len is at least base_len, so data begins within the control message.
    let data = unsafe { header.cast::<u8>().add(base_len).cast::<RawFd>() };
    let mut files = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: count derives from cmsg_len and index remains within the SCM_RIGHTS descriptor array.
        let fd = unsafe { *data.add(index) };
        // SAFETY: SCM_RIGHTS installs a new owned descriptor in this process, transferred exactly once to File.
        files.push(unsafe { File::from_raw_fd(fd) });
    }
    Ok((u32::from_be_bytes(bytes), files))
}

const fn cmsg_align(length: usize) -> usize {
    let alignment = mem::size_of::<usize>();
    (length + alignment - 1) & !(alignment - 1)
}

#[cfg(not(target_env = "musl"))]
type ControlFieldLength = usize;
#[cfg(target_env = "musl")]
type ControlFieldLength = libc::socklen_t;

#[cfg(not(target_env = "musl"))]
fn control_field_length(length: usize) -> io::Result<ControlFieldLength> {
    Ok(length)
}

#[cfg(target_env = "musl")]
fn control_field_length(length: usize) -> io::Result<ControlFieldLength> {
    length
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "control buffer is too large"))
}

#[cfg(not(target_env = "musl"))]
fn control_field_to_usize(length: ControlFieldLength) -> io::Result<usize> {
    Ok(length)
}

#[cfg(target_env = "musl")]
fn control_field_to_usize(length: ControlFieldLength) -> io::Result<usize> {
    usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid control length"))
}

const fn cmsg_space(data_length: usize) -> usize {
    cmsg_align(mem::size_of::<libc::cmsghdr>()) + cmsg_align(data_length)
}

const fn cmsg_len(data_length: usize) -> usize {
    cmsg_align(mem::size_of::<libc::cmsghdr>()) + data_length
}

fn bounded_error(error: &io::Error) -> String {
    error.to_string().chars().take(512).collect()
}

fn context(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

fn invalid_data(error: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

use std::fmt::Display;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_messages_are_bounded_and_round_trip() {
        let (mut left, mut right) = UnixStream::pair().expect("pair");
        write_internal(&mut left, INTERNAL_STDIN, b"abc").expect("write");
        let (kind, value) = read_internal(&mut right).expect("read");
        assert_eq!(kind, INTERNAL_STDIN);
        assert_eq!(value, b"abc");
    }

    #[test]
    fn file_identity_is_stable_for_a_held_descriptor() {
        let file = File::open("/dev/null").expect("open");
        assert_eq!(
            file_identity(file.as_raw_fd()).expect("identity"),
            file_identity(file.as_raw_fd()).expect("identity")
        );
    }

    #[test]
    fn kernel_abi_structures_have_expected_layout() {
        use std::mem::{offset_of, size_of};

        assert_eq!(size_of::<CapHeader>(), 8);
        assert_eq!(offset_of!(CapHeader, pid), 4);
        assert_eq!(size_of::<CapData>(), 12);
        assert_eq!(size_of::<LandlockRulesetAttr>(), 24);
        assert_eq!(size_of::<LandlockPathBeneathAttr>(), 16);
        assert_eq!(offset_of!(LandlockPathBeneathAttr, parent_fd), 8);
    }

    #[test]
    fn nonblocking_internal_decoder_preserves_partial_frames() {
        let (mut writer, mut reader) = UnixStream::pair().expect("pair");
        reader.set_nonblocking(true).expect("nonblocking");
        let mut frame = vec![INTERNAL_STDIN];
        frame.extend_from_slice(&3_u32.to_be_bytes());
        frame.extend_from_slice(b"abc");
        writer.write_all(&frame[..2]).expect("partial header");
        let mut decoder = InternalDecoder::default();
        assert!(
            decoder
                .read_available(&mut reader)
                .expect("partial")
                .is_empty()
        );
        writer.write_all(&frame[2..6]).expect("header and payload");
        assert!(
            decoder
                .read_available(&mut reader)
                .expect("partial")
                .is_empty()
        );
        writer.write_all(&frame[6..]).expect("final payload");
        assert_eq!(
            decoder.read_available(&mut reader).expect("complete"),
            vec![(INTERNAL_STDIN, b"abc".to_vec())]
        );
    }

    #[test]
    fn nonblocking_internal_decoder_rejects_length_lies() {
        let (mut writer, mut reader) = UnixStream::pair().expect("pair");
        reader.set_nonblocking(true).expect("nonblocking");
        let mut frame = vec![INTERNAL_STDIN];
        frame.extend_from_slice(&((MAX_INTERNAL_MESSAGE as u32) + 1).to_be_bytes());
        writer.write_all(&frame).expect("malformed frame");
        assert_eq!(
            InternalDecoder::default()
                .read_available(&mut reader)
                .expect_err("length must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
