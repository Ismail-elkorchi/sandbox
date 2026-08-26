#![deny(unsafe_op_in_unsafe_fn)]

use sandbox_digest::identity_digest;
use sandbox_guest::{
    GUEST_CONTROL_PORT, GUEST_DNS_TCP_TUNNEL_PORT, GUEST_DNS_UDP_TUNNEL_PORT,
    GUEST_HTTP_PROXY_PORT, GUEST_HTTP_TUNNEL_PORT, GUEST_PROTOCOL_MAJOR, GUEST_PROTOCOL_MINOR,
    GUEST_SOCKS_PROXY_PORT, GUEST_SOCKS_TUNNEL_PORT, GuestArtifactEntry, GuestLimits, GuestMask,
    GuestMount, GuestPrivateDirectory, GuestRequest, GuestResponse, MAX_GUEST_FRAME,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path};
use std::ptr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

const AUTH_MAGIC: &[u8; 8] = b"SBXAUTH1";
const MAX_VECTOR: usize = 65_536;
const ARTIFACT_CHUNK_BYTES: u64 = 1024 * 1024;

struct ImportState {
    entries: BTreeMap<String, GuestArtifactEntry>,
    maximum: u64,
    bytes: u64,
}

struct GuestProxyHandle {
    pid: libc::pid_t,
}

struct ActiveRun {
    pid: libc::pid_t,
    control: UnixStream,
}

struct GuestTargetGuard {
    pid: libc::pid_t,
    cgroup: std::path::PathBuf,
    reaped: bool,
    cleaned: bool,
}

impl Drop for GuestTargetGuard {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: pid is the exact positive target-tree process-group leader.
            unsafe { libc::kill(-self.pid, libc::SIGKILL) };
            // SAFETY: direct-child kill is the fallback before setpgid has completed.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            let mut status = 0;
            loop {
                // SAFETY: pid is the direct child unless an earlier wait reaped it.
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result == self.pid
                    || (result < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
                {
                    break;
                }
            }
        }
        if !self.cleaned {
            let _ = cleanup_target_cgroup(&self.cgroup);
            let _ = cleanup_target_staging();
        }
    }
}

impl Drop for GuestProxyHandle {
    fn drop(&mut self) {
        // SAFETY: pid is the exact positive child returned when the proxy authority was created.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        let mut status = 0;
        loop {
            // SAFETY: the proxy is a direct child and status remains writable.
            let waited = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if waited == self.pid
                || (waited < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
            {
                break;
            }
        }
    }
}

fn main() {
    if let Err(error) = agent_main() {
        eprintln!(
            "sandbox guest agent failure: {}",
            bounded(&error.to_string())
        );
        // PID 1 must not return and trigger an uncontrolled kernel panic before logs flush.
        // SAFETY: sync has no pointers or ownership effects and is valid for PID 1.
        unsafe { libc::sync() };
        std::process::exit(1);
    }
}

fn agent_main() -> io::Result<()> {
    harden_agent()?;
    mount_guest_filesystems()?;
    let nonce = read_authentication_nonce()?;
    mount_workspace()?;
    let listener = listen_vsock(GUEST_CONTROL_PORT)?;
    let mut connection = loop {
        let connection_fd = accept_connection(listener.as_raw_fd())?;
        // SAFETY: accept_connection returns one new owned connected descriptor.
        let mut candidate = unsafe { File::from_raw_fd(connection_fd) };
        if authenticate(&mut candidate, &nonce).is_ok() {
            break candidate;
        }
        // A Firecracker proxy connection may be abandoned while the guest is still booting.
        // Invalid or incomplete attempts never consume the single authenticated session.
    };
    let mut import_state = None;
    let mut managed_proxy = None;
    let mut active_run: Option<ActiveRun> = None;
    loop {
        let request: GuestRequest = read_frame(&mut connection)?;
        let response = match request {
            GuestRequest::Authenticate { .. } => GuestResponse::Error {
                code: "protocol.already_authenticated".into(),
                message: "guest channel accepts one authentication message".into(),
                target_executed: false,
            },
            GuestRequest::BeginImport { entries, max_bytes } => {
                match begin_import(&entries, max_bytes) {
                    Ok(state) => {
                        let entries = state.entries.len();
                        import_state = Some(state);
                        GuestResponse::ImportReady { entries }
                    }
                    Err(error) => guest_error("artifact.import", &error, false),
                }
            }
            GuestRequest::ImportChunk {
                path,
                offset,
                content_hex,
            } => match import_state.as_mut() {
                Some(state) => match import_chunk(state, &path, offset, &content_hex) {
                    Ok(bytes) => GuestResponse::ImportChunkAccepted { path, bytes },
                    Err(error) => guest_error("artifact.import_chunk", &error, false),
                },
                None => GuestResponse::Error {
                    code: "artifact.import_state".into(),
                    message: "no import is active".into(),
                    target_executed: false,
                },
            },
            GuestRequest::CompleteImport => match import_state.take() {
                Some(state) => {
                    let entries = state.entries.len();
                    match complete_import(state) {
                        Ok(bytes) => GuestResponse::Imported { entries, bytes },
                        Err(error) => guest_error("artifact.import_complete", &error, false),
                    }
                }
                None => GuestResponse::Error {
                    code: "artifact.import_state".into(),
                    message: "no import is active".into(),
                    target_executed: false,
                },
            },
            GuestRequest::Inspect {
                executable,
                cwd,
                mounts,
                masks,
                system_runtime,
            } => match inspect_target(&executable, &cwd, &mounts, &masks, system_runtime) {
                Ok((executable_sha256, executable_identity_digest, cwd_identity_digest)) => {
                    GuestResponse::Inspected {
                        executable_sha256,
                        executable_identity_digest,
                        cwd_identity_digest,
                    }
                }
                Err(error) => guest_error("target.inspect", &error, false),
            },
            GuestRequest::Run {
                executable,
                expected_executable_sha256,
                expected_executable_identity_digest,
                args,
                cwd,
                expected_cwd_identity_digest,
                environment,
                mounts,
                masks,
                private_home,
                temporary,
                network_mode,
                system_runtime,
                limits,
            } => {
                if active_run.is_some() {
                    GuestResponse::Error {
                        code: "target.already_running".into(),
                        message: "one guest target is already active".into(),
                        target_executed: false,
                    }
                } else {
                    match ensure_managed_proxy(&mut managed_proxy, &network_mode, &nonce).and_then(
                        |()| {
                            start_active_run(
                                executable,
                                expected_executable_sha256,
                                expected_executable_identity_digest,
                                args,
                                cwd,
                                expected_cwd_identity_digest,
                                environment,
                                mounts,
                                masks,
                                private_home,
                                temporary,
                                network_mode,
                                system_runtime,
                                limits,
                                listener.as_raw_fd(),
                                connection.as_raw_fd(),
                            )
                        },
                    ) {
                        Ok((run, response)) => {
                            active_run = run;
                            response
                        }
                        Err(error) => guest_error("target.run", &error, false),
                    }
                }
            }
            GuestRequest::WriteStdin { content_hex } => {
                forward_run_request(&mut active_run, GuestRequest::WriteStdin { content_hex })
            }
            GuestRequest::CloseStdin => {
                forward_run_request(&mut active_run, GuestRequest::CloseStdin)
            }
            GuestRequest::PollRun => forward_run_request(&mut active_run, GuestRequest::PollRun),
            GuestRequest::TerminateRun { reason } => {
                forward_run_request(&mut active_run, GuestRequest::TerminateRun { reason })
            }
            GuestRequest::Export { paths, max_bytes } => match export_entries(&paths, max_bytes) {
                Ok((entries, digest, bytes)) => GuestResponse::Exported {
                    entries,
                    digest,
                    bytes,
                },
                Err(error) => guest_error("artifact.export", &error, false),
            },
            GuestRequest::ReadArtifact {
                path,
                offset,
                max_bytes,
            } => match read_artifact_chunk(&path, offset, max_bytes) {
                Ok((content, complete)) => GuestResponse::ArtifactChunk {
                    path,
                    offset,
                    content_hex: encode_hex(&content),
                    complete,
                },
                Err(error) => guest_error("artifact.read", &error, false),
            },
            GuestRequest::Shutdown => {
                terminate_active_run(&mut active_run);
                write_frame(&mut connection, &GuestResponse::ShuttingDown)?;
                // SAFETY: sync has no pointers or ownership effects and runs before VM reboot.
                unsafe { libc::sync() };
                terminate_virtual_machine();
            }
        };
        write_frame(&mut connection, &response)?;
    }
}

fn authenticate(connection: &mut File, nonce: &[u8; 32]) -> io::Result<()> {
    let request: GuestRequest = read_frame(connection)?;
    let GuestRequest::Authenticate {
        protocol_major,
        protocol_minor,
        nonce_hex,
    } = request
    else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authentication required",
        ));
    };
    validate_authentication(protocol_major, protocol_minor, &nonce_hex, nonce)?;
    write_frame(
        connection,
        &GuestResponse::Authenticated {
            protocol_major: GUEST_PROTOCOL_MAJOR,
            protocol_minor: GUEST_PROTOCOL_MINOR,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            agent_sha256: hash_reader(&mut File::open("/proc/self/exe")?)?,
        },
    )
}

fn validate_authentication(
    protocol_major: u16,
    protocol_minor: u16,
    nonce_hex: &str,
    expected_nonce: &[u8; 32],
) -> io::Result<()> {
    let nonce = decode_hex(nonce_hex)?;
    let nonce_matches = nonce.len() == expected_nonce.len()
        && nonce
            .iter()
            .zip(expected_nonce)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0;
    if protocol_major != GUEST_PROTOCOL_MAJOR
        || protocol_minor > GUEST_PROTOCOL_MINOR
        || !nonce_matches
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guest authentication failed",
        ));
    }
    Ok(())
}

fn harden_agent() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes a scalar and prevents target tracing of the trusted agent.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: PID 1 ignores ordinary termination to retain cleanup authority.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
    Ok(())
}

fn mount_guest_filesystems() -> io::Result<()> {
    for directory in [
        "/dev",
        "/proc",
        "/run",
        "/tmp",
        "/workspace",
        "/sys/fs/cgroup",
    ] {
        fs::create_dir_all(directory)?;
    }
    if let Err(error) = mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("mode=0755"),
    ) && error.raw_os_error() != Some(libc::EBUSY)
    {
        return Err(error);
    }
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("size=32m,mode=0755"),
    )?;
    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=256m,mode=1777"),
    )?;
    if mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
    .is_ok()
    {
        let _ = fs::write("/sys/fs/cgroup/cgroup.subtree_control", "+memory +pids\n");
    }
    Ok(())
}

fn mount_workspace() -> io::Result<()> {
    mount(
        Some("/dev/vdb"),
        "/workspace",
        Some("ext4"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("errors=remount-ro"),
    )?;
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions("/workspace", permissions)?;
    let root = CString::new("/workspace").expect("static");
    // SAFETY: root is a live NUL-terminated path; the return value is checked.
    if unsafe { libc::chown(root.as_ptr(), 1000, 1000) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_authentication_nonce() -> io::Result<[u8; 32]> {
    let mut device = File::open("/dev/vdc")?;
    let mut header = [0_u8; 40];
    device.read_exact(&mut header)?;
    if &header[..8] != AUTH_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid authentication drive",
        ));
    }
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&header[8..]);
    Ok(nonce)
}

#[allow(clippy::too_many_arguments)]
fn start_active_run(
    executable: String,
    expected_executable_sha256: String,
    expected_executable_identity_digest: String,
    args: Vec<String>,
    cwd: String,
    expected_cwd_identity_digest: String,
    environment: BTreeMap<String, String>,
    mounts: Vec<GuestMount>,
    masks: Vec<GuestMask>,
    private_home: GuestPrivateDirectory,
    temporary: GuestPrivateDirectory,
    network_mode: String,
    system_runtime: bool,
    limits: GuestLimits,
    listener_fd: RawFd,
    connection_fd: RawFd,
) -> io::Result<(Option<ActiveRun>, GuestResponse)> {
    let (parent, mut worker) = UnixStream::pair()?;
    // SAFETY: the privileged guest agent is single-threaded. The child closes the host control
    // descriptors and enters the dedicated worker path without returning through agent state.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(parent);
        // SAFETY: these are inherited duplicates; the parent guest agent remains their owner.
        unsafe { libc::close(listener_fd) };
        // SAFETY: the worker must never retain or expose the authenticated host channel.
        unsafe { libc::close(connection_fd) };
        let mut target_executed = false;
        let result = run_target(
            &executable,
            &expected_executable_sha256,
            &expected_executable_identity_digest,
            &args,
            &cwd,
            &expected_cwd_identity_digest,
            &environment,
            &mounts,
            &masks,
            &private_home,
            &temporary,
            &network_mode,
            system_runtime,
            limits,
            &mut worker,
            &mut target_executed,
        );
        let succeeded = result.is_ok();
        if let Err(error) = &result {
            let _ = write_frame(
                &mut worker,
                &guest_error("target.run", error, target_executed),
            );
        }
        // SAFETY: the forked worker must not unwind through copied guest-agent state.
        unsafe { libc::_exit(if succeeded { 0 } else { 125 }) };
    }
    drop(worker);
    let mut run = ActiveRun {
        pid,
        control: parent,
    };
    let response: GuestResponse = read_frame(&mut run.control)?;
    if matches!(response, GuestResponse::RunStarted) {
        Ok((Some(run), response))
    } else {
        reap_worker(pid);
        Ok((None, response))
    }
}

fn forward_run_request(active: &mut Option<ActiveRun>, request: GuestRequest) -> GuestResponse {
    let Some(run) = active.as_mut() else {
        return GuestResponse::Error {
            code: "target.not_running".into(),
            message: "no guest target is active".into(),
            target_executed: false,
        };
    };
    let response = write_frame(&mut run.control, &request)
        .and_then(|()| read_frame::<GuestResponse>(&mut run.control));
    match response {
        Ok(response) => {
            if matches!(
                response,
                GuestResponse::RunComplete { .. } | GuestResponse::Error { .. }
            ) {
                let pid = run.pid;
                reap_worker(pid);
                *active = None;
            }
            response
        }
        Err(error) => {
            let pid = run.pid;
            reap_worker(pid);
            *active = None;
            guest_error("target.worker", &error, true)
        }
    }
}

fn terminate_active_run(active: &mut Option<ActiveRun>) {
    let Some(mut run) = active.take() else {
        return;
    };
    let _ = run.control.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = run.control.set_write_timeout(Some(Duration::from_secs(1)));
    let _ = write_frame(
        &mut run.control,
        &GuestRequest::TerminateRun {
            reason: "caller-request".into(),
        },
    );
    let _ = read_frame::<GuestResponse>(&mut run.control);
    let deadline = Instant::now() + Duration::from_secs(11);
    while Instant::now() < deadline {
        if write_frame(&mut run.control, &GuestRequest::PollRun).is_err() {
            break;
        }
        match read_frame::<GuestResponse>(&mut run.control) {
            Ok(GuestResponse::RunComplete { .. } | GuestResponse::Error { .. }) => {
                reap_worker(run.pid);
                return;
            }
            Ok(GuestResponse::RunOutput { .. }) => {}
            Ok(_) | Err(_) => break,
        }
    }
    // The VM is about to power off; stop a wedged trusted worker before reboot.
    // SAFETY: pid is the exact positive worker child returned by fork.
    unsafe { libc::kill(run.pid, libc::SIGKILL) };
    reap_worker(run.pid);
}

fn reap_worker(pid: libc::pid_t) {
    let mut status = 0;
    loop {
        // SAFETY: pid is the exact positive direct child returned by fork.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid
            || (result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
        {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_target(
    executable: &str,
    expected_executable_sha256: &str,
    expected_executable_identity_digest: &str,
    args: &[String],
    cwd: &str,
    expected_cwd_identity_digest: &str,
    environment: &BTreeMap<String, String>,
    mounts: &[GuestMount],
    masks: &[GuestMask],
    private_home: &GuestPrivateDirectory,
    temporary: &GuestPrivateDirectory,
    network_mode: &str,
    system_runtime: bool,
    limits: GuestLimits,
    control: &mut UnixStream,
    target_executed: &mut bool,
) -> io::Result<()> {
    validate_target_request(executable, args, cwd, environment, mounts, &limits)?;
    let (executable_sha256, executable_identity_digest, cwd_identity_digest) =
        inspect_target(executable, cwd, mounts, masks, system_runtime)?;
    if executable_sha256 != expected_executable_sha256
        || executable_identity_digest != expected_executable_identity_digest
        || cwd_identity_digest != expected_cwd_identity_digest
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "prepared guest executable or working-directory identity changed",
        ));
    }
    let (stdin_read, stdin_write) = pipe_cloexec()?;
    let (stdout_read, stdout_write) = pipe_cloexec()?;
    let (stderr_read, stderr_write) = pipe_cloexec()?;
    let (mut target_status_read, target_status_write) = pipe_cloexec()?;
    let (mut setup_error_read, setup_error_write) = pipe_cloexec()?;
    let target_cgroup = configure_target_cgroup(&limits)?;
    // SAFETY: guest request processing is single-threaded before this fork; the child
    // immediately enters the dedicated no-return target setup path.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(stdin_write);
        drop(stdout_read);
        drop(stderr_read);
        drop(target_status_read);
        drop(setup_error_read);
        // SAFETY: this is the post-fork child with every descriptor argument still live.
        unsafe {
            target_exec(
                executable,
                args,
                cwd,
                environment,
                limits,
                stdin_read.as_raw_fd(),
                stdout_write.as_raw_fd(),
                stderr_write.as_raw_fd(),
                mounts,
                masks,
                private_home,
                temporary,
                network_mode,
                system_runtime,
                &target_cgroup,
                target_status_write.as_raw_fd(),
                setup_error_write.as_raw_fd(),
            )
        }
    }
    let mut target_guard = GuestTargetGuard {
        pid,
        cgroup: target_cgroup.clone(),
        reaped: false,
        cleaned: false,
    };
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);
    drop(target_status_write);
    drop(setup_error_write);
    let output_limit = limits.max_output_bytes;
    let output_total = Arc::new(AtomicU64::new(0));
    let output_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_observed = Arc::new(AtomicU64::new(0));
    let stderr_observed = Arc::new(AtomicU64::new(0));
    let stdout_pending = Arc::new(Mutex::new(Vec::new()));
    let stderr_pending = Arc::new(Mutex::new(Vec::new()));
    let stdout_total = Arc::clone(&output_total);
    let stdout_exceeded = Arc::clone(&output_exceeded);
    let stdout_count = Arc::clone(&stdout_observed);
    let stdout_chunks = Arc::clone(&stdout_pending);
    let stdout_thread = std::thread::spawn(move || {
        read_streaming_output(
            stdout_read,
            output_limit,
            &stdout_total,
            &stdout_exceeded,
            &stdout_count,
            &stdout_chunks,
        )
    });
    let stderr_total = Arc::clone(&output_total);
    let stderr_exceeded = Arc::clone(&output_exceeded);
    let stderr_count = Arc::clone(&stderr_observed);
    let stderr_chunks = Arc::clone(&stderr_pending);
    let stderr_thread = std::thread::spawn(move || {
        read_streaming_output(
            stderr_read,
            output_limit,
            &stderr_total,
            &stderr_exceeded,
            &stderr_count,
            &stderr_chunks,
        )
    });
    let mut setup_error = [0_u8; 1];
    let target_setup_failed = setup_error_read.read(&mut setup_error)? != 0;
    if target_setup_failed {
        // SAFETY: pid is the positive leader of the owned target process group.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        let mut status = 0;
        // SAFETY: pid is the direct child and status is writable.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        target_guard.reaped = true;
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();
        let _ = cleanup_target_cgroup(&target_cgroup);
        let _ = cleanup_target_staging();
        target_guard.cleaned = true;
        return Err(io::Error::other(
            "guest target setup failed before executable entry",
        ));
    }
    set_nonblocking(stdin_write.as_raw_fd(), true)?;
    let mut stdin_write = Some(stdin_write);
    let started = Instant::now();
    *target_executed = true;
    write_frame(control, &GuestResponse::RunStarted)?;
    let deadline = started + Duration::from_millis(limits.wall_time_ms);
    let mut status = 0;
    let mut timed_out = false;
    let mut cpu_limited = false;
    let mut output_limited = false;
    let mut requested_termination = None;
    let mut force_deadline = None;
    loop {
        // SAFETY: pid is the direct child returned by fork and status is writable.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            target_guard.reaped = true;
            break;
        }
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if output_exceeded.load(Ordering::Acquire) {
            output_limited = true;
            // SAFETY: pid is the positive leader of the owned target process group.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            // SAFETY: pid is the direct child and status is writable.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            target_guard.reaped = true;
            break;
        }
        if force_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            // SAFETY: pid is the positive leader of the owned target process group.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            // SAFETY: pid is the direct child and status is writable.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            target_guard.reaped = true;
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            // SAFETY: pid is the positive leader of the target process group.
            unsafe { libc::kill(-pid, libc::SIGTERM) };
            std::thread::sleep(Duration::from_millis(limits.termination_grace_ms));
            // SAFETY: the same owned target process group is forcibly terminated.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            // SAFETY: pid is the direct child and status is writable.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            target_guard.reaped = true;
            break;
        }
        if let Some(maximum) = limits.cpu_time_ms
            && cgroup_cpu_usage_ms(&target_cgroup)? >= maximum
        {
            cpu_limited = true;
            // SAFETY: pid is the positive leader of the owned target process group.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            // SAFETY: pid is the direct child and status is writable.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            target_guard.reaped = true;
            break;
        }
        if control_request_ready(control.as_raw_fd())? {
            let request: GuestRequest = read_frame(control)?;
            let response = match request {
                GuestRequest::WriteStdin { content_hex } => {
                    let content = decode_hex(&content_hex)?;
                    if content.len() > 64 * 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "guest stdin chunk exceeds 64 KiB",
                        ));
                    }
                    let bytes = match stdin_write.as_mut() {
                        Some(writer) => match writer.write(&content) {
                            Ok(bytes) => bytes,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
                            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                                stdin_write = None;
                                0
                            }
                            Err(error) => return Err(error),
                        },
                        None => 0,
                    };
                    GuestResponse::StdinAccepted {
                        bytes: bytes as u64,
                    }
                }
                GuestRequest::CloseStdin => {
                    stdin_write = None;
                    GuestResponse::StdinClosed
                }
                GuestRequest::PollRun => GuestResponse::RunOutput {
                    stdout_hex: encode_hex(&take_pending(&stdout_pending, 24 * 1024)?),
                    stderr_hex: encode_hex(&take_pending(&stderr_pending, 24 * 1024)?),
                },
                GuestRequest::TerminateRun { reason } => {
                    if requested_termination.is_none() {
                        requested_termination = Some(reason);
                        // SAFETY: pid is the positive leader of the owned target process group.
                        unsafe { libc::kill(-pid, libc::SIGTERM) };
                        force_deadline = Some(
                            Instant::now() + Duration::from_millis(limits.termination_grace_ms),
                        );
                    }
                    GuestResponse::TerminationStarted
                }
                _ => GuestResponse::Error {
                    code: "protocol.run_state".into(),
                    message: "request is invalid while a guest target is active".into(),
                    target_executed: true,
                },
            };
            write_frame(control, &response)?;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(stdin_write.take());
    let mut raw_status = [0_u8; size_of::<i32>()];
    if target_status_read.read_exact(&mut raw_status).is_ok() {
        status = i32::from_ne_bytes(raw_status);
    }
    let stdout_result = stdout_thread
        .join()
        .map_err(|_| io::Error::other("stdout pump panicked"))?;
    let stderr_result = stderr_thread
        .join()
        .map_err(|_| io::Error::other("stderr pump panicked"))?;
    let output_error = stdout_result
        .err()
        .or_else(|| stderr_result.err())
        .map(|error| error.to_string());
    output_limited |= output_exceeded.load(Ordering::Acquire);
    let memory_limited = cgroup_event_count(&target_cgroup.join("memory.events"), "oom_kill")? > 0;
    let process_limited = cgroup_event_count(&target_cgroup.join("pids.events"), "max")? > 0;
    let cpu_time_ms = cgroup_cpu_usage_ms(&target_cgroup).ok();
    let peak_memory_bytes = cgroup_scalar(&target_cgroup.join("memory.peak")).ok();
    let max_concurrent_processes = cgroup_scalar(&target_cgroup.join("pids.peak"))
        .ok()
        .map(|value| value.saturating_sub(2).max(1));
    let cleanup_error = cleanup_target_cgroup(&target_cgroup).err();
    let staging_error = cleanup_target_staging().err();
    target_guard.cleaned = true;
    let signal = libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status));
    let termination_reason = if timed_out {
        Some("timeout".into())
    } else if output_limited {
        Some("output-limit".into())
    } else if memory_limited {
        Some("memory-limit".into())
    } else if process_limited {
        Some("process-limit".into())
    } else if cpu_limited || signal == Some(libc::SIGXCPU) {
        Some("cpu-limit".into())
    } else if signal == Some(libc::SIGXFSZ) {
        Some("single-file-size-limit".into())
    } else if requested_termination.is_some() {
        Some("cancelled".into())
    } else {
        None
    };
    let runtime_error = if let Some(error) = output_error {
        Some(format!("target output collection failed: {error}"))
    } else if let Some(error) = staging_error {
        Some(format!("target mount staging cleanup failed: {error}"))
    } else {
        cleanup_error.map(|error| format!("target cgroup cleanup failed: {error}"))
    };
    let response = GuestResponse::RunComplete {
        exit_code: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
        signal,
        termination_reason,
        runtime_error,
        stdout_hex: String::new(),
        stderr_hex: String::new(),
        stdout_bytes: stdout_observed.load(Ordering::Acquire),
        stderr_bytes: stderr_observed.load(Ordering::Acquire),
        wall_time_ms: started.elapsed().as_millis() as u64,
        cpu_time_ms,
        peak_memory_bytes,
        max_concurrent_processes,
    };
    serve_completed_run(control, response, &stdout_pending, &stderr_pending)
}

#[allow(clippy::too_many_arguments)]
// SAFETY: caller must be the post-fork child, pass only live owned descriptors, and
// never return to code that could run duplicated pre-fork Rust state.
unsafe fn target_exec(
    executable: &str,
    args: &[String],
    cwd: &str,
    environment: &BTreeMap<String, String>,
    limits: GuestLimits,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    mounts: &[GuestMount],
    masks: &[GuestMask],
    private_home: &GuestPrivateDirectory,
    temporary: &GuestPrivateDirectory,
    network_mode: &str,
    system_runtime: bool,
    target_cgroup: &Path,
    target_status_fd: RawFd,
    setup_error_fd: RawFd,
) -> ! {
    let fail = || -> ! {
        let marker = [1_u8];
        // SAFETY: setup_error_fd is live and marker is a readable one-byte buffer.
        unsafe { libc::write(setup_error_fd, marker.as_ptr().cast(), marker.len()) };
        // SAFETY: post-fork failure must not run inherited Rust destructors.
        unsafe { libc::_exit(125) }
    };
    // SAFETY: the child may place itself in a new process group using scalar arguments.
    if unsafe { libc::setpgid(0, 0) } != 0
        || fs::write(target_cgroup.join("cgroup.procs"), "0\n").is_err()
    {
        fail();
    }
    // SAFETY: fixed namespace flags have no pointer arguments and only affect this child.
    if unsafe {
        libc::unshare(
            libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWPID,
        )
    } != 0
    {
        fail();
    }
    // SAFETY: the helper is single-threaded after fork and the child immediately follows
    // a bounded no-return namespace-init/target branch.
    let namespace_init = unsafe { libc::fork() };
    if namespace_init < 0 {
        fail();
    }
    if namespace_init > 0 {
        // SAFETY: parent side does not use either target-only status descriptor afterward.
        unsafe { libc::close(target_status_fd) };
        // SAFETY: setup_error_fd is target-only after namespace init has started.
        unsafe { libc::close(setup_error_fd) };
        let mut status = 0;
        loop {
            // SAFETY: namespace_init is a direct child and status is writable.
            let waited = unsafe { libc::waitpid(namespace_init, &mut status, 0) };
            if waited == namespace_init {
                let code = status_exit_code(status);
                // SAFETY: post-fork helper exits without running inherited destructors.
                unsafe { libc::_exit(code) };
            }
            if waited < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                fail();
            }
        }
    }
    // SAFETY: namespace init is single-threaded and this fork creates the actual target.
    let target_pid = unsafe { libc::fork() };
    if target_pid < 0 {
        fail();
    }
    if target_pid > 0 {
        // SAFETY: namespace init never writes target setup errors itself.
        unsafe { libc::close(setup_error_fd) };
        namespace_init_reap(target_pid, target_status_fd);
    }
    for (source, target) in [(stdin_fd, 0), (stdout_fd, 1), (stderr_fd, 2)] {
        // SAFETY: source is a live inherited pipe and target is one of descriptors 0-2.
        if unsafe { libc::dup2(source, target) } < 0 {
            fail();
        }
    }
    if construct_target_root(
        mounts,
        masks,
        private_home,
        temporary,
        network_mode,
        system_runtime,
    )
    .is_err()
        || install_private_target_dev().is_err()
        || apply_limits(&limits).is_err()
    {
        fail();
    }
    for capability in 0..64 {
        // SAFETY: PR_CAPBSET_DROP accepts scalar capability numbers; unsupported values fail.
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
    }
    // SAFETY: all calls use scalar IDs or a null empty-group pointer and monotonically reduce
    // the target's credentials and privileges.
    if unsafe { libc::setgroups(0, ptr::null()) } != 0
        // SAFETY: the following scalar calls monotonically reduce the target credentials.
        || unsafe { libc::setresgid(1000, 1000, 1000) } != 0
        // SAFETY: the fixed uid becomes all three target identities.
        || unsafe { libc::setresuid(1000, 1000, 1000) } != 0
        // SAFETY: no_new_privs is a one-way scalar restriction.
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || apply_seccomp().is_err()
    {
        fail();
    }
    let cwd = CString::new(cwd).unwrap_or_else(|_| fail());
    // SAFETY: cwd is a live NUL-terminated absolute target path.
    if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
        fail();
    }
    let executable = CString::new(executable).unwrap_or_else(|_| fail());
    let mut arg_storage = Vec::with_capacity(args.len() + 1);
    arg_storage.push(executable.clone());
    for arg in args {
        arg_storage.push(CString::new(arg.as_bytes()).unwrap_or_else(|_| fail()));
    }
    let mut arg_pointers = arg_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    arg_pointers.push(ptr::null());
    let environment_storage = environment
        .iter()
        .map(|(name, value)| CString::new(format!("{name}={value}")).unwrap_or_else(|_| fail()))
        .collect::<Vec<_>>();
    let mut environment_pointers = environment_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(ptr::null());
    close_descriptors_except_standard();
    // SAFETY: executable, argv and envp are live NUL-terminated values through execve.
    unsafe {
        libc::execve(
            executable.as_ptr(),
            arg_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    fail();
}

fn namespace_init_reap(target_pid: libc::pid_t, status_fd: RawFd) -> ! {
    let mut target_status = None;
    loop {
        let mut status = 0;
        // SAFETY: namespace PID 1 owns all children and status is writable.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == target_pid {
            target_status = Some(status);
            // PID 1 owns all remaining target descendants in this namespace.
            // SAFETY: kill(-1) cannot reach outside this PID namespace.
            unsafe { libc::kill(-1, libc::SIGKILL) };
        } else if pid < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                let status = target_status.unwrap_or(125 << 8);
                let bytes = status.to_ne_bytes();
                // SAFETY: status_fd is live and bytes is a readable fixed-size buffer.
                unsafe { libc::write(status_fd, bytes.as_ptr().cast(), bytes.len()) };
                // SAFETY: PID 1 exits directly after all children have been reaped.
                unsafe { libc::_exit(status_exit_code(status)) };
            }
            // SAFETY: unrecoverable PID 1 wait failure terminates without Rust unwinding.
            unsafe { libc::_exit(125) };
        }
    }
}

fn status_exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        125
    }
}

fn configure_target_cgroup(limits: &GuestLimits) -> io::Result<std::path::PathBuf> {
    let path = Path::new("/sys/fs/cgroup").join(format!("sandbox-target-{}", std::process::id()));
    if path.exists() {
        fs::remove_dir(&path)?;
    }
    fs::create_dir(&path)?;
    let setup = (|| {
        fs::write(
            path.join("memory.max"),
            format!("{}\n", limits.memory_bytes),
        )?;
        let cgroup_process_limit = limits
            .max_processes
            .checked_add(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "process limit overflow"))?;
        fs::write(path.join("pids.max"), format!("{cgroup_process_limit}\n"))?;
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = setup {
        let _ = fs::remove_dir(&path);
        return Err(error);
    }
    Ok(path)
}

fn cgroup_event_count(path: &Path, event: &str) -> io::Result<u64> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    for line in contents.lines() {
        let mut fields = line.split_ascii_whitespace();
        if fields.next() == Some(event) {
            return fields
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing cgroup event value")
                })?
                .parse()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup event value")
                });
        }
    }
    Ok(0)
}

fn cgroup_scalar(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup scalar"))
}

fn cgroup_cpu_usage_ms(path: &Path) -> io::Result<u64> {
    cgroup_event_count(&path.join("cpu.stat"), "usage_usec").map(|usage| usage / 1000)
}

fn cleanup_target_cgroup(path: &Path) -> io::Result<()> {
    if path.join("cgroup.kill").exists() {
        let _ = fs::write(path.join("cgroup.kill"), "1\n");
    }
    for _ in 0..100 {
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("target cgroup removal was not confirmed"))
}

fn construct_target_root(
    explicit_mounts: &[GuestMount],
    masks: &[GuestMask],
    private_home: &GuestPrivateDirectory,
    temporary: &GuestPrivateDirectory,
    network_mode: &str,
    system_runtime: bool,
) -> io::Result<()> {
    mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    let suffix = unique_staging_suffix()?;
    let root = format!("/run/sandbox-target-root-{suffix}");
    fs::create_dir(&root)?;
    mount(
        Some("tmpfs"),
        &root,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=32m,mode=0755"),
    )?;
    for directory in [
        "bin",
        "sbin",
        "usr",
        "lib",
        "lib64",
        "etc",
        "proc",
        "dev",
        "tmp",
        "run",
        "home",
        "home/sandbox",
        "workspace",
        ".old-root",
    ] {
        fs::create_dir_all(Path::new(&root).join(directory))?;
    }
    if system_runtime {
        for source in ["/bin", "/sbin", "/usr", "/lib", "/lib64"] {
            if Path::new(source).exists() {
                let target = format!("{root}{source}");
                bind_mount(source, &target, true, true)?;
            }
        }
        for source in [
            "/etc/ssl",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/passwd",
            "/etc/group",
        ] {
            if Path::new(source).exists() {
                let target = Path::new(&root).join(source.trim_start_matches('/'));
                create_mount_target(&target, Path::new(source).is_dir())?;
                bind_mount(
                    source,
                    target
                        .to_str()
                        .ok_or_else(|| io::Error::other("non-UTF8 target"))?,
                    true,
                    false,
                )?;
            }
        }
    }
    bind_mount("/workspace", &format!("{root}/workspace"), false, false)?;
    for specification in explicit_mounts {
        let source = Path::new(&specification.source);
        let target = Path::new(&root).join(specification.target.trim_start_matches('/'));
        create_mount_target(&target, source.is_dir())?;
        bind_mount(
            &specification.source,
            target
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 target"))?,
            specification.read_only,
            specification.executable,
        )?;
    }
    mount_private_directory(
        &format!("{root}/tmp"),
        temporary.size_bytes,
        temporary.executable,
        0o1777,
        None,
    )?;
    mount(
        Some("tmpfs"),
        &format!("{root}/run"),
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("size=32m,mode=0755"),
    )?;
    if private_home.enabled {
        mount_private_directory(
            &format!("{root}/home/sandbox"),
            private_home.size_bytes,
            private_home.executable,
            0o700,
            Some((1000, 1000)),
        )?;
    } else {
        fs::set_permissions(
            format!("{root}/home/sandbox"),
            fs::Permissions::from_mode(0o000),
        )?;
    }
    if network_mode == "managed" {
        install_managed_resolver(&root, &suffix)?;
    }
    apply_masks(&root, masks, &suffix)?;
    let root_c = CString::new(root.as_str()).map_err(io::Error::other)?;
    // SAFETY: root_c is a live NUL-terminated path to the private target root.
    if unsafe { libc::chdir(root_c.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let dot = CString::new(".").expect("static");
    let old = CString::new(".old-root").expect("static");
    // SAFETY: dot and old are live paths in the private mount namespace and satisfy pivot_root.
    if unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let slash = CString::new("/").expect("static");
    // SAFETY: slash is a static NUL-terminated path in the new root.
    if unsafe { libc::chdir(slash.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    let old_root = CString::new("/.old-root").expect("static");
    // SAFETY: old_root names the retained old-root mount in this private namespace.
    if unsafe { libc::umount2(old_root.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::remove_dir("/.old-root")?;
    Ok(())
}

fn mount_private_directory(
    target: &str,
    size: u64,
    executable: bool,
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let mut flags = libc::MS_NOSUID | libc::MS_NODEV;
    if !executable {
        flags |= libc::MS_NOEXEC;
    }
    let owner = owner
        .map(|(uid, gid)| format!(",uid={uid},gid={gid}"))
        .unwrap_or_default();
    let options = format!("size={size},mode={mode:o}{owner}");
    mount(Some("tmpfs"), target, Some("tmpfs"), flags, Some(&options))
}

fn apply_masks(root: &str, masks: &[GuestMask], suffix: &str) -> io::Result<()> {
    let staging = format!("/run/sandbox-mask-sources-{suffix}");
    fs::create_dir(&staging)?;
    for (index, mask) in masks.iter().enumerate() {
        let target = Path::new(root).join(mask.target.trim_start_matches('/'));
        reject_symlink_components(Path::new(root), &target)?;
        let underlying_directory = fs::metadata(&target).is_ok_and(|metadata| metadata.is_dir());
        let directory = match mask.replacement.as_str() {
            "empty-directory" => true,
            "empty-file" => false,
            "inaccessible" => underlying_directory,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid filesystem mask replacement",
                ));
            }
        };
        create_mount_target(&target, directory)?;
        let source = Path::new(&staging).join(index.to_string());
        if directory {
            fs::create_dir(&source)?;
        } else {
            File::create(&source)?;
        }
        let mode = if mask.replacement == "inaccessible" {
            0o000
        } else if directory {
            0o555
        } else {
            0o444
        };
        fs::set_permissions(&source, fs::Permissions::from_mode(mode))?;
        bind_mount(
            source
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 mask source"))?,
            target
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 mask target"))?,
            true,
            false,
        )?;
    }
    Ok(())
}

fn unique_staging_suffix() -> io::Result<String> {
    let mut random = [0_u8; 8];
    // SAFETY: random is a writable fixed-size buffer and flags request nonblocking entropy.
    let count = unsafe {
        libc::getrandom(
            random.as_mut_ptr().cast(),
            random.len(),
            libc::GRND_NONBLOCK,
        )
    };
    if count != random.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(format!(
        "{}-{}",
        // SAFETY: getpid has no pointers or preconditions.
        unsafe { libc::getpid() },
        encode_hex(&random)
    ))
}

fn cleanup_target_staging() -> io::Result<()> {
    for entry in fs::read_dir("/run")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("sandbox-target-root-")
            || name.starts_with("sandbox-mask-sources-")
            || name.starts_with("sandbox-resolv-")
        {
            let result = if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())
            } else {
                fs::remove_file(entry.path())
            };
            match result {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn install_managed_resolver(root: &str, suffix: &str) -> io::Result<()> {
    let source = format!("/run/sandbox-resolv-{suffix}");
    fs::write(
        &source,
        b"nameserver 127.0.0.1\noptions timeout:1 attempts:2\n",
    )?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o444))?;
    let target = Path::new(root).join("etc/resolv.conf");
    create_mount_target(&target, false)?;
    bind_mount(
        &source,
        target
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 resolver target"))?,
        true,
        false,
    )
}

fn reject_symlink_components(root: &Path, target: &Path) -> io::Result<()> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "mask target escapes root"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid mask target component",
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "mask target contains a symbolic link",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn create_mount_target(path: &Path, directory: bool) -> io::Result<()> {
    let root = path
        .ancestors()
        .last()
        .ok_or_else(|| io::Error::other("mount target has no root"))?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("mount target has no parent"))?;
    let mut current = root.to_path_buf();
    for component in parent.components().skip(1) {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "mount target parent is not a directory",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(error) => return Err(error),
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if directory && metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(metadata) if !directory && metadata.is_file() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mount target type mismatch",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound && directory => fs::create_dir(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map(drop),
        Err(error) => Err(error),
    }
}

fn bind_mount(source: &str, target: &str, read_only: bool, executable: bool) -> io::Result<()> {
    mount(
        Some(source),
        target,
        None,
        libc::MS_BIND | libc::MS_REC,
        None,
    )?;
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV;
    if read_only {
        flags |= libc::MS_RDONLY;
    }
    if !executable {
        flags |= libc::MS_NOEXEC;
    }
    mount(None, target, None, flags, None)
}

fn install_private_target_dev() -> io::Result<()> {
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("size=1m,mode=0755"),
    )?;
    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("random", 1, 8),
        ("urandom", 1, 9),
    ] {
        let target_path = format!("/dev/{name}");
        let target = CString::new(target_path).expect("static names");
        // SAFETY: target is a live NUL-terminated path and makedev values are fixed devices.
        if unsafe {
            libc::mknod(
                target.as_ptr(),
                libc::S_IFCHR | 0o666,
                libc::makedev(major, minor),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn apply_limits(limits: &GuestLimits) -> io::Result<()> {
    if let Some(cpu) = limits.cpu_time_ms {
        let seconds = cpu.saturating_add(999) / 1000;
        set_limit(libc::RLIMIT_CPU, seconds, seconds.saturating_add(1))?;
    }
    if let Some(files) = limits.max_open_files {
        set_limit(libc::RLIMIT_NOFILE, files, files)?;
    }
    if let Some(bytes) = limits.max_single_file_bytes {
        set_limit(libc::RLIMIT_FSIZE, bytes, bytes)?;
    }
    set_limit(
        libc::RLIMIT_NPROC,
        limits.max_processes,
        limits.max_processes,
    )?;
    set_limit(libc::RLIMIT_AS, limits.memory_bytes, limits.memory_bytes)?;
    Ok(())
}

#[cfg(target_env = "gnu")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type RlimitResource = libc::c_int;

fn set_limit(resource: RlimitResource, soft: u64, hard: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: resource is one of the fixed RLIMIT selectors and limit is initialized.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn apply_seccomp() -> io::Result<()> {
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    let architecture = if cfg!(target_arch = "x86_64") {
        AUDIT_ARCH_X86_64
    } else {
        AUDIT_ARCH_AARCH64
    };
    let mut filters = vec![
        stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 4),
        jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            architecture,
            1,
            0,
        ),
        stmt((libc::BPF_RET | libc::BPF_K) as u16, RET_KILL_PROCESS),
        stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
    ];
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
        RET_ERRNO | libc::EPERM as u32,
    ));
    filters.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0));
    for syscall in [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_perf_event_open,
        libc::SYS_clone3,
    ] {
        filters.push(jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            syscall as u32,
            0,
            1,
        ));
        filters.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            RET_ERRNO
                | if syscall == libc::SYS_clone3 {
                    libc::ENOSYS as u32
                } else {
                    libc::EPERM as u32
                },
        ));
    }
    filters.push(jump(
        (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        libc::SYS_socket as u32,
        0,
        4,
    ));
    filters.push(stmt(
        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        16,
    ));
    filters.push(jump(
        (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        libc::AF_VSOCK as u32,
        0,
        1,
    ));
    filters.push(stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        RET_ERRNO | libc::EPERM as u32,
    ));
    filters.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0));
    filters.push(stmt((libc::BPF_RET | libc::BPF_K) as u16, RET_ALLOW));
    let program = libc::sock_fprog {
        len: u16::try_from(filters.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seccomp filter too large"))?,
        filter: filters.as_mut_ptr(),
    };
    // SAFETY: program references the live filter vector and the call only installs restrictions.
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn inspect_target(
    executable: &str,
    cwd: &str,
    mounts: &[GuestMount],
    masks: &[GuestMask],
    system_runtime: bool,
) -> io::Result<(String, String, String)> {
    validate_target_request(
        executable,
        &[],
        cwd,
        &BTreeMap::new(),
        mounts,
        &GuestLimits {
            wall_time_ms: 1,
            cpu_time_ms: None,
            memory_bytes: 1,
            max_processes: 1,
            max_open_files: None,
            max_single_file_bytes: None,
            max_output_bytes: 1,
            termination_grace_ms: 0,
        },
    )?;
    if masks
        .iter()
        .any(|mask| target_contains(&mask.target, executable) || target_contains(&mask.target, cwd))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable or working directory is hidden by a filesystem mask",
        ));
    }
    let executable_path = resolve_target_source(executable, mounts, system_runtime)?;
    let cwd_path = resolve_cwd_source(cwd, mounts, system_runtime)?;
    let executable_metadata = fs::metadata(&executable_path)?;
    let cwd_metadata = fs::metadata(&cwd_path)?;
    if !executable_metadata.is_file() || !cwd_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable or cwd has the wrong type",
        ));
    }
    let executable_bytes = fs::read(&executable_path)?;
    let executable_sha256 = format!("{:x}", Sha256::digest(&executable_bytes));
    use std::os::unix::fs::MetadataExt;
    let executable_identity_digest = identity_digest(&serde_json::json!({
        "contentSha256": executable_sha256,
        "mode": executable_metadata.mode(),
        "size": executable_metadata.size(),
    }))
    .map_err(io::Error::other)?;
    let cwd_identity_digest = identity_digest(&serde_json::json!({
        "targetPath": cwd,
        "device": cwd_metadata.dev(),
        "inode": cwd_metadata.ino(),
        "mode": cwd_metadata.mode(),
    }))
    .map_err(io::Error::other)?;
    Ok((
        executable_sha256,
        executable_identity_digest,
        cwd_identity_digest,
    ))
}

fn target_contains(parent: &str, child: &str) -> bool {
    child == parent
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn resolve_target_source(
    target: &str,
    mounts: &[GuestMount],
    system_runtime: bool,
) -> io::Result<std::path::PathBuf> {
    let target_path = Path::new(target);
    let mapping = mounts
        .iter()
        .filter_map(|mount| {
            let prefix = Path::new(&mount.target);
            target_path
                .strip_prefix(prefix)
                .ok()
                .map(|suffix| (prefix.components().count(), mount, suffix))
        })
        .max_by_key(|(depth, _, _)| *depth);
    let (candidate, boundary) = if let Some((_, mount, suffix)) = mapping {
        let boundary = fs::canonicalize(&mount.source)?;
        let candidate = if suffix.as_os_str().is_empty() {
            boundary.clone()
        } else {
            boundary.join(suffix)
        };
        (candidate, boundary)
    } else if target_path.starts_with("/workspace") {
        let boundary = fs::canonicalize("/workspace")?;
        let suffix = target_path
            .strip_prefix("/workspace")
            .map_err(io::Error::other)?;
        let candidate = if suffix.as_os_str().is_empty() {
            boundary.clone()
        } else {
            boundary.join(suffix)
        };
        (candidate, boundary)
    } else if system_runtime {
        (target_path.to_path_buf(), Path::new("/").to_path_buf())
    } else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target path is outside the prepared runtime view",
        ));
    };
    let resolved = fs::canonicalize(candidate)?;
    if !resolved.starts_with(&boundary) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target path escapes its prepared source",
        ));
    }
    Ok(resolved)
}

fn resolve_cwd_source(
    target: &str,
    mounts: &[GuestMount],
    system_runtime: bool,
) -> io::Result<std::path::PathBuf> {
    match resolve_target_source(target, mounts, system_runtime) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let target_path = Path::new(target);
            let is_mount_ancestor = mounts
                .iter()
                .any(|mount| Path::new(&mount.target).starts_with(target_path));
            let is_private_directory = ["/", "/tmp", "/run", "/home", "/home/sandbox"]
                .iter()
                .any(|path| target_path == Path::new(path));
            if !target_path.is_absolute()
                || (!is_mount_ancestor && !is_private_directory)
                || target_path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(error);
            }
            let metadata = fs::metadata(target_path)?;
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "working directory has the wrong type",
                ));
            }
            fs::canonicalize(target_path)
        }
        Err(error) => Err(error),
    }
}

fn begin_import(entries: &[GuestArtifactEntry], maximum: u64) -> io::Result<ImportState> {
    if entries.len() > MAX_VECTOR || maximum == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid import manifest",
        ));
    }
    let mut manifest = BTreeMap::new();
    for entry in entries {
        if entry.content_hex.is_some() || manifest.contains_key(&entry.path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "import manifest contains inline content or duplicate paths",
            ));
        }
        let relative = validate_relative(&entry.path)?;
        let path = Path::new("/workspace").join(relative);
        ensure_safe_parent(Path::new("/workspace"), &entry.path)?;
        match entry.kind.as_str() {
            "directory" => fs::create_dir(&path)?,
            "regular-file" => {
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(entry.mode & 0o777)
                    .open(&path)?;
            }
            "symbolic-link" => {
                let target = entry.link_target.as_deref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing link target")
                })?;
                std::os::unix::fs::symlink(target, &path)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported artifact type",
                ));
            }
        }
        manifest.insert(entry.path.clone(), entry.clone());
    }
    Ok(ImportState {
        entries: manifest,
        maximum,
        bytes: 0,
    })
}

fn import_chunk(
    state: &mut ImportState,
    path: &str,
    offset: u64,
    content_hex: &str,
) -> io::Result<u64> {
    let entry = state.entries.get(path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "import chunk path is not declared",
        )
    })?;
    if entry.kind != "regular-file" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "import chunks require a regular file",
        ));
    }
    let content = decode_hex(content_hex)?;
    if content.len() as u64 > ARTIFACT_CHUNK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "import chunk exceeds limit",
        ));
    }
    let path = Path::new("/workspace").join(validate_relative(path)?);
    let mut file = OpenOptions::new().append(true).read(true).open(&path)?;
    if file.metadata()?.len() != offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "import chunk offset is not contiguous",
        ));
    }
    state.bytes = state
        .bytes
        .checked_add(content.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::FileTooLarge, "import byte count overflow"))?;
    if state.bytes > state.maximum {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "import limit exceeded",
        ));
    }
    file.write_all(&content)?;
    Ok(content.len() as u64)
}

fn complete_import(state: ImportState) -> io::Result<u64> {
    for entry in state
        .entries
        .values()
        .filter(|entry| entry.kind == "regular-file")
    {
        let path = Path::new("/workspace").join(validate_relative(&entry.path)?);
        let mut file = File::open(&path)?;
        let actual = hash_reader(&mut file)?;
        if entry.sha256.as_deref() != Some(actual.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "imported file digest mismatch",
            ));
        }
    }
    for entry in state.entries.values().rev() {
        let path = Path::new("/workspace").join(validate_relative(&entry.path)?);
        set_import_owner(&path, entry.kind == "symbolic-link")?;
        match entry.kind.as_str() {
            "directory" | "regular-file" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(entry.mode & 0o777))?;
                set_modified_time(&path, entry.modified_unix_ms, false)?;
            }
            "symbolic-link" => set_modified_time(&path, entry.modified_unix_ms, true)?,
            _ => unreachable!("begin_import validated artifact kinds"),
        }
    }
    Ok(state.bytes)
}

fn set_import_owner(path: &Path, no_follow: bool) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    let flags = if no_follow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    // SAFETY: path is NUL-terminated; flags explicitly preserve symlink identity when needed.
    if unsafe { libc::fchownat(libc::AT_FDCWD, path.as_ptr(), 1000, 1000, flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_modified_time(path: &Path, modified_unix_ms: i64, no_follow: bool) -> io::Result<()> {
    let seconds = modified_unix_ms.div_euclid(1000);
    let nanoseconds = modified_unix_ms.rem_euclid(1000) * 1_000_000;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds,
        },
    ];
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    let flags = if no_follow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    // SAFETY: path and the initialized times array remain live; no-follow is explicit.
    if unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn export_entries(
    paths: &[String],
    maximum: u64,
) -> io::Result<(Vec<GuestArtifactEntry>, String, u64)> {
    if paths.len() > MAX_VECTOR || maximum == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid export request",
        ));
    }
    let mut entries = Vec::new();
    let mut bytes = 0_u64;
    for value in paths {
        validate_relative(value)?;
        ensure_safe_parent(Path::new("/workspace"), value)?;
        export_walk(
            Path::new("/workspace"),
            &Path::new("/workspace").join(value),
            &mut entries,
            &mut bytes,
            maximum,
        )?;
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries.dedup_by(|left, right| left.path == right.path);
    let encoded = serde_json::to_vec(&entries).map_err(io::Error::other)?;
    let digest = format!("{:x}", Sha256::digest(encoded));
    Ok((entries, digest, bytes))
}

fn export_walk(
    root: &Path,
    path: &Path,
    entries: &mut Vec<GuestArtifactEntry>,
    total: &mut u64,
    maximum: u64,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "export escape"))?
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 export path"))?
        .to_owned();
    use std::os::unix::fs::MetadataExt;
    let mut entry = GuestArtifactEntry {
        path: relative,
        kind: if metadata.is_dir() {
            "directory"
        } else if metadata.is_file() {
            "regular-file"
        } else if metadata.file_type().is_symlink() {
            "symbolic-link"
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported export object",
            ));
        }
        .into(),
        mode: metadata.mode() & 0o7777,
        modified_unix_ms: metadata.mtime().saturating_mul(1000) + metadata.mtime_nsec() / 1_000_000,
        content_hex: None,
        link_target: None,
        sha256: None,
    };
    if metadata.is_file() {
        let length = metadata.len();
        *total = total
            .checked_add(length)
            .ok_or_else(|| io::Error::new(io::ErrorKind::FileTooLarge, "export overflow"))?;
        if *total > maximum {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "export limit exceeded",
            ));
        }
        entry.sha256 = Some(hash_reader(&mut File::open(path)?)?);
    } else if metadata.file_type().is_symlink() {
        entry.link_target = Some(fs::read_link(path)?.to_string_lossy().into_owned());
    }
    entries.push(entry);
    if metadata.is_dir() {
        let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            export_walk(root, &child.path(), entries, total, maximum)?;
        }
    }
    Ok(())
}

fn read_artifact_chunk(path: &str, offset: u64, maximum: u64) -> io::Result<(Vec<u8>, bool)> {
    if maximum == 0 || maximum > ARTIFACT_CHUNK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid artifact chunk limit",
        ));
    }
    let relative = validate_relative(path)?;
    ensure_safe_parent(Path::new("/workspace"), path)?;
    let path = Path::new("/workspace").join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || offset > metadata.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact chunk source is not a regular file or offset is invalid",
        ));
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let remaining = metadata.len() - offset;
    let count = remaining.min(maximum);
    let count = usize::try_from(count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "artifact chunk is too large"))?;
    let mut content = vec![0_u8; count];
    file.read_exact(&mut content)?;
    Ok((
        content,
        offset.saturating_add(count as u64) == metadata.len(),
    ))
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

fn validate_target_request(
    executable: &str,
    args: &[String],
    cwd: &str,
    environment: &BTreeMap<String, String>,
    mounts: &[GuestMount],
    limits: &GuestLimits,
) -> io::Result<()> {
    if !Path::new(executable).is_absolute()
        || !Path::new(cwd).is_absolute()
        || args.len() > MAX_VECTOR
        || environment.len() > MAX_VECTOR
        || mounts.len() > 4096
        || limits.wall_time_ms == 0
        || limits.max_output_bytes == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid target request",
        ));
    }
    for mount in mounts {
        let source = Path::new(&mount.source);
        let target = Path::new(&mount.target);
        if !source.is_absolute()
            || !target.is_absolute()
            || !source.starts_with("/workspace")
            || mount.source.contains('\0')
            || mount.target.contains('\0')
            || target == Path::new("/")
            || source
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || target
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid target mount",
            ));
        }
    }
    Ok(())
}

fn validate_relative(value: &str) -> io::Result<&Path> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\0')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid relative artifact path",
        ));
    }
    Ok(path)
}

fn ensure_safe_parent(root: &Path, relative: &str) -> io::Result<()> {
    let parent = Path::new(relative)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let mut current = root.to_path_buf();
    for component in parent.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "artifact parent is not a directory",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[derive(Default)]
struct BoundedOutput {
    bytes: Vec<u8>,
    observed: u64,
}

#[cfg(test)]
fn read_bounded_shared(
    mut file: File,
    maximum: u64,
    total: &AtomicU64,
    exceeded: &AtomicBool,
) -> io::Result<BoundedOutput> {
    let mut output = Vec::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed = observed.saturating_add(count as u64);
        let prior = total.fetch_add(count as u64, Ordering::AcqRel);
        let accepted = usize::try_from(maximum.saturating_sub(prior))
            .unwrap_or(usize::MAX)
            .min(count);
        output.extend_from_slice(&buffer[..accepted]);
        if accepted != count {
            exceeded.store(true, Ordering::Release);
            break;
        }
    }
    Ok(BoundedOutput {
        bytes: output,
        observed,
    })
}

fn read_streaming_output(
    mut file: File,
    maximum: u64,
    total: &AtomicU64,
    exceeded: &AtomicBool,
    observed: &AtomicU64,
    pending: &Mutex<Vec<u8>>,
) -> io::Result<()> {
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        observed.fetch_add(count as u64, Ordering::AcqRel);
        let prior = total.fetch_add(count as u64, Ordering::AcqRel);
        let accepted = usize::try_from(maximum.saturating_sub(prior))
            .unwrap_or(usize::MAX)
            .min(count);
        pending
            .lock()
            .map_err(|_| io::Error::other("output buffer lock poisoned"))?
            .extend_from_slice(&buffer[..accepted]);
        if accepted != count {
            exceeded.store(true, Ordering::Release);
            return Ok(());
        }
    }
}

fn take_pending(pending: &Mutex<Vec<u8>>, maximum: usize) -> io::Result<Vec<u8>> {
    let mut pending = pending
        .lock()
        .map_err(|_| io::Error::other("output buffer lock poisoned"))?;
    let count = pending.len().min(maximum);
    Ok(pending.drain(..count).collect())
}

fn serve_completed_run(
    control: &mut UnixStream,
    complete: GuestResponse,
    stdout: &Mutex<Vec<u8>>,
    stderr: &Mutex<Vec<u8>>,
) -> io::Result<()> {
    loop {
        let request: GuestRequest = read_frame(control)?;
        let response = match request {
            GuestRequest::PollRun => {
                let stdout = take_pending(stdout, 24 * 1024)?;
                let stderr = take_pending(stderr, 24 * 1024)?;
                if stdout.is_empty() && stderr.is_empty() {
                    write_frame(control, &complete)?;
                    return Ok(());
                }
                GuestResponse::RunOutput {
                    stdout_hex: encode_hex(&stdout),
                    stderr_hex: encode_hex(&stderr),
                }
            }
            GuestRequest::WriteStdin { .. } => GuestResponse::StdinAccepted { bytes: 0 },
            GuestRequest::CloseStdin => GuestResponse::StdinClosed,
            GuestRequest::TerminateRun { .. } => GuestResponse::TerminationStarted,
            _ => GuestResponse::Error {
                code: "protocol.run_state".into(),
                message: "request is invalid after guest target completion".into(),
                target_executed: true,
            },
        };
        write_frame(control, &response)?;
    }
}

fn control_request_ready(fd: RawFd) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor is one initialized pollfd and timeout zero never blocks.
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result > 0 && descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0)
}

fn set_nonblocking(fd: RawFd, enabled: bool) -> io::Result<()> {
    // SAFETY: F_GETFL reads flags from one live descriptor.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if enabled {
        current | libc::O_NONBLOCK
    } else {
        current & !libc::O_NONBLOCK
    };
    // SAFETY: F_SETFL changes only status flags on the same descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ensure_managed_proxy(
    handle: &mut Option<GuestProxyHandle>,
    network_mode: &str,
    nonce: &[u8; 32],
) -> io::Result<()> {
    match network_mode {
        "none" => Ok(()),
        "managed" if handle.is_some() => Ok(()),
        "managed" => {
            *handle = Some(start_managed_proxy(*nonce)?);
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported guest network mode",
        )),
    }
}

fn start_managed_proxy(nonce: [u8; 32]) -> io::Result<GuestProxyHandle> {
    bring_loopback_up()?;
    let http = TcpListener::bind((Ipv4Addr::LOCALHOST, GUEST_HTTP_PROXY_PORT))?;
    let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, GUEST_SOCKS_PROXY_PORT))?;
    let dns_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 53))?;
    let dns_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 53))?;
    let (mut ready_read, mut ready_write) = pipe_cloexec()?;
    // SAFETY: getpid has no pointer arguments or preconditions.
    let parent = unsafe { libc::getpid() };
    // The guest agent must stay single-threaded so its later target fork cannot inherit library
    // locks. The long-lived, threaded proxy is isolated in this dedicated trusted child.
    // SAFETY: the agent is single-threaded at this point and the child never returns to it.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        drop(ready_write);
        let handle = GuestProxyHandle { pid };
        let mut ready = [0_u8; 1];
        ready_read.read_exact(&mut ready)?;
        if ready != [1] {
            return Err(io::Error::other("guest managed proxy failed to initialize"));
        }
        return Ok(handle);
    }
    drop(ready_read);
    // SAFETY: a parent-death signal binds this trusted helper to the guest agent.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        // SAFETY: scalar parent identity is checked after installing the signal to close the race.
        || unsafe { libc::getppid() } != parent
    {
        // SAFETY: the post-fork child must not unwind inherited agent state.
        unsafe { libc::_exit(125) };
    }
    close_descriptors_except(&[
        http.as_raw_fd(),
        socks.as_raw_fd(),
        dns_tcp.as_raw_fd(),
        dns_udp.as_raw_fd(),
        ready_write.as_raw_fd(),
    ]);
    let threads = vec![
        guest_tcp_proxy_loop(http, GUEST_HTTP_TUNNEL_PORT, nonce),
        guest_tcp_proxy_loop(socks, GUEST_SOCKS_TUNNEL_PORT, nonce),
        guest_tcp_proxy_loop(dns_tcp, GUEST_DNS_TCP_TUNNEL_PORT, nonce),
        guest_udp_dns_loop(dns_udp, nonce),
    ];
    if ready_write.write_all(&[1]).is_err() {
        // SAFETY: this is the isolated post-fork proxy child.
        unsafe { libc::_exit(125) };
    }
    drop(ready_write);
    for thread in threads {
        let _ = thread.join();
    }
    // SAFETY: proxy listener termination ends the dedicated child without inherited destructors.
    unsafe { libc::_exit(0) };
}

fn guest_tcp_proxy_loop(
    listener: TcpListener,
    tunnel_port: u32,
    nonce: [u8; 32],
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while let Ok((client, _)) = listener.accept() {
            std::thread::spawn(move || {
                if let Ok(host) = connect_host_tunnel(tunnel_port, &nonce) {
                    let _ = relay_guest_tcp(client, host);
                }
            });
        }
    })
}

fn guest_udp_dns_loop(socket: UdpSocket, nonce: [u8; 32]) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut query = [0_u8; 4096];
        while let Ok((count, peer)) = socket.recv_from(&mut query) {
            if count == 0 || count > u16::MAX as usize {
                continue;
            }
            let response = (|| -> io::Result<Vec<u8>> {
                let mut host = connect_host_tunnel(GUEST_DNS_UDP_TUNNEL_PORT, &nonce)?;
                host.write_all(&(count as u16).to_be_bytes())?;
                host.write_all(&query[..count])?;
                let mut length = [0_u8; 2];
                host.read_exact(&mut length)?;
                let length = u16::from_be_bytes(length) as usize;
                if length == 0 || length > query.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid tunneled DNS response length",
                    ));
                }
                let mut response = vec![0_u8; length];
                host.read_exact(&mut response)?;
                Ok(response)
            })();
            if let Ok(response) = response {
                let _ = socket.send_to(&response, peer);
            }
        }
    })
}

fn connect_host_tunnel(port: u32, nonce: &[u8; 32]) -> io::Result<File> {
    // SAFETY: socket arguments select a standard close-on-exec AF_VSOCK stream.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = set_socket_timeout(fd, Duration::from_secs(5)) {
        // SAFETY: fd is owned locally and has not been transferred.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    // SAFETY: sockaddr_vm is plain C data and all-zero is a valid initialization state.
    let mut address: libc::sockaddr_vm = unsafe { zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_port = port;
    address.svm_cid = libc::VMADDR_CID_HOST;
    // SAFETY: address has the exact sockaddr_vm layout and remains live for connect.
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_vm).cast(),
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        // SAFETY: failed connection leaves the locally owned fd live.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    // SAFETY: fd remains owned after a successful connect and is transferred once.
    let mut stream = unsafe { File::from_raw_fd(fd) };
    stream.write_all(b"SBXNET1")?;
    stream.write_all(nonce)?;
    Ok(stream)
}

fn set_socket_timeout(fd: RawFd, duration: Duration) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: duration.as_secs().min(i64::MAX as u64) as _,
        tv_usec: duration.subsec_micros().into(),
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: timeout is initialized and its exact size is supplied for a live socket.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&timeout as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn relay_guest_tcp(mut client: TcpStream, mut host: File) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut host_writer = host.try_clone()?;
    let outbound = std::thread::spawn(move || io::copy(&mut client_reader, &mut host_writer));
    let inbound = io::copy(&mut host, &mut client);
    let _ = client.shutdown(Shutdown::Both);
    // SAFETY: host owns a live connected socket descriptor; shutdown does not transfer it.
    unsafe { libc::shutdown(host.as_raw_fd(), libc::SHUT_RDWR) };
    let outbound = outbound
        .join()
        .map_err(|_| io::Error::other("guest network relay panicked"))?;
    inbound.and(outbound).map(|_| ())
}

fn bring_loopback_up() -> io::Result<()> {
    // SAFETY: socket arguments request a close-on-exec IPv4 datagram control socket.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        // SAFETY: libc::ifreq is plain C data and zero initialization is valid.
        let mut request: libc::ifreq = unsafe { zeroed() };
        for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: request is a writable ifreq buffer for this fixed ioctl and fd is live.
        if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut request) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the ioctl initialized the ifru_flags union member read and updated here.
        unsafe {
            request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        // SAFETY: request retains the ifreq layout expected by the fixed setter ioctl.
        if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &request) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    // SAFETY: fd is still owned locally and is closed exactly once.
    unsafe { libc::close(fd) };
    result
}

fn listen_vsock(port: u32) -> io::Result<File> {
    // SAFETY: socket arguments select a standard close-on-exec AF_VSOCK stream.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr_vm is plain C data and all-zero is a valid initialization state.
    let mut address: libc::sockaddr_vm = unsafe { zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_port = port;
    address.svm_cid = libc::VMADDR_CID_ANY;
    // SAFETY: address has the exact sockaddr_vm layout and remains live for bind.
    let result = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_vm).cast(),
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    // SAFETY: fd is live and the backlog is a valid scalar.
    if result != 0 || unsafe { libc::listen(fd, 1) } != 0 {
        let error = io::Error::last_os_error();
        // SAFETY: fd remains locally owned on either setup failure.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    // SAFETY: successful setup leaves one owned descriptor transferred to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn accept_connection(listener: RawFd) -> io::Result<RawFd> {
    // SAFETY: listener is borrowed and null address outputs explicitly discard the peer address.
    let fd = unsafe {
        libc::accept4(
            listener,
            ptr::null_mut(),
            ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn mount(
    source: Option<&str>,
    target: &str,
    filesystem: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = source
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let target = CString::new(target).map_err(io::Error::other)?;
    let filesystem = filesystem
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)?;
    // SAFETY: every optional CString remains live for the call; target is always non-null.
    let result = unsafe {
        libc::mount(
            source.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            filesystem
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref()
                .map_or(ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pipe_cloexec() -> io::Result<(File, File)> {
    let mut fds = [0; 2];
    // SAFETY: fds contains two writable integer slots and O_CLOEXEC is valid.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two distinct owned descriptors, transferred once each.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

fn read_frame<T: for<'de> serde::Deserialize<'de>>(reader: &mut impl Read) -> io::Result<T> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_GUEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid guest frame length",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(io::Error::other)
}

fn write_frame<T: serde::Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    if payload.len() > MAX_GUEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest frame exceeds limit",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn decode_hex(value: &str) -> io::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.len() > MAX_GUEST_FRAME * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hexadecimal data",
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid hexadecimal data")
                })
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn close_descriptors_except(allowed: &[RawFd]) {
    if let Ok(entries) = fs::read_dir("/proc/self/fd") {
        let descriptors = entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<RawFd>().ok())
            .filter(|fd| *fd > 2 && !allowed.contains(fd))
            .collect::<Vec<_>>();
        for fd in descriptors {
            // SAFETY: each value came from /proc/self/fd and is closed only in pre-exec cleanup.
            unsafe { libc::close(fd) };
        }
    }
}

fn close_descriptors_except_standard() {
    close_descriptors_except(&[]);
}

fn terminate_virtual_machine() -> ! {
    // Firecracker treats the kernel's configured keyboard-controller reboot path as a
    // terminal VMM event. A guest power-off merely halts its vCPUs and can leave the
    // host VMM alive indefinitely.
    // SAFETY: reboot uses a fixed command and this privileged guest agent is PID 1.
    unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_RESTART) };
    loop {
        // SAFETY: pause has no pointer arguments and keeps PID 1 alive if reboot fails.
        unsafe { libc::pause() };
    }
}

fn guest_error(code: &str, error: &io::Error, target_executed: bool) -> GuestResponse {
    GuestResponse::Error {
        code: code.into(),
        message: bounded(&error.to_string()),
        target_executed,
    }
}

fn bounded(value: &str) -> String {
    value
        .chars()
        .take(1024)
        .filter(|character| !character.is_control() || *character == ' ')
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_kernel_abi_structures_have_expected_layout() {
        use std::mem::{offset_of, size_of};

        assert_eq!(size_of::<libc::sockaddr_vm>(), 16);
        assert_eq!(offset_of!(libc::sockaddr_vm, svm_family), 0);
        assert_eq!(offset_of!(libc::sockaddr_vm, svm_port), 4);
        assert_eq!(offset_of!(libc::sockaddr_vm, svm_cid), 8);
        assert_eq!(size_of::<libc::ifreq>(), libc::IFNAMSIZ + 24);
        assert_eq!(offset_of!(libc::ifreq, ifr_name), 0);
        assert_eq!(offset_of!(libc::ifreq, ifr_ifru), libc::IFNAMSIZ);
        assert_eq!(size_of::<libc::sock_filter>(), 8);
        assert_eq!(offset_of!(libc::sock_filter, code), 0);
        assert_eq!(offset_of!(libc::sock_filter, jt), 2);
        assert_eq!(offset_of!(libc::sock_filter, jf), 3);
        assert_eq!(offset_of!(libc::sock_filter, k), 4);
    }

    #[test]
    fn guest_authentication_rejects_wrong_nonce_and_protocol() {
        let nonce = [0x5a_u8; 32];
        let encoded = encode_hex(&nonce);
        assert!(
            validate_authentication(GUEST_PROTOCOL_MAJOR, GUEST_PROTOCOL_MINOR, &encoded, &nonce)
                .is_ok()
        );
        assert!(
            validate_authentication(
                GUEST_PROTOCOL_MAJOR + 1,
                GUEST_PROTOCOL_MINOR,
                &encoded,
                &nonce,
            )
            .is_err()
        );
        assert!(
            validate_authentication(
                GUEST_PROTOCOL_MAJOR,
                GUEST_PROTOCOL_MINOR + 1,
                &encoded,
                &nonce,
            )
            .is_err()
        );
        let mut wrong = nonce;
        wrong[31] ^= 1;
        assert!(
            validate_authentication(
                GUEST_PROTOCOL_MAJOR,
                GUEST_PROTOCOL_MINOR,
                &encode_hex(&wrong),
                &nonce,
            )
            .is_err()
        );
    }

    #[test]
    fn aggregate_output_reader_signals_the_hard_limit() {
        let (reader, mut writer) = pipe_cloexec().expect("pipe");
        writer.write_all(b"abcdef").expect("write output");
        drop(writer);
        let total = AtomicU64::new(0);
        let exceeded = AtomicBool::new(false);
        let output = read_bounded_shared(reader, 4, &total, &exceeded).expect("read output");
        assert_eq!(output.bytes, b"abcd");
        assert_eq!(output.observed, 6);
        assert!(exceeded.load(Ordering::Acquire));
        assert_eq!(total.load(Ordering::Acquire), 6);
    }
}
