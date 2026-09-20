use crate::{OutputSpool, RetainedPage, SpoolError};
use sandsurf_protocol::{
    Counter, Digest, OutputBoundary, ProcessId, ProcessLifetime, ProcessOutcome, SandboxId,
    SpawnRequest, StdioMode, Stream, TerminalSize, bytes_digest,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const READ_BUFFER: usize = sandsurf_protocol::MAX_STREAM_BYTES;
const PROCESS_EXIT_GRACE: Duration = Duration::from_millis(500);
const MAX_PASSWD_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub enum ProcessError {
    Io(io::Error),
    Invalid(&'static str),
    Conflict(&'static str),
    Missing,
    Spool(SpoolError),
    Timeout,
    Unknown(Digest),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "process I/O: {error}"),
            Self::Invalid(message) => write!(output, "invalid process request: {message}"),
            Self::Conflict(message) => write!(output, "process conflict: {message}"),
            Self::Missing => output.write_str("process does not exist"),
            Self::Spool(error) => error.fmt(output),
            Self::Timeout => output.write_str("process wait timed out"),
            Self::Unknown(evidence) => write!(output, "process outcome is unknown: {evidence:?}"),
        }
    }
}

impl std::error::Error for ProcessError {}
impl From<io::Error> for ProcessError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<SpoolError> for ProcessError {
    fn from(value: SpoolError) -> Self {
        Self::Spool(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCompletion {
    pub outcome: ProcessOutcome,
    pub output: OutputBoundary,
    pub cleanup_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Exited(ProcessCompletion),
    Unknown { evidence: Digest },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub request: SpawnRequest,
    pub guest_pid: u32,
    pub state: ProcessState,
}

pub struct ProcessSupervisor {
    sandbox_id: SandboxId,
    epoch: Counter,
    root: PathBuf,
    processes: Mutex<BTreeMap<ProcessId, Arc<ProcessEntry>>>,
}

struct ProcessEntry {
    request: SpawnRequest,
    pid: u32,
    group: i32,
    input: Mutex<Option<Input>>,
    terminal: Option<File>,
    spool: Arc<OutputSpool>,
    state: Mutex<ProcessState>,
    changed: Condvar,
}

enum Input {
    Pipe(ChildStdin),
    Terminal(File),
}

struct Spawned {
    child: Child,
    input: Input,
    terminal: Option<File>,
    readers: Vec<(Box<dyn Read + Send>, Stream)>,
}

impl ProcessSupervisor {
    pub fn create(
        root: &Path,
        sandbox_id: SandboxId,
        epoch: Counter,
    ) -> Result<Self, ProcessError> {
        if !root.is_absolute() || epoch == Counter::ZERO {
            return Err(ProcessError::Invalid(
                "supervisor root must be absolute and epoch positive",
            ));
        }
        fs::create_dir_all(root)?;
        if !fs::metadata(root)?.is_dir() {
            return Err(ProcessError::Invalid("supervisor root is not a directory"));
        }
        Ok(Self {
            sandbox_id,
            epoch,
            root: root.to_path_buf(),
            processes: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn spawn(&self, request: SpawnRequest) -> Result<ProcessSnapshot, ProcessError> {
        request
            .validate()
            .map_err(|_| ProcessError::Invalid("spawn validation failed"))?;
        if request.sandbox_id != self.sandbox_id || request.epoch != self.epoch {
            return Err(ProcessError::Conflict("sandbox epoch mismatch"));
        }
        let mut processes = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?;
        if let Some(existing) = processes.get(&request.process_id) {
            if existing.request != request {
                return Err(ProcessError::Conflict(
                    "process identity is already bound to another request",
                ));
            }
            return existing.snapshot();
        }
        let directory = self.root.join(request.process_id.as_str());
        fs::create_dir(&directory)?;
        let spool = Arc::new(OutputSpool::create(
            &directory.join("output.ssf"),
            request.output_bytes,
        )?);
        let mut spawned = spawn_child(&request)?;
        let pid = spawned.child.id();
        let entry = Arc::new(ProcessEntry {
            request: request.clone(),
            pid,
            group: i32::try_from(pid).map_err(|_| ProcessError::Invalid("PID overflow"))?,
            input: Mutex::new(Some(spawned.input)),
            terminal: spawned.terminal,
            spool,
            state: Mutex::new(ProcessState::Running),
            changed: Condvar::new(),
        });
        processes.insert(request.process_id.clone(), Arc::clone(&entry));
        drop(processes);

        let mut readers = Vec::new();
        for (reader, stream) in spawned.readers.drain(..) {
            readers.push(start_reader(Arc::clone(&entry), reader, stream));
        }
        start_waiter(Arc::clone(&entry), spawned.child, readers);
        entry.snapshot()
    }

    pub fn get(&self, id: &ProcessId) -> Result<ProcessSnapshot, ProcessError> {
        self.entry(id)?.snapshot()
    }

    pub fn list(&self) -> Result<Vec<ProcessSnapshot>, ProcessError> {
        let entries: Vec<_> = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?
            .values()
            .cloned()
            .collect();
        entries.into_iter().map(|entry| entry.snapshot()).collect()
    }

    pub fn write_input(&self, id: &ProcessId, bytes: &[u8]) -> Result<(), ProcessError> {
        if bytes.is_empty() || bytes.len() > sandsurf_protocol::MAX_STREAM_BYTES {
            return Err(ProcessError::Invalid("input chunk is outside frame bounds"));
        }
        let entry = self.entry(id)?;
        if !matches!(entry.state()?, ProcessState::Running) {
            return Err(ProcessError::Conflict("process is not running"));
        }
        let mut input = entry
            .input
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-input-poisoned")))?;
        match input
            .as_mut()
            .ok_or(ProcessError::Conflict("input is closed"))?
        {
            Input::Pipe(value) => value.write_all(bytes)?,
            Input::Terminal(value) => value.write_all(bytes)?,
        }
        Ok(())
    }

    pub fn close_input(&self, id: &ProcessId) -> Result<(), ProcessError> {
        let entry = self.entry(id)?;
        entry
            .input
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-input-poisoned")))?
            .take();
        Ok(())
    }

    pub fn resize_terminal(&self, id: &ProcessId, size: TerminalSize) -> Result<(), ProcessError> {
        size.validate()
            .map_err(|_| ProcessError::Invalid("terminal size is invalid"))?;
        let entry = self.entry(id)?;
        let terminal = entry
            .terminal
            .as_ref()
            .ok_or(ProcessError::Conflict("process has no terminal"))?;
        set_terminal_size(terminal, size)?;
        Ok(())
    }

    pub fn signal(&self, id: &ProcessId, signal: i32, group: bool) -> Result<(), ProcessError> {
        if !(1..=64).contains(&signal) {
            return Err(ProcessError::Invalid("signal is outside supported range"));
        }
        let entry = self.entry(id)?;
        if group {
            send_group_signal(entry.group, signal)
        } else {
            send_process_signal(entry.pid, signal)
        }
    }

    pub fn terminate(&self, id: &ProcessId, grace: Duration) -> Result<(), ProcessError> {
        if grace > Duration::from_secs(60) {
            return Err(ProcessError::Invalid(
                "termination grace exceeds 60 seconds",
            ));
        }
        let entry = self.entry(id)?;
        if !matches!(entry.state()?, ProcessState::Running) {
            return Ok(());
        }
        let group = entry.group;
        send_group_signal(group, libc::SIGTERM)?;
        std::thread::spawn(move || {
            let deadline = Instant::now() + grace;
            while Instant::now() < deadline && group_exists(group) {
                std::thread::sleep(Duration::from_millis(10));
            }
            if group_exists(group) {
                let _ = send_group_signal(group, libc::SIGKILL);
            }
        });
        Ok(())
    }

    pub fn wait(
        &self,
        id: &ProcessId,
        timeout: Option<Duration>,
    ) -> Result<ProcessCompletion, ProcessError> {
        let entry = self.entry(id)?;
        let mut state = entry
            .state
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-state-poisoned")))?;
        let deadline = timeout.map(|value| Instant::now() + value);
        loop {
            match &*state {
                ProcessState::Exited(value) => return Ok(value.clone()),
                ProcessState::Unknown { evidence } => {
                    return Err(ProcessError::Unknown(evidence.clone()));
                }
                ProcessState::Running => {}
            }
            state = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ProcessError::Timeout);
                    }
                    let (next, timeout) =
                        entry.changed.wait_timeout(state, remaining).map_err(|_| {
                            ProcessError::Unknown(bytes_digest(b"process-state-poisoned"))
                        })?;
                    if timeout.timed_out() && matches!(*next, ProcessState::Running) {
                        return Err(ProcessError::Timeout);
                    }
                    next
                }
                None => entry
                    .changed
                    .wait(state)
                    .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-state-poisoned")))?,
            };
        }
    }

    pub fn read_output(
        &self,
        id: &ProcessId,
        after: Counter,
        maximum: usize,
    ) -> Result<RetainedPage, ProcessError> {
        Ok(self.entry(id)?.spool.read(after, maximum)?)
    }

    fn entry(&self, id: &ProcessId) -> Result<Arc<ProcessEntry>, ProcessError> {
        self.processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?
            .get(id)
            .cloned()
            .ok_or(ProcessError::Missing)
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        if let Ok(processes) = self.processes.lock() {
            for entry in processes.values() {
                let _ = send_group_signal(entry.group, libc::SIGKILL);
            }
        }
    }
}

impl ProcessEntry {
    fn state(&self) -> Result<ProcessState, ProcessError> {
        self.state
            .lock()
            .map(|value| value.clone())
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-state-poisoned")))
    }

    fn snapshot(&self) -> Result<ProcessSnapshot, ProcessError> {
        Ok(ProcessSnapshot {
            request: self.request.clone(),
            guest_pid: self.pid,
            state: self.state()?,
        })
    }

    fn finish(&self, value: ProcessState) {
        if let Ok(mut state) = self.state.lock() {
            *state = value;
            self.changed.notify_all();
        }
    }
}

fn spawn_child(request: &SpawnRequest) -> Result<Spawned, ProcessError> {
    let mut command = Command::new(&request.argv[0]);
    command
        .args(&request.argv[1..])
        .current_dir(&request.cwd)
        .env_clear()
        .envs(&request.environment);
    if let Some(user) = &request.user {
        let (uid, gid) = resolve_user(user)?;
        command.uid(uid).gid(gid);
    }
    match request.stdio {
        StdioMode::Pipes => {
            // SAFETY: this closure executes after fork and before exec, invokes
            // only async-signal-safe setpgid, and does not access shared memory.
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let input = child
                .stdin
                .take()
                .ok_or(ProcessError::Invalid("child stdin is unavailable"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or(ProcessError::Invalid("child stdout is unavailable"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or(ProcessError::Invalid("child stderr is unavailable"))?;
            Ok(Spawned {
                child,
                input: Input::Pipe(input),
                terminal: None,
                readers: vec![
                    (Box::new(stdout), Stream::Stdout),
                    (Box::new(stderr), Stream::Stderr),
                ],
            })
        }
        StdioMode::Terminal => {
            let size = request
                .terminal_size
                .ok_or(ProcessError::Invalid("terminal size is absent"))?;
            let pty = open_terminal(size)?;
            let input = pty.master.try_clone()?;
            let control = pty.master.try_clone()?;
            let stdin = pty.slave.try_clone()?;
            let stdout = pty.slave.try_clone()?;
            command
                .stdin(Stdio::from(stdin))
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::from(pty.slave));
            // SAFETY: this closure executes after fork and before exec, invokes
            // only async-signal-safe session/ioctl operations, and fd 0 has
            // already been installed from the retained PTY slave.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn()?;
            Ok(Spawned {
                child,
                input: Input::Terminal(input),
                terminal: Some(control),
                readers: vec![(Box::new(pty.master), Stream::Terminal)],
            })
        }
    }
}

fn start_reader(
    entry: Arc<ProcessEntry>,
    mut reader: Box<dyn Read + Send>,
    stream: Stream,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; READ_BUFFER];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if entry.spool.append(stream, &buffer[..count]).is_err() {
                        let _ = send_group_signal(entry.group, libc::SIGKILL);
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error)
                    if stream == Stream::Terminal && error.raw_os_error() == Some(libc::EIO) =>
                {
                    break;
                }
                Err(_) => {
                    let _ = send_group_signal(entry.group, libc::SIGKILL);
                    break;
                }
            }
        }
    })
}

fn start_waiter(entry: Arc<ProcessEntry>, mut child: Child, readers: Vec<JoinHandle<()>>) {
    std::thread::spawn(move || {
        let waited = child.wait();
        if entry.request.lifetime == ProcessLifetime::Job {
            terminate_group(entry.group, PROCESS_EXIT_GRACE);
        } else {
            while group_exists(entry.group) && !entry.spool.has_failed() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let readers_complete = readers.into_iter().all(|reader| reader.join().is_ok());
        if !readers_complete || entry.spool.has_failed() {
            entry.finish(ProcessState::Unknown {
                evidence: bytes_digest(b"output-retention-incomplete"),
            });
            return;
        }
        let Ok(status) = waited else {
            entry.finish(ProcessState::Unknown {
                evidence: bytes_digest(b"wait-status-unavailable"),
            });
            return;
        };
        let outcome = match (status.code(), status.signal()) {
            (Some(code), _) => ProcessOutcome::Exit { code },
            (None, Some(signal)) => ProcessOutcome::Signal {
                signal: signal as u32,
            },
            _ => ProcessOutcome::Interrupted {
                evidence: bytes_digest(b"exit-status-unclassified"),
            },
        };
        match entry.spool.finalize() {
            Ok(output) => entry.finish(ProcessState::Exited(ProcessCompletion {
                outcome,
                output,
                cleanup_digest: bytes_digest(b"process-group-empty"),
            })),
            Err(_) => entry.finish(ProcessState::Unknown {
                evidence: bytes_digest(b"output-finalization-failed"),
            }),
        }
    });
}

struct PtyPair {
    master: File,
    slave: File,
}

fn open_terminal(size: TerminalSize) -> Result<PtyPair, ProcessError> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let dimensions = libc::winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: size.pixel_width,
        ws_ypixel: size.pixel_height,
    };
    // SAFETY: master/slave are valid out pointers, dimensions is initialized,
    // and no termios override is requested. Successful descriptors are uniquely
    // transferred to File below.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &dimensions,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: openpty succeeded and returned two independently owned fds.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: openpty succeeded and returned two independently owned fds.
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok(PtyPair { master, slave })
}

fn set_terminal_size(terminal: &File, size: TerminalSize) -> Result<(), ProcessError> {
    use std::os::fd::AsRawFd;
    let dimensions = libc::winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: size.pixel_width,
        ws_ypixel: size.pixel_height,
    };
    // SAFETY: terminal is an open retained PTY master and dimensions points to
    // a fully initialized winsize for the duration of the ioctl.
    if unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCSWINSZ as _, &dimensions) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn send_group_signal(group: i32, signal: i32) -> Result<(), ProcessError> {
    // SAFETY: a negative nonzero PID addresses exactly the retained process
    // group; signal range is validated by public callers or is a fixed constant.
    if unsafe { libc::kill(-group, signal) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

fn send_process_signal(pid: u32, signal: i32) -> Result<(), ProcessError> {
    let pid = i32::try_from(pid).map_err(|_| ProcessError::Invalid("PID overflow"))?;
    // SAFETY: pid is the exact positive child identity retained by this entry;
    // the public method validated the signal range.
    if unsafe { libc::kill(pid, signal) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

fn group_exists(group: i32) -> bool {
    // SAFETY: signal zero performs a membership/permission check and has no
    // signal effect; group is a positive PID obtained from a child.
    let result = unsafe { libc::kill(-group, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn terminate_group(group: i32, grace: Duration) {
    let _ = send_group_signal(group, libc::SIGTERM);
    let deadline = Instant::now() + grace;
    while group_exists(group) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if group_exists(group) {
        let _ = send_group_signal(group, libc::SIGKILL);
    }
}

fn resolve_user(value: &str) -> Result<(u32, u32), ProcessError> {
    if let Some((uid, gid)) = value.split_once(':')
        && let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse())
    {
        return Ok((uid, gid));
    }
    if let Ok(uid) = value.parse::<u32>() {
        return Ok((uid, uid));
    }
    let mut bytes = Vec::new();
    File::open("/etc/passwd")?
        .take(MAX_PASSWD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PASSWD_BYTES {
        return Err(ProcessError::Invalid("passwd database exceeds bound"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ProcessError::Invalid("passwd database is not UTF-8"))?;
    let mut matches = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() >= 4 && fields[0] == value {
            let uid = fields[2]
                .parse::<u32>()
                .map_err(|_| ProcessError::Invalid("passwd UID is invalid"))?;
            let gid = fields[3]
                .parse::<u32>()
                .map_err(|_| ProcessError::Invalid("passwd GID is invalid"))?;
            matches.insert((uid, gid));
        }
    }
    match matches.into_iter().collect::<Vec<_>>().as_slice() {
        [value] => Ok(*value),
        [] => Err(ProcessError::Invalid("workload user does not exist")),
        _ => Err(ProcessError::Invalid("workload user is ambiguous")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::{OperationId, ProcessId};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-process-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(id: &str, script: &str, stdio: StdioMode) -> SpawnRequest {
        SpawnRequest {
            sandbox_id: SandboxId::try_from("box").unwrap(),
            epoch: Counter::ONE,
            process_id: ProcessId::try_from(id).unwrap(),
            operation_id: OperationId::try_from(format!("op-{id}")).unwrap(),
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: "/".into(),
            environment: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            user: None,
            stdio,
            terminal_size: (stdio == StdioMode::Terminal).then_some(TerminalSize {
                columns: 80,
                rows: 24,
                pixel_width: 0,
                pixel_height: 0,
            }),
            lifetime: ProcessLifetime::Job,
            output_bytes: (1024 * 1024u64).try_into().unwrap(),
        }
    }

    #[test]
    fn concurrent_processes_have_independent_binary_streams() {
        let root = Temp::new();
        let supervisor =
            ProcessSupervisor::create(&root.0, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        supervisor
            .spawn(request(
                "one",
                "printf 'one\\000byte'; sleep 0.1",
                StdioMode::Pipes,
            ))
            .unwrap();
        supervisor
            .spawn(request("two", "printf two >&2", StdioMode::Pipes))
            .unwrap();
        supervisor
            .wait(
                &ProcessId::try_from("one").unwrap(),
                Some(Duration::from_secs(5)),
            )
            .unwrap();
        supervisor
            .wait(
                &ProcessId::try_from("two").unwrap(),
                Some(Duration::from_secs(5)),
            )
            .unwrap();
        let one = supervisor
            .read_output(&ProcessId::try_from("one").unwrap(), Counter::ZERO, 1024)
            .unwrap();
        let two = supervisor
            .read_output(&ProcessId::try_from("two").unwrap(), Counter::ZERO, 1024)
            .unwrap();
        assert_eq!(one.chunks[0].bytes, b"one\0byte");
        assert_eq!(two.chunks[0].stream, Stream::Stderr);
        assert_eq!(two.chunks[0].bytes, b"two");
    }

    #[test]
    fn terminal_is_merged_resizable_and_interactive() {
        let root = Temp::new();
        let supervisor =
            ProcessSupervisor::create(&root.0, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let id = ProcessId::try_from("terminal").unwrap();
        supervisor
            .spawn(request(
                "terminal",
                "read value; printf 'got:%s' \"$value\"",
                StdioMode::Terminal,
            ))
            .unwrap();
        supervisor
            .resize_terminal(
                &id,
                TerminalSize {
                    columns: 120,
                    rows: 40,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            )
            .unwrap();
        supervisor.write_input(&id, b"hello\n").unwrap();
        let completion = supervisor.wait(&id, Some(Duration::from_secs(5))).unwrap();
        assert!(completion.output.terminal_bytes.get() > 0);
        assert_eq!(completion.output.stdout_bytes, Counter::ZERO);
        let bytes: Vec<_> = supervisor
            .read_output(&id, Counter::ZERO, 4096)
            .unwrap()
            .chunks
            .into_iter()
            .flat_map(|value| value.bytes)
            .collect();
        assert!(String::from_utf8_lossy(&bytes).contains("got:hello"));
    }

    #[test]
    fn duplicate_identity_reconciles_only_the_exact_request() {
        let root = Temp::new();
        let supervisor =
            ProcessSupervisor::create(&root.0, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let value = request("same", "exit 0", StdioMode::Pipes);
        supervisor.spawn(value.clone()).unwrap();
        supervisor.spawn(value.clone()).unwrap();
        let mut conflict = value;
        conflict.argv.push("different".into());
        assert!(matches!(
            supervisor.spawn(conflict),
            Err(ProcessError::Conflict(_))
        ));
    }

    #[test]
    fn timeout_wait_does_not_terminate_process() {
        let root = Temp::new();
        let supervisor =
            ProcessSupervisor::create(&root.0, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let id = ProcessId::try_from("wait").unwrap();
        supervisor
            .spawn(request("wait", "sleep 0.2", StdioMode::Pipes))
            .unwrap();
        assert!(matches!(
            supervisor.wait(&id, Some(Duration::from_millis(10))),
            Err(ProcessError::Timeout)
        ));
        assert!(matches!(
            supervisor.get(&id).unwrap().state,
            ProcessState::Running
        ));
        supervisor.wait(&id, Some(Duration::from_secs(5))).unwrap();
    }
}
