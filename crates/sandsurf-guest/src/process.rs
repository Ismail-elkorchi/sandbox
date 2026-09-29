use crate::{OutputSpool, SpoolError};
use sandsurf_protocol::{
    Counter, Digest, ExecutionCompletion, ExecutionId, ExecutionLineage, ExecutionOutcome,
    ExecutionSnapshot, ExecutionState, MachineId, RetainedPage, SnapshotId, SpawnRequest,
    StdioMode, Stream, TerminalId, TerminalSize, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{
    Arc, Condvar, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const READ_BUFFER: usize = sandsurf_protocol::MAX_STREAM_BYTES;
const OUTPUT_COALESCE_MILLIS: i32 = 2;
const DEADLINE_TERMINATION_GRACE: Duration = Duration::from_secs(1);
const MAX_PASSWD_BYTES: u64 = 1024 * 1024;
const PROCESS_RECORD_VERSION: u16 = 1;
const MAX_PROCESS_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_RETAINED_PROCESSES: usize = 65_536;

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

pub struct ExecutionKeeper {
    identity: RwLock<SupervisorIdentity>,
    root: PathBuf,
    processes: Mutex<BTreeMap<ExecutionId, Arc<ProcessEntry>>>,
}

struct ProcessEntry {
    request: RwLock<SpawnRequest>,
    lineage: RwLock<Option<ExecutionLineage>>,
    pid: u32,
    group: i32,
    input: Mutex<Option<Input>>,
    input_lease: Mutex<Option<TerminalId>>,
    terminal: Option<File>,
    spool: Arc<OutputSpool>,
    state: Mutex<ExecutionState>,
    changed: Condvar,
    deadline_exceeded: AtomicBool,
    record_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProcessRecord {
    pub(crate) version: u16,
    pub(crate) request: SpawnRequest,
    pub(crate) guest_pid: u32,
    pub(crate) state: ExecutionState,
    #[serde(default)]
    pub(crate) lineage: Option<ExecutionLineage>,
}

#[derive(Clone)]
struct SupervisorIdentity {
    machine_id: MachineId,
    generation: Counter,
}

enum Input {
    Pipe(ChildStdin),
    Terminal(File),
}

struct Spawned {
    child: Child,
    input: Input,
    terminal: Option<File>,
    readers: Vec<(Box<dyn ReadFd>, Stream)>,
}

trait ReadFd: Read + AsRawFd + Send {}
impl<T: Read + AsRawFd + Send> ReadFd for T {}

impl ExecutionKeeper {
    pub fn create(
        root: &Path,
        machine_id: MachineId,
        generation: Counter,
    ) -> Result<Self, ProcessError> {
        if !root.is_absolute() || generation == Counter::ZERO {
            return Err(ProcessError::Invalid(
                "supervisor root must be absolute and generation positive",
            ));
        }
        fs::create_dir_all(root)?;
        if !fs::metadata(root)?.is_dir() {
            return Err(ProcessError::Invalid("supervisor root is not a directory"));
        }
        let mut value = Self {
            identity: RwLock::new(SupervisorIdentity {
                machine_id,
                generation,
            }),
            root: root.to_path_buf(),
            processes: Mutex::new(BTreeMap::new()),
        };
        value.recover_processes()?;
        Ok(value)
    }

    #[cfg(test)]
    pub fn spawn(&self, request: SpawnRequest) -> Result<ExecutionSnapshot, ProcessError> {
        self.spawn_with_environment(request, &BTreeMap::new())
    }

    /// Add supervisor-held environment capabilities only to the child launch.
    /// The retained request and every guardian observation remain the exact
    /// host-authorized request, so secret bytes never enter process metadata.
    pub fn spawn_with_environment(
        &self,
        request: SpawnRequest,
        additional_environment: &BTreeMap<String, String>,
    ) -> Result<ExecutionSnapshot, ProcessError> {
        request
            .validate()
            .map_err(|_| ProcessError::Invalid("spawn validation failed"))?;
        let identity = self
            .identity
            .read()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-identity-poisoned")))?
            .clone();
        if request.machine_id != identity.machine_id || request.generation != identity.generation {
            return Err(ProcessError::Conflict("machine generation mismatch"));
        }
        let mut processes = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?;
        if let Some(existing) = processes.get(&request.execution_id) {
            if *existing
                .request
                .read()
                .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-request-poisoned")))?
                != request
            {
                return Err(ProcessError::Conflict(
                    "process identity is already bound to another request",
                ));
            }
            return existing.snapshot();
        }
        let directory = self.root.join(request.execution_id.as_str());
        fs::create_dir(&directory)?;
        let spool = Arc::new(OutputSpool::create(
            &directory.join("output.ssf"),
            request.output_bytes,
            &identity.machine_id,
            &request.execution_id,
            identity.generation,
        )?);
        let record_path = directory.join("process.json");
        write_process_record(
            &record_path,
            &ProcessRecord {
                version: PROCESS_RECORD_VERSION,
                request: request.clone(),
                guest_pid: 0,
                state: ExecutionState::Unknown {
                    evidence: bytes_digest(b"process-spawn-dispatch-in-progress"),
                },
                lineage: None,
            },
            true,
        )?;
        let mut launch_request = request.clone();
        for (name, value) in additional_environment {
            if launch_request
                .environment
                .insert(name.clone(), value.clone())
                .is_some()
            {
                return Err(ProcessError::Conflict(
                    "process environment overrides a delivered capability",
                ));
            }
        }
        launch_request
            .validate()
            .map_err(|_| ProcessError::Invalid("effective spawn environment is invalid"))?;
        let mut spawned = spawn_child(&launch_request)?;
        let pid = spawned.child.id();
        let initial_state = ExecutionState::Running;
        if let Err(error) = write_process_record(
            &record_path,
            &ProcessRecord {
                version: PROCESS_RECORD_VERSION,
                request: request.clone(),
                guest_pid: pid,
                state: initial_state.clone(),
                lineage: None,
            },
            false,
        ) {
            let _ = send_group_signal(
                i32::try_from(pid).map_err(|_| ProcessError::Invalid("PID overflow"))?,
                libc::SIGKILL,
            );
            return Err(error);
        }
        let entry = Arc::new(ProcessEntry {
            request: RwLock::new(request.clone()),
            lineage: RwLock::new(None),
            pid,
            group: i32::try_from(pid).map_err(|_| ProcessError::Invalid("PID overflow"))?,
            input: Mutex::new(Some(spawned.input)),
            input_lease: Mutex::new(None),
            terminal: spawned.terminal,
            spool,
            state: Mutex::new(initial_state),
            changed: Condvar::new(),
            deadline_exceeded: AtomicBool::new(false),
            record_path,
        });
        processes.insert(request.execution_id.clone(), Arc::clone(&entry));
        drop(processes);

        let mut readers = Vec::new();
        for (reader, stream) in spawned.readers.drain(..) {
            readers.push(start_reader(Arc::clone(&entry), reader, stream));
        }
        start_waiter(Arc::clone(&entry), spawned.child, readers);
        if let Some(deadline) = request.active_deadline_millis {
            start_deadline(Arc::clone(&entry), Duration::from_millis(deadline.get()));
        }
        if let Some(deadline) = request.elapsed_deadline_unix_millis {
            start_elapsed_deadline(Arc::clone(&entry), deadline);
        }
        entry.snapshot()
    }

    pub fn rebind_generation(
        &self,
        snapshot_id: &SnapshotId,
        machine_id: MachineId,
        previous_generation: Counter,
        generation: Counter,
    ) -> Result<(), ProcessError> {
        if generation == Counter::ZERO {
            return Err(ProcessError::Invalid(
                "restored generation must be positive",
            ));
        }
        let mut identity = self
            .identity
            .write()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-identity-poisoned")))?;
        if identity.generation != previous_generation {
            return Err(ProcessError::Conflict(
                "restored source generation mismatch",
            ));
        }
        let source_machine_id = identity.machine_id.clone();
        let processes = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?;
        for entry in processes.values() {
            let mut request = entry
                .request
                .write()
                .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-request-poisoned")))?;
            if request.generation != previous_generation {
                continue;
            }
            request.machine_id = machine_id.clone();
            request.generation = generation;
            let lineage = ExecutionLineage {
                source_machine_id: source_machine_id.clone(),
                source_generation: previous_generation,
                snapshot_id: snapshot_id.clone(),
            };
            *entry
                .lineage
                .write()
                .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-lineage-poisoned")))? =
                Some(lineage.clone());
            write_process_record(
                &entry.record_path,
                &ProcessRecord {
                    version: PROCESS_RECORD_VERSION,
                    request: request.clone(),
                    guest_pid: entry.pid,
                    state: entry.state()?,
                    lineage: Some(lineage),
                },
                false,
            )?;
        }
        identity.machine_id = machine_id;
        identity.generation = generation;
        Ok(())
    }

    pub fn get(&self, id: &ExecutionId) -> Result<ExecutionSnapshot, ProcessError> {
        self.entry(id)?.snapshot()
    }

    pub fn acquire_terminal_input(
        &self,
        id: &ExecutionId,
        lease_id: &TerminalId,
    ) -> Result<(), ProcessError> {
        let entry = self.entry(id)?;
        if !matches!(
            entry.state()?,
            ExecutionState::Running | ExecutionState::Draining { .. }
        ) || entry
            .request
            .read()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-request-poisoned")))?
            .stdio
            != StdioMode::Terminal
        {
            return Err(ProcessError::Conflict(
                "terminal input lease requires a running terminal",
            ));
        }
        let mut lease = entry
            .input_lease
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-input-lease-poisoned")))?;
        match lease.as_ref() {
            Some(current) if current == lease_id => Ok(()),
            Some(_) => Err(ProcessError::Conflict("terminal input is already leased")),
            None => {
                *lease = Some(lease_id.clone());
                Ok(())
            }
        }
    }

    pub fn release_terminal_input(
        &self,
        id: &ExecutionId,
        lease_id: &TerminalId,
    ) -> Result<(), ProcessError> {
        let entry = self.entry(id)?;
        let mut lease = entry
            .input_lease
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-input-lease-poisoned")))?;
        if lease.as_ref() != Some(lease_id) {
            return Err(ProcessError::Conflict("terminal input lease is stale"));
        }
        *lease = None;
        Ok(())
    }

    pub fn write_input(
        &self,
        id: &ExecutionId,
        terminal_lease_id: Option<&TerminalId>,
        bytes: &[u8],
    ) -> Result<(), ProcessError> {
        if bytes.is_empty() || bytes.len() > sandsurf_protocol::MAX_STREAM_BYTES {
            return Err(ProcessError::Invalid("input chunk is outside frame bounds"));
        }
        let entry = self.entry(id)?;
        if !matches!(
            entry.state()?,
            ExecutionState::Running | ExecutionState::Draining { .. }
        ) {
            return Err(ProcessError::Conflict("process is not running"));
        }
        entry.check_input_lease(terminal_lease_id)?;
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

    pub fn close_input(
        &self,
        id: &ExecutionId,
        terminal_lease_id: Option<&TerminalId>,
    ) -> Result<(), ProcessError> {
        let entry = self.entry(id)?;
        entry.check_input_lease(terminal_lease_id)?;
        entry
            .input
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-input-poisoned")))?
            .take();
        Ok(())
    }

    pub fn resize_terminal(
        &self,
        id: &ExecutionId,
        size: TerminalSize,
    ) -> Result<(), ProcessError> {
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

    pub fn signal(&self, id: &ExecutionId, signal: i32, group: bool) -> Result<(), ProcessError> {
        if !(1..=64).contains(&signal) {
            return Err(ProcessError::Invalid("signal is outside supported range"));
        }
        let entry = self.entry(id)?;
        if !matches!(
            entry.state()?,
            ExecutionState::Running | ExecutionState::Draining { .. }
        ) {
            return Err(ProcessError::Conflict("process is not running"));
        }
        if group {
            send_group_signal(entry.group, signal)
        } else {
            send_process_signal(entry.pid, signal)
        }
    }

    pub fn terminate(&self, id: &ExecutionId, grace: Duration) -> Result<(), ProcessError> {
        if grace > Duration::from_secs(60) {
            return Err(ProcessError::Invalid(
                "termination grace exceeds 60 seconds",
            ));
        }
        let entry = self.entry(id)?;
        if !matches!(
            entry.state()?,
            ExecutionState::Running | ExecutionState::Draining { .. }
        ) {
            return Ok(());
        }
        send_group_signal(entry.group, libc::SIGTERM)?;
        std::thread::spawn(move || {
            let deadline = Instant::now() + grace;
            while Instant::now() < deadline && entry.owned_processes_exist() {
                std::thread::sleep(Duration::from_millis(10));
            }
            if entry.owned_processes_exist() {
                entry.kill_owned();
            }
        });
        Ok(())
    }

    #[cfg(test)]
    pub fn wait(
        &self,
        id: &ExecutionId,
        timeout: Option<Duration>,
    ) -> Result<ExecutionCompletion, ProcessError> {
        let entry = self.entry(id)?;
        let mut state = entry
            .state
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-state-poisoned")))?;
        let deadline = timeout.map(|value| Instant::now() + value);
        loop {
            match &*state {
                ExecutionState::Exited(value) => return Ok(value.clone()),
                ExecutionState::Unknown { evidence } => {
                    return Err(ProcessError::Unknown(evidence.clone()));
                }
                ExecutionState::Running | ExecutionState::Draining { .. } => {}
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
                    if timeout.timed_out()
                        && matches!(
                            *next,
                            ExecutionState::Running | ExecutionState::Draining { .. }
                        )
                    {
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
        id: &ExecutionId,
        after: Counter,
        maximum: usize,
    ) -> Result<RetainedPage, ProcessError> {
        Ok(self.entry(id)?.spool.read(after, maximum)?)
    }

    fn entry(&self, id: &ExecutionId) -> Result<Arc<ProcessEntry>, ProcessError> {
        self.processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?
            .get(id)
            .cloned()
            .ok_or(ProcessError::Missing)
    }

    fn recover_processes(&mut self) -> Result<(), ProcessError> {
        let mut recovered = BTreeMap::new();
        let mut directories = fs::read_dir(&self.root)?.collect::<Result<Vec<_>, _>>()?;
        directories.sort_by_key(|entry| entry.file_name());
        if directories.len() > MAX_RETAINED_PROCESSES {
            return Err(ProcessError::Invalid(
                "retained process table exceeds bound",
            ));
        }
        for directory in directories {
            if !directory.file_type()?.is_dir() {
                return Err(ProcessError::Invalid(
                    "process spool root contains a non-directory entry",
                ));
            }
            let execution_id: ExecutionId = directory
                .file_name()
                .to_str()
                .ok_or(ProcessError::Invalid("process directory is not UTF-8"))?
                .try_into()
                .map_err(|_| ProcessError::Invalid("process directory identity is invalid"))?;
            let record_path = directory.path().join("process.json");
            let mut record = read_process_record(&record_path)?;
            if record.version != PROCESS_RECORD_VERSION
                || record.request.execution_id != execution_id
                || record.request.machine_id
                    != self
                        .identity
                        .read()
                        .map_err(|_| {
                            ProcessError::Unknown(bytes_digest(b"process-identity-poisoned"))
                        })?
                        .machine_id
            {
                return Err(ProcessError::Invalid(
                    "retained process record identity is invalid",
                ));
            }
            if matches!(
                record.state,
                ExecutionState::Running | ExecutionState::Draining { .. }
            ) {
                record.state = ExecutionState::Unknown {
                    evidence: bytes_digest(b"process-interrupted-before-cold-rebind"),
                };
                write_process_record(&record_path, &record, false)?;
            }
            let spool = Arc::new(OutputSpool::open(
                &directory.path().join("output.ssf"),
                record.request.output_bytes,
                &record.request.machine_id,
                &execution_id,
                record.request.generation,
                true,
            )?);
            recovered.insert(
                execution_id,
                Arc::new(ProcessEntry {
                    request: RwLock::new(record.request),
                    lineage: RwLock::new(record.lineage),
                    pid: record.guest_pid,
                    group: 0,
                    input: Mutex::new(None),
                    input_lease: Mutex::new(None),
                    terminal: None,
                    spool,
                    state: Mutex::new(record.state),
                    changed: Condvar::new(),
                    deadline_exceeded: AtomicBool::new(false),
                    record_path,
                }),
            );
        }
        *self
            .processes
            .get_mut()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))? = recovered;
        Ok(())
    }
}

impl ProcessEntry {
    fn state(&self) -> Result<ExecutionState, ProcessError> {
        self.state
            .lock()
            .map(|value| value.clone())
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-state-poisoned")))
    }

    fn check_input_lease(
        &self,
        terminal_lease_id: Option<&TerminalId>,
    ) -> Result<(), ProcessError> {
        let stdio = self
            .request
            .read()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-request-poisoned")))?
            .stdio;
        let lease = self
            .input_lease
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-input-lease-poisoned")))?;
        match (stdio, terminal_lease_id, lease.as_ref()) {
            (StdioMode::Pipes, None, None) => Ok(()),
            (StdioMode::Terminal, Some(supplied), Some(current)) if supplied == current => Ok(()),
            (StdioMode::Pipes, _, _) => Err(ProcessError::Invalid(
                "pipe input cannot use a terminal lease",
            )),
            (StdioMode::Terminal, _, _) => Err(ProcessError::Conflict(
                "terminal input lease is absent or stale",
            )),
        }
    }

    fn snapshot(&self) -> Result<ExecutionSnapshot, ProcessError> {
        Ok(ExecutionSnapshot {
            request: self
                .request
                .read()
                .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-request-poisoned")))?
                .clone(),
            guest_pid: self.pid,
            state: self.state()?,
            lineage: self
                .lineage
                .read()
                .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-lineage-poisoned")))?
                .clone(),
        })
    }

    fn finish(&self, value: ExecutionState) {
        let (Ok(request), Ok(lineage)) = (self.request.read(), self.lineage.read()) else {
            if let Ok(mut state) = self.state.lock() {
                *state = ExecutionState::Unknown {
                    evidence: bytes_digest(b"process-terminal-identity-unavailable"),
                };
                self.changed.notify_all();
            }
            return;
        };
        let record = ProcessRecord {
            version: PROCESS_RECORD_VERSION,
            request: request.clone(),
            guest_pid: self.pid,
            state: value.clone(),
            lineage: lineage.clone(),
        };
        let value = match write_process_record(&self.record_path, &record, false) {
            Ok(()) => value,
            Err(error) => {
                eprintln!("sandsurf process terminal record failed: {error}");
                ExecutionState::Unknown {
                    evidence: bytes_digest(b"process-terminal-record-unavailable"),
                }
            }
        };
        if let Ok(mut state) = self.state.lock() {
            *state = value;
            self.changed.notify_all();
        }
    }

    fn owned_processes_exist(&self) -> bool {
        group_exists(self.group)
    }

    fn kill_owned(&self) {
        if !matches!(
            self.state(),
            Ok(ExecutionState::Running | ExecutionState::Draining { .. })
        ) {
            return;
        }
        let _ = send_group_signal(self.group, libc::SIGKILL);
    }
}

pub(crate) fn read_process_record(path: &Path) -> Result<ProcessRecord, ProcessError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_PROCESS_RECORD_BYTES
    {
        return Err(ProcessError::Invalid(
            "process record is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_PROCESS_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| ProcessError::Invalid("process record is malformed"))
}

fn write_process_record(
    path: &Path,
    value: &ProcessRecord,
    create: bool,
) -> Result<(), ProcessError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ProcessError::Invalid("process record cannot be encoded"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PROCESS_RECORD_BYTES {
        return Err(ProcessError::Invalid("process record exceeds bound"));
    }
    if create {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    } else {
        let temporary = path.with_extension("json.new");
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
    }
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn spawn_child(request: &SpawnRequest) -> Result<Spawned, ProcessError> {
    let mut command = Command::new(&request.argv[0]);
    command
        .args(&request.argv[1..])
        .env_clear()
        .envs(&request.environment);
    command.current_dir(&request.cwd);
    let credentials = request.user.as_deref().map(resolve_user).transpose()?;
    match request.stdio {
        StdioMode::Pipes => {
            // SAFETY: this closure executes after fork and before exec, invokes
            // only async-signal-safe setpgid, and does not access shared memory.
            unsafe {
                command.pre_exec(move || {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    enter_user(credentials.as_ref())?;
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
                command.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    enter_user(credentials.as_ref())?;
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

fn enter_user(credentials: Option<&UserCredentials>) -> io::Result<()> {
    if let Some(credentials) = credentials {
        // SAFETY: these calls only read the current process credentials.
        if unsafe { libc::geteuid() } != 0
            // SAFETY: this call only reads the current process credentials.
            && unsafe { libc::geteuid() } == credentials.uid
            // SAFETY: this call only reads the current process credentials.
            && unsafe { libc::getegid() } == credentials.gid
        {
            return Ok(());
        }
        // SAFETY: the supplementary-group array was resolved before fork and
        // remains alive for the call; these credential setters are async-signal-safe.
        if unsafe { libc::setgroups(credentials.groups.len(), credentials.groups.as_ptr()) } != 0
            // SAFETY: the validated group ID is a scalar, and setgid is async-signal-safe.
            || unsafe { libc::setgid(credentials.gid) } != 0
            // SAFETY: the validated user ID is a scalar, and setuid is async-signal-safe.
            || unsafe { libc::setuid(credentials.uid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn start_reader(
    entry: Arc<ProcessEntry>,
    mut reader: Box<dyn ReadFd>,
    stream: Stream,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; READ_BUFFER];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(initial) => {
                    let mut count = initial;
                    let mut ended = false;
                    let mut failed = false;
                    // One durable spool record per bounded burst, not per small
                    // producer write. The short idle window keeps PTY feedback
                    // responsive while collapsing chatty command output.
                    while count < buffer.len() {
                        let mut descriptor = libc::pollfd {
                            fd: reader.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        // SAFETY: descriptor points to a live pollfd for this
                        // thread's retained pipe or PTY descriptor.
                        let ready =
                            unsafe { libc::poll(&raw mut descriptor, 1, OUTPUT_COALESCE_MILLIS) };
                        if ready == 0 {
                            break;
                        }
                        if ready < 0 {
                            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            failed = true;
                            break;
                        }
                        if descriptor.revents & libc::POLLNVAL != 0 {
                            failed = true;
                            break;
                        }
                        if descriptor.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0
                        {
                            break;
                        }
                        match reader.read(&mut buffer[count..]) {
                            Ok(0) => {
                                ended = true;
                                break;
                            }
                            Ok(read) => count += read,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error)
                                if stream == Stream::Terminal
                                    && error.raw_os_error() == Some(libc::EIO) =>
                            {
                                ended = true;
                                break;
                            }
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if entry.spool.append(stream, &buffer[..count]).is_err() || failed {
                        entry.kill_owned();
                        break;
                    }
                    if ended {
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
                    entry.kill_owned();
                    break;
                }
            }
        }
    })
}

fn start_deadline(entry: Arc<ProcessEntry>, deadline: Duration) {
    std::thread::spawn(move || {
        let Ok(state) = entry.state.lock() else {
            return;
        };
        let Ok((state, timeout)) = entry.changed.wait_timeout_while(state, deadline, |state| {
            matches!(
                state,
                ExecutionState::Running | ExecutionState::Draining { .. }
            )
        }) else {
            return;
        };
        if !timeout.timed_out()
            || !matches!(
                *state,
                ExecutionState::Running | ExecutionState::Draining { .. }
            )
        {
            return;
        }
        drop(state);
        expire_deadline(&entry);
    });
}

fn start_elapsed_deadline(entry: Arc<ProcessEntry>, deadline: Counter) {
    std::thread::spawn(move || {
        loop {
            let Ok(state) = entry.state.lock() else {
                return;
            };
            if !matches!(
                *state,
                ExecutionState::Running | ExecutionState::Draining { .. }
            ) {
                return;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|value| u64::try_from(value.as_millis()).ok());
            let Some(now) = now else {
                return;
            };
            if now >= deadline.get() {
                drop(state);
                expire_deadline(&entry);
                return;
            }
            // Recheck wall time periodically so clock adjustment and a VM
            // pause/resume cannot turn the absolute boundary into a relative
            // guest timer.
            let wait = Duration::from_millis((deadline.get() - now).min(1_000));
            let Ok((next, _)) = entry.changed.wait_timeout(state, wait) else {
                return;
            };
            drop(next);
        }
    });
}

fn expire_deadline(entry: &Arc<ProcessEntry>) {
    if entry.deadline_exceeded.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = send_group_signal(entry.group, libc::SIGTERM);
    let grace_deadline = Instant::now() + DEADLINE_TERMINATION_GRACE;
    while entry.owned_processes_exist() && Instant::now() < grace_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if entry.owned_processes_exist() {
        entry.kill_owned();
    }
}

fn start_waiter(entry: Arc<ProcessEntry>, child: Child, readers: Vec<JoinHandle<()>>) {
    std::thread::spawn(move || {
        let Ok((status, accounting_digest)) = wait_child(child) else {
            entry.finish(ExecutionState::Unknown {
                evidence: bytes_digest(b"wait-status-unavailable"),
            });
            return;
        };
        let outcome = if entry.deadline_exceeded.load(Ordering::Acquire) {
            ExecutionOutcome::DeadlineExceeded
        } else {
            match (status.code(), status.signal()) {
                (Some(code), _) => ExecutionOutcome::Exit { code },
                (None, Some(signal)) => ExecutionOutcome::Signal {
                    signal: signal as u32,
                },
                _ => ExecutionOutcome::Interrupted {
                    evidence: bytes_digest(b"exit-status-unclassified"),
                },
            }
        };
        entry.finish(ExecutionState::Draining {
            outcome: outcome.clone(),
            accounting_digest: accounting_digest.clone(),
        });
        // Linux descendants are independent processes. Leader exit neither
        // kills them nor waits for their process-group lifetime. Only owners
        // of inherited output descriptors delay this capture boundary.
        let readers_complete = readers.into_iter().all(|reader| reader.join().is_ok());
        if !readers_complete || entry.spool.has_failed() {
            entry.finish(ExecutionState::Unknown {
                evidence: bytes_digest(b"output-retention-incomplete"),
            });
            return;
        }
        match entry.spool.finalize() {
            Ok(output) => entry.finish(ExecutionState::Exited(ExecutionCompletion {
                outcome,
                output,
                cleanup_digest: bytes_digest(
                    b"guest-report-leader-reaped-and-output-eof-not-descendant-cleanup",
                ),
                accounting_digest,
            })),
            Err(_) => entry.finish(ExecutionState::Unknown {
                evidence: bytes_digest(b"output-finalization-failed"),
            }),
        }
    });
}

fn wait_child(child: Child) -> io::Result<(std::process::ExitStatus, Digest)> {
    use std::os::unix::process::ExitStatusExt;

    let pid = i32::try_from(child.id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child PID overflow"))?;
    let mut status = 0_i32;
    // SAFETY: wait4 initializes status and usage for this exact positive child.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    loop {
        // SAFETY: pointers refer to live writable objects and pid is the direct
        // child retained by `child`; options zero performs a blocking reap.
        let result = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
        if result == pid {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    let mut evidence = b"linux-wait4-leader-v1".to_vec();
    for value in [
        usage.ru_utime.tv_sec,
        usage.ru_utime.tv_usec,
        usage.ru_stime.tv_sec,
        usage.ru_stime.tv_usec,
        usage.ru_maxrss,
        usage.ru_minflt,
        usage.ru_majflt,
        usage.ru_inblock,
        usage.ru_oublock,
        usage.ru_nvcsw,
        usage.ru_nivcsw,
    ] {
        evidence.extend_from_slice(&(value as i128).to_be_bytes());
    }
    drop(child);
    Ok((
        std::process::ExitStatus::from_raw(status),
        bytes_digest(&evidence),
    ))
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

struct UserCredentials {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

fn resolve_user(value: &str) -> Result<UserCredentials, ProcessError> {
    if let Some((uid, gid)) = value.split_once(':')
        && let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse())
    {
        return Ok(UserCredentials {
            uid,
            gid,
            groups: vec![gid],
        });
    }
    let name = std::ffi::CString::new(value)
        .map_err(|_| ProcessError::Invalid("guest user contains NUL"))?;
    let mut buffer = vec![0_u8; 4096];
    let mut user = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    loop {
        // SAFETY: the output pointers and bounded buffer are live. Lookup runs
        // before fork, using ordinary guest OS account resolution.
        let code = unsafe {
            match value.parse::<u32>() {
                Ok(uid) => libc::getpwuid_r(
                    uid,
                    user.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                ),
                Err(_) => libc::getpwnam_r(
                    name.as_ptr(),
                    user.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                ),
            }
        };
        if code == libc::ERANGE && buffer.len() < MAX_PASSWD_BYTES as usize {
            buffer.resize((buffer.len() * 2).min(MAX_PASSWD_BYTES as usize), 0);
            continue;
        }
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code).into());
        }
        if result.is_null() {
            return Err(ProcessError::Invalid("guest user does not exist"));
        }
        break;
    }
    // SAFETY: successful reentrant lookup initialized user and its name points
    // inside buffer, which remains alive while the name is copied.
    let user = unsafe { user.assume_init() };
    let username = unsafe { std::ffi::CStr::from_ptr(user.pw_name) }.to_owned();
    let mut count: libc::c_int = 16;
    let mut groups = vec![0_u32; count as usize];
    loop {
        // SAFETY: username and group outputs are valid, with count equal to
        // the allocation's bound. This lookup also completes before fork.
        let result = unsafe {
            libc::getgrouplist(
                username.as_ptr(),
                user.pw_gid,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        if result >= 0 {
            groups.truncate(count as usize);
            break;
        }
        if count <= 0 || count > 65_536 || count as usize <= groups.len() {
            return Err(ProcessError::Invalid(
                "guest group list exceeds bound or lookup failed",
            ));
        }
        groups.resize(count as usize, 0);
    }
    Ok(UserCredentials {
        uid: user.pw_uid,
        gid: user.pw_gid,
        groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::{ExecutionId, OperationId};
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
            machine_id: MachineId::try_from("box").unwrap(),
            generation: Counter::ONE,
            execution_id: ExecutionId::try_from(id).unwrap(),
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
            active_deadline_millis: None,
            elapsed_deadline_unix_millis: None,
            output_bytes: (1024 * 1024u64).try_into().unwrap(),
        }
    }

    #[test]
    fn concurrent_processes_have_independent_binary_streams() {
        let root = Temp::new();
        let supervisor =
            ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
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
                &ExecutionId::try_from("one").unwrap(),
                Some(Duration::from_secs(5)),
            )
            .unwrap();
        supervisor
            .wait(
                &ExecutionId::try_from("two").unwrap(),
                Some(Duration::from_secs(5)),
            )
            .unwrap();
        let one = supervisor
            .read_output(&ExecutionId::try_from("one").unwrap(), Counter::ZERO, 1024)
            .unwrap();
        let two = supervisor
            .read_output(&ExecutionId::try_from("two").unwrap(), Counter::ZERO, 1024)
            .unwrap();
        assert_eq!(one.chunks[0].bytes, b"one\0byte");
        assert_eq!(two.chunks[0].stream, Stream::Stderr);
        assert_eq!(two.chunks[0].bytes, b"two");
    }

    #[test]
    fn tiny_writes_are_coalesced_without_losing_receipt_coverage() {
        let root = Temp::new();
        let supervisor =
            ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let id = ExecutionId::try_from("chatty").unwrap();
        supervisor
            .spawn(request(
                "chatty",
                "i=0; while [ \"$i\" -lt 8192 ]; do printf x; i=$((i+1)); done",
                StdioMode::Pipes,
            ))
            .unwrap();
        let completion = supervisor.wait(&id, Some(Duration::from_secs(10))).unwrap();
        assert_eq!(completion.output.stdout_bytes.get(), 8192);
        assert!(completion.output.chunks.get() < 128);
        let page = supervisor.read_output(&id, Counter::ZERO, 8192).unwrap();
        assert_eq!(page.available.get(), 8192);
        assert_eq!(
            page.chunks
                .iter()
                .map(|chunk| chunk.bytes.len())
                .sum::<usize>(),
            8192
        );
        assert!(
            page.chunks
                .iter()
                .all(|chunk| chunk.bytes.iter().all(|byte| *byte == b'x'))
        );
    }

    #[test]
    fn terminal_is_merged_resizable_and_interactive() {
        let root = Temp::new();
        let supervisor =
            ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let id = ExecutionId::try_from("terminal").unwrap();
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
        let lease = TerminalId::try_from("writer").unwrap();
        let competing = TerminalId::try_from("competing").unwrap();
        supervisor.acquire_terminal_input(&id, &lease).unwrap();
        assert!(matches!(
            supervisor.acquire_terminal_input(&id, &competing),
            Err(ProcessError::Conflict(_))
        ));
        assert!(matches!(
            supervisor.write_input(&id, Some(&competing), b"wrong\n"),
            Err(ProcessError::Conflict(_))
        ));
        supervisor
            .write_input(&id, Some(&lease), b"hello\n")
            .unwrap();
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
            ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
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
            ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let id = ExecutionId::try_from("wait").unwrap();
        supervisor
            .spawn(request("wait", "sleep 0.2", StdioMode::Pipes))
            .unwrap();
        assert!(matches!(
            supervisor.wait(&id, Some(Duration::from_millis(10))),
            Err(ProcessError::Timeout)
        ));
        assert!(matches!(
            supervisor.get(&id).unwrap().state,
            ExecutionState::Running
        ));
        supervisor.wait(&id, Some(Duration::from_secs(5))).unwrap();
    }

    #[test]
    fn workload_deadline_terminates_only_its_process_group() {
        let root = Temp::new();
        let supervisor =
            ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let timed = ExecutionId::try_from("timed").unwrap();
        let sibling = ExecutionId::try_from("sibling").unwrap();
        let mut timed_request = request("timed", "sleep 30", StdioMode::Pipes);
        timed_request.active_deadline_millis = Some(Counter::try_from(30).unwrap());
        supervisor.spawn(timed_request).unwrap();
        supervisor
            .spawn(request("sibling", "sleep 0.2", StdioMode::Pipes))
            .unwrap();
        let completion = supervisor
            .wait(&timed, Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(completion.outcome, ExecutionOutcome::DeadlineExceeded);
        assert!(matches!(
            supervisor.get(&sibling).unwrap().state,
            ExecutionState::Running
        ));
        supervisor
            .wait(&sibling, Some(Duration::from_secs(5)))
            .unwrap();
    }

    #[test]
    fn elapsed_deadline_uses_an_absolute_wall_clock_boundary() {
        let root = Temp::new();
        let supervisor =
            ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let process = ExecutionId::try_from("elapsed").unwrap();
        let mut request = request("elapsed", "sleep 30", StdioMode::Pipes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        request.elapsed_deadline_unix_millis =
            Some(Counter::try_from(u64::try_from(now + 30).unwrap()).unwrap());
        supervisor.spawn(request).unwrap();
        let completion = supervisor
            .wait(&process, Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(completion.outcome, ExecutionOutcome::DeadlineExceeded);
    }

    #[test]
    fn completed_process_and_binary_output_reopen_after_cold_generation() {
        let root = Temp::new();
        let id = ExecutionId::try_from("retained").unwrap();
        {
            let supervisor =
                ExecutionKeeper::create(&root.0, MachineId::try_from("box").unwrap(), Counter::ONE)
                    .unwrap();
            supervisor
                .spawn(request(
                    "retained",
                    "printf 'before\\000reboot'",
                    StdioMode::Pipes,
                ))
                .unwrap();
            supervisor.wait(&id, Some(Duration::from_secs(5))).unwrap();
        }
        let reopened = ExecutionKeeper::create(
            &root.0,
            MachineId::try_from("box").unwrap(),
            Counter::try_from(2).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            reopened.get(&id).unwrap().state,
            ExecutionState::Exited(_)
        ));
        let bytes: Vec<_> = reopened
            .read_output(&id, Counter::ZERO, 4096)
            .unwrap()
            .chunks
            .into_iter()
            .flat_map(|chunk| chunk.bytes)
            .collect();
        assert_eq!(bytes, b"before\0reboot");
        assert!(matches!(
            reopened.signal(&id, libc::SIGTERM, true),
            Err(ProcessError::Conflict(_))
        ));
    }
}
