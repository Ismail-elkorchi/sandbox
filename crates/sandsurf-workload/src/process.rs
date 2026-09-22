use crate::{CgroupLimits, CgroupManager, CgroupUsage, OutputSpool, ProcessCgroup, SpoolError};
use sandsurf_protocol::{
    CheckpointId, Counter, Digest, ProcessCompletion, ProcessId, ProcessLifetime, ProcessLineage,
    ProcessOutcome, ProcessSnapshot, ProcessState, RetainedPage, SandboxId, SpawnRequest,
    StdioMode, Stream, TerminalId, TerminalSize, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
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
const PROCESS_EXIT_GRACE: Duration = Duration::from_millis(500);
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

pub struct ProcessSupervisor {
    identity: RwLock<SupervisorIdentity>,
    root: PathBuf,
    workload_root: Option<PathBuf>,
    processes: Mutex<BTreeMap<ProcessId, Arc<ProcessEntry>>>,
    cgroups: Option<(CgroupManager, CgroupLimits)>,
}

struct ProcessEntry {
    request: RwLock<SpawnRequest>,
    lineage: RwLock<Option<ProcessLineage>>,
    pid: u32,
    group: i32,
    input: Mutex<Option<Input>>,
    input_lease: Mutex<Option<TerminalId>>,
    terminal: Option<File>,
    spool: Arc<OutputSpool>,
    state: Mutex<ProcessState>,
    changed: Condvar,
    deadline_exceeded: AtomicBool,
    cgroup: Option<ProcessCgroup>,
    record_path: PathBuf,
}

pub(crate) struct ProcessCompletionObserver {
    entry: Arc<ProcessEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessRecord {
    version: u16,
    request: SpawnRequest,
    guest_pid: u32,
    state: ProcessState,
    #[serde(default)]
    lineage: Option<ProcessLineage>,
}

#[derive(Clone)]
struct SupervisorIdentity {
    sandbox_id: SandboxId,
    epoch: Counter,
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
        let mut value = Self {
            identity: RwLock::new(SupervisorIdentity { sandbox_id, epoch }),
            root: root.to_path_buf(),
            workload_root: None,
            processes: Mutex::new(BTreeMap::new()),
            cgroups: None,
        };
        value.recover_processes()?;
        Ok(value)
    }

    /// Construct a supervisor whose children execute inside one persistent
    /// workload tree. The trusted supervisor and its spool remain outside this
    /// root; every process in the Sandbox sees the same Linux filesystem.
    pub fn create_in_workload(
        root: &Path,
        workload_root: &Path,
        sandbox_id: SandboxId,
        epoch: Counter,
    ) -> Result<Self, ProcessError> {
        if !workload_root.is_absolute() || !workload_root.is_dir() {
            return Err(ProcessError::Invalid(
                "workload root must be an existing absolute directory",
            ));
        }
        let mut supervisor = Self::create(root, sandbox_id, epoch)?;
        supervisor.workload_root = Some(workload_root.to_path_buf());
        Ok(supervisor)
    }

    pub fn create_with_cgroups(
        root: &Path,
        sandbox_id: SandboxId,
        epoch: Counter,
        cgroups: CgroupManager,
        default_limits: CgroupLimits,
    ) -> Result<Self, ProcessError> {
        let mut supervisor = Self::create(root, sandbox_id, epoch)?;
        supervisor.cgroups = Some((cgroups, default_limits));
        Ok(supervisor)
    }

    pub fn create_in_workload_with_cgroups(
        root: &Path,
        workload_root: &Path,
        sandbox_id: SandboxId,
        epoch: Counter,
        cgroups: CgroupManager,
        default_limits: CgroupLimits,
    ) -> Result<Self, ProcessError> {
        let mut supervisor = Self::create_in_workload(root, workload_root, sandbox_id, epoch)?;
        supervisor.cgroups = Some((cgroups, default_limits));
        Ok(supervisor)
    }

    pub fn spawn(&self, request: SpawnRequest) -> Result<ProcessSnapshot, ProcessError> {
        self.spawn_with_environment(request, &BTreeMap::new())
    }

    /// Add supervisor-held environment capabilities only to the child launch.
    /// The retained request and every guardian observation remain the exact
    /// host-authorized request, so secret bytes never enter process metadata.
    pub fn spawn_with_environment(
        &self,
        request: SpawnRequest,
        additional_environment: &BTreeMap<String, String>,
    ) -> Result<ProcessSnapshot, ProcessError> {
        request
            .validate()
            .map_err(|_| ProcessError::Invalid("spawn validation failed"))?;
        let identity = self
            .identity
            .read()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-identity-poisoned")))?
            .clone();
        if request.sandbox_id != identity.sandbox_id || request.epoch != identity.epoch {
            return Err(ProcessError::Conflict("sandbox epoch mismatch"));
        }
        let mut processes = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?;
        if let Some(existing) = processes.get(&request.process_id) {
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
        let directory = self.root.join(request.process_id.as_str());
        fs::create_dir(&directory)?;
        let spool = Arc::new(OutputSpool::create(
            &directory.join("output.ssf"),
            request.output_bytes,
            &identity.sandbox_id,
            &request.process_id,
            identity.epoch,
        )?);
        let record_path = directory.join("process.json");
        write_process_record(
            &record_path,
            &ProcessRecord {
                version: PROCESS_RECORD_VERSION,
                request: request.clone(),
                guest_pid: 0,
                state: ProcessState::Unknown {
                    evidence: bytes_digest(b"process-spawn-dispatch-in-progress"),
                },
                lineage: None,
            },
            true,
        )?;
        let cgroup = self
            .cgroups
            .as_ref()
            .map(|(manager, limits)| manager.create_process(&request.process_id, *limits))
            .transpose()?;
        let attachment = cgroup.as_ref().map(ProcessCgroup::attachment).transpose()?;
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
        let mut spawned = match spawn_child(
            &launch_request,
            attachment.as_ref(),
            self.workload_root.as_deref(),
        ) {
            Ok(value) => value,
            Err(error) => {
                if let Some(cgroup) = &cgroup {
                    let _ = cgroup.cleanup();
                }
                return Err(error);
            }
        };
        let pid = spawned.child.id();
        let initial_state = ProcessState::Running;
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
            if let Some(cgroup) = &cgroup {
                let _ = cgroup.cleanup();
            }
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
            cgroup,
            record_path,
        });
        processes.insert(request.process_id.clone(), Arc::clone(&entry));
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

    pub fn identity(&self) -> Result<(SandboxId, Counter), ProcessError> {
        self.identity
            .read()
            .map(|value| (value.sandbox_id.clone(), value.epoch))
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-identity-poisoned")))
    }

    pub fn rebind_epoch(
        &self,
        checkpoint_id: &CheckpointId,
        sandbox_id: SandboxId,
        previous_epoch: Counter,
        epoch: Counter,
    ) -> Result<(), ProcessError> {
        if epoch == Counter::ZERO {
            return Err(ProcessError::Invalid("restored epoch must be positive"));
        }
        let mut identity = self
            .identity
            .write()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-identity-poisoned")))?;
        if identity.epoch != previous_epoch {
            return Err(ProcessError::Conflict("restored source epoch mismatch"));
        }
        let source_sandbox_id = identity.sandbox_id.clone();
        let processes = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?;
        for entry in processes.values() {
            let mut request = entry
                .request
                .write()
                .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-request-poisoned")))?;
            if request.epoch != previous_epoch {
                continue;
            }
            request.sandbox_id = sandbox_id.clone();
            request.epoch = epoch;
            let lineage = ProcessLineage {
                source_sandbox_id: source_sandbox_id.clone(),
                source_epoch: previous_epoch,
                checkpoint_id: checkpoint_id.clone(),
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
        identity.sandbox_id = sandbox_id;
        identity.epoch = epoch;
        Ok(())
    }

    pub fn get(&self, id: &ProcessId) -> Result<ProcessSnapshot, ProcessError> {
        self.entry(id)?.snapshot()
    }

    pub(crate) fn completion_observer(
        &self,
        id: &ProcessId,
    ) -> Result<ProcessCompletionObserver, ProcessError> {
        Ok(ProcessCompletionObserver {
            entry: self.entry(id)?,
        })
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

    pub fn acquire_terminal_input(
        &self,
        id: &ProcessId,
        lease_id: &TerminalId,
    ) -> Result<(), ProcessError> {
        let entry = self.entry(id)?;
        if !matches!(entry.state()?, ProcessState::Running)
            || entry
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
        id: &ProcessId,
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
        id: &ProcessId,
        terminal_lease_id: Option<&TerminalId>,
        bytes: &[u8],
    ) -> Result<(), ProcessError> {
        if bytes.is_empty() || bytes.len() > sandsurf_protocol::MAX_STREAM_BYTES {
            return Err(ProcessError::Invalid("input chunk is outside frame bounds"));
        }
        let entry = self.entry(id)?;
        if !matches!(entry.state()?, ProcessState::Running) {
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
        id: &ProcessId,
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
        if !matches!(entry.state()?, ProcessState::Running) {
            return Err(ProcessError::Conflict("process is not running"));
        }
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

    pub fn usage(&self, id: &ProcessId) -> Result<Option<CgroupUsage>, ProcessError> {
        let entry = self.entry(id)?;
        entry
            .cgroup
            .as_ref()
            .map(|cgroup| cgroup.usage(!matches!(entry.state(), Ok(ProcessState::Running))))
            .transpose()
            .map_err(ProcessError::Io)
    }

    /// Quiesce every admitted workload group and wait until output readers have
    /// durably finalized their spools. This is the guest shutdown barrier: a
    /// VMM may not be terminated after this returns an error.
    pub fn quiesce(&self, grace: Duration) -> Result<(), ProcessError> {
        if grace > Duration::from_secs(60) {
            return Err(ProcessError::Invalid("quiesce grace exceeds 60 seconds"));
        }
        let entries: Vec<_> = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Unknown(bytes_digest(b"process-map-poisoned")))?
            .values()
            .cloned()
            .collect();
        for entry in &entries {
            if matches!(entry.state()?, ProcessState::Running) {
                send_group_signal(entry.group, libc::SIGTERM)?;
            }
        }
        let deadline = Instant::now() + grace;
        for entry in &entries {
            while matches!(entry.state()?, ProcessState::Running) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if matches!(entry.state()?, ProcessState::Running) {
                entry.kill_owned();
            }
        }
        let finalization_deadline = Instant::now() + PROCESS_EXIT_GRACE;
        for entry in entries {
            while matches!(entry.state()?, ProcessState::Running)
                && Instant::now() < finalization_deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            if matches!(entry.state()?, ProcessState::Running) {
                return Err(ProcessError::Timeout);
            }
        }
        Ok(())
    }

    fn entry(&self, id: &ProcessId) -> Result<Arc<ProcessEntry>, ProcessError> {
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
            let process_id: ProcessId = directory
                .file_name()
                .to_str()
                .ok_or(ProcessError::Invalid("process directory is not UTF-8"))?
                .try_into()
                .map_err(|_| ProcessError::Invalid("process directory identity is invalid"))?;
            let record_path = directory.path().join("process.json");
            let mut record = read_process_record(&record_path)?;
            if record.version != PROCESS_RECORD_VERSION
                || record.request.process_id != process_id
                || record.request.sandbox_id
                    != self
                        .identity
                        .read()
                        .map_err(|_| {
                            ProcessError::Unknown(bytes_digest(b"process-identity-poisoned"))
                        })?
                        .sandbox_id
            {
                return Err(ProcessError::Invalid(
                    "retained process record identity is invalid",
                ));
            }
            if matches!(record.state, ProcessState::Running) {
                record.state = ProcessState::Unknown {
                    evidence: bytes_digest(b"process-interrupted-before-cold-rebind"),
                };
                write_process_record(&record_path, &record, false)?;
            }
            let spool = Arc::new(OutputSpool::open(
                &directory.path().join("output.ssf"),
                record.request.output_bytes,
                &record.request.sandbox_id,
                &process_id,
                record.request.epoch,
                true,
            )?);
            recovered.insert(
                process_id,
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
                    cgroup: None,
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

impl ProcessCompletionObserver {
    pub(crate) fn wait(self) {
        let Ok(mut state) = self.entry.state.lock() else {
            return;
        };
        while matches!(*state, ProcessState::Running) {
            let Ok(next) = self.entry.changed.wait(state) else {
                return;
            };
            state = next;
        }
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        if let Ok(processes) = self.processes.lock() {
            for entry in processes.values() {
                entry.kill_owned();
            }
        }
    }
}

/// Stops all currently admitted workload groups while a trusted filesystem
/// worker verifies and installs a conditional mutation. New spawns are fenced
/// by the process-table lock used to take this snapshot.
pub struct ProcessWriterGuard {
    groups: Vec<i32>,
}

impl crate::WriterBarrier for ProcessSupervisor {
    type Guard = ProcessWriterGuard;

    fn acquire(&self) -> Result<Self::Guard, crate::FilesystemError> {
        let processes = self
            .processes
            .lock()
            .map_err(|_| crate::FilesystemError::Barrier)?;
        let mut groups = Vec::new();
        for entry in processes.values() {
            if matches!(entry.state(), Ok(ProcessState::Running)) {
                send_group_signal(entry.group, libc::SIGSTOP)
                    .map_err(|_| crate::FilesystemError::Barrier)?;
                groups.push(entry.group);
            }
        }
        Ok(ProcessWriterGuard { groups })
    }
}

impl Drop for ProcessWriterGuard {
    fn drop(&mut self) {
        for group in &self.groups {
            let _ = send_group_signal(*group, libc::SIGCONT);
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

    fn snapshot(&self) -> Result<ProcessSnapshot, ProcessError> {
        Ok(ProcessSnapshot {
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

    fn finish(&self, value: ProcessState) {
        let (Ok(request), Ok(lineage)) = (self.request.read(), self.lineage.read()) else {
            if let Ok(mut state) = self.state.lock() {
                *state = ProcessState::Unknown {
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
                ProcessState::Unknown {
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
        self.cgroup
            .as_ref()
            .and_then(|cgroup| cgroup.populated().ok())
            .unwrap_or_else(|| group_exists(self.group))
    }

    fn kill_owned(&self) {
        if !matches!(self.state(), Ok(ProcessState::Running)) {
            return;
        }
        if self
            .cgroup
            .as_ref()
            .is_none_or(|cgroup| cgroup.kill().is_err())
        {
            let _ = send_group_signal(self.group, libc::SIGKILL);
        }
    }
}

fn read_process_record(path: &Path) -> Result<ProcessRecord, ProcessError> {
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

fn reap_group_children(group: i32) {
    loop {
        let mut status = 0_i32;
        // SAFETY: a negative process-group id restricts reaping to adopted
        // workload descendants in this owned group. WNOHANG never blocks the
        // trusted supervisor.
        let result = unsafe { libc::waitpid(-group, &mut status, libc::WNOHANG) };
        if result > 0 {
            continue;
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
}

fn spawn_child(
    request: &SpawnRequest,
    attachment: Option<&File>,
    workload_root: Option<&Path>,
) -> Result<Spawned, ProcessError> {
    let mut command = Command::new(&request.argv[0]);
    let cwd = match workload_root {
        Some(root) => root.join(request.cwd.trim_start_matches('/')),
        None => PathBuf::from(&request.cwd),
    };
    command
        .args(&request.argv[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(&request.environment);
    let credentials = request
        .user
        .as_deref()
        .map(|user| resolve_user(workload_root, user))
        .transpose()?;
    match request.stdio {
        StdioMode::Pipes => {
            // SAFETY: this closure executes after fork and before exec, invokes
            // only async-signal-safe setpgid, and does not access shared memory.
            unsafe {
                let attachment = attachment.map(AsRawFd::as_raw_fd);
                let workload_root = open_workload_root(workload_root)?;
                command.pre_exec(move || {
                    attach_current_process(attachment)?;
                    if libc::setpgid(0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    enter_workload(workload_root, credentials)?;
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
            let pty = open_terminal(size, workload_root)?;
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
                let attachment = attachment.map(AsRawFd::as_raw_fd);
                let workload_root = open_workload_root(workload_root)?;
                command.pre_exec(move || {
                    attach_current_process(attachment)?;
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    enter_workload(workload_root, credentials)?;
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

fn open_workload_root(root: Option<&Path>) -> Result<Option<RawFd>, ProcessError> {
    let Some(root) = root else {
        return Ok(None);
    };
    let file = File::open(root)?;
    Ok(Some(file.into_raw_fd()))
}

fn enter_workload(root: Option<RawFd>, credentials: Option<(u32, u32)>) -> io::Result<()> {
    let confined = root.is_some();
    if let Some(root) = root {
        // SAFETY: root is a retained descriptor opened by the trusted
        // supervisor. fchdir/chroot operate on that exact directory and the
        // descriptor is closed in this child immediately afterwards.
        let changed = unsafe { libc::fchdir(root) };
        if changed != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: "." is a static NUL-terminated path and this child still has
        // the guest supervisor's privilege at this point.
        if unsafe { libc::chroot(c".".as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the inherited descriptor is no longer needed after chroot.
        unsafe { libc::close(root) };
    }
    if confined {
        restrict_workload_capabilities()?;
    }
    if let Some((uid, gid)) = credentials {
        // SAFETY: fixed scalar credentials were resolved by the trusted
        // supervisor before fork. Supplementary groups are removed before the
        // permanent gid/uid drop.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
            // SAFETY: gid is a trusted scalar resolved before fork.
            || unsafe { libc::setgid(gid) } != 0
            // SAFETY: uid is a trusted scalar resolved before fork.
            || unsafe { libc::setuid(uid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn restrict_workload_capabilities() -> io::Result<()> {
    const ALLOWED: &[libc::c_int] = &[
        0,  // CAP_CHOWN
        1,  // CAP_DAC_OVERRIDE
        2,  // CAP_DAC_READ_SEARCH
        3,  // CAP_FOWNER
        4,  // CAP_FSETID
        5,  // CAP_KILL
        6,  // CAP_SETGID
        7,  // CAP_SETUID
        10, // CAP_NET_BIND_SERVICE
    ];
    for capability in 0..64 {
        if ALLOWED.contains(&capability) {
            continue;
        }
        // SAFETY: PR_CAPBSET_READ/DROP take a scalar capability and perform a
        // monotonic restriction in this workload child.
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
        // SAFETY: PR_CAPBSET_DROP takes the supported scalar capability read above.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut allowed = 0_u64;
    for capability in ALLOWED {
        allowed |= 1_u64 << capability;
    }
    let header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        CapabilityData {
            effective: allowed as u32,
            permitted: allowed as u32,
            inheritable: 0,
        },
        CapabilityData {
            effective: (allowed >> 32) as u32,
            permitted: (allowed >> 32) as u32,
            inheritable: 0,
        },
    ];
    // SAFETY: capset receives the documented version-3 header and two fully
    // initialized 32-bit capability words for the current process.
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both prctl operations monotonically prevent ambient or setuid
    // escalation after this trusted pre-exec boundary.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
        // SAFETY: PR_SET_NO_NEW_PRIVS with scalar one is a monotonic restriction.
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn attach_current_process(attachment: Option<RawFd>) -> io::Result<()> {
    let Some(attachment) = attachment else {
        return Ok(());
    };
    let value = b"0";
    // SAFETY: the retained descriptor is an open cgroup.procs file inherited
    // across fork, and this async-signal-safe write uses a static one-byte buffer.
    let written = unsafe { libc::write(attachment, value.as_ptr().cast(), value.len()) };
    if written == value.len() as isize {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
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
                        entry.kill_owned();
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
            matches!(state, ProcessState::Running)
        }) else {
            return;
        };
        if !timeout.timed_out() || !matches!(*state, ProcessState::Running) {
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
            if !matches!(*state, ProcessState::Running) {
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
        let waited = wait_child(child);
        if entry
            .request
            .read()
            .map_or(ProcessLifetime::Job, |request| request.lifetime)
            == ProcessLifetime::Job
        {
            terminate_owned(&entry, PROCESS_EXIT_GRACE);
            reap_group_children(entry.group);
        } else {
            loop {
                reap_group_children(entry.group);
                if !entry.owned_processes_exist() || entry.spool.has_failed() {
                    break;
                }
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
        let Ok((status, leader_accounting)) = waited else {
            entry.finish(ProcessState::Unknown {
                evidence: bytes_digest(b"wait-status-unavailable"),
            });
            return;
        };
        let (accounting_digest, cleanup_digest) = match &entry.cgroup {
            Some(cgroup) => match cgroup.usage(true) {
                Ok(usage) => {
                    let mut evidence = b"sandsurf-process-accounting-v1".to_vec();
                    evidence.extend_from_slice(leader_accounting.as_str().as_bytes());
                    evidence.extend_from_slice(usage.digest().as_str().as_bytes());
                    let cleanup = if cgroup.cleanup().is_ok() {
                        bytes_digest(b"cgroup-v2-empty-and-removed")
                    } else {
                        entry.finish(ProcessState::Unknown {
                            evidence: bytes_digest(b"cgroup-v2-cleanup-unconfirmed"),
                        });
                        return;
                    };
                    (bytes_digest(&evidence), cleanup)
                }
                Err(_) => {
                    entry.finish(ProcessState::Unknown {
                        evidence: bytes_digest(b"cgroup-v2-accounting-unavailable"),
                    });
                    return;
                }
            },
            None => (leader_accounting, bytes_digest(b"process-group-empty")),
        };
        let outcome = if entry.deadline_exceeded.load(Ordering::Acquire) {
            ProcessOutcome::DeadlineExceeded
        } else {
            match (status.code(), status.signal()) {
                (Some(code), _) => ProcessOutcome::Exit { code },
                (None, Some(signal)) => ProcessOutcome::Signal {
                    signal: signal as u32,
                },
                _ => ProcessOutcome::Interrupted {
                    evidence: bytes_digest(b"exit-status-unclassified"),
                },
            }
        };
        match entry.spool.finalize() {
            Ok(output) => entry.finish(ProcessState::Exited(ProcessCompletion {
                outcome,
                output,
                cleanup_digest,
                accounting_digest,
            })),
            Err(_) => entry.finish(ProcessState::Unknown {
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

fn open_terminal(
    size: TerminalSize,
    workload_root: Option<&Path>,
) -> Result<PtyPair, ProcessError> {
    if let Some(root) = workload_root {
        let master = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(root.join("dev/pts/ptmx"))?;
        let mut unlocked: libc::c_int = 0;
        // SAFETY: master is one live PTY multiplexer descriptor and unlocked
        // points to an initialized scalar for the duration of this ioctl.
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSPTLCK, &mut unlocked) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut number: libc::c_uint = 0;
        // SAFETY: master is the same live descriptor and number is writable.
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTN, &mut number) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(root.join("dev/pts").join(number.to_string()))?;
        set_terminal_size(&master, size)?;
        return Ok(PtyPair { master, slave });
    }
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

fn terminate_owned(entry: &ProcessEntry, grace: Duration) {
    let _ = send_group_signal(entry.group, libc::SIGTERM);
    let deadline = Instant::now() + grace;
    while entry.owned_processes_exist() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if entry.owned_processes_exist() {
        entry.kill_owned();
        let _ = entry
            .cgroup
            .as_ref()
            .map(|cgroup| cgroup.wait_empty(PROCESS_EXIT_GRACE));
    }
}

fn resolve_user(workload_root: Option<&Path>, value: &str) -> Result<(u32, u32), ProcessError> {
    if let Some((uid, gid)) = value.split_once(':')
        && let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse())
    {
        return Ok((uid, gid));
    }
    if let Ok(uid) = value.parse::<u32>() {
        return Ok((uid, uid));
    }
    let mut bytes = Vec::new();
    let passwd = workload_root.map_or_else(
        || PathBuf::from("/etc/passwd"),
        |root| root.join("etc/passwd"),
    );
    File::open(passwd)?
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
            active_deadline_millis: None,
            elapsed_deadline_unix_millis: None,
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

    #[test]
    fn workload_deadline_terminates_only_its_process_group() {
        let root = Temp::new();
        let supervisor =
            ProcessSupervisor::create(&root.0, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let timed = ProcessId::try_from("timed").unwrap();
        let sibling = ProcessId::try_from("sibling").unwrap();
        let mut timed_request = request("timed", "sleep 30", StdioMode::Pipes);
        timed_request.active_deadline_millis = Some(Counter::try_from(30).unwrap());
        supervisor.spawn(timed_request).unwrap();
        supervisor
            .spawn(request("sibling", "sleep 0.2", StdioMode::Pipes))
            .unwrap();
        let completion = supervisor
            .wait(&timed, Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(completion.outcome, ProcessOutcome::DeadlineExceeded);
        assert!(matches!(
            supervisor.get(&sibling).unwrap().state,
            ProcessState::Running
        ));
        supervisor
            .wait(&sibling, Some(Duration::from_secs(5)))
            .unwrap();
    }

    #[test]
    fn elapsed_deadline_uses_an_absolute_wall_clock_boundary() {
        let root = Temp::new();
        let supervisor =
            ProcessSupervisor::create(&root.0, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let process = ProcessId::try_from("elapsed").unwrap();
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
        assert_eq!(completion.outcome, ProcessOutcome::DeadlineExceeded);
    }

    #[test]
    fn completed_process_and_binary_output_reopen_after_cold_epoch() {
        let root = Temp::new();
        let id = ProcessId::try_from("retained").unwrap();
        {
            let supervisor = ProcessSupervisor::create(
                &root.0,
                SandboxId::try_from("box").unwrap(),
                Counter::ONE,
            )
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
        let reopened = ProcessSupervisor::create(
            &root.0,
            SandboxId::try_from("box").unwrap(),
            Counter::try_from(2).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            reopened.get(&id).unwrap().state,
            ProcessState::Exited(_)
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
