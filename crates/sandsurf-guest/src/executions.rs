//! Managed-execution routing. Linux and each independent keeper own processes;
//! the management daemon owns neither pipe/PTY descriptors nor their lifetime.

use crate::OutputSpool;
use crate::process::{
    ExecutionKeeper, ProcessError, ProcessRecord, read_process_record, write_process_record,
};
use sandsurf_protocol::{
    Counter, Digest, ExecutionCompletion, ExecutionId, ExecutionSnapshot, ExecutionState, Frame,
    FrameKind, MachineId, RetainedPage, RetainedPageMetadata, SnapshotId, SpawnRequest, TerminalId,
    TerminalSize, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const MAX_EXECUTIONS: usize = 65_536;
const IPC_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPER_START_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_KEEPER_CONNECTIONS: usize = 16;

type Connection = Arc<Mutex<Option<UnixStream>>>;

pub struct ExecutionRegistry {
    root: PathBuf,
    executable: PathBuf,
    identity: RwLock<(MachineId, Counter)>,
    connections: Mutex<BTreeMap<ExecutionId, Connection>>,
    archives: Mutex<BTreeMap<ExecutionId, Arc<OutputSpool>>>,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum KeeperRequest {
    Start {
        environment: BTreeMap<String, String>,
    },
    Inspect,
    AcquireInput {
        lease: TerminalId,
    },
    ReleaseInput {
        lease: TerminalId,
    },
    WriteInput {
        lease: Option<TerminalId>,
        length: u32,
    },
    CloseInput {
        lease: Option<TerminalId>,
    },
    Resize {
        size: TerminalSize,
    },
    Signal {
        signal: i32,
        group: bool,
    },
    Terminate {
        grace_millis: u32,
    },
    Output {
        after: Counter,
        maximum: u32,
    },
    Restore {
        snapshot: SnapshotId,
        captured: Box<sandsurf_protocol::CapturedExecution>,
        generation: Counter,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum KeeperResponse {
    Execution {
        value: Box<ExecutionSnapshot>,
    },
    Complete,
    Output {
        metadata: RetainedPageMetadata,
    },
    Error {
        category: String,
        evidence: Option<Digest>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeeperEnvelope {
    execution_id: ExecutionId,
    request: KeeperRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeeperRoute {
    keeper_id: ExecutionId,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreMembership {
    snapshot_id: SnapshotId,
    capture_operation_id: sandsurf_protocol::OperationId,
    machine_id: MachineId,
    previous_generation: Counter,
    generation: Counter,
    executions: Vec<sandsurf_protocol::CapturedExecution>,
}

impl ExecutionRegistry {
    pub fn create(
        root: &Path,
        machine: MachineId,
        generation: Counter,
        executable: &Path,
    ) -> Result<Self, ProcessError> {
        if !root.is_absolute() || !executable.is_absolute() || generation == Counter::ZERO {
            return Err(ProcessError::Invalid(
                "execution registry identity or paths invalid",
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;
        Ok(Self {
            root: root.to_owned(),
            executable: executable.to_owned(),
            identity: RwLock::new((machine, generation)),
            connections: Mutex::new(BTreeMap::new()),
            archives: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn identity(&self) -> Result<(MachineId, Counter), ProcessError> {
        self.identity
            .read()
            .map(|identity| identity.clone())
            .map_err(|_| unavailable())
    }

    pub fn spawn(&self, request: SpawnRequest) -> Result<ExecutionSnapshot, ProcessError> {
        self.spawn_with_environment(request, &BTreeMap::new())
    }

    pub fn spawn_with_environment(
        &self,
        request: SpawnRequest,
        environment: &BTreeMap<String, String>,
    ) -> Result<ExecutionSnapshot, ProcessError> {
        request
            .validate()
            .map_err(|_| ProcessError::Invalid("spawn request invalid"))?;
        if self.identity()? != (request.machine_id.clone(), request.generation) {
            return Err(ProcessError::Conflict(
                "execution targets another generation",
            ));
        }
        let directory = self.directory(&request.execution_id);
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if admission(&directory)? != request {
                    return Err(ProcessError::Conflict(
                        "execution identity already admitted",
                    ));
                }
                // Never launch a second keeper after ambiguous admission.
                return self.get(&request.execution_id);
            }
            Err(error) => return Err(error.into()),
        }
        write_admission(&directory, &request)?;
        let mut command = Command::new(&self.executable);
        command
            .arg("--execution-keeper")
            .arg(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: setsid is async-signal-safe and detaches the keeper from the
        // management service's process group. No parent-death signal is used.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = command.spawn()?;
        let deadline = Instant::now() + KEEPER_START_TIMEOUT;
        loop {
            match UnixStream::connect(directory.join("keeper.sock")) {
                Ok(stream) => {
                    set_timeout(&stream)?;
                    *self
                        .connection(&request.execution_id)?
                        .lock()
                        .map_err(|_| unavailable())? = Some(stream);
                    break;
                }
                Err(_) if child.try_wait()?.is_none() && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => {
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                    return Err(unavailable());
                }
            }
        }
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        match self.call(
            &request.execution_id,
            KeeperRequest::Start {
                environment: environment.clone(),
            },
            None,
        )? {
            KeeperResponse::Execution { value } => Ok(*value),
            _ => Err(ProcessError::Invalid(
                "keeper returned wrong spawn response",
            )),
        }
    }

    pub fn get(&self, id: &ExecutionId) -> Result<ExecutionSnapshot, ProcessError> {
        match self.call(id, KeeperRequest::Inspect, None) {
            Ok(KeeperResponse::Execution { value }) => Ok(*value),
            Ok(_) => Err(ProcessError::Invalid("keeper returned wrong inspection")),
            Err(ProcessError::Io(_))
            | Err(ProcessError::Unknown(_))
            | Err(ProcessError::Missing) => self.retained_snapshot(id),
            Err(error) => Err(error),
        }
    }

    fn retained_snapshot(&self, id: &ExecutionId) -> Result<ExecutionSnapshot, ProcessError> {
        let mut record = read_process_record(&self.record(id)?)?;
        if record.version != 1 || record.request.execution_id != *id {
            return Err(ProcessError::Invalid("retained execution identity invalid"));
        }
        if matches!(
            record.state,
            ExecutionState::Running | ExecutionState::Draining { .. }
        ) {
            // This does not assert that any Linux process has exited.
            record.state = ExecutionState::Unknown {
                evidence: bytes_digest(b"execution-keeper-unavailable-capture-state-unknown-v1"),
            };
        }
        Ok(ExecutionSnapshot {
            request: record.request,
            guest_pid: record.guest_pid,
            state: record.state,
            lineage: record.lineage,
        })
    }

    pub fn list(&self) -> Result<Vec<ExecutionSnapshot>, ProcessError> {
        let identity = self.identity()?;
        let mut result = Vec::new();
        for (index, entry) in fs::read_dir(&self.root)?.enumerate() {
            if index >= MAX_EXECUTIONS {
                return Err(ProcessError::Invalid("execution registry exceeds bound"));
            }
            let entry = entry?;
            if entry.file_name() == ".restore.json"
                || entry.file_name().to_str().is_some_and(|name| {
                    name.strip_prefix(".routing-")
                        .and_then(|name| name.strip_suffix(".tmp"))
                        .is_some_and(|nonce| {
                            nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                })
            {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                return Err(ProcessError::Invalid(
                    "execution registry contains non-directory",
                ));
            }
            let id: ExecutionId = entry
                .file_name()
                .to_str()
                .ok_or(ProcessError::Invalid("execution directory not UTF-8"))?
                .try_into()
                .map_err(|_| ProcessError::Invalid("execution directory identity invalid"))?;
            let value = match self.get(&id) {
                Ok(value) => value,
                // Admission is not a PID assertion; a lost spawn response or
                // absent keeper remains unobserved in the host journal.
                Err(ProcessError::Io(error)) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(ProcessError::Missing) => continue,
                Err(error) => return Err(error),
            };
            if value.guest_pid != 0
                && (value.request.machine_id.clone(), value.request.generation) == identity
            {
                result.push(value);
            }
        }
        Ok(result)
    }

    pub fn acquire_terminal_input(
        &self,
        id: &ExecutionId,
        lease: &TerminalId,
    ) -> Result<(), ProcessError> {
        self.complete(
            id,
            KeeperRequest::AcquireInput {
                lease: lease.clone(),
            },
            None,
        )
    }
    pub fn release_terminal_input(
        &self,
        id: &ExecutionId,
        lease: &TerminalId,
    ) -> Result<(), ProcessError> {
        self.complete(
            id,
            KeeperRequest::ReleaseInput {
                lease: lease.clone(),
            },
            None,
        )
    }
    pub fn write_input(
        &self,
        id: &ExecutionId,
        lease: Option<&TerminalId>,
        bytes: &[u8],
    ) -> Result<(), ProcessError> {
        if bytes.is_empty() || bytes.len() > sandsurf_protocol::MAX_STREAM_BYTES {
            return Err(ProcessError::Invalid("input exceeds frame bound"));
        }
        self.complete(
            id,
            KeeperRequest::WriteInput {
                lease: lease.cloned(),
                length: bytes.len() as u32,
            },
            Some(bytes),
        )
    }
    pub fn close_input(
        &self,
        id: &ExecutionId,
        lease: Option<&TerminalId>,
    ) -> Result<(), ProcessError> {
        self.complete(
            id,
            KeeperRequest::CloseInput {
                lease: lease.cloned(),
            },
            None,
        )
    }
    pub fn resize_terminal(
        &self,
        id: &ExecutionId,
        size: TerminalSize,
    ) -> Result<(), ProcessError> {
        self.complete(id, KeeperRequest::Resize { size }, None)
    }
    pub fn signal(&self, id: &ExecutionId, signal: i32, group: bool) -> Result<(), ProcessError> {
        self.complete(id, KeeperRequest::Signal { signal, group }, None)
    }
    pub fn terminate(&self, id: &ExecutionId, grace: Duration) -> Result<(), ProcessError> {
        if grace > Duration::from_secs(60) {
            return Err(ProcessError::Invalid("termination grace exceeds bound"));
        }
        self.complete(
            id,
            KeeperRequest::Terminate {
                grace_millis: grace.as_millis() as u32,
            },
            None,
        )
    }
    pub fn wait(
        &self,
        id: &ExecutionId,
        timeout: Option<Duration>,
    ) -> Result<ExecutionCompletion, ProcessError> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        loop {
            match self.get(id)?.state {
                ExecutionState::Exited(completion) => return Ok(completion),
                ExecutionState::Unknown { evidence } => {
                    return Err(ProcessError::Unknown(evidence));
                }
                _ => {}
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(ProcessError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn read_output(
        &self,
        id: &ExecutionId,
        after: Counter,
        maximum: usize,
    ) -> Result<RetainedPage, ProcessError> {
        if maximum == 0 || maximum > sandsurf_protocol::MAX_STREAM_BYTES {
            return Err(ProcessError::Invalid("output page exceeds bound"));
        }
        match self.call_output(id, after, maximum) {
            Ok(page) => Ok(page),
            Err(ProcessError::Io(_))
            | Err(ProcessError::Unknown(_))
            | Err(ProcessError::Missing) => {
                let mut archives = self.archives.lock().map_err(|_| unavailable())?;
                if !archives.contains_key(id) {
                    let snapshot = self.retained_snapshot(id)?;
                    let reader = OutputSpool::open_read_only(
                        &self.record(id)?.with_file_name("output.ssf"),
                        snapshot.request.output_bytes,
                        &snapshot.request.machine_id,
                        id,
                        snapshot.request.generation,
                    )?;
                    archives.insert(id.clone(), Arc::new(reader));
                }
                Ok(archives
                    .get(id)
                    .ok_or(ProcessError::Missing)?
                    .read(after, maximum)?)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn completion_observer(
        &self,
        id: &ExecutionId,
    ) -> Result<RegistryCompletionObserver, ProcessError> {
        self.get(id)?;
        Ok(RegistryCompletionObserver {
            directory: self.keeper_directory(id)?,
            id: id.clone(),
        })
    }

    pub fn stage_restore(
        &self,
        snapshot_id: SnapshotId,
        capture_operation_id: sandsurf_protocol::OperationId,
        machine_id: MachineId,
        previous_generation: Counter,
        generation: Counter,
        executions: Vec<sandsurf_protocol::CapturedExecution>,
    ) -> Result<(), ProcessError> {
        let identity = self.identity()?;
        if identity.0 != machine_id
            || (identity.1 != previous_generation && identity.1 != generation)
            || generation <= previous_generation
        {
            return Err(ProcessError::Conflict(
                "restore membership identity mismatch",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for execution in &executions {
            if execution.admission.generation != previous_generation
                || !seen.insert(execution.admission.execution_id.clone())
            {
                return Err(ProcessError::Invalid("restore membership invalid"));
            }
            execution
                .restored(&snapshot_id, &machine_id, generation)
                .map_err(|_| ProcessError::Invalid("restore membership invalid"))?;
        }
        let value = RestoreMembership {
            snapshot_id,
            capture_operation_id,
            machine_id,
            previous_generation,
            generation,
            executions,
        };
        let path = self.root.join(".restore.json");
        if path.exists() {
            let old: RestoreMembership = read_json(&path)?;
            if old == value {
                return Ok(());
            }
            if identity.1 != previous_generation {
                return Err(ProcessError::Conflict(
                    "restored generation already has another membership",
                ));
            }
            if old.machine_id != value.machine_id || old.generation > previous_generation {
                return Err(ProcessError::Conflict("restore membership already bound"));
            }
            return write_json(&path, &value, true);
        }
        if identity.1 != previous_generation {
            return Err(ProcessError::Conflict(
                "restored generation has no admitted membership",
            ));
        }
        write_json_new(&path, &value)
    }

    pub fn rebind_generation(
        &self,
        snapshot: &SnapshotId,
        capture_operation: &sandsurf_protocol::OperationId,
        machine: MachineId,
        previous: Counter,
        generation: Counter,
    ) -> Result<(), ProcessError> {
        let mut identity = self.identity.write().map_err(|_| unavailable())?;
        let staged: RestoreMembership = read_json(&self.root.join(".restore.json"))?;
        if staged.snapshot_id != *snapshot
            || staged.capture_operation_id != *capture_operation
            || staged.machine_id != machine
            || staged.previous_generation != previous
            || staged.generation != generation
            || identity.0 != machine
            || (identity.1 != previous && identity.1 != generation)
        {
            return Err(ProcessError::Conflict(
                "restore source or staged membership mismatch",
            ));
        }
        for captured in &staged.executions {
            let (request, lineage) = captured
                .restored(snapshot, &machine, generation)
                .map_err(|_| ProcessError::Invalid("restore admission invalid"))?;
            let id = &request.execution_id;
            let physical = self.keeper_directory(&captured.admission.execution_id)?;
            let keeper_id: ExecutionId = physical
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ProcessError::Invalid("keeper route invalid"))?
                .try_into()
                .map_err(|_| ProcessError::Invalid("keeper route invalid"))?;
            let directory = self.directory(id);
            if directory.exists() {
                match admission(&directory) {
                    Ok(old) if old == request => {}
                    Err(ProcessError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                        write_admission(&directory, &request)?
                    }
                    Ok(_) => return Err(ProcessError::Conflict("restore admission already bound")),
                    Err(error) => return Err(error),
                }
            } else {
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                write_admission(&directory, &request)?;
            }
            let route_path = directory.join("route.json");
            if route_path.exists() {
                if read_json::<KeeperRoute>(&route_path)?.keeper_id != keeper_id {
                    return Err(ProcessError::Conflict("restore keeper route changed"));
                }
            } else {
                write_json_new(&route_path, &KeeperRoute { keeper_id })?;
            }
            match self.complete(
                &captured.admission.execution_id,
                KeeperRequest::Restore {
                    snapshot: snapshot.clone(),
                    captured: Box::new(captured.clone()),
                    generation,
                },
                None,
            ) {
                Ok(()) => {}
                Err(ProcessError::Io(_))
                | Err(ProcessError::Unknown(_))
                | Err(ProcessError::Missing) => {
                    if UnixStream::connect(physical.join("keeper.sock")).is_ok() {
                        match self.call(id, KeeperRequest::Inspect, None) {
                            Ok(KeeperResponse::Execution { value })
                                if value.request == request
                                    && value.lineage == Some(lineage.clone()) =>
                            {
                                continue;
                            }
                            _ => return Err(unavailable()),
                        }
                    }
                    let target = physical.join("data").join(id.as_str());
                    if target.join("process.json").exists() {
                        let restored = read_process_record(&target.join("process.json"))?;
                        if restored.request != request || restored.lineage != Some(lineage.clone())
                        {
                            return Err(ProcessError::Conflict(
                                "restored archive identity changed",
                            ));
                        }
                        continue;
                    }
                    let source = match read_process_record(
                        &self.record(&captured.admission.execution_id)?,
                    ) {
                        Ok(source) => source,
                        Err(ProcessError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if source.request != captured.admission || source.lineage != captured.lineage {
                        return Err(ProcessError::Conflict(
                            "archived restore source differs from captured admission",
                        ));
                    }
                    // A missing live keeper never receives a replayed spawn.
                    // Closed spools can still acquire independent archive lineage.
                    fs::create_dir_all(&target)?;
                    let old = OutputSpool::open_read_only(
                        &self
                            .record(&captured.admission.execution_id)?
                            .with_file_name("output.ssf"),
                        source.request.output_bytes,
                        &source.request.machine_id,
                        &source.request.execution_id,
                        source.request.generation,
                    )?;
                    let spool = old.restored_suffix(
                        &target.join("output.ssf"),
                        &source.request,
                        &captured.output,
                        &request,
                    )?;
                    let mut state = source.state;
                    match &mut state {
                        ExecutionState::Exited(completion) => {
                            completion.output = spool.finalize()?
                        }
                        ExecutionState::Running | ExecutionState::Draining { .. } => {
                            state = ExecutionState::Unknown {
                                evidence: bytes_digest(b"restored-execution-keeper-unavailable"),
                            }
                        }
                        _ => {}
                    }
                    write_process_record(
                        &target.join("process.json"),
                        &ProcessRecord {
                            version: 1,
                            request,
                            guest_pid: source.guest_pid,
                            state,
                            lineage: Some(lineage),
                        },
                        true,
                    )?;
                }
                Err(error) => return Err(error),
            }
        }
        self.connections.lock().map_err(|_| unavailable())?.clear();
        self.archives.lock().map_err(|_| unavailable())?.clear();
        *identity = (machine, generation);
        // Keep the admission through ambiguous handshakes. A subsequent snapshot
        // restores its own registry state; routine reconnect needs no mutation.
        Ok(())
    }

    fn keeper_directory(&self, id: &ExecutionId) -> Result<PathBuf, ProcessError> {
        let route = self.directory(id).join("route.json");
        match read_json::<KeeperRoute>(&route) {
            Ok(route) => Ok(self.root.join(route.keeper_id.as_str())),
            Err(ProcessError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(self.directory(id))
            }
            Err(error) => Err(error),
        }
    }
    fn directory(&self, id: &ExecutionId) -> PathBuf {
        self.root.join(id.as_str())
    }
    fn record(&self, id: &ExecutionId) -> Result<PathBuf, ProcessError> {
        Ok(self
            .keeper_directory(id)?
            .join("data")
            .join(id.as_str())
            .join("process.json"))
    }
    fn connection(&self, id: &ExecutionId) -> Result<Connection, ProcessError> {
        let mut connections = self.connections.lock().map_err(|_| unavailable())?;
        if connections.len() >= MAX_EXECUTIONS && !connections.contains_key(id) {
            return Err(ProcessError::Invalid(
                "keeper connection cache exceeds bound",
            ));
        }
        Ok(Arc::clone(
            connections
                .entry(id.clone())
                .or_insert_with(|| Arc::new(Mutex::new(None))),
        ))
    }
    fn complete(
        &self,
        id: &ExecutionId,
        request: KeeperRequest,
        bytes: Option<&[u8]>,
    ) -> Result<(), ProcessError> {
        match self.call(id, request, bytes)? {
            KeeperResponse::Complete => Ok(()),
            _ => Err(ProcessError::Invalid(
                "keeper returned wrong command response",
            )),
        }
    }
    fn call(
        &self,
        id: &ExecutionId,
        request: KeeperRequest,
        bytes: Option<&[u8]>,
    ) -> Result<KeeperResponse, ProcessError> {
        let connection = self.connection(id)?;
        let mut held = connection.lock().map_err(|_| unavailable())?;
        let result = (|| {
            if held.is_none() {
                let stream = UnixStream::connect(self.keeper_directory(id)?.join("keeper.sock"))?;
                set_timeout(&stream)?;
                *held = Some(stream);
            }
            let stream = held.as_mut().ok_or_else(unavailable)?;
            write_control(
                stream,
                &KeeperEnvelope {
                    execution_id: id.clone(),
                    request,
                },
            )?;
            if let Some(bytes) = bytes {
                write_data(stream, bytes)?;
            }
            let response: KeeperResponse = read_control(stream)?;
            response_result(response)
        })();
        if result.is_err() {
            *held = None;
        }
        result
    }
    fn call_output(
        &self,
        id: &ExecutionId,
        after: Counter,
        maximum: usize,
    ) -> Result<RetainedPage, ProcessError> {
        let connection = self.connection(id)?;
        let mut held = connection.lock().map_err(|_| unavailable())?;
        let result = (|| {
            if held.is_none() {
                let stream = UnixStream::connect(self.keeper_directory(id)?.join("keeper.sock"))?;
                set_timeout(&stream)?;
                *held = Some(stream);
            }
            let stream = held.as_mut().ok_or_else(unavailable)?;
            write_control(
                stream,
                &KeeperEnvelope {
                    execution_id: id.clone(),
                    request: KeeperRequest::Output {
                        after,
                        maximum: maximum as u32,
                    },
                },
            )?;
            let response: KeeperResponse = read_control(stream)?;
            let KeeperResponse::Output { metadata } = response_result(response)? else {
                return Err(ProcessError::Invalid(
                    "keeper returned wrong output response",
                ));
            };
            if metadata.after != after
                || metadata
                    .validate_lengths()
                    .map_err(|_| ProcessError::Invalid("keeper output metadata invalid"))?
                    > maximum
            {
                return Err(ProcessError::Invalid(
                    "keeper output exceeds requested bound",
                ));
            }
            let mut data = Vec::with_capacity(metadata.chunks.len());
            for chunk in &metadata.chunks {
                data.push(read_data(stream, chunk.length as usize)?);
            }
            metadata
                .with_binary_parts(data)
                .map_err(|_| ProcessError::Invalid("keeper output bytes invalid"))
        })();
        if result.is_err() {
            *held = None;
        }
        result
    }
}

pub(crate) struct RegistryCompletionObserver {
    directory: PathBuf,
    id: ExecutionId,
}
impl RegistryCompletionObserver {
    pub fn wait(self) {
        let path = self
            .directory
            .join("data")
            .join(self.id.as_str())
            .join("process.json");
        loop {
            match read_process_record(&path) {
                Ok(record)
                    if matches!(
                        record.state,
                        ExecutionState::Running | ExecutionState::Draining { .. }
                    ) => {}
                _ => return,
            }
            if UnixStream::connect(self.directory.join("keeper.sock")).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Entry point for the independently detached guest-side keeper executable.
pub fn execution_keeper_main(directory: &Path) -> io::Result<()> {
    let request = admission(directory).map_err(io::Error::other)?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(directory.join("keeper.lock"))?;
    // SAFETY: the lease descriptor is live and retained until this function exits.
    if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = directory.join("keeper.sock");
    match fs::symlink_metadata(&socket) {
        Ok(metadata) if std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) => {
            fs::remove_file(&socket)?
        }
        Ok(_) => return Err(io::Error::other("keeper socket path is not a socket")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let engine = Arc::new(
        ExecutionKeeper::create(
            &directory.join("data"),
            request.machine_id.clone(),
            request.generation,
        )
        .map_err(io::Error::other)?,
    );
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let connections = Arc::new(AtomicUsize::new(0));
    let pending = Arc::new(AtomicUsize::new(0));
    let startup = Instant::now();
    loop {
        match engine.current_execution_id().and_then(|id| engine.get(&id)) {
            Ok(value)
                if matches!(
                    value.state,
                    ExecutionState::Exited(_) | ExecutionState::Unknown { .. }
                ) && pending.load(Ordering::Acquire) == 0 =>
            {
                break;
            }
            Err(ProcessError::Missing) if startup.elapsed() >= KEEPER_START_TIMEOUT => break,
            _ => {}
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if connections
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        (value < MAX_KEEPER_CONNECTIONS).then_some(value + 1)
                    })
                    .is_err()
                {
                    continue;
                }
                set_timeout(&stream)?;
                let engine = Arc::clone(&engine);
                let connections = Arc::clone(&connections);
                let request = request.clone();
                let pending = Arc::clone(&pending);
                std::thread::spawn(move || {
                    struct Guard(Arc<AtomicUsize>);
                    impl Drop for Guard {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    let _guard = Guard(connections);
                    let _ = serve_keeper(stream, &engine, &request, &pending);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error),
        }
    }
    fs::remove_file(socket)?;
    drop(lease);
    Ok(())
}

fn serve_keeper(
    mut stream: UnixStream,
    engine: &ExecutionKeeper,
    admitted: &SpawnRequest,
    pending: &AtomicUsize,
) -> io::Result<()> {
    loop {
        let envelope: KeeperEnvelope = read_control(&mut stream)?;
        let request = envelope.request;
        pending.fetch_add(1, Ordering::AcqRel);
        struct Pending<'a>(&'a AtomicUsize);
        impl Drop for Pending<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _pending = Pending(pending);
        let id = &envelope.execution_id;
        let result: Result<(KeeperResponse, Vec<Vec<u8>>), ProcessError> = (|| {
            let response = match request {
                KeeperRequest::Start { environment } => {
                    if id != &admitted.execution_id {
                        return Err(ProcessError::Conflict("keeper start admission differs"));
                    }
                    KeeperResponse::Execution {
                        value: Box::new(
                            engine.spawn_with_environment(admitted.clone(), &environment)?,
                        ),
                    }
                }
                KeeperRequest::Inspect => KeeperResponse::Execution {
                    value: Box::new(engine.get(id)?),
                },
                KeeperRequest::AcquireInput { lease } => {
                    engine.acquire_terminal_input(id, &lease)?;
                    KeeperResponse::Complete
                }
                KeeperRequest::ReleaseInput { lease } => {
                    engine.release_terminal_input(id, &lease)?;
                    KeeperResponse::Complete
                }
                KeeperRequest::WriteInput { lease, length } => {
                    let bytes = read_data(&mut stream, length as usize)?;
                    engine.write_input(id, lease.as_ref(), &bytes)?;
                    KeeperResponse::Complete
                }
                KeeperRequest::CloseInput { lease } => {
                    engine.close_input(id, lease.as_ref())?;
                    KeeperResponse::Complete
                }
                KeeperRequest::Resize { size } => {
                    engine.resize_terminal(id, size)?;
                    KeeperResponse::Complete
                }
                KeeperRequest::Signal { signal, group } => {
                    engine.signal(id, signal, group)?;
                    KeeperResponse::Complete
                }
                KeeperRequest::Terminate { grace_millis } => {
                    engine.terminate(id, Duration::from_millis(u64::from(grace_millis)))?;
                    KeeperResponse::Complete
                }
                KeeperRequest::Output { after, maximum } => {
                    if maximum == 0 || maximum as usize > sandsurf_protocol::MAX_STREAM_BYTES {
                        return Err(ProcessError::Invalid("output page bound invalid"));
                    }
                    let (metadata, data) = engine
                        .read_output(id, after, maximum as usize)?
                        .into_binary_parts()
                        .map_err(|_| ProcessError::Invalid("output metadata invalid"))?;
                    return Ok((KeeperResponse::Output { metadata }, data));
                }
                KeeperRequest::Restore {
                    snapshot,
                    captured,
                    generation,
                } => {
                    if id != &captured.admission.execution_id {
                        return Err(ProcessError::Conflict("keeper restore source differs"));
                    }
                    engine.restore_execution(&snapshot, &captured, generation)?;
                    KeeperResponse::Complete
                }
            };
            Ok((response, Vec::new()))
        })();
        let (response, data) = match result {
            Ok(result) => result,
            Err(error) => (error_response(error), Vec::new()),
        };
        write_control(&mut stream, &response)?;
        for bytes in data {
            write_data(&mut stream, &bytes)?;
        }
    }
}

fn unavailable() -> ProcessError {
    ProcessError::Unknown(bytes_digest(b"execution-keeper-observation-unavailable-v1"))
}
fn set_timeout(stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(IPC_TIMEOUT))
}
fn admission(directory: &Path) -> Result<SpawnRequest, ProcessError> {
    use std::io::Read;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("request.json"))?;
    if !file.metadata()?.is_file()
        || file.metadata()?.len() > sandsurf_protocol::MAX_CONTROL_BYTES as u64
    {
        return Err(ProcessError::Invalid("keeper admission exceeds bound"));
    }
    let mut bytes = Vec::new();
    file.take(sandsurf_protocol::MAX_CONTROL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let request: SpawnRequest = serde_json::from_slice(&bytes)
        .map_err(|_| ProcessError::Invalid("keeper admission invalid"))?;
    request
        .validate()
        .map_err(|_| ProcessError::Invalid("keeper admission invalid"))?;
    if directory.file_name().and_then(|name| name.to_str()) != Some(request.execution_id.as_str()) {
        return Err(ProcessError::Invalid("keeper directory identity mismatch"));
    }
    Ok(request)
}
fn write_admission(directory: &Path, request: &SpawnRequest) -> Result<(), ProcessError> {
    write_json_new(&directory.join("request.json"), request)
}

fn write_control(stream: &mut UnixStream, value: &impl Serialize) -> io::Result<()> {
    Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ONE,
        authentication: [0; 32],
        payload: serde_json::to_vec(value).map_err(io::Error::other)?,
    }
    .write(stream)
}
fn read_control<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> io::Result<T> {
    let frame = Frame::read(stream)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "keeper channel closed"))?;
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence != Counter::ONE
        || frame.authentication != [0; 32]
    {
        return Err(io::Error::other("keeper control frame invalid"));
    }
    serde_json::from_slice(&frame.payload).map_err(io::Error::other)
}
fn write_data(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    Frame {
        kind: FrameKind::Data,
        stream: 1,
        sequence: Counter::ONE,
        authentication: [0; 32],
        payload: bytes.to_vec(),
    }
    .write(stream)
}
fn read_data(stream: &mut UnixStream, length: usize) -> io::Result<Vec<u8>> {
    if length == 0 || length > sandsurf_protocol::MAX_STREAM_BYTES {
        return Err(io::Error::other("keeper byte length invalid"));
    }
    let frame = Frame::read(stream)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "keeper data channel closed")
    })?;
    if frame.kind != FrameKind::Data
        || frame.stream != 1
        || frame.sequence != Counter::ONE
        || frame.authentication != [0; 32]
        || frame.payload.len() != length
    {
        return Err(io::Error::other("keeper data frame invalid"));
    }
    Ok(frame.payload)
}
fn error_response(error: ProcessError) -> KeeperResponse {
    let (category, evidence) = match error {
        ProcessError::Invalid(_) => ("invalid", None),
        ProcessError::Conflict(_) => ("conflict", None),
        ProcessError::Missing => ("missing", None),
        ProcessError::Timeout => ("timeout", None),
        ProcessError::Unknown(evidence) => ("unknown", Some(evidence)),
        ProcessError::Io(_) | ProcessError::Spool(_) => (
            "unknown",
            Some(bytes_digest(b"keeper-effect-or-capture-failed-v1")),
        ),
    };
    KeeperResponse::Error {
        category: category.to_owned(),
        evidence,
    }
}
fn response_result(response: KeeperResponse) -> Result<KeeperResponse, ProcessError> {
    match response {
        KeeperResponse::Error { category, evidence } => Err(match category.as_str() {
            "invalid" => ProcessError::Invalid("keeper rejected request"),
            "conflict" => ProcessError::Conflict("keeper operation conflict"),
            "missing" => ProcessError::Missing,
            "timeout" => ProcessError::Timeout,
            _ => ProcessError::Unknown(
                evidence.unwrap_or_else(|| bytes_digest(b"keeper-returned-unknown-v1")),
            ),
        }),
        response => Ok(response),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ProcessError> {
    use std::io::Read;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file()
        || file.metadata()?.len() > sandsurf_protocol::MAX_CONTROL_BYTES as u64
    {
        return Err(ProcessError::Invalid(
            "execution routing record exceeds bound",
        ));
    }
    let mut bytes = Vec::new();
    file.take(sandsurf_protocol::MAX_CONTROL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ProcessError::Invalid("execution routing record invalid"))
}
fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), ProcessError> {
    write_json(path, value, false)
}
fn write_json(path: &Path, value: &impl Serialize, replace: bool) -> Result<(), ProcessError> {
    use std::io::Write;
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ProcessError::Invalid("execution routing encoding failed"))?;
    if bytes.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
        return Err(ProcessError::Invalid(
            "execution routing record exceeds bound",
        ));
    }
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| ProcessError::Invalid("routing publication entropy unavailable"))?;
    let temporary =
        path.with_file_name(format!(".routing-{:032x}.tmp", u128::from_le_bytes(nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let result = if replace {
        fs::rename(&temporary, path)
    } else {
        fs::hard_link(&temporary, path)
    };
    let _ = fs::remove_file(&temporary);
    result?;
    File::open(
        path.parent()
            .ok_or(ProcessError::Invalid("execution routing parent missing"))?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(test)]
mod restore_tests {
    use super::*;
    use sandsurf_protocol::{
        CapturedExecution, ExecutionOutcome, StdioMode, Stream, extend_output_boundary,
        initial_output_boundary,
    };

    #[test]
    fn archive_routes_survive_reconnect_and_repeated_restore_without_rewriting_physical_admissions()
    {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "sandsurf-registry-restore-{:032x}",
            u128::from_le_bytes(nonce)
        ));
        let machine: MachineId = "box".try_into().unwrap();
        let registry = ExecutionRegistry::create(
            &root,
            machine.clone(),
            Counter::ONE,
            Path::new("/bin/false"),
        )
        .unwrap();
        let source = SpawnRequest {
            machine_id: machine.clone(),
            generation: Counter::ONE,
            execution_id: "source".try_into().unwrap(),
            operation_id: "source-operation".try_into().unwrap(),
            argv: vec!["/bin/true".into()],
            cwd: "/".into(),
            environment: BTreeMap::new(),
            user: None,
            stdio: StdioMode::Pipes,
            terminal_size: None,
            active_deadline_millis: None,
            elapsed_deadline_unix_millis: None,
            output_bytes: 100_u64.try_into().unwrap(),
        };
        let physical = root.join(source.execution_id.as_str());
        fs::create_dir(&physical).unwrap();
        write_admission(&physical, &source).unwrap();
        let data = physical.join("data").join(source.execution_id.as_str());
        let spool = OutputSpool::create(
            &data.join("output.ssf"),
            source.output_bytes,
            &machine,
            &source.execution_id,
            Counter::ONE,
        )
        .unwrap();
        spool.append(Stream::Stdout, b"prefix").unwrap();
        let empty = initial_output_boundary(&machine, &source.execution_id, Counter::ONE).unwrap();
        let anchor =
            extend_output_boundary(&empty, Counter::ONE, Stream::Stdout, b"prefix").unwrap();
        spool.append(Stream::Stdout, b"suffix").unwrap();
        let output = spool.finalize().unwrap();
        let state = ExecutionState::Exited(ExecutionCompletion {
            outcome: ExecutionOutcome::Exit { code: 0 },
            output,
            cleanup_digest: bytes_digest(b"reported"),
            accounting_digest: bytes_digest(b"reported"),
        });
        write_process_record(
            &data.join("process.json"),
            &ProcessRecord {
                version: 1,
                request: source.clone(),
                guest_pid: 123,
                state,
                lineage: None,
            },
            true,
        )
        .unwrap();
        let source_record = fs::read(data.join("process.json")).unwrap();
        let source_output = fs::read(data.join("output.ssf")).unwrap();
        let captured = CapturedExecution {
            admission: source.clone(),
            lineage: None,
            observation: None,
            output: anchor,
        };
        let snapshot: SnapshotId = "first-snapshot".try_into().unwrap();
        let capture_operation: sandsurf_protocol::OperationId =
            "capture-operation".try_into().unwrap();
        let generation: Counter = 2_u64.try_into().unwrap();
        registry
            .stage_restore(
                snapshot.clone(),
                capture_operation.clone(),
                machine.clone(),
                Counter::ONE,
                generation,
                vec![captured.clone()],
            )
            .unwrap();
        registry
            .rebind_generation(
                &snapshot,
                &capture_operation,
                machine.clone(),
                Counter::ONE,
                generation,
            )
            .unwrap();
        registry
            .rebind_generation(
                &snapshot,
                &capture_operation,
                machine.clone(),
                Counter::ONE,
                generation,
            )
            .unwrap();
        let (restored, lineage) = captured.restored(&snapshot, &machine, generation).unwrap();
        assert_eq!(
            registry.keeper_directory(&restored.execution_id).unwrap(),
            physical
        );
        assert_eq!(
            registry.get(&restored.execution_id).unwrap().lineage,
            Some(lineage.clone())
        );
        assert_eq!(
            registry
                .read_output(&restored.execution_id, Counter::ZERO, 1024)
                .unwrap()
                .chunks[0]
                .bytes,
            b"suffix"
        );
        assert_eq!(admission(&physical).unwrap(), source);
        assert_eq!(fs::read(data.join("process.json")).unwrap(), source_record);
        assert_eq!(fs::read(data.join("output.ssf")).unwrap(), source_output);
        drop(registry);
        let reopened =
            ExecutionRegistry::create(&root, machine.clone(), generation, Path::new("/bin/false"))
                .unwrap();
        let report = reopened.get(&restored.execution_id).unwrap();
        let ExecutionState::Exited(completion) = &report.state else {
            panic!("archive lost completion");
        };
        let next = CapturedExecution {
            admission: restored.clone(),
            lineage: Some(lineage),
            observation: Some(report.clone()),
            output: completion.output.clone(),
        };
        let snapshot: SnapshotId = "second-snapshot".try_into().unwrap();
        let capture_operation: sandsurf_protocol::OperationId =
            "capture-second".try_into().unwrap();
        let third_generation: Counter = 3_u64.try_into().unwrap();
        reopened
            .stage_restore(
                snapshot.clone(),
                capture_operation.clone(),
                machine.clone(),
                generation,
                third_generation,
                vec![next.clone()],
            )
            .unwrap();
        reopened
            .rebind_generation(
                &snapshot,
                &capture_operation,
                machine.clone(),
                generation,
                third_generation,
            )
            .unwrap();
        let (third, origin) = next
            .restored(&snapshot, &machine, third_generation)
            .unwrap();
        assert_eq!(origin.logical_execution_id, source.execution_id);
        assert_eq!(
            reopened.keeper_directory(&third.execution_id).unwrap(),
            physical
        );
        assert_eq!(
            reopened.get(&third.execution_id).unwrap().lineage,
            Some(origin)
        );
        assert!(
            reopened
                .read_output(&third.execution_id, Counter::ZERO, 1024)
                .unwrap()
                .chunks
                .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
