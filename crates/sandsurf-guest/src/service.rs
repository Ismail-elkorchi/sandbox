use crate::{ExecutionRegistry, FilesystemError, FilesystemService, ProcessError};
use sandsurf_protocol::{
    Counter, Digest, ExecutionId, ExecutionState, FileExpectation, FilesystemRequest,
    FilesystemResponse, GuestCommand, GuestEffectOutcome, GuestRequest, GuestServiceRequest,
    GuestServiceResponse, MachineId, OperationId, SecretCleanupReport, SecretDestination, SecretId,
    SecretLifetime, SnapshotId, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

const LEDGER_VERSION: u16 = 1;
const MAX_OPERATIONS: usize = 65_536;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// Ordinary, root-controlled Linux management service. Its records are guest
/// reports, not host attestations. Client connections do not own the computer.
pub struct ManagementService {
    processes: ExecutionRegistry,
    filesystem: Arc<FilesystemService>,
    ledger_root: PathBuf,
    operations: Mutex<BTreeMap<OperationId, OperationRecord>>,
    command_barrier: RwLock<()>,
    installed_secrets: Arc<Mutex<BTreeMap<OperationId, InstalledSecret>>>,
}

#[derive(Clone)]
struct InstalledSecret {
    id: SecretId,
    version: sandsurf_protocol::SecretVersionId,
    destination: SecretDestination,
    lifetime: sandsurf_protocol::SecretLifetime,
    execution_id: Option<ExecutionId>,
    bytes: Vec<u8>,
    cleanup_armed: bool,
}

#[derive(Clone)]
struct OperationRecord {
    request_digest: Digest,
    response: Option<GuestServiceResponse>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRecord {
    version: u16,
    operation_id: OperationId,
    request_digest: Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletionRecord {
    version: u16,
    operation_id: OperationId,
    request_digest: Digest,
    response: GuestServiceResponse,
}

struct ServiceFailure {
    code: &'static str,
    message: String,
}

type ServiceResult<T> = Result<T, ServiceFailure>;

impl From<(&'static str, String)> for ServiceFailure {
    fn from((code, message): (&'static str, String)) -> Self {
        Self { code, message }
    }
}

impl ManagementService {
    pub fn open(
        processes: ExecutionRegistry,
        filesystem: FilesystemService,
        ledger_root: &Path,
    ) -> io::Result<Self> {
        fs::create_dir_all(ledger_root)?;
        let operations = load_operations(ledger_root)?;
        Ok(Self {
            processes,
            filesystem: Arc::new(filesystem),
            ledger_root: ledger_root.to_path_buf(),
            operations: Mutex::new(operations),
            command_barrier: RwLock::new(()),
            installed_secrets: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub fn processes(&self) -> &ExecutionRegistry {
        &self.processes
    }

    pub fn handle(&self, request: GuestServiceRequest) -> GuestServiceResponse {
        let Ok(_guard) = self.command_barrier.read() else {
            return GuestServiceResponse::Error {
                code: "service.unavailable".into(),
                message: "workload command barrier is unavailable".into(),
            };
        };
        match self.handle_inner(request) {
            Ok(value) => value,
            Err(error) => GuestServiceResponse::Error {
                code: error.code.to_owned(),
                message: error.message,
            },
        }
    }

    /// Rebind management transport after a native memory restore. This request
    /// rotates connection identity; it does not establish a filesystem barrier.
    pub fn rebind_generation(
        &self,
        snapshot_id: &SnapshotId,
        capture_operation_id: &OperationId,
        machine_id: MachineId,
        previous_generation: Counter,
        generation: Counter,
    ) -> io::Result<Digest> {
        let _guard = self
            .command_barrier
            .write()
            .map_err(|_| io::Error::other("workload command barrier is unavailable"))?;
        self.processes
            .rebind_generation(
                snapshot_id,
                capture_operation_id,
                machine_id,
                previous_generation,
                generation,
            )
            .map_err(io::Error::other)?;
        Ok(bytes_digest(b"guest-workload-generation-rebound-v1"))
    }

    fn handle_inner(&self, request: GuestServiceRequest) -> ServiceResult<GuestServiceResponse> {
        match request {
            GuestServiceRequest::StageExecutionRestore {
                snapshot_id,
                capture_operation_id,
                machine_id,
                previous_generation,
                generation,
                executions,
            } => {
                self.processes
                    .stage_restore(
                        snapshot_id,
                        capture_operation_id,
                        machine_id,
                        previous_generation,
                        generation,
                        executions,
                    )
                    .map_err(process_error)?;
                Ok(GuestServiceResponse::Effect {
                    outcome: sandsurf_protocol::GuestEffectOutcome::Applied {
                        evidence: bytes_digest(b"execution-restore-membership-staged"),
                    },
                })
            }
            GuestServiceRequest::RebindGeneration { .. } | GuestServiceRequest::ProbeIdentity => {
                Err((
                    "request.internal",
                    "transport identity requests are owned by the management endpoint".into(),
                )
                    .into())
            }
            GuestServiceRequest::InstallSecret {
                operation_id,
                delivery,
                bytes,
            } => self.install_secret(&operation_id, delivery, bytes),
            GuestServiceRequest::RevokeSecret {
                operation_id,
                secret_id,
                version,
                deliveries,
                terminate_recipients,
            } => self.revoke_secret(
                &operation_id,
                &secret_id,
                &version,
                &deliveries,
                terminate_recipients,
            ),
            GuestServiceRequest::FilesystemQuery { request } => self.filesystem_query(request),
            GuestServiceRequest::Dispatch { command } => self.dispatch(command),
            GuestServiceRequest::Process { execution_id } => self
                .processes
                .get(&execution_id)
                .map(|process| GuestServiceResponse::Process {
                    process: Box::new(process),
                })
                .map_err(process_error),
            GuestServiceRequest::Processes => self
                .processes
                .list()
                .map(|processes| GuestServiceResponse::Processes { processes })
                .map_err(process_error),
            GuestServiceRequest::ReadOutput {
                execution_id,
                after,
                maximum,
            } => {
                if maximum == 0 || maximum as usize > sandsurf_protocol::MAX_STREAM_BYTES {
                    return Err(("request.invalid", "output page bound is invalid".into()).into());
                }
                self.processes
                    .read_output(&execution_id, after, maximum as usize)
                    .map(|page| GuestServiceResponse::Output { page })
                    .map_err(process_error)
            }
            GuestServiceRequest::Operation {
                operation_id,
                request_digest,
            } => self
                .reconcile(&operation_id, &request_digest)?
                .ok_or_else(|| {
                    (
                        "operation.missing",
                        "guest operation is not retained".into(),
                    )
                        .into()
                }),
        }
    }

    fn dispatch(&self, command: GuestCommand) -> ServiceResult<GuestServiceResponse> {
        if command.validate().is_err() {
            return Err((
                "authority.invalid",
                "workload authority does not match request".into(),
            )
                .into());
        }
        let (machine_id, generation) = self.processes.identity().map_err(process_error)?;
        if command.machine_id != machine_id || command.generation != generation {
            return Err((
                "authority.stale-generation",
                "workload authority targets a stale machine generation".into(),
            )
                .into());
        }
        if let GuestRequest::Filesystem { request } = &command.request {
            return self.filesystem(
                command.operation_id.clone(),
                command.request_digest.clone(),
                (**request).clone(),
            );
        }
        if let Some(value) = self.admit(&command.operation_id, &command.request_digest)? {
            return Ok(value);
        }
        let result = match &command.request {
            GuestRequest::Spawn { request } => {
                let request = (**request).clone();
                let secrets = self.process_secrets(&request)?;
                let execution_id = request.execution_id.clone();
                self.processes
                    .spawn_with_environment(request, &secrets)
                    .and_then(|_| self.arm_process_secret_cleanup(&execution_id))
            }
            GuestRequest::WriteInput {
                execution_id,
                terminal_lease_id,
                bytes,
            } => self
                .processes
                .write_input(execution_id, terminal_lease_id.as_ref(), bytes),
            GuestRequest::CloseInput {
                execution_id,
                terminal_lease_id,
            } => self
                .processes
                .close_input(execution_id, terminal_lease_id.as_ref()),
            GuestRequest::AcquireTerminalInput {
                execution_id,
                terminal_lease_id,
            } => self
                .processes
                .acquire_terminal_input(execution_id, terminal_lease_id),
            GuestRequest::ReleaseTerminalInput {
                execution_id,
                terminal_lease_id,
            } => self
                .processes
                .release_terminal_input(execution_id, terminal_lease_id),
            GuestRequest::ResizeTerminal { execution_id, size } => {
                self.processes.resize_terminal(execution_id, *size)
            }
            GuestRequest::Signal {
                execution_id,
                signal,
                group,
            } => self
                .processes
                .signal(execution_id, i32::from(*signal), *group),
            GuestRequest::Terminate {
                execution_id,
                grace_millis,
            } => self.processes.terminate(
                execution_id,
                Duration::from_millis(u64::from(*grace_millis)),
            ),
            GuestRequest::Filesystem { .. } => unreachable!("filesystem requests branch above"),
        };
        if let Err(error) = &result {
            eprintln!(
                "sandsurf workload operation failed: {}",
                error.to_string().chars().take(1024).collect::<String>()
            );
        }
        let outcome = match result {
            Ok(()) => GuestEffectOutcome::Applied {
                evidence: effect_digest(&command.request_digest, b"workload-effect-applied"),
            },
            Err(
                ProcessError::Invalid(_)
                | ProcessError::Conflict(_)
                | ProcessError::Missing
                | ProcessError::Timeout,
            ) => GuestEffectOutcome::NotApplied {
                evidence: effect_digest(&command.request_digest, b"workload-effect-rejected"),
            },
            Err(ProcessError::Io(_) | ProcessError::Spool(_) | ProcessError::Unknown(_)) => {
                GuestEffectOutcome::Unknown
            }
        };
        let response = GuestServiceResponse::Effect { outcome };
        self.commit(command.operation_id, command.request_digest, response)
    }

    fn install_secret(
        &self,
        operation_id: &OperationId,
        delivery: sandsurf_protocol::SecretDelivery,
        bytes: Vec<u8>,
    ) -> ServiceResult<GuestServiceResponse> {
        delivery.validate().map_err(|error| ServiceFailure {
            code: "secret.invalid",
            message: error.to_string(),
        })?;
        if bytes.len() as u64 != delivery.secret.bytes.get() {
            return Err((
                "secret.integrity",
                "secret byte count differs from the host delivery envelope".into(),
            )
                .into());
        }
        let mut installed = self.installed_secrets.lock().map_err(|_| ServiceFailure {
            code: "service.unavailable",
            message: "secret delivery state is unavailable".into(),
        })?;
        if let Some(old) = installed.get(operation_id) {
            if old.id == delivery.secret.id
                && old.version == delivery.secret.version
                && old.destination == delivery.destination
                && old.lifetime == delivery.lifetime
                && old.execution_id == delivery.execution_id
            {
                return Ok(GuestServiceResponse::SecretInstalled {
                    evidence: bytes_digest(b"secret-delivery-already-installed"),
                });
            }
            return Err((
                "secret.conflict",
                "secret identity is already bound to another active delivery".into(),
            )
                .into());
        }
        if let SecretDestination::Environment { .. } = &delivery.destination
            && (std::str::from_utf8(&bytes).is_err() || bytes.contains(&0))
        {
            return Err((
                "secret.invalid",
                "environment secret must be UTF-8 without NUL".into(),
            )
                .into());
        }
        if let SecretDestination::File { path, mode } = &delivery.destination {
            let expected = FileExpectation::Any;
            self.filesystem.write_file_from(
                path,
                &mut bytes.as_slice(),
                crate::WriteOptions {
                    maximum: bytes.len() as u64,
                    mode: *mode,
                    operation_id,
                    expected: &expected,
                },
            )?;
        }
        let evidence = sandsurf_protocol::digest(
            sandsurf_protocol::Domain::Secret,
            &(
                "sandsurf-secret-installed-v1",
                operation_id,
                &delivery.secret,
                &delivery.destination,
                &delivery.lifetime,
                &delivery.execution_id,
            ),
        )
        .map_err(|error| ServiceFailure {
            code: "secret.invalid",
            message: error.to_string(),
        })?;
        let execution_id = delivery.execution_id.clone();
        installed.insert(
            operation_id.clone(),
            InstalledSecret {
                id: delivery.secret.id,
                version: delivery.secret.version,
                destination: delivery.destination,
                lifetime: delivery.lifetime,
                execution_id: execution_id.clone(),
                bytes,
                cleanup_armed: false,
            },
        );
        drop(installed);
        if let Some(execution_id) = execution_id.as_ref()
            && self.processes.get(execution_id).is_ok()
        {
            self.arm_process_secret_cleanup(execution_id)
                .map_err(process_error)?;
        }
        Ok(GuestServiceResponse::SecretInstalled { evidence })
    }

    fn revoke_secret(
        &self,
        operation_id: &OperationId,
        secret_id: &SecretId,
        version: &sandsurf_protocol::SecretVersionId,
        deliveries: &[sandsurf_protocol::SecretDelivery],
        terminate_recipients: bool,
    ) -> ServiceResult<GuestServiceResponse> {
        if deliveries.is_empty() || deliveries.len() > 1024 {
            return Err((
                "secret.invalid",
                "secret revocation delivery set is empty or oversized".into(),
            )
                .into());
        }
        for delivery in deliveries {
            delivery.validate().map_err(|error| ServiceFailure {
                code: "secret.invalid",
                message: error.to_string(),
            })?;
            if &delivery.secret.id != secret_id || &delivery.secret.version != version {
                return Err((
                    "secret.invalid",
                    "secret revocation contains another secret version".into(),
                )
                    .into());
            }
        }
        let mut installed = self.installed_secrets.lock().map_err(|_| ServiceFailure {
            code: "service.unavailable",
            message: "secret delivery state is unavailable".into(),
        })?;
        let operations = installed
            .iter()
            .filter(|(_, value)| &value.id == secret_id && &value.version == version)
            .map(|(operation, _)| operation.clone())
            .collect::<Vec<_>>();
        let mut environment_bindings_removed = 0_u64;
        for operation in operations {
            let mut value = installed
                .remove(&operation)
                .ok_or_else(|| ("secret.missing", "secret delivery disappeared".into()))?;
            if matches!(value.destination, SecretDestination::Environment { .. }) {
                environment_bindings_removed += 1;
            }
            value.bytes.fill(0);
        }
        drop(installed);

        let mut files_removed = 0_u64;
        let mut recipients = std::collections::BTreeSet::new();
        for delivery in deliveries {
            if let Some(execution_id) = delivery.execution_id.as_ref() {
                recipients.insert(execution_id.clone());
            }
            if let SecretDestination::File { path, .. } = &delivery.destination {
                match self.filesystem.remove_path(path, false) {
                    Ok(()) => files_removed += 1,
                    Err(FilesystemError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(FilesystemError::Conflict) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }

        let mut recipients_terminated = Vec::new();
        let mut recipients_already_stopped = Vec::new();
        let mut actions_reported_complete = true;
        for execution_id in recipients {
            match self.processes.get(&execution_id) {
                Ok(process) if matches!(process.state, ExecutionState::Running) => {
                    if terminate_recipients {
                        if self
                            .processes
                            .terminate(&execution_id, Duration::from_secs(2))
                            .and_then(|()| {
                                self.processes
                                    .wait(&execution_id, Some(Duration::from_secs(5)))
                                    .map(drop)
                            })
                            .is_ok()
                        {
                            recipients_terminated.push(execution_id);
                        } else {
                            actions_reported_complete = false;
                        }
                    }
                }
                Ok(_) | Err(ProcessError::Missing) => {
                    recipients_already_stopped.push(execution_id);
                }
                Err(_) => actions_reported_complete = false,
            }
        }
        let evidence = SecretCleanupReport {
            files_removed: Counter::try_from(files_removed).map_err(|_| ServiceFailure {
                code: "secret.invalid",
                message: "secret file count cannot be represented".into(),
            })?,
            environment_bindings_removed: Counter::try_from(environment_bindings_removed).map_err(
                |_| ServiceFailure {
                    code: "secret.invalid",
                    message: "secret environment count cannot be represented".into(),
                },
            )?,
            recipients_terminated,
            recipients_already_stopped,
            // Raw delivery can never prove that a process did not copy bytes.
            residual_copies_possible: true,
            actions_reported_complete,
        };
        let _ = operation_id;
        Ok(GuestServiceResponse::SecretCleanupReported { report: evidence })
    }

    fn arm_process_secret_cleanup(&self, execution_id: &ExecutionId) -> Result<(), ProcessError> {
        let observer = self.processes.completion_observer(execution_id)?;
        let operations = {
            let mut installed = self
                .installed_secrets
                .lock()
                .map_err(|_| ProcessError::Unknown(bytes_digest(b"secret-state-poisoned")))?;
            installed
                .iter_mut()
                .filter(|(_, value)| {
                    value.execution_id.as_ref() == Some(execution_id)
                        && !value.cleanup_armed
                        && (matches!(value.lifetime, SecretLifetime::Process)
                            || matches!(value.destination, SecretDestination::Environment { .. }))
                })
                .map(|(operation, value)| {
                    value.cleanup_armed = true;
                    operation.clone()
                })
                .collect::<Vec<_>>()
        };
        if operations.is_empty() {
            return Ok(());
        }
        let secrets = Arc::clone(&self.installed_secrets);
        let filesystem = Arc::clone(&self.filesystem);
        std::thread::Builder::new()
            .name("sandsurf-secret-lifetime".into())
            .spawn(move || {
                observer.wait();
                for operation in operations {
                    let path = secrets
                        .lock()
                        .ok()
                        .and_then(|installed| installed.get(&operation).cloned())
                        .and_then(|value| match value.destination {
                            SecretDestination::File { path, .. } => Some(path),
                            SecretDestination::Environment { .. } => None,
                        });
                    if let Some(path) = path {
                        match filesystem.remove_path(&path, false) {
                            Ok(()) | Err(FilesystemError::Conflict) => {}
                            Err(FilesystemError::Io(error))
                                if error.kind() == io::ErrorKind::NotFound => {}
                            Err(error) => {
                                eprintln!("process secret cleanup failed: {error}");
                                continue;
                            }
                        }
                    }
                    if let Ok(mut installed) = secrets.lock()
                        && let Some(mut value) = installed.remove(&operation)
                    {
                        value.bytes.fill(0);
                    }
                }
            })?;
        Ok(())
    }

    fn process_secrets(
        &self,
        request: &sandsurf_protocol::SpawnRequest,
    ) -> ServiceResult<BTreeMap<String, String>> {
        let installed = self.installed_secrets.lock().map_err(|_| ServiceFailure {
            code: "service.unavailable",
            message: "secret delivery state is unavailable".into(),
        })?;
        let mut environment = BTreeMap::new();
        for value in installed.values() {
            if value.execution_id.as_ref() != Some(&request.execution_id) {
                continue;
            }
            if let SecretDestination::Environment { name } = &value.destination {
                let secret = std::str::from_utf8(&value.bytes).map_err(|_| ServiceFailure {
                    code: "secret.invalid",
                    message: "environment secret is no longer valid UTF-8".into(),
                })?;
                if request.environment.contains_key(name)
                    || environment.insert(name.clone(), secret.into()).is_some()
                {
                    return Err((
                        "secret.conflict",
                        "spawn environment overrides a delivered secret".into(),
                    )
                        .into());
                }
            }
        }
        Ok(environment)
    }

    fn filesystem(
        &self,
        operation_id: OperationId,
        request_digest: Digest,
        request: FilesystemRequest,
    ) -> ServiceResult<GuestServiceResponse> {
        if request.validate().is_err() {
            return Err((
                "authority.invalid",
                "filesystem authority does not bind request".into(),
            )
                .into());
        }
        if let Some(value) = self.admit(&operation_id, &request_digest)? {
            return Ok(value);
        }
        let response = match request {
            FilesystemRequest::Stat { path, follow } => {
                let value = if follow {
                    self.filesystem.stat_path(&path)
                } else {
                    self.filesystem.lstat_path(&path)
                }?;
                FilesystemResponse::Stat { value }
            }
            FilesystemRequest::List {
                path,
                after,
                maximum,
            } => FilesystemResponse::List {
                page: self
                    .filesystem
                    .list_page(&path, after.as_deref(), maximum.into())?,
            },
            FilesystemRequest::Read {
                path,
                offset,
                maximum,
            } => FilesystemResponse::Read {
                range: self
                    .filesystem
                    .read_range(&path, offset, maximum as usize)?,
            },
            FilesystemRequest::Write {
                path,
                bytes,
                mode,
                expected,
            } => {
                if bytes.len() > sandsurf_protocol::MAX_STREAM_BYTES {
                    return Err((
                        "request.invalid",
                        "inline write exceeds stream bound".into(),
                    )
                        .into());
                }
                let revision = self.filesystem.write_file_from(
                    &path,
                    &mut bytes.as_slice(),
                    crate::WriteOptions {
                        maximum: bytes.len() as u64,
                        mode,
                        operation_id: &operation_id,
                        expected: &expected,
                    },
                )?;
                FilesystemResponse::Written { revision }
            }
            FilesystemRequest::BeginWrite { transfer } => {
                self.filesystem.begin_write_transfer(&transfer)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::WriteChunk {
                transfer,
                offset,
                bytes,
            } => {
                self.filesystem
                    .write_transfer_chunk(&transfer, offset, &bytes)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::CommitWrite { transfer } => {
                let revision = self.filesystem.commit_write_transfer(&transfer)?;
                FilesystemResponse::Written { revision }
            }
            FilesystemRequest::AbortWrite { transfer } => {
                self.filesystem.abort_write_transfer(&transfer)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::Mkdir { path, recursive } => {
                self.filesystem.mkdir_path(&path, recursive)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::Rename { from, to } => {
                self.filesystem.rename_path(&from, &to)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::Remove { path, recursive } => {
                self.filesystem.remove_path(&path, recursive)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::Chmod { path, mode } => {
                self.filesystem.chmod(&path, mode)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::Readlink { path } => FilesystemResponse::Link {
                target: self.filesystem.read_link_path(&path)?,
            },
            FilesystemRequest::Symlink { path, target } => {
                self.filesystem.symlink_path(&target, &path)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::Watch {
                watcher_id,
                generation,
                path,
                recursive,
            } => {
                self.filesystem
                    .watch(watcher_id, generation, path, recursive)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::PollWatch {
                watcher_id,
                generation,
                after,
                maximum,
            } => FilesystemResponse::Watch {
                page: self.filesystem.poll_watcher(
                    &watcher_id,
                    generation,
                    after,
                    maximum.into(),
                )?,
            },
            FilesystemRequest::Unwatch {
                watcher_id,
                generation,
            } => {
                self.filesystem.unwatch(&watcher_id, generation)?;
                FilesystemResponse::Complete
            }
        };
        self.commit(
            operation_id,
            request_digest,
            GuestServiceResponse::File { response },
        )
    }

    fn filesystem_query(&self, request: FilesystemRequest) -> ServiceResult<GuestServiceResponse> {
        if !request.is_query() || request.validate().is_err() {
            return Err(("request.invalid", "filesystem query is malformed".into()).into());
        }
        let response = match request {
            FilesystemRequest::Stat { path, follow } => {
                let value = if follow {
                    self.filesystem.stat_path(&path)
                } else {
                    self.filesystem.lstat_path(&path)
                }?;
                FilesystemResponse::Stat { value }
            }
            FilesystemRequest::List {
                path,
                after,
                maximum,
            } => FilesystemResponse::List {
                page: self
                    .filesystem
                    .list_page(&path, after.as_deref(), maximum.into())?,
            },
            FilesystemRequest::Read {
                path,
                offset,
                maximum,
            } => FilesystemResponse::Read {
                range: self
                    .filesystem
                    .read_range(&path, offset, maximum as usize)?,
            },
            FilesystemRequest::Readlink { path } => FilesystemResponse::Link {
                target: self.filesystem.read_link_path(&path)?,
            },
            FilesystemRequest::PollWatch {
                watcher_id,
                generation,
                after,
                maximum,
            } => FilesystemResponse::Watch {
                page: self.filesystem.poll_watcher(
                    &watcher_id,
                    generation,
                    after,
                    maximum.into(),
                )?,
            },
            _ => {
                return Err((
                    "request.invalid",
                    "filesystem command cannot use the query route".into(),
                )
                    .into());
            }
        };
        Ok(GuestServiceResponse::File { response })
    }

    fn reconcile(
        &self,
        operation_id: &OperationId,
        request_digest: &Digest,
    ) -> ServiceResult<Option<GuestServiceResponse>> {
        let operations = self.operations.lock().map_err(|_| ServiceFailure {
            code: "service.unavailable",
            message: "operation ledger is unavailable".into(),
        })?;
        match operations.get(operation_id) {
            Some(record) if &record.request_digest == request_digest => {
                Ok(Some(record.response.clone().unwrap_or(
                    GuestServiceResponse::Effect {
                        outcome: GuestEffectOutcome::Unknown,
                    },
                )))
            }
            Some(_) => Err((
                "operation.conflict",
                "operation identity is bound to another request".into(),
            )
                .into()),
            None => Ok(None),
        }
    }

    /// Persist admission before dispatch. An admitted operation without a
    /// completion is never replayed after reconnect or guest restart.
    fn admit(
        &self,
        operation_id: &OperationId,
        request_digest: &Digest,
    ) -> ServiceResult<Option<GuestServiceResponse>> {
        if let Some(value) = self.reconcile(operation_id, request_digest)? {
            return Ok(Some(value));
        }
        let mut operations = self.operations.lock().map_err(|_| ServiceFailure {
            code: "service.unavailable",
            message: "operation ledger is unavailable".into(),
        })?;
        if operations.len() >= MAX_OPERATIONS {
            return Err(("service.capacity", "operation ledger is full".into()).into());
        }
        let record = AdmissionRecord {
            version: LEDGER_VERSION,
            operation_id: operation_id.clone(),
            request_digest: request_digest.clone(),
        };
        write_new_record(&admission_path(&self.ledger_root, operation_id), &record).map_err(
            |error| ServiceFailure {
                code: "service.unavailable",
                message: format!("operation admission could not be retained: {error}"),
            },
        )?;
        operations.insert(
            operation_id.clone(),
            OperationRecord {
                request_digest: request_digest.clone(),
                response: None,
            },
        );
        Ok(None)
    }

    fn commit(
        &self,
        operation_id: OperationId,
        request_digest: Digest,
        response: GuestServiceResponse,
    ) -> ServiceResult<GuestServiceResponse> {
        let mut operations = self.operations.lock().map_err(|_| ServiceFailure {
            code: "service.unavailable",
            message: "operation ledger is unavailable".into(),
        })?;
        let Some(record) = operations.get_mut(&operation_id) else {
            return Err(("service.unavailable", "operation was not admitted".into()).into());
        };
        if record.request_digest != request_digest {
            return Err((
                "operation.conflict",
                "operation identity is bound to another request".into(),
            )
                .into());
        }
        if let Some(existing) = &record.response {
            return Ok(existing.clone());
        }
        let completion = CompletionRecord {
            version: LEDGER_VERSION,
            operation_id: operation_id.clone(),
            request_digest,
            response: response.clone(),
        };
        if let Err(error) = write_new_record(
            &completion_path(&self.ledger_root, &operation_id),
            &completion,
        ) {
            eprintln!(
                "sandsurf operation completion retention failed: {}",
                error.to_string().chars().take(1024).collect::<String>()
            );
            return Ok(GuestServiceResponse::Effect {
                outcome: GuestEffectOutcome::Unknown,
            });
        }
        record.response = Some(response.clone());
        Ok(response)
    }
}

fn load_operations(root: &Path) -> io::Result<BTreeMap<OperationId, OperationRecord>> {
    let mut admissions = BTreeMap::new();
    let mut completions = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operation ledger contains an invalid object",
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ledger name is not UTF-8"))?;
        if name.ends_with(".admitted.json") {
            let record: AdmissionRecord = read_record(&entry.path())?;
            validate_record_name(&name, &record.operation_id, ".admitted.json")?;
            if record.version != LEDGER_VERSION
                || admissions
                    .insert(
                        record.operation_id,
                        OperationRecord {
                            request_digest: record.request_digest,
                            response: None,
                        },
                    )
                    .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "operation admission is invalid or duplicated",
                ));
            }
        } else if name.ends_with(".completed.json") {
            let record: CompletionRecord = read_record(&entry.path())?;
            validate_record_name(&name, &record.operation_id, ".completed.json")?;
            completions.push(record);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operation ledger contains an unknown record",
            ));
        }
    }
    if admissions.len() > MAX_OPERATIONS || completions.len() > MAX_OPERATIONS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "operation ledger exceeds its retained identity bound",
        ));
    }
    for completion in completions {
        if completion.version != LEDGER_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operation completion version is unsupported",
            ));
        }
        let admission = admissions
            .get_mut(&completion.operation_id)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "operation completion has no durable admission",
                )
            })?;
        if admission.request_digest != completion.request_digest || admission.response.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operation completion conflicts with its admission",
            ));
        }
        admission.response = Some(completion.response);
    }
    Ok(admissions)
}

fn write_new_record(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "operation record exceeds bound",
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "operation record has no parent",
        )
    })?)?
    .sync_all()
}

fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let size = file.metadata()?.len();
    if size == 0 || size > MAX_RECORD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "operation record size is invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn admission_path(root: &Path, operation_id: &OperationId) -> PathBuf {
    root.join(format!("{}.admitted.json", operation_id.as_str()))
}

fn completion_path(root: &Path, operation_id: &OperationId) -> PathBuf {
    root.join(format!("{}.completed.json", operation_id.as_str()))
}

fn validate_record_name(name: &str, operation_id: &OperationId, suffix: &str) -> io::Result<()> {
    if name == format!("{}{}", operation_id.as_str(), suffix) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "operation record name does not bind its identity",
        ))
    }
}

fn effect_digest(request: &Digest, label: &[u8]) -> Digest {
    let mut bytes = label.to_vec();
    bytes.extend_from_slice(request.as_str().as_bytes());
    bytes_digest(&bytes)
}

fn process_error(error: ProcessError) -> ServiceFailure {
    let code = match &error {
        ProcessError::Invalid(_) => "process.invalid",
        ProcessError::Conflict(_) => "process.conflict",
        ProcessError::Missing => "process.missing",
        ProcessError::Timeout => "process.timeout",
        ProcessError::Io(_) | ProcessError::Spool(_) | ProcessError::Unknown(_) => {
            "process.unavailable"
        }
    };
    ServiceFailure {
        code,
        message: error.to_string(),
    }
}

impl From<FilesystemError> for ServiceFailure {
    fn from(error: FilesystemError) -> Self {
        let code = match &error {
            FilesystemError::Invalid(_) => "filesystem.invalid",
            FilesystemError::Conflict => "filesystem.conflict",
            FilesystemError::Capacity => "filesystem.capacity",
            FilesystemError::Unavailable => "filesystem.unavailable",
            FilesystemError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
                "filesystem.missing"
            }
            FilesystemError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                "filesystem.permission"
            }
            FilesystemError::Io(_) => "filesystem.io",
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filesystem_missing_is_distinct_from_other_io_failures() {
        let missing = ServiceFailure::from(FilesystemError::Io(io::Error::from(
            io::ErrorKind::NotFound,
        )));
        let denied = ServiceFailure::from(FilesystemError::Io(io::Error::from(
            io::ErrorKind::PermissionDenied,
        )));
        assert_eq!(missing.code, "filesystem.missing");
        assert_eq!(denied.code, "filesystem.permission");
    }
}
