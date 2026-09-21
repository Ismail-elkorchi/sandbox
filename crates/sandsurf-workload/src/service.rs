use crate::{
    ExpectedRevision, FilesystemError, FilesystemService, ProcessError, ProcessSupervisor,
};
use sandsurf_protocol::{
    Capability, Digest, FileExpectation, FileRevision, FilesystemRequest, FilesystemResponse,
    GuestEffectOutcome, GuestServiceRequest, GuestServiceResponse, Mutation, OperationId,
    WorkloadRequest, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

const LEDGER_VERSION: u16 = 1;
const MAX_OPERATIONS: usize = 65_536;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// The protected guest supervisor owns this service for one machine epoch.
/// Client connections do not own it. Exact operation outcomes remain available
/// across authenticated reconnects and conflicting identity reuse is rejected.
pub struct PersistentWorkloadService {
    processes: ProcessSupervisor,
    filesystem: FilesystemService,
    ledger_root: PathBuf,
    operations: Mutex<BTreeMap<OperationId, OperationRecord>>,
    mutation_barrier: RwLock<()>,
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

impl PersistentWorkloadService {
    pub fn open(
        processes: ProcessSupervisor,
        filesystem: FilesystemService,
        ledger_root: &Path,
    ) -> io::Result<Self> {
        fs::create_dir_all(ledger_root)?;
        let operations = load_operations(ledger_root)?;
        Ok(Self {
            processes,
            filesystem,
            ledger_root: ledger_root.to_path_buf(),
            operations: Mutex::new(operations),
            mutation_barrier: RwLock::new(()),
        })
    }

    pub fn processes(&self) -> &ProcessSupervisor {
        &self.processes
    }

    pub fn handle(&self, request: GuestServiceRequest) -> GuestServiceResponse {
        let Ok(_guard) = self.mutation_barrier.read() else {
            return GuestServiceResponse::Error {
                code: "service.unavailable".into(),
                message: "workload mutation barrier is unavailable".into(),
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

    /// Fence all ordinary guest requests while the machine owner stops jobs
    /// and establishes the persistent filesystem boundary.
    pub fn prepare_stop(
        &self,
        grace: Duration,
        flush: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let _guard = self
            .mutation_barrier
            .write()
            .map_err(|_| io::Error::other("workload mutation barrier is unavailable"))?;
        self.processes.quiesce(grace).map_err(io::Error::other)?;
        flush()
    }

    fn handle_inner(&self, request: GuestServiceRequest) -> ServiceResult<GuestServiceResponse> {
        match request {
            GuestServiceRequest::PrepareStop => Err((
                "request.internal",
                "the machine shutdown barrier is owned by the guest supervisor".into(),
            )
                .into()),
            GuestServiceRequest::Dispatch {
                mutation,
                capability,
            } => self.dispatch(mutation, capability),
            GuestServiceRequest::Process { process_id } => self
                .processes
                .get(&process_id)
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
                process_id,
                after,
                maximum,
            } => {
                if maximum == 0 || maximum as usize > sandsurf_protocol::MAX_STREAM_BYTES {
                    return Err(("request.invalid", "output page bound is invalid".into()).into());
                }
                self.processes
                    .read_output(&process_id, after, maximum as usize)
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

    fn dispatch(
        &self,
        mutation: Mutation,
        capability: Capability,
    ) -> ServiceResult<GuestServiceResponse> {
        if mutation.validate().is_err() || mutation.required_capability() != capability {
            return Err((
                "authority.invalid",
                "workload authority does not match request".into(),
            )
                .into());
        }
        if let WorkloadRequest::Filesystem { request } = &mutation.request {
            return self.filesystem(
                mutation.operation_id.clone(),
                capability,
                mutation.request_digest.clone(),
                (**request).clone(),
            );
        }
        if let Some(value) = self.admit(&mutation.operation_id, &mutation.request_digest)? {
            return Ok(value);
        }
        let result = match &mutation.request {
            WorkloadRequest::Spawn { request } => {
                let mut request = (**request).clone();
                if request.user.is_none() {
                    request.user = Some("agent".into());
                }
                self.processes.spawn(request).map(drop)
            }
            WorkloadRequest::WriteInput { process_id, bytes } => {
                self.processes.write_input(process_id, bytes)
            }
            WorkloadRequest::CloseInput { process_id } => self.processes.close_input(process_id),
            WorkloadRequest::ResizeTerminal { process_id, size } => {
                self.processes.resize_terminal(process_id, *size)
            }
            WorkloadRequest::Signal {
                process_id,
                signal,
                group,
            } => self
                .processes
                .signal(process_id, i32::from(*signal), *group),
            WorkloadRequest::Terminate {
                process_id,
                grace_millis,
            } => self
                .processes
                .terminate(process_id, Duration::from_millis(u64::from(*grace_millis))),
            WorkloadRequest::Filesystem { .. } => unreachable!("filesystem requests branch above"),
        };
        if let Err(error) = &result {
            eprintln!(
                "sandsurf workload operation failed: {}",
                error.to_string().chars().take(1024).collect::<String>()
            );
        }
        let outcome = match result {
            Ok(()) => GuestEffectOutcome::Applied {
                evidence: effect_digest(&mutation.request_digest, b"workload-effect-applied"),
            },
            Err(
                ProcessError::Invalid(_)
                | ProcessError::Conflict(_)
                | ProcessError::Missing
                | ProcessError::Timeout,
            ) => GuestEffectOutcome::NotApplied {
                evidence: effect_digest(&mutation.request_digest, b"workload-effect-rejected"),
            },
            Err(ProcessError::Io(_) | ProcessError::Spool(_) | ProcessError::Unknown(_)) => {
                GuestEffectOutcome::Unknown
            }
        };
        let response = GuestServiceResponse::Effect { outcome };
        self.commit(mutation.operation_id, mutation.request_digest, response)
    }

    fn filesystem(
        &self,
        operation_id: OperationId,
        capability: Capability,
        request_digest: Digest,
        request: FilesystemRequest,
    ) -> ServiceResult<GuestServiceResponse> {
        if capability != request.required_capability() || request.validate().is_err() {
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
                let expected = expectation(expected);
                let revision = self.filesystem.write_file_from(
                    &path,
                    &mut bytes.as_slice(),
                    crate::WriteOptions {
                        maximum: bytes.len() as u64,
                        mode,
                        operation_id: &operation_id,
                        expected: &expected,
                    },
                    &self.processes,
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
                let revision = self
                    .filesystem
                    .commit_write_transfer(&transfer, &self.processes)?;
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
                epoch,
                path,
                recursive,
            } => {
                self.filesystem.watch(watcher_id, epoch, path, recursive)?;
                FilesystemResponse::Complete
            }
            FilesystemRequest::PollWatch {
                watcher_id,
                epoch,
                maximum,
            } => FilesystemResponse::Watch {
                events: self
                    .filesystem
                    .poll_watcher(&watcher_id, epoch, maximum.into())?,
            },
            FilesystemRequest::Unwatch { watcher_id, epoch } => {
                self.filesystem.unwatch(&watcher_id, epoch)?;
                FilesystemResponse::Complete
            }
        };
        self.commit(
            operation_id,
            request_digest,
            GuestServiceResponse::File { response },
        )
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

fn expectation(value: FileExpectation) -> ExpectedRevision {
    match value {
        FileExpectation::Any => ExpectedRevision::Any,
        FileExpectation::Absent => ExpectedRevision::Absent,
        FileExpectation::Matches { size, digest } => {
            ExpectedRevision::Matches(FileRevision { size, digest })
        }
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
            FilesystemError::Barrier => "filesystem.barrier",
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
    use sandsurf_protocol::{Counter, GuestPath, SandboxId, bytes_digest};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let value = std::env::temp_dir().join(format!(
                "sandsurf-workload-service-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&value).unwrap();
            Self(value)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn filesystem_operations_reconcile_exact_identity_without_reapplying() {
        let root = Temp::new();
        let files = root.0.join("files");
        let spool = root.0.join("spool");
        fs::create_dir(&files).unwrap();
        let processes =
            ProcessSupervisor::create(&spool, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap();
        let service = PersistentWorkloadService::open(
            processes,
            FilesystemService::open(&files, "/").unwrap(),
            &root.0.join("operations"),
        )
        .unwrap();
        let operation = OperationId::try_from("mkdir").unwrap();
        let request = FilesystemRequest::Mkdir {
            path: GuestPath::try_from("/created").unwrap(),
            recursive: false,
        };
        let mutation = Mutation::new(
            SandboxId::try_from("box").unwrap(),
            Counter::ONE,
            operation.clone(),
            "write".try_into().unwrap(),
            Counter::ONE,
            WorkloadRequest::Filesystem {
                request: Box::new(request),
            },
        )
        .unwrap();
        let first = service.handle(GuestServiceRequest::Dispatch {
            mutation: mutation.clone(),
            capability: Capability::WriteFiles,
        });
        assert_eq!(
            first,
            service.handle(GuestServiceRequest::Operation {
                operation_id: operation.clone(),
                request_digest: mutation.request_digest.clone(),
            })
        );
        assert!(files.join("created").is_dir());

        drop(service);
        let reopened = PersistentWorkloadService::open(
            ProcessSupervisor::create(&spool, SandboxId::try_from("box").unwrap(), Counter::ONE)
                .unwrap(),
            FilesystemService::open(&files, "/").unwrap(),
            &root.0.join("operations"),
        )
        .unwrap();
        assert_eq!(
            first,
            reopened.handle(GuestServiceRequest::Operation {
                operation_id: operation.clone(),
                request_digest: mutation.request_digest.clone(),
            })
        );

        let conflict = reopened.handle(GuestServiceRequest::Operation {
            operation_id: operation,
            request_digest: bytes_digest(b"different"),
        });
        assert!(
            matches!(conflict, GuestServiceResponse::Error { code, .. } if code == "operation.conflict")
        );
    }
}
