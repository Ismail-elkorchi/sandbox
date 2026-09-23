use crate::api::OciSource;
use crate::api::{
    HOST_API_VERSION, HostInspection, HostRequest, HostResponse, ReservationView, SandboxView,
};
use sandsurf_control::{
    Guardian, GuardianClient, HostGuardianLink, HostLifecycleResult, apply_lifecycle,
    serve_guardian,
};
use sandsurf_machine::GuestArchitecture;
use sandsurf_native::local::{LocalConnection, LocalListener};
use sandsurf_protocol::*;
use sandsurf_state::{
    Approval, CatalogLimits, GrantChange, HostCatalog, ReservationState, RuntimeJournal,
    RuntimeLimits, SandboxRecord,
};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;
use zeroize::Zeroizing;

// Full-state capture/restore includes bounded memory and disk persistence plus
// native recovery probes. Transport waits must cover that operation without
// converting a still-running, identity-bound mutation into a client timeout.
const API_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_HOST_CONNECTIONS: usize = 64;

#[derive(Debug)]
pub enum HostError {
    Io(io::Error),
    EndpointUnavailable(io::Error),
    Json(serde_json::Error),
    State(sandsurf_state::Error),
    Control(sandsurf_control::Error),
    Contract(sandsurf_protocol::Invalid),
    Workspace(crate::workspace::WorkspaceError),
    Secret(crate::secrets::SecretError),
    Checkpoint(crate::checkpoints::CheckpointError),
    Image(crate::images::ImageBuildError),
    GuardianStartup(String),
    #[cfg(target_os = "linux")]
    Linux(crate::linux::LinuxError),
    #[cfg(target_os = "macos")]
    Apple(crate::apple::AppleError),
    #[cfg(target_os = "windows")]
    Windows(crate::windows::WindowsError),
    Invalid(&'static str),
}

impl fmt::Display for HostError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "host I/O: {error}"),
            Self::EndpointUnavailable(error) => {
                write!(output, "host endpoint unavailable: {error}")
            }
            Self::Json(error) => write!(output, "host message: {error}"),
            Self::State(error) => write!(output, "host catalog: {error}"),
            Self::Control(error) => write!(output, "host/guardian: {error}"),
            Self::Contract(error) => write!(output, "host contract: {error}"),
            Self::Workspace(error) => error.fmt(output),
            Self::Secret(error) => error.fmt(output),
            Self::Checkpoint(error) => error.fmt(output),
            Self::Image(error) => error.fmt(output),
            Self::GuardianStartup(message) => output.write_str(message),
            #[cfg(target_os = "linux")]
            Self::Linux(error) => error.fmt(output),
            #[cfg(target_os = "macos")]
            Self::Apple(error) => error.fmt(output),
            #[cfg(target_os = "windows")]
            Self::Windows(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for HostError {}
impl From<io::Error> for HostError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for HostError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_state::Error> for HostError {
    fn from(value: sandsurf_state::Error) -> Self {
        Self::State(value)
    }
}
impl From<sandsurf_control::Error> for HostError {
    fn from(value: sandsurf_control::Error) -> Self {
        Self::Control(value)
    }
}
impl From<sandsurf_protocol::Invalid> for HostError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}
impl From<crate::workspace::WorkspaceError> for HostError {
    fn from(value: crate::workspace::WorkspaceError) -> Self {
        Self::Workspace(value)
    }
}
impl From<crate::secrets::SecretError> for HostError {
    fn from(value: crate::secrets::SecretError) -> Self {
        Self::Secret(value)
    }
}
impl From<crate::checkpoints::CheckpointError> for HostError {
    fn from(value: crate::checkpoints::CheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}
impl From<crate::images::ImageBuildError> for HostError {
    fn from(value: crate::images::ImageBuildError) -> Self {
        Self::Image(value)
    }
}
#[cfg(target_os = "linux")]
impl From<crate::linux::LinuxError> for HostError {
    fn from(value: crate::linux::LinuxError) -> Self {
        Self::Linux(value)
    }
}
#[cfg(target_os = "macos")]
impl From<crate::apple::AppleError> for HostError {
    fn from(value: crate::apple::AppleError) -> Self {
        Self::Apple(value)
    }
}
#[cfg(target_os = "windows")]
impl From<crate::windows::WindowsError> for HostError {
    fn from(value: crate::windows::WindowsError) -> Self {
        Self::Windows(value)
    }
}

pub type Result<T> = std::result::Result<T, HostError>;

pub struct HostService {
    root: PathBuf,
    catalog: HostCatalog,
    executable: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    verified_guardians: BTreeSet<SandboxId>,
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    verified_workload_defaults: BTreeMap<String, crate::api::WorkloadDefaultsView>,
    workspace: crate::workspace::WorkspaceAuthority,
    secrets: crate::secrets::SecretAuthority,
}

impl HostService {
    pub fn open(root: &Path, executable: PathBuf) -> Result<Self> {
        prepare_directory(root)?;
        let catalog_path = root.join("catalog");
        let catalog = if catalog_path.exists() {
            HostCatalog::open(&catalog_path)?
        } else {
            let host_id = random_id("host")?
                .try_into()
                .map_err(|_| HostError::Invalid("host identity generation failed"))?;
            HostCatalog::create(&catalog_path, host_id, catalog_limits())?
        };
        prepare_directory(&root.join("api"))?;
        prepare_directory(&root.join("sandboxes"))?;
        prepare_directory(&root.join("images"))?;
        prepare_directory(&root.join("checkpoints"))?;
        prepare_directory(&root.join("transfers"))?;
        let workspace = crate::workspace::WorkspaceAuthority::open(&root.join("transfers"))?;
        let secrets = crate::secrets::SecretAuthority::open(&root.join("secrets"))?;
        let mut service = Self {
            root: root.to_path_buf(),
            catalog,
            executable,
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            verified_guardians: BTreeSet::new(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            verified_workload_defaults: BTreeMap::new(),
            workspace,
            secrets,
        };
        service.recover_guest_capture_barriers();
        service.recover_checkpoint_barriers();
        service.recover_secret_authority();
        service.recover_image_releases();
        Ok(service)
    }

    pub fn endpoint(&self) -> PathBuf {
        self.root.join("api")
    }

    pub fn handle(&mut self, request: HostRequest) -> HostResponse {
        match self.handle_inner(request) {
            Ok(response) => response,
            Err(error) => rejected(error),
        }
    }

    fn route(&mut self, request: HostRequest) -> HostDispatch {
        match self.defer_runtime_read(&request) {
            Ok(Some(read)) => HostDispatch::Runtime(Box::new(read)),
            Ok(None) => HostDispatch::Ready(Box::new(self.handle(request))),
            Err(error) => HostDispatch::Ready(Box::new(rejected(error))),
        }
    }

    fn defer_runtime_read(&mut self, request: &HostRequest) -> Result<Option<DeferredRuntimeRead>> {
        let (sandbox_id, query) = match request {
            HostRequest::ListEvents {
                sandbox_id,
                after,
                maximum,
            } => (
                sandbox_id.clone(),
                RuntimeRequest::Events {
                    after: *after,
                    maximum: *maximum,
                },
            ),
            HostRequest::GetProcess {
                sandbox_id,
                process_id,
            } => (
                sandbox_id.clone(),
                RuntimeRequest::Process {
                    process_id: process_id.clone(),
                },
            ),
            HostRequest::ListProcesses { sandbox_id } => {
                (sandbox_id.clone(), RuntimeRequest::Processes)
            }
            HostRequest::GetReceipt {
                sandbox_id,
                process_id,
            } => (
                sandbox_id.clone(),
                RuntimeRequest::Receipt {
                    process_id: process_id.clone(),
                },
            ),
            HostRequest::ReadEvidence {
                sandbox_id,
                process_id,
                after,
                maximum,
            } => (
                sandbox_id.clone(),
                RuntimeRequest::ReadOutput {
                    process_id: process_id.clone(),
                    after: *after,
                    maximum: *maximum,
                },
            ),
            HostRequest::ReadPinnedEvidence {
                sandbox_id,
                pin_id,
                after,
                maximum,
            } => (
                sandbox_id.clone(),
                RuntimeRequest::ReadPin {
                    pin_id: pin_id.clone(),
                    after: *after,
                    maximum: *maximum,
                },
            ),
            _ => return Ok(None),
        };
        self.provision_guardian(&sandbox_id)?;
        Ok(Some(DeferredRuntimeRead {
            endpoint: self.guardian_endpoint(&sandbox_id),
            sandbox_id,
            query,
        }))
    }

    fn handle_inner(&mut self, request: HostRequest) -> Result<HostResponse> {
        match request {
            HostRequest::Inspect => Ok(HostResponse::Inspection {
                value: self.inspect(),
            }),
            HostRequest::StopService => Ok(HostResponse::Complete),
            HostRequest::ListSandboxes { after, maximum } => {
                let records = self.catalog.sandboxes(after.as_ref(), maximum)?;
                let mut values = Vec::with_capacity(records.len());
                for record in records {
                    values.push(self.view(record)?);
                }
                Ok(HostResponse::Sandboxes { values })
            }
            HostRequest::GetSandbox { sandbox_id } => {
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox does not exist"))?;
                Ok(HostResponse::Sandbox {
                    value: self.view(record)?,
                })
            }
            HostRequest::GetHostOperation { operation_id } => Ok(HostResponse::HostOperation {
                value: self.catalog.operation(&operation_id)?,
            }),
            HostRequest::ListGrants {
                sandbox_id,
                after,
                maximum,
            } => Ok(HostResponse::Grants {
                values: self.catalog.grants(&sandbox_id, after.as_ref(), maximum)?,
            }),
            HostRequest::GetGrant {
                sandbox_id,
                grant_id,
            } => {
                let grant = self
                    .catalog
                    .grant(&grant_id)?
                    .ok_or(HostError::Invalid("grant does not exist"))?;
                if grant.sandbox_id != sandbox_id {
                    return Err(HostError::Invalid("grant belongs to another sandbox"));
                }
                Ok(HostResponse::Grant { grant })
            }
            HostRequest::ListImages { after, maximum } => Ok(HostResponse::Images {
                values: self.catalog.images(after.as_ref(), maximum)?,
            }),
            HostRequest::GetImage { digest } => Ok(HostResponse::Image {
                value: self
                    .catalog
                    .image(&digest)?
                    .ok_or(HostError::Invalid("image does not exist"))?,
            }),
            HostRequest::GetImageImport { operation_id } => Ok(HostResponse::ImageImport {
                operation: self
                    .catalog
                    .image_import(&operation_id)?
                    .ok_or(HostError::Invalid("image import operation does not exist"))?,
            }),
            HostRequest::ReleaseImage {
                digest: image_digest,
                operation_id,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Image,
                    &("sandsurf-release-image-v1", &operation_id, &image_digest),
                )?;
                let release = self.catalog.release_image(
                    operation_id.clone(),
                    image_digest.clone(),
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
                let operation = if release.cleanup_pending {
                    crate::images::cleanup(&self.root, &image_digest)?;
                    self.catalog
                        .complete_image_release(&operation_id, &request_digest)?
                } else {
                    release
                };
                Ok(HostResponse::ImageRelease { operation })
            }
            HostRequest::ListCheckpoints { after, maximum } => Ok(HostResponse::Checkpoints {
                values: self.catalog.checkpoints(after.as_ref(), maximum)?,
            }),
            HostRequest::GetCheckpoint { checkpoint_id } => Ok(HostResponse::Checkpoint {
                value: self
                    .catalog
                    .checkpoint(&checkpoint_id)?
                    .ok_or(HostError::Invalid("checkpoint does not exist"))?,
            }),
            HostRequest::CreateCheckpoint {
                request,
                scope_digest,
                approval_id,
            } => {
                let request_digest =
                    digest(Domain::Checkpoint, &("sandsurf-checkpoint-v1", &request))?;
                let historical = self.catalog.operation(&request.operation_id)?.is_some();
                if !historical {
                    self.catalog.active_grant(
                        &request.sandbox_id,
                        request.expected_revision,
                        Capability::Checkpoint,
                        &scope_digest,
                    )?;
                    self.provision_guardian(&request.sandbox_id)?;
                    let inspection =
                        GuardianClient::new(self.guardian_endpoint(&request.sandbox_id))
                            .inspect(request.sandbox_id.clone(), None)?;
                    let Observation::Current { value: machine } = inspection.observation else {
                        return Err(HostError::Invalid(
                            "checkpoint requires a current machine observation",
                        ));
                    };
                    if machine.epoch != request.expected_epoch
                        || machine.applied_revision != request.expected_revision
                        || machine.state != MachineState::Running
                    {
                        return Err(HostError::Invalid(
                            "checkpoint requires the expected running epoch and revision",
                        ));
                    }
                }
                let admitted = self.catalog.admit_checkpoint(
                    request.clone(),
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
                if admitted.phase == CheckpointPhase::Ready {
                    return Ok(HostResponse::Checkpoint { value: admitted });
                }
                self.provision_guardian(&request.sandbox_id)?;
                let capture_root = self.root.join("checkpoints");
                if admitted.phase == CheckpointPhase::Capturing {
                    let client = GuardianClient::new(self.guardian_endpoint(&request.sandbox_id));
                    match request.kind {
                        CheckpointKind::Filesystem => {
                            client.guest(
                                request.sandbox_id.clone(),
                                GuestServiceRequest::FinishFilesystemCapture {
                                    operation_id: request.operation_id.clone(),
                                },
                            )?;
                        }
                        CheckpointKind::Full => {
                            client.native_checkpoint(
                                request.sandbox_id.clone(),
                                NativeCheckpointRequest::FinishFull {
                                    operation_id: request.operation_id.clone(),
                                },
                            )?;
                        }
                    }
                }
                let capturing = self
                    .catalog
                    .begin_checkpoint(&request.id, &request_digest)?;
                if let Some(captured) =
                    crate::checkpoints::published_filesystem(&capture_root, &capturing)?
                {
                    return Ok(HostResponse::Checkpoint {
                        value: complete_checkpoint_capture(
                            &mut self.catalog,
                            &request.id,
                            &request_digest,
                            captured,
                        )?,
                    });
                }
                let client = GuardianClient::new(self.guardian_endpoint(&request.sandbox_id));
                let sandbox_root = self.sandbox_root(&request.sandbox_id);
                let (captured, finished) = match request.kind {
                    CheckpointKind::Filesystem => {
                        let prepared = client.guest(
                            request.sandbox_id.clone(),
                            GuestServiceRequest::PrepareFilesystemCapture {
                                operation_id: request.operation_id.clone(),
                            },
                        )?;
                        if !matches!(
                            prepared,
                            GuestServiceResponse::FilesystemCapturePrepared { .. }
                        ) {
                            return Err(HostError::Invalid(
                                "guest did not establish a filesystem capture boundary",
                            ));
                        }
                        let captured = crate::checkpoints::capture_filesystem(
                            &capture_root,
                            &capturing,
                            &sandbox_root.join("disks").join(workload_disk_name()),
                        );
                        let finished = client
                            .guest(
                                request.sandbox_id.clone(),
                                GuestServiceRequest::FinishFilesystemCapture {
                                    operation_id: request.operation_id.clone(),
                                },
                            )
                            .map(|response| {
                                matches!(
                                    response,
                                    GuestServiceResponse::FilesystemCaptureFinished { .. }
                                )
                            });
                        (captured, finished)
                    }
                    CheckpointKind::Full => {
                        let prepared = client.native_checkpoint(
                            request.sandbox_id.clone(),
                            NativeCheckpointRequest::PrepareFull {
                                checkpoint_id: request.id.clone(),
                                operation_id: request.operation_id.clone(),
                            },
                        )?;
                        let NativeCheckpointResponse::Prepared { capture, processes } = prepared
                        else {
                            return Err(HostError::Invalid(
                                "guardian did not establish a full capture boundary",
                            ));
                        };
                        let captured = crate::checkpoints::capture_full(
                            &capture_root,
                            &capturing,
                            &sandbox_root.join("disks").join(workload_disk_name()),
                            &sandbox_root.join("disks").join(control_disk_name()),
                            &sandbox_root
                                .join("guardian/full-captures")
                                .join(request.operation_id.as_str()),
                            capture,
                            processes,
                        );
                        let finished = client
                            .native_checkpoint(
                                request.sandbox_id.clone(),
                                NativeCheckpointRequest::FinishFull {
                                    operation_id: request.operation_id.clone(),
                                },
                            )
                            .map(|response| {
                                matches!(response, NativeCheckpointResponse::Complete { .. })
                            });
                        (captured, finished)
                    }
                };
                let captured = captured?;
                if !finished? {
                    return Err(HostError::Invalid(
                        "guardian did not release the checkpoint capture boundary",
                    ));
                }
                Ok(HostResponse::Checkpoint {
                    value: complete_checkpoint_capture(
                        &mut self.catalog,
                        &request.id,
                        &request_digest,
                        captured,
                    )?,
                })
            }
            HostRequest::ImportOci {
                source,
                platform,
                operation_id,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Image,
                    &("sandsurf-import-oci-v1", &source, &platform, &operation_id),
                )?;
                let admitted = self.catalog.admit_image_import(
                    operation_id.clone(),
                    request_digest.clone(),
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
                if admitted.phase == sandsurf_state::ImageImportPhase::Published {
                    return Ok(HostResponse::ImageImport {
                        operation: admitted,
                    });
                }
                let registry_credential = match &source {
                    OciSource::Registry {
                        credential: Some(secret),
                        ..
                    } => {
                        let bytes = self.secrets.read(&secret.id, &secret.version)?;
                        if Counter::try_from(bytes.len() as u64)? != secret.bytes {
                            return Err(HostError::Invalid(
                                "registry credential length differs from its approved version",
                            ));
                        }
                        Some(Zeroizing::new(bytes))
                    }
                    _ => None,
                };
                let image = crate::images::import_oci(
                    &self.root,
                    &self.executable,
                    &source,
                    &platform,
                    &operation_id,
                    &request_digest,
                    registry_credential.as_ref().map(|value| value.as_slice()),
                )?;
                Ok(HostResponse::ImageImport {
                    operation: self.catalog.complete_image_import(
                        &operation_id,
                        &request_digest,
                        image,
                    )?,
                })
            }
            HostRequest::PublishCheckpointImage {
                checkpoint_id,
                inclusion,
                operation_id,
                approval_id,
            } => {
                let checkpoint = self
                    .catalog
                    .checkpoint(&checkpoint_id)?
                    .ok_or(HostError::Invalid("image checkpoint does not exist"))?;
                let request_digest = digest(
                    Domain::Image,
                    &(
                        "sandsurf-publish-checkpoint-image-v1",
                        &checkpoint_id,
                        inclusion,
                        &operation_id,
                    ),
                )?;
                let admitted = self.catalog.admit_image_import(
                    operation_id.clone(),
                    request_digest.clone(),
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
                if admitted.phase == sandsurf_state::ImageImportPhase::Published {
                    return Ok(HostResponse::ImageImport {
                        operation: admitted,
                    });
                }
                let image = crate::images::publish_checkpoint(
                    &self.root,
                    &checkpoint,
                    inclusion,
                    &operation_id,
                    &request_digest,
                )?;
                Ok(HostResponse::ImageImport {
                    operation: self.catalog.complete_image_import(
                        &operation_id,
                        &request_digest,
                        image,
                    )?,
                })
            }
            HostRequest::CaptureHostTree {
                sandbox_id,
                operation_id,
                expected_revision,
                scope_digest,
                source,
                exclusions,
                maximum_bytes,
                approval_id,
            } => {
                self.require_active_grant_for_new_host_operation(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    Capability::WriteFiles,
                    &scope_digest,
                )?;
                let request_digest = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-host-tree-capture-admission-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &scope_digest,
                        &source,
                        &exclusions,
                        maximum_bytes,
                    ),
                )?;
                let operation = self.catalog.admit_transfer_operation(
                    operation_id.clone(),
                    sandbox_id.clone(),
                    request_digest.clone(),
                )?;
                let capture = self.workspace.capture(
                    sandbox_id,
                    operation_id.clone(),
                    &source,
                    &exclusions,
                    maximum_bytes,
                    approval_id,
                )?;
                if !operation.applied {
                    self.catalog
                        .complete_transfer_operation(&operation_id, &request_digest)?;
                }
                Ok(HostResponse::HostTreeCapture { capture })
            }
            HostRequest::CaptureGuestTree {
                sandbox_id,
                operation_id,
                expected_epoch,
                expected_revision,
                scope_digest,
                maximum_bytes,
            } => {
                let request_digest = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-guest-tree-capture-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_epoch,
                        expected_revision,
                        &scope_digest,
                        maximum_bytes,
                    ),
                )?;
                if self.catalog.operation(&operation_id)?.is_none() {
                    self.catalog.active_grant(
                        &sandbox_id,
                        expected_revision,
                        Capability::ReadFiles,
                        &scope_digest,
                    )?;
                }
                let admitted = self.catalog.admit_transfer_operation(
                    operation_id.clone(),
                    sandbox_id.clone(),
                    request_digest.clone(),
                )?;
                if let Some(capture) = self.workspace.existing_guest_capture(
                    &sandbox_id,
                    &operation_id,
                    &request_digest,
                )? {
                    if self.workspace.guest_capture_pending(&operation_id)? {
                        self.recover_guest_capture_barriers();
                        if self.workspace.guest_capture_pending(&operation_id)? {
                            return Err(HostError::Invalid(
                                "published guest tree still has an unresolved freeze barrier",
                            ));
                        }
                    }
                    if !admitted.applied {
                        self.catalog
                            .complete_transfer_operation(&operation_id, &request_digest)?;
                    }
                    return Ok(HostResponse::HostTreeCapture { capture });
                }
                if admitted.applied {
                    return Err(HostError::Invalid(
                        "completed guest capture has no published tree",
                    ));
                }
                let sandbox = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("guest capture sandbox is missing"))?;
                if maximum_bytes > sandbox.resources.disk_bytes {
                    return Err(HostError::Invalid(
                        "guest capture bound exceeds the sandbox disk budget",
                    ));
                }
                self.provision_guardian(&sandbox_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&sandbox_id));
                let inspection = client.inspect(sandbox_id.clone(), None)?;
                let Observation::Current { value: machine } = inspection.observation else {
                    return Err(HostError::Invalid(
                        "guest capture requires a current machine observation",
                    ));
                };
                if machine.epoch != expected_epoch
                    || machine.applied_revision != expected_revision
                    || machine.state != MachineState::Running
                {
                    return Err(HostError::Invalid(
                        "guest capture requires the expected running epoch and revision",
                    ));
                }
                self.workspace
                    .begin_guest_capture(&crate::workspace::PendingGuestCapture {
                        sandbox_id: sandbox_id.clone(),
                        operation_id: operation_id.clone(),
                        epoch: expected_epoch,
                    })?;
                let result = (|| {
                    if !matches!(
                        client.guest(
                            sandbox_id.clone(),
                            GuestServiceRequest::PrepareGuestTreeCapture {
                                operation_id: operation_id.clone(),
                            },
                        )?,
                        GuestServiceResponse::FilesystemCapturePrepared { .. }
                    ) {
                        return Err(HostError::Invalid(
                            "guest did not establish the filesystem capture barrier",
                        ));
                    }
                    self.workspace
                        .capture_guest(
                            sandbox_id.clone(),
                            operation_id.clone(),
                            request_digest.clone(),
                            maximum_bytes,
                            |request| match client.guest(
                                sandbox_id.clone(),
                                GuestServiceRequest::CaptureFilesystemQuery {
                                    operation_id: operation_id.clone(),
                                    request,
                                },
                            ) {
                                Ok(GuestServiceResponse::File { response }) => Ok(response),
                                Ok(GuestServiceResponse::Error { code, message }) => {
                                    Err(crate::workspace::WorkspaceError::Guest(format!(
                                        "{code}: {message}"
                                    )))
                                }
                                Ok(_) => Err(crate::workspace::WorkspaceError::Invalid(
                                    "guest capture query returned the wrong response",
                                )),
                                Err(error) => {
                                    Err(crate::workspace::WorkspaceError::Guest(error.to_string()))
                                }
                            },
                            |path, offset, maximum| match client.guest(
                                sandbox_id.clone(),
                                GuestServiceRequest::CaptureFilesystemRead {
                                    operation_id: operation_id.clone(),
                                    path,
                                    offset,
                                    maximum,
                                },
                            ) {
                                Ok(GuestServiceResponse::FilesystemCaptureRead { range }) => {
                                    Ok(range)
                                }
                                Ok(GuestServiceResponse::Error { code, message }) => {
                                    Err(crate::workspace::WorkspaceError::Guest(format!(
                                        "{code}: {message}"
                                    )))
                                }
                                Ok(_) => Err(crate::workspace::WorkspaceError::Invalid(
                                    "guest capture read returned the wrong response",
                                )),
                                Err(error) => {
                                    Err(crate::workspace::WorkspaceError::Guest(error.to_string()))
                                }
                            },
                        )
                        .map_err(HostError::from)
                })();
                let finish = client.guest(
                    sandbox_id.clone(),
                    GuestServiceRequest::FinishGuestTreeCapture {
                        operation_id: operation_id.clone(),
                    },
                )?;
                if !matches!(
                    finish,
                    GuestServiceResponse::FilesystemCaptureFinished { .. }
                ) {
                    return Err(HostError::Invalid(
                        "guest did not release the filesystem capture barrier",
                    ));
                }
                self.workspace.finish_guest_capture(&operation_id)?;
                let capture = result?;
                self.catalog
                    .complete_transfer_operation(&operation_id, &request_digest)?;
                Ok(HostResponse::HostTreeCapture { capture })
            }
            HostRequest::ListHostTree {
                sandbox_id,
                operation_id,
                after,
                maximum,
            } => {
                let (capture, entries, next) =
                    self.workspace
                        .capture_entries(&sandbox_id, &operation_id, after, maximum)?;
                Ok(HostResponse::HostTreeEntries {
                    capture,
                    entries,
                    next,
                })
            }
            HostRequest::ReadHostTreeBlob {
                sandbox_id,
                operation_id,
                digest,
                offset,
                maximum,
            } => {
                let (bytes, eof) = self.workspace.read_capture_blob(
                    &sandbox_id,
                    &operation_id,
                    &digest,
                    offset,
                    maximum,
                )?;
                Ok(HostResponse::HostBlob {
                    offset,
                    bytes,
                    eof,
                    digest,
                })
            }
            HostRequest::BeginHostBlob {
                sandbox_id,
                operation_id,
                expected_revision,
                scope_digest,
                transfer,
                approval_id,
            } => {
                self.require_active_grant_for_new_host_operation(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                let request_digest = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-host-blob-begin-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &scope_digest,
                        &transfer,
                    ),
                )?;
                let operation = self.catalog.admit_transfer_operation(
                    operation_id.clone(),
                    sandbox_id.clone(),
                    request_digest.clone(),
                )?;
                if !operation.applied {
                    self.workspace
                        .begin_upload(sandbox_id, transfer, approval_id)?;
                    self.catalog
                        .complete_transfer_operation(&operation_id, &request_digest)?;
                }
                Ok(HostResponse::Complete)
            }
            HostRequest::WriteHostBlob {
                sandbox_id,
                operation_id,
                expected_revision,
                scope_digest,
                transfer,
                offset,
                bytes,
            } => {
                self.require_active_grant_for_new_host_operation(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                let request_digest = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-host-blob-chunk-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &scope_digest,
                        &transfer,
                        offset,
                        bytes_digest(&bytes),
                        bytes.len(),
                    ),
                )?;
                let operation = self.catalog.admit_transfer_operation(
                    operation_id.clone(),
                    sandbox_id.clone(),
                    request_digest.clone(),
                )?;
                if !operation.applied {
                    self.workspace
                        .write_upload(&sandbox_id, &transfer, offset, &bytes)?;
                    self.catalog
                        .complete_transfer_operation(&operation_id, &request_digest)?;
                }
                Ok(HostResponse::Complete)
            }
            HostRequest::CommitHostBlob {
                sandbox_id,
                operation_id,
                expected_revision,
                scope_digest,
                transfer,
            } => {
                self.require_active_grant_for_new_host_operation(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                let request_digest = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-host-blob-commit-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &scope_digest,
                        &transfer,
                    ),
                )?;
                let operation = self.catalog.admit_transfer_operation(
                    operation_id.clone(),
                    sandbox_id.clone(),
                    request_digest.clone(),
                )?;
                if !operation.applied {
                    self.workspace.commit_upload(&sandbox_id, &transfer)?;
                    self.catalog
                        .complete_transfer_operation(&operation_id, &request_digest)?;
                }
                Ok(HostResponse::Complete)
            }
            HostRequest::ApplyHostWorkspace {
                sandbox_id,
                operation_id,
                expected_revision,
                scope_digest,
                destination,
                change_set,
                approval_id,
            } => {
                self.require_active_grant_for_new_host_operation(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                let request_digest = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-host-apply-admission-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &scope_digest,
                        &destination,
                        &change_set,
                    ),
                )?;
                let operation = self.catalog.admit_transfer_operation(
                    operation_id.clone(),
                    sandbox_id.clone(),
                    request_digest.clone(),
                )?;
                let report = self.workspace.apply(
                    sandbox_id,
                    operation_id.clone(),
                    &destination,
                    change_set,
                    approval_id,
                )?;
                if !operation.applied {
                    self.catalog
                        .complete_transfer_operation(&operation_id, &request_digest)?;
                }
                Ok(HostResponse::HostApply { report })
            }
            HostRequest::CreateSandbox {
                sandbox_id,
                image_digest,
                resources,
                workload_configuration,
                lifetime,
                operation_id,
                approval_id,
            } => {
                #[cfg(target_os = "linux")]
                let native_config = crate::linux::prepare_config(
                    &self.root,
                    &self.executable,
                    &sandbox_id,
                    &image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "macos")]
                let native_config = crate::apple::prepare_config(
                    &self.root,
                    &self.executable,
                    &sandbox_id,
                    &image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "windows")]
                let native_config = crate::windows::prepare_config(
                    &self.root,
                    &self.executable,
                    &sandbox_id,
                    &image_digest,
                    &resources,
                )?;
                let approval = Approval {
                    id: approval_id,
                    request_digest: digest(
                        Domain::Sandbox,
                        &(
                            &sandbox_id,
                            &image_digest,
                            &resources,
                            &workload_configuration,
                            &lifetime,
                            &operation_id,
                        ),
                    )?,
                };
                self.catalog.create_sandbox(
                    sandsurf_state::SandboxAdmission {
                        id: sandbox_id.clone(),
                        image: image_digest,
                        resources,
                        workload: workload_configuration,
                        lifetime,
                        operation: operation_id.clone(),
                    },
                    approval,
                )?;
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                self.provision_guardian_with_config(&sandbox_id, Some(&native_config))?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &operation_id)?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid(
                        "created sandbox disappeared from catalog",
                    ))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::ForkSandbox {
                sandbox_id,
                checkpoint_id,
                resources,
                lifetime,
                operation_id,
                approval_id,
            } => {
                let checkpoint = self
                    .catalog
                    .checkpoint(&checkpoint_id)?
                    .ok_or(HostError::Invalid("fork checkpoint does not exist"))?;
                if checkpoint.phase != CheckpointPhase::Ready {
                    return Err(HostError::Invalid("fork checkpoint is not ready"));
                }
                #[cfg(target_os = "linux")]
                let native_config = crate::linux::prepare_config(
                    &self.root,
                    &self.executable,
                    &sandbox_id,
                    &checkpoint.image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "macos")]
                let native_config = crate::apple::prepare_config(
                    &self.root,
                    &self.executable,
                    &sandbox_id,
                    &checkpoint.image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "windows")]
                let native_config = crate::windows::prepare_config(
                    &self.root,
                    &self.executable,
                    &sandbox_id,
                    &checkpoint.image_digest,
                    &resources,
                )?;
                let request_digest = digest(
                    Domain::Checkpoint,
                    &(
                        "sandsurf-filesystem-fork-v1",
                        &checkpoint_id,
                        &sandbox_id,
                        &resources,
                        &lifetime,
                        &operation_id,
                    ),
                )?;
                let previously_admitted = self.catalog.operation(&operation_id)?.is_some();
                let intent = self.catalog.create_sandbox_from_checkpoint(
                    sandbox_id.clone(),
                    &checkpoint_id,
                    resources,
                    lifetime,
                    operation_id.clone(),
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                let sandbox_root = self.sandbox_root(&sandbox_id);
                prepare_directory(&sandbox_root)?;
                let disks = sandbox_root.join("disks");
                prepare_directory(&disks)?;
                let workload_disk = disks.join(workload_disk_name());
                // The guardian creates a blank mutable disk when none exists.
                // A new fork must install its captured disk before the guardian
                // is allowed to open that VM. An interrupted pre-launch copy is
                // verified and resumed by the same exact checkpoint identity.
                let materialized_before_owner = !workload_disk.exists();
                if materialized_before_owner {
                    crate::checkpoints::materialize_fork(
                        &self.root.join("checkpoints"),
                        &checkpoint,
                        &workload_disk,
                    )?;
                }
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                self.provision_guardian_with_config(&sandbox_id, Some(&native_config))?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let mut lifecycle = if previously_admitted {
                    Some(apply_lifecycle(
                        &mut self.catalog,
                        endpoint.clone(),
                        &operation_id,
                    )?)
                } else {
                    None
                };
                // Never overwrite a fork disk while an earlier launch has an
                // ambiguous outcome. A completed retry returns its immutable
                // history; only a fresh operation or positive NotApplied
                // evidence permits materialization.
                if lifecycle.as_ref().is_none_or(|value| {
                    value.completed_intent.is_none()
                        && value.guardian_operation.delivery == Delivery::NotApplied
                }) {
                    if !materialized_before_owner {
                        crate::checkpoints::materialize_fork(
                            &self.root.join("checkpoints"),
                            &checkpoint,
                            &workload_disk,
                        )?;
                    }
                    lifecycle = Some(apply_lifecycle(
                        &mut self.catalog,
                        endpoint,
                        &intent.operation_id,
                    )?);
                }
                let lifecycle = lifecycle.ok_or(HostError::Invalid(
                    "fork lifecycle recovery produced no operation",
                ))?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("forked sandbox disappeared"))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::RollbackFilesystem {
                sandbox_id,
                checkpoint_id,
                operation_id,
                expected_revision,
                scope_digest,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Checkpoint,
                    &(
                        "sandsurf-filesystem-rollback-v1",
                        &sandbox_id,
                        &checkpoint_id,
                        &operation_id,
                        expected_revision,
                    ),
                )?;
                if self.catalog.operation(&operation_id)?.is_none() {
                    self.catalog.active_grant(
                        &sandbox_id,
                        expected_revision,
                        Capability::Checkpoint,
                        &scope_digest,
                    )?;
                }
                let admitted = self.catalog.admit_rollback(
                    &sandbox_id,
                    &checkpoint_id,
                    operation_id.clone(),
                    expected_revision,
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
                if admitted.phase == RollbackPhase::Applied {
                    return Ok(HostResponse::Rollback { value: admitted });
                }
                self.provision_guardian(&sandbox_id)?;
                let inspection = GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                    .inspect(sandbox_id.clone(), None)?;
                if !matches!(
                    inspection.observation,
                    Observation::Current {
                        value: MachineObservation {
                            state: MachineState::Stopped,
                            ..
                        }
                    }
                ) {
                    return Err(HostError::Invalid(
                        "filesystem rollback requires a confirmed stopped machine",
                    ));
                }
                let checkpoint = self
                    .catalog
                    .checkpoint(&checkpoint_id)?
                    .ok_or(HostError::Invalid("rollback checkpoint disappeared"))?;
                let evidence = crate::checkpoints::rollback(
                    &self.root.join("checkpoints"),
                    &checkpoint,
                    &self
                        .sandbox_root(&sandbox_id)
                        .join("disks")
                        .join(workload_disk_name()),
                    &operation_id,
                )?;
                Ok(HostResponse::Rollback {
                    value: self.catalog.complete_rollback(
                        &operation_id,
                        &request_digest,
                        evidence,
                    )?,
                })
            }
            HostRequest::Lifecycle {
                sandbox_id,
                operation_id,
                expected_revision,
                desired,
                approval_id,
            } => {
                self.require_lifecycle_precondition(&sandbox_id, &operation_id, expected_revision)?;
                let approval = Approval {
                    id: approval_id,
                    request_digest: digest(
                        Domain::Operation,
                        &(&sandbox_id, &operation_id, expected_revision, desired),
                    )?,
                };
                let intent = self.catalog.request_lifecycle(
                    &sandbox_id,
                    operation_id.clone(),
                    expected_revision,
                    desired,
                    approval,
                )?;
                self.provision_guardian(&sandbox_id)?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let lifecycle = self.apply_lifecycle_intent(&intent, endpoint)?;
                if desired == DesiredState::Running && lifecycle.completed_intent.is_some() {
                    self.catalog.observe_activity(&sandbox_id, unix_millis()?)?;
                    self.reconcile_secret_authority(&sandbox_id)?;
                }
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox disappeared from catalog"))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::SetGrant {
                sandbox_id,
                operation_id,
                grant_id,
                expected_revision,
                capability,
                scope_digest,
                revoked,
                approval_id,
            } => {
                self.require_configuration_precondition(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                )?;
                let request_digest = digest(
                    Domain::Grant,
                    &(
                        "sandsurf-grant-change-v1",
                        &sandbox_id,
                        &operation_id,
                        &grant_id,
                        expected_revision,
                        capability,
                        &scope_digest,
                        revoked,
                    ),
                )?;
                let grant = self.catalog.set_grant(
                    GrantChange {
                        sandbox_id: sandbox_id.clone(),
                        operation_id,
                        id: grant_id,
                        expected_revision,
                        capability,
                        scope_digest,
                        revoked,
                    },
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration_if_current(&sandbox_id, grant.revision)?;
                Ok(HostResponse::Grant { grant })
            }
            HostRequest::SetNetworkPolicy {
                sandbox_id,
                operation_id,
                expected_revision,
                policy,
                approval_id,
            } => {
                policy.validate()?;
                self.require_configuration_precondition(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                )?;
                let request_digest = digest(
                    Domain::Network,
                    &(
                        "sandsurf-network-policy-change-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &policy,
                    ),
                )?;
                let mut configuration = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox does not exist"))?
                    .runtime_configuration;
                configuration.network = policy;
                let operation = self.catalog.set_runtime_configuration(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    configuration,
                    request_digest.clone(),
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration_if_current(&sandbox_id, operation.revision)?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox disappeared from catalog"))?;
                Ok(HostResponse::Configuration {
                    revision: operation.revision,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::SetExposure {
                sandbox_id,
                operation_id,
                expected_revision,
                exposure_id,
                mut spec,
                active,
                approval_id,
            } => {
                self.require_configuration_precondition(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                )?;
                let requested_spec = spec.clone();
                let request_digest = digest(
                    Domain::Exposure,
                    &(
                        "sandsurf-port-exposure-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &exposure_id,
                        &requested_spec,
                        active,
                    ),
                )?;
                if active && spec.host_port == 0 {
                    spec.host_port = reserve_ephemeral_port(&spec.host_address)?;
                }
                spec.validate()?;
                let mut configuration = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox does not exist"))?
                    .runtime_configuration;
                let existing = configuration
                    .exposures
                    .iter()
                    .position(|value| value.id == exposure_id);
                let grant_id: GrantId = format!("exposure-{}", exposure_id.as_str())
                    .try_into()
                    .map_err(HostError::Contract)?;
                let bound_port = active.then_some(spec.host_port);
                let exposure = Exposure {
                    id: exposure_id,
                    sandbox_id: sandbox_id.clone(),
                    grant_id,
                    revision: expected_revision.next()?,
                    spec,
                    active,
                    bound_port,
                };
                match existing {
                    Some(index) => configuration.exposures[index] = exposure.clone(),
                    None if active => configuration.exposures.push(exposure.clone()),
                    None => {
                        return Err(HostError::Invalid("cannot revoke a missing port exposure"));
                    }
                }
                configuration
                    .exposures
                    .sort_by(|left, right| left.id.cmp(&right.id));
                let operation = self.catalog.set_runtime_configuration(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    configuration,
                    request_digest.clone(),
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration_if_current(&sandbox_id, operation.revision)?;
                let exposure = operation
                    .configuration
                    .exposures
                    .iter()
                    .find(|value| value.id == exposure.id)
                    .cloned()
                    .ok_or(HostError::Invalid(
                        "committed exposure is missing from its configuration",
                    ))?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox disappeared from catalog"))?;
                Ok(HostResponse::Exposure {
                    exposure,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::PutSecret {
                secret_id,
                bytes,
                operation_id,
                approval_id,
            } => {
                let version = bytes_digest(&bytes);
                let secret = SecretVersion {
                    id: secret_id.clone(),
                    version: version.clone(),
                    bytes: counter(bytes.len() as u64),
                };
                let request_digest = digest(
                    Domain::Secret,
                    &(
                        "sandsurf-put-secret-v1",
                        &secret_id,
                        &version,
                        bytes.len(),
                        &operation_id,
                    ),
                )?;
                let operation = self.catalog.admit_secret_put(
                    operation_id.clone(),
                    request_digest.clone(),
                    secret.clone(),
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
                if !operation.applied {
                    let stored = self.secrets.put(secret_id, &bytes)?;
                    self.catalog
                        .complete_secret_put(&operation_id, &request_digest, &stored)?;
                }
                Ok(HostResponse::Secret { secret })
            }
            HostRequest::DeliverSecret {
                sandbox_id,
                operation_id,
                expected_revision,
                scope_digest,
                delivery,
                approval_id,
            } => {
                delivery.validate()?;
                let (record, request_digest) = match self.catalog.operation(&operation_id)? {
                    Some(sandsurf_state::HostOperationRecord::SecretDelivery(record)) => {
                        let grants =
                            self.catalog
                                .grants(&sandbox_id, None, Counter::try_from(256)?)?;
                        let exact = record.sandbox_id == sandbox_id
                            && record.delivery == delivery
                            && grants.iter().any(|grant| {
                                grant.sandbox_id == sandbox_id
                                    && grant.capability == Capability::DeliverSecret
                                    && grant.scope_digest == scope_digest
                                    && digest(
                                        Domain::Secret,
                                        &(
                                            "sandsurf-deliver-secret-v1",
                                            &sandbox_id,
                                            &operation_id,
                                            expected_revision,
                                            &grant.id,
                                            &scope_digest,
                                            &delivery,
                                        ),
                                    )
                                    .is_ok_and(|value| value == record.request_digest)
                            });
                        if !exact {
                            return Err(sandsurf_state::Error::Conflict(
                                "secret delivery operation identity conflict",
                            )
                            .into());
                        }
                        let request_digest = record.request_digest.clone();
                        (record, request_digest)
                    }
                    Some(_) => {
                        return Err(sandsurf_state::Error::Conflict(
                            "secret delivery operation identity belongs to another operation",
                        )
                        .into());
                    }
                    None => {
                        let grant = self.catalog.active_grant(
                            &sandbox_id,
                            expected_revision,
                            Capability::DeliverSecret,
                            &scope_digest,
                        )?;
                        let request_digest = digest(
                            Domain::Secret,
                            &(
                                "sandsurf-deliver-secret-v1",
                                &sandbox_id,
                                &operation_id,
                                expected_revision,
                                &grant.id,
                                &scope_digest,
                                &delivery,
                            ),
                        )?;
                        let record = self.catalog.admit_secret_delivery(
                            sandsurf_state::SecretDeliveryRecord {
                                operation_id: operation_id.clone(),
                                sandbox_id: sandbox_id.clone(),
                                request_digest: request_digest.clone(),
                                delivery: delivery.clone(),
                                applied: false,
                                revocation_operation: None,
                                revoked: false,
                            },
                            Approval {
                                id: approval_id,
                                request_digest: request_digest.clone(),
                            },
                        )?;
                        (record, request_digest)
                    }
                };
                if !record.applied {
                    let bytes = self
                        .secrets
                        .read(&delivery.secret.id, &delivery.secret.version)?;
                    self.provision_guardian(&sandbox_id)?;
                    let response = GuardianClient::new(self.guardian_endpoint(&sandbox_id)).guest(
                        sandbox_id.clone(),
                        GuestServiceRequest::InstallSecret {
                            operation_id: operation_id.clone(),
                            delivery: delivery.clone(),
                            bytes,
                        },
                    )?;
                    if !matches!(response, GuestServiceResponse::SecretInstalled { .. }) {
                        return Err(HostError::Invalid(
                            "guest did not establish secret delivery",
                        ));
                    }
                    self.catalog
                        .complete_secret_delivery(&operation_id, &request_digest)?;
                }
                Ok(HostResponse::Secret {
                    secret: delivery.secret,
                })
            }
            HostRequest::RevokeSecret {
                sandbox_id,
                operation_id,
                expected_revision,
                secret,
                terminate_recipients,
                approval_id,
            } => {
                if secret.bytes == Counter::ZERO || secret.bytes.get() > 1024 * 1024 {
                    return Err(HostError::Invalid("secret version size is invalid"));
                }
                let request_digest = digest(
                    Domain::Secret,
                    &(
                        "sandsurf-revoke-secret-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &secret,
                        terminate_recipients,
                    ),
                )?;
                let record = self.catalog.admit_secret_revocation(
                    sandsurf_state::SecretRevocationAdmission {
                        sandbox_id,
                        operation_id,
                        expected_revision,
                        secret,
                        terminate_recipients,
                        request_digest: request_digest.clone(),
                    },
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                Ok(HostResponse::SecretRevocation {
                    revocation: self.enforce_secret_revocation(record)?,
                })
            }
            HostRequest::UpdateResources {
                sandbox_id,
                operation_id,
                expected_revision,
                resources,
                live,
                approval_id,
            } => {
                self.require_configuration_precondition(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                )?;
                let request_digest = digest(
                    Domain::Grant,
                    &(
                        "sandsurf-live-resources-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &resources,
                        &live,
                    ),
                )?;
                let operation = self.catalog.update_live_resources(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    resources,
                    live,
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration_if_current(&sandbox_id, operation.revision)?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox disappeared from catalog"))?;
                Ok(HostResponse::Configuration {
                    revision: operation.revision,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::GetUsage { sandbox_id } => {
                self.provision_guardian(&sandbox_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&sandbox_id));
                let inspection = client.inspect(sandbox_id.clone(), None)?;
                let Observation::Current { value: machine } = inspection.observation else {
                    return Err(HostError::Invalid(
                        "resource usage requires a current machine observation",
                    ));
                };
                let response =
                    client.guest(sandbox_id.clone(), GuestServiceRequest::ResourceUsage)?;
                let GuestServiceResponse::ResourceUsage { mut usage } = response else {
                    return Err(HostError::Invalid(
                        "guest resource accounting is unavailable",
                    ));
                };
                let (logical, allocated) = directory_usage(&self.sandbox_root(&sandbox_id))?;
                usage.disk_logical_bytes = logical;
                usage.disk_allocated_bytes = allocated;
                Ok(HostResponse::Usage {
                    usage: self
                        .catalog
                        .observe_usage(&sandbox_id, machine.epoch, usage)?,
                })
            }
            HostRequest::Workload {
                sandbox_id,
                epoch,
                operation_id,
                expected_revision,
                request,
                scope_digest,
            } => {
                let capability = request.required_capability();
                if self.catalog.operation(&operation_id)?.is_some() {
                    return Err(sandsurf_state::Error::Conflict(
                        "operation identity already belongs to a host operation",
                    )
                    .into());
                }
                self.provision_guardian(&sandbox_id)?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let prior = GuardianClient::new(endpoint.clone())
                    .inspect(sandbox_id.clone(), Some(operation_id.clone()))?
                    .operation;
                if let Some(operation) = prior {
                    let grant = self.catalog.grant(&operation.request.grant_id)?.ok_or(
                        HostError::Invalid("workload operation references a missing host grant"),
                    )?;
                    let retry = Mutation::new(
                        sandbox_id.clone(),
                        epoch,
                        operation_id,
                        operation.request.grant_id.clone(),
                        expected_revision,
                        request,
                    )?;
                    let operation = validate_workload_retry(
                        operation,
                        &grant,
                        retry,
                        capability,
                        &scope_digest,
                    )?;
                    self.catalog.observe_activity(&sandbox_id, unix_millis()?)?;
                    return Ok(HostResponse::Dispatch { operation });
                }
                let grant = self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    capability,
                    &scope_digest,
                )?;
                self.catalog.observe_activity(&sandbox_id, unix_millis()?)?;
                let mutation = Mutation::new(
                    sandbox_id.clone(),
                    epoch,
                    operation_id,
                    grant.id,
                    expected_revision,
                    request,
                )?;
                let link = HostGuardianLink::new(&self.catalog, endpoint);
                Ok(HostResponse::Dispatch {
                    operation: link.dispatch(mutation, capability, &scope_digest)?,
                })
            }
            HostRequest::Guest {
                sandbox_id,
                expected_revision,
                capability,
                scope_digest,
                request,
            } => {
                if matches!(
                    request,
                    GuestServiceRequest::Dispatch { .. }
                        | GuestServiceRequest::PrepareStop
                        | GuestServiceRequest::PrepareFilesystemCapture { .. }
                        | GuestServiceRequest::FinishFilesystemCapture { .. }
                        | GuestServiceRequest::PrepareGuestTreeCapture { .. }
                        | GuestServiceRequest::FinishGuestTreeCapture { .. }
                        | GuestServiceRequest::CaptureFilesystemQuery { .. }
                        | GuestServiceRequest::CaptureFilesystemRead { .. }
                        | GuestServiceRequest::RebindEpoch { .. }
                        | GuestServiceRequest::ProbeIdentity
                        | GuestServiceRequest::InstallSecret { .. }
                        | GuestServiceRequest::RevokeSecret { .. }
                        | GuestServiceRequest::ApplyResources { .. }
                        | GuestServiceRequest::ResourceUsage
                ) {
                    return Err(HostError::Invalid(
                        "internal guest control requests cannot use the application route",
                    ));
                }
                if let GuestServiceRequest::FilesystemQuery { request } = &request
                    && (!request.is_query() || request.required_capability() != capability)
                {
                    return Err(HostError::Invalid(
                        "filesystem query does not match its capability",
                    ));
                }
                // A digest-bound operation query reads an already admitted
                // guest result. It must remain available after revision
                // changes or grant revocation and cannot admit a new effect.
                if !matches!(request, GuestServiceRequest::Operation { .. }) {
                    self.catalog.active_grant(
                        &sandbox_id,
                        expected_revision,
                        capability,
                        &scope_digest,
                    )?;
                    self.catalog.observe_activity(&sandbox_id, unix_millis()?)?;
                }
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Guest {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                        .guest(sandbox_id, request)?,
                })
            }
            HostRequest::GetOperation {
                sandbox_id,
                operation_id,
            } => {
                if let Some(value) = self.catalog.operation(&operation_id)? {
                    if value.sandbox_id() != Some(&sandbox_id) {
                        return Err(HostError::Invalid(
                            "host operation belongs to another authority scope",
                        ));
                    }
                    return Ok(HostResponse::HostOperation { value: Some(value) });
                }
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                        .runtime(sandbox_id, RuntimeRequest::Operation { operation_id })?,
                })
            }
            request @ (HostRequest::ListEvents { .. }
            | HostRequest::GetProcess { .. }
            | HostRequest::ListProcesses { .. }
            | HostRequest::GetReceipt { .. }
            | HostRequest::ReadEvidence { .. }
            | HostRequest::ReadPinnedEvidence { .. }) => self
                .defer_runtime_read(&request)?
                .ok_or(HostError::Invalid("runtime read route is unavailable"))?
                .execute(),
            HostRequest::AcknowledgeReceipt {
                sandbox_id,
                operation_id,
                process_id,
                receipt_digest,
                expected_revision,
                scope_digest,
            } => {
                self.provision_guardian(&sandbox_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&sandbox_id));
                let prior = runtime_operation(&client, &sandbox_id, &operation_id)?;
                match prior {
                    Some(RuntimeOperationRecord::ReceiptAcknowledgement {
                        operation_id: old_operation,
                        process_id: old_process,
                        receipt_digest: old_receipt,
                    }) if old_operation == operation_id
                        && old_process == process_id
                        && old_receipt == receipt_digest =>
                    {
                        return Ok(HostResponse::Runtime {
                            response: RuntimeResponse::Complete,
                        });
                    }
                    Some(_) => {
                        return Err(sandsurf_state::Error::Conflict(
                            "receipt acknowledgement operation identity conflict",
                        )
                        .into());
                    }
                    None => {}
                }
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ReleaseEvidence,
                    &scope_digest,
                )?;
                Ok(HostResponse::Runtime {
                    response: client.runtime(
                        sandbox_id,
                        RuntimeRequest::AcknowledgeReceipt {
                            operation_id,
                            process_id,
                            receipt_digest,
                        },
                    )?,
                })
            }
            HostRequest::PinEvidence {
                sandbox_id,
                operation_id,
                process_id,
                receipt_digest,
                pin_id,
                expected_revision,
                scope_digest,
            } => {
                self.provision_guardian(&sandbox_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&sandbox_id));
                let prior = runtime_operation(&client, &sandbox_id, &operation_id)?;
                match prior {
                    Some(RuntimeOperationRecord::EvidencePin {
                        operation_id: old_operation,
                        pin_id: old_pin,
                        process_id: old_process,
                        receipt_digest: old_receipt,
                    }) if old_operation == operation_id
                        && old_pin == pin_id
                        && old_process == process_id
                        && old_receipt == receipt_digest =>
                    {
                        return Ok(HostResponse::Runtime {
                            response: RuntimeResponse::Complete,
                        });
                    }
                    Some(_) => {
                        return Err(sandsurf_state::Error::Conflict(
                            "evidence pin operation identity conflict",
                        )
                        .into());
                    }
                    None => {}
                }
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ReleaseEvidence,
                    &scope_digest,
                )?;
                Ok(HostResponse::Runtime {
                    response: client.runtime(
                        sandbox_id,
                        RuntimeRequest::Pin {
                            operation_id,
                            process_id,
                            receipt_digest,
                            pin_id,
                        },
                    )?,
                })
            }
            HostRequest::ReleaseEvidence {
                sandbox_id,
                process_id,
                request,
                expected_revision,
                scope_digest,
                loss_approval_id,
            } => {
                self.provision_guardian(&sandbox_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&sandbox_id));
                let prior = runtime_operation(&client, &sandbox_id, &request.operation_id)?;
                match prior {
                    Some(RuntimeOperationRecord::EvidenceRelease {
                        process_id: old_process,
                        request: old_request,
                        status,
                    }) if old_process == process_id && old_request == request => {
                        return Ok(HostResponse::Runtime {
                            response: RuntimeResponse::Release { status },
                        });
                    }
                    Some(_) => {
                        return Err(sandsurf_state::Error::Conflict(
                            "evidence release operation identity conflict",
                        )
                        .into());
                    }
                    None => {}
                }
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ReleaseEvidence,
                    &scope_digest,
                )?;
                match (&request.disposition, loss_approval_id) {
                    (ReleaseDisposition::AuthorizedLoss { authorization }, Some(approval_id))
                        if *authorization == approval_id =>
                    {
                        let authorized = self.catalog.authorize_output_loss(
                            &sandbox_id,
                            &process_id,
                            &request.receipt_digest,
                            &request.output,
                            Approval {
                                id: approval_id,
                                request_digest: digest(
                                    Domain::Release,
                                    &(
                                        &sandbox_id,
                                        &process_id,
                                        &request.receipt_digest,
                                        &request.output,
                                        "loss",
                                    ),
                                )?,
                            },
                        )?;
                        client.runtime(
                            sandbox_id.clone(),
                            RuntimeRequest::RecordLoss {
                                authorization: authorized,
                            },
                        )?;
                    }
                    (ReleaseDisposition::AuthorizedLoss { .. }, _) => {
                        return Err(HostError::Invalid(
                            "authorized loss requires its exact approval identity",
                        ));
                    }
                    (_, Some(_)) => {
                        return Err(HostError::Invalid(
                            "loss approval is invalid for this release disposition",
                        ));
                    }
                    (_, None) => {}
                }
                Ok(HostResponse::Runtime {
                    response: client.runtime(
                        sandbox_id,
                        RuntimeRequest::Release {
                            process_id,
                            request,
                        },
                    )?,
                })
            }
            HostRequest::CleanupReleasedEvidence {
                sandbox_id,
                process_id,
                request_digest,
            } => {
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id)).runtime(
                        sandbox_id,
                        RuntimeRequest::CleanupReleased {
                            process_id,
                            request_digest,
                        },
                    )?,
                })
            }
        }
    }

    fn inspect(&self) -> HostInspection {
        let engine = if cfg!(target_os = "macos") {
            VmEngine::AppleVirtualization
        } else if cfg!(target_os = "windows") {
            VmEngine::HyperV
        } else {
            VmEngine::Firecracker
        };
        let reason = format!(
            "{} driver has no retained real-hardware qualification for this exact build/configuration",
            std::env::consts::OS
        );
        HostInspection {
            host_id: self.catalog.host_id().as_str().into(),
            platform: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            guest_architecture: match native_guest_architecture() {
                GuestArchitecture::Amd64 => "amd64",
                GuestArchitecture::Arm64 => "arm64",
            }
            .into(),
            engine,
            lifecycle: Qualification::Unqualified {
                reasons: vec![reason.clone()],
            },
            full_state: Qualification::Unqualified {
                reasons: vec![reason],
            },
            images: { crate::images::qualification() },
            guest_platform: format!(
                "linux/{}",
                match native_guest_architecture() {
                    GuestArchitecture::Amd64 => "amd64",
                    GuestArchitecture::Arm64 => "arm64",
                }
            ),
            default_image_digest: crate::images::bundled_image_digest(),
        }
    }

    fn apply_lifecycle_intent(
        &mut self,
        intent: &LifecycleIntent,
        endpoint: PathBuf,
    ) -> Result<HostLifecycleResult> {
        if intent.completion.is_some() {
            return Ok(apply_lifecycle(
                &mut self.catalog,
                endpoint,
                &intent.operation_id,
            )?);
        }
        let client = GuardianClient::new(endpoint.clone());
        let inspection = client.inspect(intent.sandbox_id.clone(), None)?;
        let current = match inspection.observation {
            Observation::Current { value } => Some(value),
            Observation::Unavailable { .. } => None,
        };
        match (intent.desired, current.as_ref().map(|value| value.state)) {
            (DesiredState::Suspended, Some(_)) => {
                self.suspend_with_full_checkpoint(intent, endpoint, current.as_ref().unwrap())
            }
            (DesiredState::Running, Some(MachineState::Suspended)) => {
                self.restore_suspended_checkpoint(intent, endpoint, current.as_ref().unwrap())
            }
            _ => Ok(apply_lifecycle(
                &mut self.catalog,
                endpoint,
                &intent.operation_id,
            )?),
        }
    }

    fn suspend_with_full_checkpoint(
        &mut self,
        intent: &LifecycleIntent,
        endpoint: PathBuf,
        current: &MachineObservation,
    ) -> Result<HostLifecycleResult> {
        let (checkpoint_id, capture_operation_id) = suspension_identities(intent)?;
        if current.state == MachineState::Suspended {
            let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &intent.operation_id)?;
            if lifecycle.completed_intent.is_some() {
                let checkpoint =
                    self.catalog
                        .checkpoint(&checkpoint_id)?
                        .ok_or(HostError::Invalid(
                            "suspended machine has no lifecycle checkpoint",
                        ))?;
                let manifest = checkpoint
                    .manifest_digest
                    .as_ref()
                    .ok_or(HostError::Invalid(
                        "suspension checkpoint has no committed manifest",
                    ))?;
                self.catalog.record_suspension(
                    &intent.sandbox_id,
                    &intent.operation_id,
                    &checkpoint_id,
                    manifest,
                )?;
            }
            return Ok(lifecycle);
        }
        if !matches!(current.state, MachineState::Running | MachineState::Paused)
            || current.applied_revision.next()? != intent.revision
        {
            return Err(HostError::Invalid(
                "suspend requires the current running or paused revision",
            ));
        }
        let request = CheckpointRequest {
            id: checkpoint_id.clone(),
            operation_id: capture_operation_id.clone(),
            sandbox_id: intent.sandbox_id.clone(),
            expected_epoch: current.epoch,
            expected_revision: current.applied_revision,
            kind: CheckpointKind::Full,
            parent: None,
        };
        let request_digest = digest(Domain::Checkpoint, &("sandsurf-checkpoint-v1", &request))?;
        let admitted = self
            .catalog
            .admit_suspension_checkpoint(request.clone(), &intent.operation_id)?;
        let checkpoint = if admitted.phase == CheckpointPhase::Ready {
            admitted
        } else {
            let capturing = self
                .catalog
                .begin_checkpoint(&checkpoint_id, &request_digest)?;
            if let Some(captured) = crate::checkpoints::published_filesystem(
                &self.root.join("checkpoints"),
                &capturing,
            )? {
                complete_checkpoint_capture(
                    &mut self.catalog,
                    &checkpoint_id,
                    &request_digest,
                    captured,
                )?
            } else {
                let client = GuardianClient::new(endpoint.clone());
                let prepared = client.native_checkpoint(
                    intent.sandbox_id.clone(),
                    NativeCheckpointRequest::PrepareFull {
                        checkpoint_id: checkpoint_id.clone(),
                        operation_id: capture_operation_id.clone(),
                    },
                )?;
                let NativeCheckpointResponse::Prepared { capture, processes } = prepared else {
                    return Err(HostError::Invalid(
                        "guardian did not establish the suspension capture boundary",
                    ));
                };
                let sandbox_root = self.sandbox_root(&intent.sandbox_id);
                let captured = crate::checkpoints::capture_full(
                    &self.root.join("checkpoints"),
                    &capturing,
                    &sandbox_root.join("disks").join(workload_disk_name()),
                    &sandbox_root.join("disks").join(control_disk_name()),
                    &sandbox_root
                        .join("guardian/full-captures")
                        .join(capture_operation_id.as_str()),
                    capture,
                    processes,
                )?;
                complete_checkpoint_capture(
                    &mut self.catalog,
                    &checkpoint_id,
                    &request_digest,
                    captured,
                )?
            }
        };
        let manifest_digest = checkpoint
            .manifest_digest
            .clone()
            .ok_or(HostError::Invalid(
                "suspension checkpoint has no committed manifest",
            ))?;
        if !matches!(
            GuardianClient::new(endpoint.clone()).native_checkpoint(
                intent.sandbox_id.clone(),
                NativeCheckpointRequest::CommitSuspend {
                    operation_id: capture_operation_id,
                    manifest_digest: manifest_digest.clone(),
                },
            )?,
            NativeCheckpointResponse::Complete { .. }
        ) {
            return Err(HostError::Invalid(
                "guardian did not commit the suspension checkpoint",
            ));
        }
        let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &intent.operation_id)?;
        if lifecycle.completed_intent.is_some() {
            self.catalog.record_suspension(
                &intent.sandbox_id,
                &intent.operation_id,
                &checkpoint_id,
                &manifest_digest,
            )?;
        }
        Ok(lifecycle)
    }

    fn restore_suspended_checkpoint(
        &mut self,
        intent: &LifecycleIntent,
        endpoint: PathBuf,
        current: &MachineObservation,
    ) -> Result<HostLifecycleResult> {
        let suspension = self
            .catalog
            .suspension(&intent.sandbox_id)?
            .ok_or(HostError::Invalid(
                "suspended machine has no committed restore checkpoint",
            ))?;
        let checkpoint = self
            .catalog
            .checkpoint(&suspension.checkpoint_id)?
            .ok_or(HostError::Invalid("restore checkpoint does not exist"))?;
        let full = checkpoint.full.clone().ok_or(HostError::Invalid(
            "restore checkpoint has no machine state",
        ))?;
        let workload_disk = CheckpointArtifact {
            digest: checkpoint
                .workload_disk_digest
                .clone()
                .ok_or(HostError::Invalid(
                    "restore checkpoint has no workload disk",
                ))?,
            bytes: checkpoint.workload_disk_bytes,
        };
        if current.applied_revision.next()? != intent.revision {
            return Err(HostError::Invalid(
                "restore does not follow the suspended configuration revision",
            ));
        }
        if !matches!(
            GuardianClient::new(endpoint.clone()).native_checkpoint(
                intent.sandbox_id.clone(),
                NativeCheckpointRequest::StageRestore {
                    checkpoint_id: suspension.checkpoint_id.clone(),
                    manifest_digest: suspension.manifest_digest.clone(),
                    workload_disk,
                    expected: Box::new(full),
                },
            )?,
            NativeCheckpointResponse::Complete { .. }
        ) {
            return Err(HostError::Invalid(
                "guardian did not stage the suspended machine restore",
            ));
        }
        let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &intent.operation_id)?;
        if lifecycle.completed_intent.is_some() {
            self.catalog
                .clear_suspension(&intent.sandbox_id, &suspension.checkpoint_id)?;
        }
        Ok(lifecycle)
    }

    fn recover_checkpoint_barriers(&mut self) {
        let mut after = None;
        loop {
            let Ok(values) = self.catalog.checkpoints(
                after.as_ref(),
                Counter::try_from(256).expect("constant is positive"),
            ) else {
                return;
            };
            if values.is_empty() {
                return;
            }
            for checkpoint in &values {
                if checkpoint.phase != CheckpointPhase::Capturing
                    || checkpoint.request.kind != CheckpointKind::Filesystem
                {
                    continue;
                }
                let sandbox = checkpoint.request.sandbox_id.clone();
                if self.provision_guardian(&sandbox).is_ok() {
                    let _ = GuardianClient::new(self.guardian_endpoint(&sandbox)).guest(
                        sandbox,
                        GuestServiceRequest::FinishFilesystemCapture {
                            operation_id: checkpoint.request.operation_id.clone(),
                        },
                    );
                }
            }
            if values.len() < 256 {
                return;
            }
            after = values.last().map(|value| value.request.id.clone());
        }
    }

    fn recover_guest_capture_barriers(&mut self) {
        let pending = match self.workspace.pending_guest_captures() {
            Ok(values) => values,
            Err(error) => {
                eprintln!("sandsurf guest capture recovery deferred: {error}");
                return;
            }
        };
        for capture in pending {
            if self.provision_guardian(&capture.sandbox_id).is_err() {
                continue;
            }
            let client = GuardianClient::new(self.guardian_endpoint(&capture.sandbox_id));
            let Ok(inspection) = client.inspect(capture.sandbox_id.clone(), None) else {
                continue;
            };
            let Observation::Current { value: machine } = inspection.observation else {
                continue;
            };
            if machine.epoch > capture.epoch
                || (machine.epoch == capture.epoch
                    && matches!(
                        machine.state,
                        MachineState::Stopped | MachineState::Destroyed
                    ))
            {
                let _ = self.workspace.finish_guest_capture(&capture.operation_id);
                continue;
            }
            if machine.epoch != capture.epoch {
                continue;
            }
            if matches!(
                client.guest(
                    capture.sandbox_id,
                    GuestServiceRequest::FinishGuestTreeCapture {
                        operation_id: capture.operation_id.clone(),
                    },
                ),
                Ok(GuestServiceResponse::FilesystemCaptureFinished { .. })
            ) {
                let _ = self.workspace.finish_guest_capture(&capture.operation_id);
            }
        }
    }

    fn recover_secret_authority(&mut self) {
        let mut after = None;
        loop {
            let Ok(values) = self.catalog.sandboxes(
                after.as_ref(),
                Counter::try_from(256).expect("constant is positive"),
            ) else {
                return;
            };
            if values.is_empty() {
                return;
            }
            for sandbox in &values {
                if let Ok(inspection) = GuardianClient::new(self.guardian_endpoint(&sandbox.id))
                    .inspect(sandbox.id.clone(), None)
                    && matches!(
                        inspection.observation,
                        Observation::Current {
                            value: MachineObservation {
                                state: MachineState::Running,
                                ..
                            }
                        }
                    )
                {
                    let _ = self.reconcile_secret_authority(&sandbox.id);
                }
            }
            if values.len() < 256 {
                return;
            }
            after = values.last().map(|value| value.id.clone());
        }
    }

    fn recover_image_releases(&mut self) {
        let Ok(releases) = self.catalog.pending_image_releases() else {
            return;
        };
        for release in releases {
            if crate::images::cleanup(&self.root, &release.image_digest).is_ok() {
                let _ = self
                    .catalog
                    .complete_image_release(&release.operation_id, &release.request_digest);
            }
        }
    }

    fn enforce_secret_revocation(
        &mut self,
        record: sandsurf_state::SecretRevocationRecord,
    ) -> Result<sandsurf_state::SecretRevocationRecord> {
        self.provision_guardian(&record.sandbox_id)?;
        let client = GuardianClient::new(self.guardian_endpoint(&record.sandbox_id));
        let inspection = client.inspect(record.sandbox_id.clone(), None)?;
        if !matches!(
            inspection.observation,
            Observation::Current {
                value: MachineObservation {
                    state: MachineState::Running,
                    ..
                }
            }
        ) {
            return Ok(record);
        }
        let response = client.guest(
            record.sandbox_id.clone(),
            GuestServiceRequest::RevokeSecret {
                operation_id: record.operation_id.clone(),
                secret_id: record.secret.id.clone(),
                version: record.secret.version.clone(),
                deliveries: record.deliveries.clone(),
                terminate_recipients: record.terminate_recipients,
            },
        )?;
        let GuestServiceResponse::SecretRevoked { evidence } = response else {
            return Err(HostError::Invalid(
                "guest did not establish secret revocation",
            ));
        };
        if !evidence.enforcement_complete {
            return Ok(record);
        }
        if let Some(committed) = record.evidence.as_ref() {
            if !committed.enforcement_complete {
                return Err(HostError::Invalid(
                    "committed secret revocation evidence is incomplete",
                ));
            }
            return Ok(record);
        }
        Ok(self.catalog.complete_secret_revocation(
            &record.operation_id,
            &record.request_digest,
            evidence,
        )?)
    }

    fn reconcile_secret_authority(&mut self, sandbox: &SandboxId) -> Result<()> {
        for revocation in self.catalog.secret_revocations(sandbox)? {
            let enforced = self.enforce_secret_revocation(revocation)?;
            if enforced.evidence.is_none() {
                return Err(HostError::Invalid(
                    "secret revocation remains unenforced after machine start",
                ));
            }
        }
        let client = GuardianClient::new(self.guardian_endpoint(sandbox));
        for record in self.catalog.active_secret_deliveries(sandbox)? {
            if matches!(record.delivery.lifetime, SecretLifetime::Process)
                || matches!(
                    record.delivery.destination,
                    SecretDestination::Environment { .. }
                )
            {
                continue;
            }
            let bytes = self
                .secrets
                .read(&record.delivery.secret.id, &record.delivery.secret.version)?;
            let response = client.guest(
                sandbox.clone(),
                GuestServiceRequest::InstallSecret {
                    operation_id: record.operation_id,
                    delivery: record.delivery,
                    bytes,
                },
            )?;
            if !matches!(response, GuestServiceResponse::SecretInstalled { .. }) {
                return Err(HostError::Invalid(
                    "guest did not restore active sandbox secret",
                ));
            }
        }
        Ok(())
    }

    fn provision_guardian(&mut self, sandbox: &SandboxId) -> Result<()> {
        #[cfg(target_os = "linux")]
        return self.provision_guardian_with_config(sandbox, None);
        #[cfg(target_os = "macos")]
        return self.provision_guardian_with_config(sandbox, None);
        #[cfg(target_os = "windows")]
        return self.provision_guardian_with_config(sandbox, None);
    }

    #[cfg(target_os = "linux")]
    fn provision_guardian_with_config(
        &mut self,
        sandbox: &SandboxId,
        config: Option<&crate::linux::LinuxGuardianConfig>,
    ) -> Result<()> {
        let root = self.sandbox_root(sandbox);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let config_path = root.join("guardian/config.json");
        if let Some(config) = config {
            crate::linux::write_config(&config_path, config)?;
            self.verified_guardians.insert(sandbox.clone());
        } else if !self.verified_guardians.contains(sandbox) {
            crate::linux::read_config(&config_path, sandbox)?;
            self.verified_guardians.insert(sandbox.clone());
        }
        self.provision_guardian_inner(sandbox)
    }

    #[cfg(target_os = "macos")]
    fn provision_guardian_with_config(
        &mut self,
        sandbox: &SandboxId,
        config: Option<&crate::apple::AppleGuardianConfig>,
    ) -> Result<()> {
        let root = self.sandbox_root(sandbox);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let config_path = root.join("guardian/config.json");
        if let Some(config) = config {
            crate::apple::write_config(&config_path, config)?;
            self.verified_guardians.insert(sandbox.clone());
        } else if !self.verified_guardians.contains(sandbox) {
            crate::apple::read_config(&config_path, sandbox)?;
            self.verified_guardians.insert(sandbox.clone());
        }
        self.provision_guardian_inner(sandbox)
    }

    #[cfg(target_os = "windows")]
    fn provision_guardian_with_config(
        &mut self,
        sandbox: &SandboxId,
        config: Option<&crate::windows::WindowsGuardianConfig>,
    ) -> Result<()> {
        let root = self.sandbox_root(sandbox);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let config_path = root.join("guardian/config.json");
        if let Some(config) = config {
            crate::windows::write_config(&config_path, config)?;
            self.verified_guardians.insert(sandbox.clone());
        } else if !self.verified_guardians.contains(sandbox) {
            crate::windows::read_config(&config_path, sandbox)?;
            self.verified_guardians.insert(sandbox.clone());
        }
        self.provision_guardian_inner(sandbox)
    }

    fn provision_guardian_inner(&self, sandbox: &SandboxId) -> Result<()> {
        let root = self.sandbox_root(sandbox);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        prepare_directory(&root.join("disks"))?;
        prepare_directory(&root.join("output"))?;
        let runtime = root.join("runtime");
        if !runtime.exists() {
            let resources = self
                .catalog
                .sandbox(sandbox)?
                .ok_or(HostError::Invalid("sandbox is missing from host authority"))?
                .resources;
            RuntimeJournal::create(
                &runtime,
                sandbox.clone(),
                runtime_limits(&resources),
                self.catalog.authority_binding().clone(),
            )?;
        }
        let endpoint = self.guardian_endpoint(sandbox);
        match GuardianClient::new(endpoint.clone()).inspect(sandbox.clone(), None) {
            Ok(_) => return Ok(()),
            Err(sandsurf_control::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => {
                return Err(HostError::GuardianStartup(format!(
                    "an existing guardian endpoint is incompatible or unhealthy; refusing a second owner: {error}"
                )));
            }
        }
        let guardian_log = open_guardian_log(&root.join("guardian/guardian.log"))?;
        let mut child = Command::new(&self.executable)
            .arg("guardian")
            .arg("--directory")
            .arg(&self.root)
            .arg("--sandbox")
            .arg(sandbox.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(guardian_log))
            .spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if GuardianClient::new(endpoint.clone())
                .inspect(sandbox.clone(), None)
                .is_ok()
            {
                return Ok(());
            }
            if let Some(status) = child.try_wait()? {
                return Err(HostError::GuardianStartup(format!(
                    "guardian exited before becoming reachable ({status}); inspect {}",
                    root.join("guardian/guardian.log").display()
                )));
            }
            if std::time::Instant::now() >= deadline {
                // A process which never publishes its authenticated endpoint is
                // not an independently owned guardian. Do not leave it behind.
                let _ = child.kill();
                let _ = child.wait();
                return Err(HostError::GuardianStartup(format!(
                    "guardian did not become reachable; inspect {}",
                    root.join("guardian/guardian.log").display()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn view(&mut self, record: SandboxRecord) -> Result<SandboxView> {
        let machine = match GuardianClient::new(self.guardian_endpoint(&record.id))
            .inspect(record.id.clone(), None)
        {
            Ok(value) => value.observation,
            Err(_) => Observation::Unavailable { last_known: None },
        };
        #[cfg(target_os = "linux")]
        let workload_defaults = if let Some(value) = self
            .verified_workload_defaults
            .get(record.image_digest.as_str())
            .cloned()
        {
            value
        } else {
            let value = crate::linux::workload_defaults(&self.root, &record.image_digest)?;
            self.verified_workload_defaults
                .insert(record.image_digest.as_str().to_owned(), value.clone());
            value
        };
        #[cfg(target_os = "macos")]
        let workload_defaults = if let Some(value) = self
            .verified_workload_defaults
            .get(record.image_digest.as_str())
            .cloned()
        {
            value
        } else {
            let value = crate::apple::workload_defaults(&self.root, &record.image_digest)?;
            self.verified_workload_defaults
                .insert(record.image_digest.as_str().to_owned(), value.clone());
            value
        };
        #[cfg(target_os = "windows")]
        let workload_defaults = if let Some(value) = self
            .verified_workload_defaults
            .get(record.image_digest.as_str())
            .cloned()
        {
            value
        } else {
            let value = crate::windows::workload_defaults(&self.root, &record.image_digest)?;
            self.verified_workload_defaults
                .insert(record.image_digest.as_str().to_owned(), value.clone());
            value
        };
        let mut workload_defaults = workload_defaults;
        workload_defaults
            .environment
            .extend(record.workload_configuration.environment.clone());
        if record.workload_configuration.user.is_some() {
            workload_defaults.user = record.workload_configuration.user.clone();
        }
        if record.workload_configuration.working_directory.is_some() {
            workload_defaults.working_directory =
                record.workload_configuration.working_directory.clone();
        }
        Ok(SandboxView {
            workload_defaults,
            lifetime: record.lifetime,
            last_activity_unix_millis: record.last_activity_unix_millis,
            id: record.id,
            image_digest: record.image_digest,
            resources: record.resources,
            runtime_configuration: record.runtime_configuration,
            configuration_revision: record.configuration_revision,
            reservation: match record.reservation {
                ReservationState::Held => ReservationView::Held,
                ReservationState::Released => ReservationView::Released,
            },
            lifecycle_intent: record.latest_intent,
            machine,
        })
    }

    fn apply_configuration(&mut self, sandbox: &SandboxId, revision: Counter) -> Result<()> {
        self.provision_guardian(sandbox)?;
        let authorization = self.catalog.authorize_configuration(sandbox, revision)?;
        let operation =
            GuardianClient::new(self.guardian_endpoint(sandbox)).configure(authorization)?;
        if operation.delivery != Delivery::Applied || operation.command.revision != revision {
            return Err(HostError::Invalid(
                "guardian did not apply the host configuration revision",
            ));
        }
        Ok(())
    }

    fn require_active_grant_for_new_host_operation(
        &self,
        sandbox: &SandboxId,
        operation: &OperationId,
        expected_revision: Counter,
        capability: Capability,
        scope_digest: &Digest,
    ) -> Result<()> {
        if self.catalog.operation(operation)?.is_none() {
            self.catalog
                .active_grant(sandbox, expected_revision, capability, scope_digest)?;
        }
        Ok(())
    }

    /// A fresh host configuration change is admitted only from the revision
    /// the guardian currently observes. Historical retries bypass this gate;
    /// their catalog methods validate the immutable operation binding and
    /// `apply_configuration_if_current` ensures they cannot roll a newer
    /// guardian configuration backward.
    fn require_configuration_precondition(
        &mut self,
        sandbox: &SandboxId,
        operation: &OperationId,
        expected_revision: Counter,
    ) -> Result<()> {
        if self.catalog.operation(operation)?.is_some() {
            return Ok(());
        }
        self.provision_guardian(sandbox)?;
        let inspection =
            GuardianClient::new(self.guardian_endpoint(sandbox)).inspect(sandbox.clone(), None)?;
        let Observation::Current { value } = inspection.observation else {
            return Err(HostError::Invalid(
                "new configuration requires a current guardian observation",
            ));
        };
        if value.applied_revision != expected_revision {
            return Err(sandsurf_state::Error::Conflict(
                "guardian has not applied the expected host configuration revision",
            )
            .into());
        }
        Ok(())
    }

    /// Admit a fresh lifecycle mutation only from the configuration revision
    /// the guardian currently observes. Exact historical retries are resolved
    /// from their immutable host/guardian records instead of consulting current
    /// machine state.
    fn require_lifecycle_precondition(
        &mut self,
        sandbox: &SandboxId,
        operation: &OperationId,
        expected_revision: Counter,
    ) -> Result<()> {
        if self.catalog.operation(operation)?.is_some() {
            return Ok(());
        }
        self.provision_guardian(sandbox)?;
        let inspection =
            GuardianClient::new(self.guardian_endpoint(sandbox)).inspect(sandbox.clone(), None)?;
        let Observation::Current { value } = inspection.observation else {
            return Err(HostError::Invalid(
                "new lifecycle intent requires a current guardian observation",
            ));
        };
        if value.applied_revision != expected_revision {
            return Err(sandsurf_state::Error::Conflict(
                "guardian has not applied the expected host configuration revision",
            )
            .into());
        }
        Ok(())
    }

    fn apply_configuration_if_current(
        &mut self,
        sandbox: &SandboxId,
        operation_revision: Counter,
    ) -> Result<()> {
        let current = self
            .catalog
            .sandbox(sandbox)?
            .ok_or(HostError::Invalid("sandbox does not exist"))?
            .configuration_revision;
        if operation_revision > current {
            return Err(HostError::Invalid(
                "configuration operation is ahead of host authority",
            ));
        }
        if operation_revision == current {
            self.apply_configuration(sandbox, current)?;
        }
        Ok(())
    }

    fn reconcile_configuration(&mut self, record: &SandboxRecord) -> Result<()> {
        self.provision_guardian(&record.id)?;
        let inspection = GuardianClient::new(self.guardian_endpoint(&record.id))
            .inspect(record.id.clone(), None)?;
        let Observation::Current { value } = inspection.observation else {
            return Ok(());
        };
        if value.applied_revision > record.configuration_revision {
            return Err(HostError::Invalid(
                "guardian configuration is ahead of host authority",
            ));
        }
        if value.applied_revision == record.configuration_revision {
            return Ok(());
        }
        if value.applied_revision.next()? != record.configuration_revision {
            return Err(HostError::Invalid(
                "guardian configuration history has an unrecoverable gap",
            ));
        }
        self.apply_configuration(&record.id, record.configuration_revision)
    }

    /// Reconcile unfinished lifecycle work and enforce only policies that were
    /// admitted with Sandbox creation/fork. Policy decisions update host
    /// lifecycle intent; the guardian still exclusively records whether the
    /// machine transition occurred.
    fn reconcile_lifetime_policies(&mut self) -> Result<()> {
        let now = unix_millis()?;
        let mut after = None;
        loop {
            let records = self.catalog.sandboxes(after.as_ref(), counter(256))?;
            if records.is_empty() {
                break;
            }
            after = records.last().map(|record| record.id.clone());
            for mut record in records {
                if record.reservation == ReservationState::Released {
                    continue;
                }
                if record.latest_intent.completion.is_none() {
                    self.provision_guardian(&record.id)?;
                    let endpoint = self.guardian_endpoint(&record.id);
                    self.apply_lifecycle_intent(&record.latest_intent, endpoint)?;
                    record = self.catalog.sandbox(&record.id)?.ok_or(HostError::Invalid(
                        "sandbox disappeared during reconciliation",
                    ))?;
                    if record.latest_intent.completion.is_none() {
                        continue;
                    }
                }

                self.reconcile_configuration(&record)?;

                if let Some(expires) = record.lifetime.expires_at_unix_millis
                    && now >= expires
                {
                    let desired = match record.lifetime.expiration_action {
                        ExpirationAction::Stop => DesiredState::Stopped,
                        ExpirationAction::Destroy => DesiredState::Destroyed,
                    };
                    if record.latest_intent.desired != desired
                        && !(record.latest_intent.desired == DesiredState::Destroyed)
                    {
                        self.apply_policy_lifecycle(record, desired, "expiration")?;
                    }
                    continue;
                }

                let Some(idle) = record.lifetime.idle_stop_after_millis else {
                    continue;
                };
                if record.latest_intent.desired != DesiredState::Running {
                    continue;
                }
                self.provision_guardian(&record.id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&record.id));
                let inspection = client.inspect(record.id.clone(), None)?;
                if !matches!(
                    inspection.observation,
                    Observation::Current {
                        value: MachineObservation {
                            state: MachineState::Running,
                            ..
                        }
                    }
                ) {
                    // Idle time does not advance while paused, suspended,
                    // stopped, or unreachable.
                    self.catalog.observe_activity(&record.id, now)?;
                    continue;
                }
                let RuntimeResponse::Processes { processes } =
                    client.runtime(record.id.clone(), RuntimeRequest::Processes)?
                else {
                    return Err(HostError::Invalid(
                        "guardian returned the wrong process inventory response",
                    ));
                };
                let busy_or_uncertain = processes.iter().any(|process| match process {
                    Observation::Unavailable { .. } => true,
                    Observation::Current { value } => {
                        !matches!(value.state, ProcessState::Exited(_))
                    }
                });
                if busy_or_uncertain {
                    self.catalog.observe_activity(&record.id, now)?;
                    continue;
                }
                if now
                    .get()
                    .saturating_sub(record.last_activity_unix_millis.get())
                    >= idle.get()
                {
                    self.apply_policy_lifecycle(record, DesiredState::Stopped, "idle")?;
                }
            }
            if after.is_none() {
                break;
            }
        }
        Ok(())
    }

    fn apply_policy_lifecycle(
        &mut self,
        record: SandboxRecord,
        desired: DesiredState,
        reason: &str,
    ) -> Result<()> {
        let identity = digest(
            Domain::Operation,
            &(
                "sandsurf-lifetime-policy-v1",
                &record.id,
                record.configuration_revision,
                desired,
                reason,
            ),
        )?;
        let operation_id: OperationId =
            format!("policy-{}", &identity.as_str()[..48])
                .try_into()
                .map_err(|_| HostError::Invalid("lifetime operation identity is invalid"))?;
        let request_digest = digest(
            Domain::Operation,
            &(
                &record.id,
                &operation_id,
                record.configuration_revision,
                desired,
            ),
        )?;
        let approval_id: CommitmentId = format!("policy-approval-{}", &identity.as_str()[..48])
            .try_into()
            .map_err(|_| HostError::Invalid("lifetime approval identity is invalid"))?;
        let intent = self.catalog.request_lifecycle(
            &record.id,
            operation_id,
            record.configuration_revision,
            desired,
            Approval {
                id: approval_id,
                request_digest,
            },
        )?;
        self.provision_guardian(&record.id)?;
        let endpoint = self.guardian_endpoint(&record.id);
        self.apply_lifecycle_intent(&intent, endpoint)?;
        Ok(())
    }

    fn sandbox_root(&self, sandbox: &SandboxId) -> PathBuf {
        self.root.join("sandboxes").join(sandbox.as_str())
    }

    fn guardian_endpoint(&self, sandbox: &SandboxId) -> PathBuf {
        self.sandbox_root(sandbox).join("guardian")
    }
}

pub fn serve_host(root: &Path, executable: PathBuf) -> Result<()> {
    let mut service = HostService::open(root, executable)?;
    let listener = LocalListener::bind(&service.endpoint())?;
    let stopped = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::sync_channel::<HostIngress>(MAX_HOST_CONNECTIONS);
    std::thread::scope(|scope| {
        let stopped_accept = Arc::clone(&stopped);
        let active_accept = Arc::clone(&active);
        let accept_worker = scope.spawn(move || {
            while !stopped_accept.load(Ordering::Acquire) {
                let connection = match listener.accept(Duration::from_secs(1)) {
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
                    Err(error) => {
                        let _ = sender.send(HostIngress::Failed(error));
                        return;
                    }
                };
                if active_accept.fetch_add(1, Ordering::AcqRel) >= MAX_HOST_CONNECTIONS {
                    active_accept.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                let sender = sender.clone();
                let active = Arc::clone(&active_accept);
                let worker = std::thread::Builder::new()
                    .name("sandsurf-host-client".into())
                    .spawn(move || {
                        let _active = ActiveHostConnection(active);
                        let mut connection = connection;
                        let frame = match connection.read_frame(API_TIMEOUT) {
                            Ok(Some(frame)) => frame,
                            Ok(None) | Err(_) => return,
                        };
                        let sequence = frame.sequence;
                        let parsed = parse_host_request(frame);
                        let (reply, response) = mpsc::channel();
                        let (completed, delivered) = mpsc::channel();
                        if sender
                            .send(HostIngress::Request {
                                parsed: Box::new(parsed),
                                reply,
                                delivered,
                            })
                            .is_err()
                        {
                            return;
                        }
                        if let Ok(dispatch) = response.recv() {
                            // A lost response never reverses an admitted operation.
                            let written =
                                write_host_response(&mut connection, sequence, dispatch.finish())
                                    .is_ok();
                            drop(connection);
                            if written {
                                let _ = completed.send(());
                            }
                        }
                    });
                if let Err(error) = worker {
                    active_accept.fetch_sub(1, Ordering::AcqRel);
                    eprintln!("sandsurf host connection rejected: {error}");
                }
            }
        });
        let result = loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(HostIngress::Request {
                    parsed,
                    reply,
                    delivered,
                }) => {
                    let stopping = matches!(&*parsed, Ok(HostRequest::StopService));
                    let response = (*parsed)
                        .map(|request| service.route(request))
                        .unwrap_or_else(|error| HostDispatch::Ready(Box::new(rejected(error))));
                    if stopping {
                        break Ok((reply, delivered, response));
                    }
                    let _ = reply.send(response);
                }
                Ok(HostIngress::Failed(error)) => break Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(error) = service.reconcile_lifetime_policies() {
                        eprintln!("sandsurf host reconciliation deferred: {error}");
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(HostError::Invalid("host ingress stopped unexpectedly"));
                }
            }
        };
        stopped.store(true, Ordering::Release);
        drop(receiver);
        accept_worker
            .join()
            .map_err(|_| HostError::Invalid("host ingress accept worker panicked"))?;
        // Terminal acknowledgement is published only after both the listening
        // endpoint and the catalog writer have released their owned resources.
        drop(service);
        match result {
            Ok((reply, delivered, response)) => {
                let _ = reply.send(response);
                let _ = delivered.recv_timeout(Duration::from_secs(10));
                Ok(())
            }
            Err(error) => Err(error),
        }
    })
}

enum HostIngress {
    Request {
        parsed: Box<Result<HostRequest>>,
        reply: mpsc::Sender<HostDispatch>,
        delivered: mpsc::Receiver<()>,
    },
    Failed(io::Error),
}

enum HostDispatch {
    Ready(Box<HostResponse>),
    Runtime(Box<DeferredRuntimeRead>),
}

impl HostDispatch {
    fn finish(self) -> HostResponse {
        match self {
            Self::Ready(response) => *response,
            Self::Runtime(read) => (*read).execute().unwrap_or_else(rejected),
        }
    }
}

struct DeferredRuntimeRead {
    endpoint: PathBuf,
    sandbox_id: SandboxId,
    query: RuntimeRequest,
}

impl DeferredRuntimeRead {
    fn execute(self) -> Result<HostResponse> {
        Ok(HostResponse::Runtime {
            response: GuardianClient::new(self.endpoint).runtime(self.sandbox_id, self.query)?,
        })
    }
}

fn rejected(error: HostError) -> HostResponse {
    HostResponse::Rejected {
        category: error_category(&error).into(),
        message: error.to_string(),
    }
}

struct ActiveHostConnection(Arc<AtomicUsize>);
impl Drop for ActiveHostConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn serve_sandbox_guardian(root: &Path, sandbox: SandboxId) -> Result<()> {
    let sandbox_root = root.join("sandboxes").join(sandbox.as_str());
    let journal = RuntimeJournal::open(&sandbox_root.join("runtime"), &sandbox)?;
    #[cfg(target_os = "linux")]
    {
        let config =
            crate::linux::read_config(&sandbox_root.join("guardian/config.json"), &sandbox)?;
        let effect = crate::linux::LinuxGuardianEffect::open(&sandbox_root, config)?;
        let mut guardian = Guardian::new(journal, effect);
        serve_guardian(&sandbox_root.join("guardian"), &mut guardian)?;
    }
    #[cfg(target_os = "macos")]
    {
        let config =
            crate::apple::read_config(&sandbox_root.join("guardian/config.json"), &sandbox)?;
        let effect = crate::apple::AppleGuardianEffect::open(&sandbox_root, config)?;
        let mut guardian = Guardian::new(journal, effect);
        serve_guardian(&sandbox_root.join("guardian"), &mut guardian)?;
    }
    #[cfg(target_os = "windows")]
    {
        let config =
            crate::windows::read_config(&sandbox_root.join("guardian/config.json"), &sandbox)?;
        let effect = crate::windows::WindowsGuardianEffect::open(&sandbox_root, config)?;
        let mut guardian = Guardian::new(journal, effect);
        serve_guardian(&sandbox_root.join("guardian"), &mut guardian)?;
    }
    Ok(())
}

pub fn host_call(root: &Path, request: HostRequest) -> Result<HostResponse> {
    let endpoint = root.join("api");
    let stopping = matches!(request, HostRequest::StopService);
    if let Err(error) = fs::symlink_metadata(&endpoint)
        && error.kind() == io::ErrorKind::NotFound
    {
        return Err(HostError::EndpointUnavailable(error));
    }
    let mut connection =
        LocalConnection::connect(&endpoint, API_TIMEOUT).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                HostError::EndpointUnavailable(error)
            }
            _ => HostError::Io(error),
        })?;
    let payload = serde_json::to_vec(&(HOST_API_VERSION, request))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(HostError::Invalid("host request exceeds control bound"));
    }
    connection.write_frame(
        &Frame {
            kind: FrameKind::Control,
            stream: 0,
            sequence: Counter::ONE,
            authentication: [0; AUTHENTICATION_BYTES],
            payload,
        },
        API_TIMEOUT,
    )?;
    let frame = connection
        .read_frame(API_TIMEOUT)?
        .ok_or(HostError::Invalid("host closed without a response"))?;
    let response = match parse_host_response(frame)? {
        HostResponse::Runtime {
            response: RuntimeResponse::OutputMetadata { page },
        } => HostResponse::Runtime {
            response: RuntimeResponse::Output {
                page: read_host_output_frames(&mut connection, page)?,
            },
        },
        HostResponse::Runtime {
            response: RuntimeResponse::Output { .. },
        } => {
            return Err(HostError::Invalid(
                "host output must use binary data frames",
            ));
        }
        response => response,
    };
    if stopping && connection.read_frame(Duration::from_secs(10))?.is_some() {
        return Err(HostError::Invalid(
            "host sent data after its terminal response",
        ));
    }
    Ok(response)
}

fn parse_host_request(frame: Frame) -> Result<HostRequest> {
    require_frame(&frame)?;
    let (version, request): (u16, HostRequest) = serde_json::from_slice(&frame.payload)?;
    if version != HOST_API_VERSION {
        return Err(HostError::Invalid("host API version mismatch"));
    }
    Ok(request)
}

fn host_response_frame(sequence: Counter, response: &HostResponse) -> Result<Frame> {
    let payload = serde_json::to_vec(&(HOST_API_VERSION, response))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(HostError::Invalid("host response exceeds control bound"));
    }
    Ok(Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence,
        authentication: [0; AUTHENTICATION_BYTES],
        payload,
    })
}

fn bounded_host_response_frame(sequence: Counter, response: &HostResponse) -> Result<Frame> {
    host_response_frame(sequence, response)
        .or_else(|error| host_response_frame(sequence, &rejected(error)))
}

fn write_host_response(
    connection: &mut LocalConnection,
    sequence: Counter,
    response: HostResponse,
) -> Result<()> {
    let HostResponse::Runtime {
        response: RuntimeResponse::Output { page },
    } = response
    else {
        connection.write_frame(
            &bounded_host_response_frame(sequence, &response)?,
            API_TIMEOUT,
        )?;
        return Ok(());
    };
    let (page, chunks) = match page.into_binary_parts() {
        Ok(parts) => parts,
        Err(error) => {
            connection.write_frame(
                &host_response_frame(sequence, &rejected(error.into()))?,
                API_TIMEOUT,
            )?;
            return Ok(());
        }
    };
    let total = page.validate_lengths()?;
    connection.write_frame(
        &host_response_frame(
            sequence,
            &HostResponse::Runtime {
                response: RuntimeResponse::OutputMetadata { page },
            },
        )?,
        API_TIMEOUT,
    )?;
    let credit = connection
        .read_frame(API_TIMEOUT)?
        .ok_or(HostError::Invalid("host output credit is missing"))?;
    if credit.kind != FrameKind::Credit
        || credit.stream != OUTPUT_DATA_STREAM
        || credit.sequence != Counter::ONE
        || credit.authentication != [0; AUTHENTICATION_BYTES]
        || credit.payload != (total as u64).to_be_bytes()
    {
        return Err(HostError::Invalid("host output credit is invalid"));
    }
    let mut data_sequence = Counter::ZERO;
    for bytes in chunks {
        data_sequence = data_sequence.next()?;
        connection.write_frame(
            &Frame {
                kind: FrameKind::Data,
                stream: OUTPUT_DATA_STREAM,
                sequence: data_sequence,
                authentication: [0; AUTHENTICATION_BYTES],
                payload: bytes,
            },
            API_TIMEOUT,
        )?;
    }
    data_sequence = data_sequence.next()?;
    connection.write_frame(
        &Frame {
            kind: FrameKind::End,
            stream: OUTPUT_DATA_STREAM,
            sequence: data_sequence,
            authentication: [0; AUTHENTICATION_BYTES],
            payload: Vec::new(),
        },
        API_TIMEOUT,
    )?;
    Ok(())
}

fn read_host_output_frames(
    connection: &mut LocalConnection,
    metadata: EvidencePageMetadata,
) -> Result<EvidencePage> {
    let total = metadata.validate_lengths()?;
    connection.write_frame(
        &Frame {
            kind: FrameKind::Credit,
            stream: OUTPUT_DATA_STREAM,
            sequence: Counter::ONE,
            authentication: [0; AUTHENTICATION_BYTES],
            payload: (total as u64).to_be_bytes().to_vec(),
        },
        API_TIMEOUT,
    )?;
    let mut chunks = Vec::with_capacity(metadata.chunks.len());
    for (index, chunk) in metadata.chunks.iter().enumerate() {
        let frame = connection
            .read_frame(API_TIMEOUT)?
            .ok_or(HostError::Invalid("host output data is incomplete"))?;
        if frame.kind != FrameKind::Data
            || frame.stream != OUTPUT_DATA_STREAM
            || frame.sequence != Counter::try_from(index as u64 + 1)?
            || frame.authentication != [0; AUTHENTICATION_BYTES]
            || frame.payload.len() != chunk.length as usize
        {
            return Err(HostError::Invalid("host output data frame is invalid"));
        }
        chunks.push(frame.payload);
    }
    let end = connection
        .read_frame(API_TIMEOUT)?
        .ok_or(HostError::Invalid("host output stream end is missing"))?;
    if end.kind != FrameKind::End
        || end.stream != OUTPUT_DATA_STREAM
        || end.sequence != Counter::try_from(metadata.chunks.len() as u64 + 1)?
        || end.authentication != [0; AUTHENTICATION_BYTES]
    {
        return Err(HostError::Invalid("host output stream end is invalid"));
    }
    Ok(metadata.with_binary_parts(chunks)?)
}

fn parse_host_response(frame: Frame) -> Result<HostResponse> {
    require_frame(&frame)?;
    if frame.sequence != Counter::ONE {
        return Err(HostError::Invalid("host response sequence mismatch"));
    }
    let (version, response): (u16, HostResponse) = serde_json::from_slice(&frame.payload)?;
    if version != HOST_API_VERSION {
        return Err(HostError::Invalid("host API version mismatch"));
    }
    Ok(response)
}

fn require_frame(frame: &Frame) -> Result<()> {
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence == Counter::ZERO
        || frame.authentication != [0; AUTHENTICATION_BYTES]
    {
        return Err(HostError::Invalid("host API frame is malformed"));
    }
    Ok(())
}

fn catalog_limits() -> CatalogLimits {
    CatalogLimits {
        identities: counter(4096),
        operations: counter(1_000_000),
        grants: counter(100_000),
        usage_records: counter(1_000_000),
        image_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
        resources: Resources {
            vcpus: counter(4096),
            memory_mib: counter(4 * 1024 * 1024),
            disk_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
            output_bytes: counter(1024 * 1024 * 1024 * 1024),
            processes: counter(1_000_000),
        },
    }
}

fn runtime_limits(resources: &Resources) -> RuntimeLimits {
    RuntimeLimits {
        identities: counter(1_000_000),
        operations: counter(1_000_000),
        observations: counter(1_000_000),
        events: counter(20_000_000),
        chunks: counter(10_000_000),
        pins: counter(1_000_000),
        output_bytes: resources.output_bytes,
        disks: counter(100_000),
        disk_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
        disk_headroom_bytes: counter(64 * 1024 * 1024),
    }
}

fn counter(value: u64) -> Counter {
    Counter::try_from(value).expect("static host bound is a safe integer")
}

fn unix_millis() -> Result<Counter> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HostError::Invalid("host wall clock is before the Unix epoch"))?
        .as_millis();
    let millis = u64::try_from(millis)
        .map_err(|_| HostError::Invalid("host wall clock exceeds the counter range"))?;
    Ok(Counter::try_from(millis)?)
}

fn complete_checkpoint_capture(
    catalog: &mut HostCatalog,
    id: &CheckpointId,
    request_digest: &Digest,
    captured: crate::checkpoints::CaptureResult,
) -> Result<Checkpoint> {
    match captured.full {
        Some(full) => Ok(catalog.complete_full_checkpoint(
            id,
            request_digest,
            captured.disk_digest,
            captured.manifest_digest,
            CheckpointConsistency::Filesystem,
            full,
        )?),
        None => Ok(catalog.complete_checkpoint(
            id,
            request_digest,
            captured.disk_digest,
            captured.manifest_digest,
            CheckpointConsistency::Filesystem,
        )?),
    }
}

fn suspension_identities(intent: &LifecycleIntent) -> Result<(CheckpointId, OperationId)> {
    let identity = digest(
        Domain::Checkpoint,
        &(
            "sandsurf-suspension-identities-v1",
            &intent.sandbox_id,
            &intent.operation_id,
            intent.revision,
            &intent.request_digest,
        ),
    )?;
    let suffix = &identity.as_str()[..40];
    Ok((
        format!("suspend-{suffix}").try_into()?,
        format!("suspend-capture-{suffix}").try_into()?,
    ))
}

fn reserve_ephemeral_port(address: &str) -> Result<u16> {
    let listener = std::net::TcpListener::bind((address, 0))?;
    Ok(listener.local_addr()?.port())
}

fn directory_usage(root: &Path) -> Result<(Counter, Counter)> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let mut logical = 0_u64;
    let mut allocated = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            logical = logical
                .checked_add(metadata.len())
                .ok_or(HostError::Invalid("disk usage overflow"))?;
            #[cfg(unix)]
            {
                allocated = allocated
                    .checked_add(metadata.blocks().saturating_mul(512))
                    .ok_or(HostError::Invalid("allocated disk usage overflow"))?;
            }
            #[cfg(not(unix))]
            {
                allocated = allocated
                    .checked_add(metadata.len())
                    .ok_or(HostError::Invalid("allocated disk usage overflow"))?;
            }
        }
    }
    Ok((Counter::try_from(logical)?, Counter::try_from(allocated)?))
}

fn validate_workload_retry(
    operation: Operation,
    historical_grant: &Grant,
    retry: Mutation,
    capability: Capability,
    scope_digest: &Digest,
) -> Result<Operation> {
    if operation.request != retry
        || operation.capability != capability
        || historical_grant.id != operation.request.grant_id
        || historical_grant.sandbox_id != operation.request.sandbox_id
        || historical_grant.capability != capability
        || &historical_grant.scope_digest != scope_digest
    {
        return Err(sandsurf_state::Error::Conflict(
            "workload operation retry changed its identity or authority",
        )
        .into());
    }
    // Revocation affects new admission, not immutable history. Returning this
    // operation does not restore or delegate the historical grant.
    Ok(operation)
}

fn runtime_operation(
    client: &GuardianClient,
    sandbox: &SandboxId,
    operation: &OperationId,
) -> Result<Option<RuntimeOperationRecord>> {
    match client.runtime(
        sandbox.clone(),
        RuntimeRequest::Operation {
            operation_id: operation.clone(),
        },
    )? {
        RuntimeResponse::Operation { operation } => Ok(operation),
        _ => Err(HostError::Invalid(
            "guardian returned the wrong runtime operation response",
        )),
    }
}

fn random_id(prefix: &str) -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| HostError::Invalid("host entropy unavailable"))?;
    let mut value = String::with_capacity(prefix.len() + 33);
    value.push_str(prefix);
    value.push('-');
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("string formatting cannot fail");
    }
    Ok(value)
}

pub(crate) fn native_guest_architecture() -> GuestArchitecture {
    if cfg!(target_arch = "aarch64") {
        GuestArchitecture::Arm64
    } else {
        GuestArchitecture::Amd64
    }
}

#[cfg(target_os = "windows")]
fn workload_disk_name() -> &'static str {
    "workload-state.vhdx"
}

#[cfg(not(target_os = "windows"))]
fn workload_disk_name() -> &'static str {
    "workload-state.ext4"
}

#[cfg(target_os = "windows")]
fn control_disk_name() -> &'static str {
    "control-state.vhdx"
}

#[cfg(not(target_os = "windows"))]
fn control_disk_name() -> &'static str {
    "control-state.ext4"
}

fn error_category(error: &HostError) -> &'static str {
    match error {
        HostError::Io(_) | HostError::EndpointUnavailable(_) => "transport",
        HostError::Json(_) | HostError::Contract(_) | HostError::Invalid(_) => "protocol",
        #[cfg(target_os = "linux")]
        HostError::Linux(_) => "native",
        #[cfg(target_os = "macos")]
        HostError::Apple(_) => "native",
        #[cfg(target_os = "windows")]
        HostError::Windows(_) => "native",
        HostError::State(_) => "state",
        HostError::Control(_) | HostError::GuardianStartup(_) => "guardian",
        HostError::Workspace(crate::workspace::WorkspaceError::Conflict(_)) => "conflict",
        HostError::Workspace(crate::workspace::WorkspaceError::Capacity(_)) => "capacity",
        HostError::Workspace(_) => "workspace",
        HostError::Secret(crate::secrets::SecretError::Conflict(_)) => "conflict",
        HostError::Secret(crate::secrets::SecretError::Invalid(_)) => "protocol",
        HostError::Secret(_) => "secret",
        HostError::Checkpoint(crate::checkpoints::CheckpointError::Invalid(_)) => "conflict",
        HostError::Checkpoint(_) => "checkpoint",
        HostError::Image(_) => "image",
    }
}

#[cfg(unix)]
fn open_guardian_log(path: &Path) -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(windows)]
fn open_guardian_log(path: &Path) -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?)
}

#[cfg(unix)]
fn prepare_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(HostError::Invalid(
            "host state directory must be private and non-symbolic",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn prepare_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        sandsurf_native::local::create_private_directory(path)?;
    }
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(HostError::Invalid(
            "host state path is not a private directory",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn oversized_response_is_reported_instead_of_closing_the_connection() {
        let oversized = HostResponse::Rejected {
            category: "fixture".into(),
            message: "x".repeat(MAX_CONTROL_BYTES),
        };
        let frame = bounded_host_response_frame(Counter::ONE, &oversized).unwrap();
        assert!(matches!(
            parse_host_response(frame).unwrap(),
            HostResponse::Rejected { category, message }
                if category == "protocol" && message.contains("control bound")
        ));
    }

    #[test]
    fn local_host_output_uses_credit_limited_binary_frames() {
        let parent = if cfg!(target_os = "macos") {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let root = parent.join(format!(
            "ssout-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        prepare_directory(&root).unwrap();
        let bytes = vec![255; 64 * 1024];
        let content = bytes_digest(&bytes);
        let boundary = Counter::try_from(bytes.len() as u64).unwrap();
        let page = EvidencePage {
            after: Counter::ZERO,
            cursor: boundary,
            available: boundary,
            chunks: vec![EvidenceChunk {
                sequence: Counter::ONE,
                offset: Counter::ZERO,
                stream: Stream::Stdout,
                bytes: bytes.clone(),
                bytes_digest: content.clone(),
                chain_digest: content,
            }],
        };
        prepare_directory(&root.join("api")).unwrap();
        let listener = LocalListener::bind(&root.join("api")).unwrap();
        let server = thread::spawn(move || {
            let mut connection = listener.accept(Duration::from_secs(5)).unwrap();
            let request = connection.read_frame(API_TIMEOUT).unwrap().unwrap();
            write_host_response(
                &mut connection,
                request.sequence,
                HostResponse::Runtime {
                    response: RuntimeResponse::Output { page },
                },
            )
            .unwrap();
        });
        let response = host_call(&root, HostRequest::Inspect).unwrap();
        let HostResponse::Runtime {
            response: RuntimeResponse::Output { page },
        } = response
        else {
            panic!("host did not return binary output");
        };
        assert_eq!(page.chunks[0].bytes, bytes);
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn idle_client_cannot_block_other_host_requests() {
        // Darwin's AF_UNIX address is short; use the stable sticky temp root
        // rather than its long per-process TMPDIR alias for this IPC fixture.
        let parent = if cfg!(target_os = "macos") {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let root = parent.join(format!(
            "ssing-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        prepare_directory(&root).unwrap();
        let service_root = root.clone();
        let server =
            thread::spawn(move || serve_host(&service_root, std::env::current_exe().unwrap()));
        let endpoint = root.join("api");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let idle = loop {
            match LocalConnection::connect(&endpoint, Duration::from_millis(100)) {
                Ok(connection) => break connection,
                Err(error)
                    if std::time::Instant::now() < deadline
                        && matches!(
                            error.kind(),
                            io::ErrorKind::NotFound
                                | io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::TimedOut
                        ) =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => {
                    let service = if server.is_finished() {
                        format!("{:?}", server.join().unwrap())
                    } else {
                        "still starting".into()
                    };
                    panic!("host did not start: {error}; service: {service}");
                }
            }
        };
        thread::sleep(Duration::from_millis(100));
        let (ready, observed) = mpsc::channel();
        let client_root = root.clone();
        thread::spawn(move || {
            let _ = ready.send(host_call(&client_root, HostRequest::Inspect));
        });
        let result = observed
            .recv_timeout(Duration::from_secs(3))
            .expect("idle client stalled the host")
            .unwrap();
        assert!(matches!(result, HostResponse::Inspection { .. }));
        drop(idle);
        assert!(matches!(
            host_call(&root, HostRequest::StopService).unwrap(),
            HostResponse::Complete
        ));
        server.join().unwrap().unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    fn count(value: u64) -> Counter {
        value.try_into().unwrap()
    }

    fn historical_retry() -> (Operation, Grant, Digest) {
        let sandbox: SandboxId = "box".try_into().unwrap();
        let operation_id: OperationId = "mkdir-operation".try_into().unwrap();
        let grant_id: GrantId = "write-files".try_into().unwrap();
        let scope = bytes_digest(b"write-scope");
        let request = WorkloadRequest::Filesystem {
            request: Box::new(FilesystemRequest::Mkdir {
                path: GuestPath::try_from("/workspace/new").unwrap(),
                recursive: false,
            }),
        };
        let mutation = Mutation::new(
            sandbox.clone(),
            Counter::ONE,
            operation_id,
            grant_id.clone(),
            count(3),
            request,
        )
        .unwrap();
        (
            Operation {
                request: mutation,
                capability: Capability::WriteFiles,
                delivery: Delivery::Applied,
                evidence_digest: Some(bytes_digest(b"applied")),
            },
            Grant {
                id: grant_id,
                sandbox_id: sandbox,
                capability: Capability::WriteFiles,
                scope_digest: scope.clone(),
                revision: count(2),
                revoked: true,
            },
            scope,
        )
    }

    #[test]
    fn exact_workload_retry_returns_history_after_grant_revocation() {
        let (operation, grant, scope) = historical_retry();
        assert_eq!(
            validate_workload_retry(
                operation.clone(),
                &grant,
                operation.request.clone(),
                Capability::WriteFiles,
                &scope,
            )
            .unwrap(),
            operation
        );

        let changed = Mutation::new(
            operation.request.sandbox_id.clone(),
            operation.request.epoch,
            operation.request.operation_id.clone(),
            operation.request.grant_id.clone(),
            operation.request.expected_revision,
            WorkloadRequest::Filesystem {
                request: Box::new(FilesystemRequest::Mkdir {
                    path: GuestPath::try_from("/workspace/changed").unwrap(),
                    recursive: false,
                }),
            },
        )
        .unwrap();
        assert!(
            validate_workload_retry(operation, &grant, changed, Capability::WriteFiles, &scope,)
                .is_err()
        );
    }
}
