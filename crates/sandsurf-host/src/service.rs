use crate::api::{
    HOST_API_VERSION, HostInspection, HostRequest, HostResponse, OciSource, ReservationView,
    SandboxView,
};
#[cfg(not(target_os = "linux"))]
use sandsurf_control::{EffectOutcome, GuardianEffect, LifecycleEffect, Result as ControlResult};
use sandsurf_control::{
    Guardian, GuardianClient, HostGuardianLink, HostLifecycleResult, apply_lifecycle,
    serve_guardian,
};
use sandsurf_machine::GuestArchitecture;
#[cfg(not(target_os = "linux"))]
use sandsurf_machine::MachineOutcome;
use sandsurf_native::local::{LocalConnection, LocalListener};
use sandsurf_protocol::*;
use sandsurf_state::{
    Approval, CatalogLimits, GrantChange, HostCatalog, ReservationState, RuntimeJournal,
    RuntimeLimits, SandboxRecord,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

// Full-state capture/restore includes bounded memory and disk persistence plus
// native recovery probes. Transport waits must cover that operation without
// converting a still-running, identity-bound mutation into a client timeout.
const API_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum HostError {
    Io(io::Error),
    Json(serde_json::Error),
    State(sandsurf_state::Error),
    Control(sandsurf_control::Error),
    Contract(sandsurf_protocol::Invalid),
    Workspace(crate::workspace::WorkspaceError),
    Secret(crate::secrets::SecretError),
    Checkpoint(crate::checkpoints::CheckpointError),
    #[cfg(target_os = "linux")]
    Linux(crate::linux::LinuxError),
    Invalid(&'static str),
}

impl fmt::Display for HostError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "host I/O: {error}"),
            Self::Json(error) => write!(output, "host message: {error}"),
            Self::State(error) => write!(output, "host catalog: {error}"),
            Self::Control(error) => write!(output, "host/guardian: {error}"),
            Self::Contract(error) => write!(output, "host contract: {error}"),
            Self::Workspace(error) => error.fmt(output),
            Self::Secret(error) => error.fmt(output),
            Self::Checkpoint(error) => error.fmt(output),
            #[cfg(target_os = "linux")]
            Self::Linux(error) => error.fmt(output),
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
#[cfg(target_os = "linux")]
impl From<crate::linux::LinuxError> for HostError {
    fn from(value: crate::linux::LinuxError) -> Self {
        Self::Linux(value)
    }
}

pub type Result<T> = std::result::Result<T, HostError>;

pub struct HostService {
    root: PathBuf,
    catalog: HostCatalog,
    executable: PathBuf,
    verified_guardians: BTreeSet<SandboxId>,
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
            verified_guardians: BTreeSet::new(),
            verified_workload_defaults: BTreeMap::new(),
            workspace,
            secrets,
        };
        service.recover_checkpoint_barriers();
        Ok(service)
    }

    pub fn endpoint(&self) -> PathBuf {
        self.root.join("api")
    }

    pub fn handle(&mut self, request: HostRequest) -> HostResponse {
        match self.handle_inner(request) {
            Ok(response) => response,
            Err(error) => HostResponse::Rejected {
                category: error_category(&error).into(),
                message: error.to_string(),
            },
        }
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
                self.catalog.active_grant(
                    &request.sandbox_id,
                    request.expected_revision,
                    Capability::Checkpoint,
                    &scope_digest,
                )?;
                self.provision_guardian(&request.sandbox_id)?;
                let inspection = GuardianClient::new(self.guardian_endpoint(&request.sandbox_id))
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
                let request_digest =
                    digest(Domain::Checkpoint, &("sandsurf-checkpoint-v1", &request))?;
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
                            &sandbox_root.join("disks/workload-state.ext4"),
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
                            &sandbox_root.join("disks/workload-state.ext4"),
                            &sandbox_root.join("disks/control-state.ext4"),
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
                #[cfg(target_os = "linux")]
                let image = crate::images::import_oci(
                    &self.root,
                    &self.executable,
                    &source,
                    &platform,
                    &operation_id,
                    &request_digest,
                    registry_credential.as_ref().map(|value| value.as_slice()),
                )?;
                #[cfg(not(target_os = "linux"))]
                return Err(HostError::Invalid(
                    "OCI VM-image materialization is unqualified on this host build",
                ));
                #[cfg(target_os = "linux")]
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
                #[cfg(target_os = "linux")]
                let image = crate::images::publish_checkpoint(
                    &self.root,
                    &checkpoint,
                    inclusion,
                    &operation_id,
                    &request_digest,
                )?;
                #[cfg(not(target_os = "linux"))]
                return Err(HostError::Invalid(
                    "derived VM-image publication is unqualified on this host build",
                ));
                #[cfg(target_os = "linux")]
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
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::WriteFiles,
                    &scope_digest,
                )?;
                Ok(HostResponse::HostTreeCapture {
                    capture: self.workspace.capture(
                        sandbox_id,
                        operation_id,
                        &source,
                        &exclusions,
                        maximum_bytes,
                        approval_id,
                    )?,
                })
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
                expected_revision,
                scope_digest,
                transfer,
                approval_id,
            } => {
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                self.workspace
                    .begin_upload(sandbox_id, transfer, approval_id)?;
                Ok(HostResponse::Complete)
            }
            HostRequest::WriteHostBlob {
                sandbox_id,
                expected_revision,
                scope_digest,
                transfer,
                offset,
                bytes,
            } => {
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                self.workspace
                    .write_upload(&sandbox_id, &transfer, offset, &bytes)?;
                Ok(HostResponse::Complete)
            }
            HostRequest::CommitHostBlob {
                sandbox_id,
                expected_revision,
                scope_digest,
                transfer,
            } => {
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                self.workspace.commit_upload(&sandbox_id, &transfer)?;
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
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ApplyToHost,
                    &scope_digest,
                )?;
                Ok(HostResponse::HostApply {
                    report: self.workspace.apply(
                        sandbox_id,
                        operation_id,
                        &destination,
                        change_set,
                        approval_id,
                    )?,
                })
            }
            HostRequest::CreateSandbox {
                sandbox_id,
                image_digest,
                resources,
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
                let approval = Approval {
                    id: approval_id,
                    request_digest: digest(
                        Domain::Sandbox,
                        &(&sandbox_id, &image_digest, &resources, &operation_id),
                    )?,
                };
                self.catalog.create_sandbox(
                    sandbox_id.clone(),
                    image_digest,
                    resources,
                    operation_id.clone(),
                    approval,
                )?;
                #[cfg(target_os = "linux")]
                self.provision_guardian_with_config(&sandbox_id, Some(&native_config))?;
                #[cfg(not(target_os = "linux"))]
                self.provision_guardian(&sandbox_id)?;
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
                let request_digest = digest(
                    Domain::Checkpoint,
                    &(
                        "sandsurf-filesystem-fork-v1",
                        &checkpoint_id,
                        &sandbox_id,
                        &resources,
                        &operation_id,
                    ),
                )?;
                self.catalog.create_sandbox_from_checkpoint(
                    sandbox_id.clone(),
                    &checkpoint_id,
                    resources,
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
                crate::checkpoints::materialize_fork(
                    &self.root.join("checkpoints"),
                    &checkpoint,
                    &disks.join("workload-state.ext4"),
                )?;
                #[cfg(target_os = "linux")]
                self.provision_guardian_with_config(&sandbox_id, Some(&native_config))?;
                #[cfg(not(target_os = "linux"))]
                self.provision_guardian(&sandbox_id)?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &operation_id)?;
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
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::Checkpoint,
                    &scope_digest,
                )?;
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
                let checkpoint = self
                    .catalog
                    .checkpoint(&checkpoint_id)?
                    .ok_or(HostError::Invalid("rollback checkpoint disappeared"))?;
                let evidence = crate::checkpoints::rollback(
                    &self.root.join("checkpoints"),
                    &checkpoint,
                    &self
                        .sandbox_root(&sandbox_id)
                        .join("disks/workload-state.ext4"),
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
                grant_id,
                expected_revision,
                capability,
                scope_digest,
                revoked,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Grant,
                    &(
                        &sandbox_id,
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
                self.provision_guardian(&sandbox_id)?;
                let authorization = self
                    .catalog
                    .authorize_configuration(&sandbox_id, grant.revision)?;
                let operation = GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                    .configure(authorization)?;
                if operation.delivery != Delivery::Applied
                    || operation.command.revision != grant.revision
                {
                    return Err(HostError::Invalid(
                        "guardian did not apply the host configuration revision",
                    ));
                }
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
                let mut configuration = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox does not exist"))?
                    .runtime_configuration;
                configuration.network = policy;
                let request_digest = digest(
                    Domain::Grant,
                    &(
                        "sandsurf-runtime-configuration-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &configuration,
                    ),
                )?;
                let revision = self.catalog.set_runtime_configuration(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    configuration,
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration(&sandbox_id, revision)?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox disappeared from catalog"))?;
                Ok(HostResponse::Configuration {
                    revision,
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
                let request_digest = digest(
                    Domain::Grant,
                    &(
                        "sandsurf-runtime-configuration-v1",
                        &sandbox_id,
                        &operation_id,
                        expected_revision,
                        &configuration,
                    ),
                )?;
                let revision = self.catalog.set_runtime_configuration(
                    &sandbox_id,
                    &operation_id,
                    expected_revision,
                    configuration,
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration(&sandbox_id, revision)?;
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
                self.catalog.record_host_approval(Approval {
                    id: approval_id,
                    request_digest,
                })?;
                Ok(HostResponse::Secret {
                    secret: self.secrets.put(secret_id, &bytes)?,
                })
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
                let record = sandsurf_state::SecretDeliveryRecord {
                    operation_id: operation_id.clone(),
                    sandbox_id: sandbox_id.clone(),
                    request_digest: request_digest.clone(),
                    delivery: delivery.clone(),
                    applied: false,
                };
                let record = self.catalog.admit_secret_delivery(
                    record,
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
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
            HostRequest::UpdateResources {
                sandbox_id,
                operation_id,
                expected_revision,
                resources,
                live,
                approval_id,
            } => {
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
                let revision = self.catalog.update_live_resources(
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
                self.apply_configuration(&sandbox_id, revision)?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox disappeared from catalog"))?;
                Ok(HostResponse::Configuration {
                    revision,
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
                let grant = self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    capability,
                    &scope_digest,
                )?;
                let mutation = Mutation::new(
                    sandbox_id.clone(),
                    epoch,
                    operation_id,
                    grant.id,
                    expected_revision,
                    request,
                )?;
                self.provision_guardian(&sandbox_id)?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
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
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    capability,
                    &scope_digest,
                )?;
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
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                        .runtime(sandbox_id, RuntimeRequest::Operation { operation_id })?,
                })
            }
            HostRequest::GetProcess {
                sandbox_id,
                process_id,
            } => {
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                        .runtime(sandbox_id, RuntimeRequest::Process { process_id })?,
                })
            }
            HostRequest::ListProcesses { sandbox_id } => {
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                        .runtime(sandbox_id, RuntimeRequest::Processes)?,
                })
            }
            HostRequest::GetReceipt {
                sandbox_id,
                process_id,
            } => {
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                        .runtime(sandbox_id, RuntimeRequest::Receipt { process_id })?,
                })
            }
            HostRequest::ReadEvidence {
                sandbox_id,
                process_id,
                after,
                maximum,
            } => {
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id)).runtime(
                        sandbox_id,
                        RuntimeRequest::ReadOutput {
                            process_id,
                            after,
                            maximum,
                        },
                    )?,
                })
            }
            HostRequest::ReadPinnedEvidence {
                sandbox_id,
                pin_id,
                after,
                maximum,
            } => {
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id)).runtime(
                        sandbox_id,
                        RuntimeRequest::ReadPin {
                            pin_id,
                            after,
                            maximum,
                        },
                    )?,
                })
            }
            HostRequest::AcknowledgeReceipt {
                sandbox_id,
                process_id,
                receipt_digest,
                expected_revision,
                scope_digest,
            } => {
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ReleaseEvidence,
                    &scope_digest,
                )?;
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id)).runtime(
                        sandbox_id,
                        RuntimeRequest::AcknowledgeReceipt {
                            process_id,
                            receipt_digest,
                        },
                    )?,
                })
            }
            HostRequest::PinEvidence {
                sandbox_id,
                process_id,
                receipt_digest,
                pin_id,
                expected_revision,
                scope_digest,
            } => {
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ReleaseEvidence,
                    &scope_digest,
                )?;
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id)).runtime(
                        sandbox_id,
                        RuntimeRequest::Pin {
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
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    Capability::ReleaseEvidence,
                    &scope_digest,
                )?;
                self.provision_guardian(&sandbox_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&sandbox_id));
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
            images: {
                #[cfg(target_os = "linux")]
                {
                    crate::images::qualification()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Qualification::Unqualified {
                        reasons: vec![
                            "OCI VM-image materialization is not implemented for this native driver"
                                .into(),
                        ],
                    }
                }
            },
            guest_platform: format!(
                "linux/{}",
                match native_guest_architecture() {
                    GuestArchitecture::Amd64 => "amd64",
                    GuestArchitecture::Arm64 => "arm64",
                }
            ),
        }
    }

    fn apply_lifecycle_intent(
        &mut self,
        intent: &LifecycleIntent,
        endpoint: PathBuf,
    ) -> Result<HostLifecycleResult> {
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
                    &sandbox_root.join("disks/workload-state.ext4"),
                    &sandbox_root.join("disks/control-state.ext4"),
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

    fn provision_guardian(&mut self, sandbox: &SandboxId) -> Result<()> {
        #[cfg(target_os = "linux")]
        return self.provision_guardian_with_config(sandbox, None);
        #[cfg(not(target_os = "linux"))]
        self.provision_guardian_inner(sandbox)
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

    fn provision_guardian_inner(&self, sandbox: &SandboxId) -> Result<()> {
        let root = self.sandbox_root(sandbox);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        prepare_directory(&root.join("disks"))?;
        prepare_directory(&root.join("output"))?;
        let runtime = root.join("runtime");
        if !runtime.exists() {
            RuntimeJournal::create(
                &runtime,
                sandbox.clone(),
                runtime_limits(),
                self.catalog.authority_binding().clone(),
            )?;
        }
        let endpoint = self.guardian_endpoint(sandbox);
        if GuardianClient::new(endpoint.clone())
            .inspect(sandbox.clone(), None)
            .is_ok()
        {
            return Ok(());
        }
        let guardian_log = open_guardian_log(&root.join("guardian/guardian.log"))?;
        Command::new(&self.executable)
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
            if std::time::Instant::now() >= deadline {
                return Err(HostError::Invalid("guardian did not become reachable"));
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
        Ok(SandboxView {
            #[cfg(target_os = "linux")]
            workload_defaults,
            #[cfg(not(target_os = "linux"))]
            workload_defaults: crate::api::WorkloadDefaultsView {
                environment: Default::default(),
                user: Some("agent".into()),
                working_directory: Some("/workspace".into()),
                entrypoint: Vec::new(),
                command: Vec::new(),
            },
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
    loop {
        let mut connection = match listener.accept(Duration::from_secs(1)) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error.into()),
        };
        let frame = match connection.read_frame(API_TIMEOUT) {
            Ok(Some(value)) => value,
            Ok(None) | Err(_) => continue,
        };
        let sequence = frame.sequence;
        let parsed = parse_host_request(frame);
        let stopping = matches!(&parsed, Ok(HostRequest::StopService));
        let response = parsed
            .map(|request| service.handle(request))
            .unwrap_or_else(|error| HostResponse::Rejected {
                category: error_category(&error).into(),
                message: error.to_string(),
            });
        let _ = connection.write_frame(&host_response_frame(sequence, &response)?, API_TIMEOUT);
        if stopping {
            return Ok(());
        }
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
    #[cfg(not(target_os = "linux"))]
    let mut guardian = Guardian::new(journal, UnqualifiedEffect);
    #[cfg(not(target_os = "linux"))]
    serve_guardian(&sandbox_root.join("guardian"), &mut guardian)?;
    Ok(())
}

pub fn host_call(root: &Path, request: HostRequest) -> Result<HostResponse> {
    let mut connection = LocalConnection::connect(&root.join("api"), API_TIMEOUT)?;
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
    parse_host_response(frame)
}

#[cfg(not(target_os = "linux"))]
struct UnqualifiedEffect;
#[cfg(not(target_os = "linux"))]
impl GuardianEffect for UnqualifiedEffect {
    fn dispatch(&mut self, _: &Mutation, _: Capability) -> EffectOutcome {
        EffectOutcome::NotApplied(bytes_digest(b"native-guest-driver-unqualified"))
    }

    fn transition(
        &mut self,
        _: &LifecycleCommand,
        _: Option<&MachineObservation>,
    ) -> LifecycleEffect {
        MachineOutcome::NotApplied(bytes_digest(b"native-machine-driver-unqualified"))
    }

    fn query(&mut self, _: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        Err(sandsurf_control::Error::Unsupported(
            "guest is unavailable because this native configuration is unqualified",
        ))
    }
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
        resources: Resources {
            vcpus: counter(4096),
            memory_mib: counter(4 * 1024 * 1024),
            disk_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
            output_bytes: counter(1024 * 1024 * 1024 * 1024),
            processes: counter(1_000_000),
        },
    }
}

fn runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        identities: counter(1_000_000),
        operations: counter(1_000_000),
        observations: counter(1_000_000),
        chunks: counter(10_000_000),
        pins: counter(1_000_000),
        output_bytes: counter(1024 * 1024 * 1024 * 1024),
        disks: counter(100_000),
        disk_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
        disk_headroom_bytes: counter(64 * 1024 * 1024),
    }
}

fn counter(value: u64) -> Counter {
    Counter::try_from(value).expect("static host bound is a safe integer")
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

fn error_category(error: &HostError) -> &'static str {
    match error {
        HostError::Io(_) => "transport",
        HostError::Json(_) | HostError::Contract(_) | HostError::Invalid(_) => "protocol",
        #[cfg(target_os = "linux")]
        HostError::Linux(_) => "native",
        HostError::State(_) => "state",
        HostError::Control(_) => "guardian",
        HostError::Workspace(crate::workspace::WorkspaceError::Conflict(_)) => "conflict",
        HostError::Workspace(crate::workspace::WorkspaceError::Capacity(_)) => "capacity",
        HostError::Workspace(_) => "workspace",
        HostError::Secret(crate::secrets::SecretError::Conflict(_)) => "conflict",
        HostError::Secret(crate::secrets::SecretError::Invalid(_)) => "protocol",
        HostError::Secret(_) => "secret",
        HostError::Checkpoint(crate::checkpoints::CheckpointError::Invalid(_)) => "conflict",
        HostError::Checkpoint(_) => "checkpoint",
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
