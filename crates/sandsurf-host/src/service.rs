use crate::api::OciSource;
use crate::api::{
    HOST_API_VERSION, HostInspection, HostRequest, HostResponse, MachineView, ReservationView,
};
use crate::guardian::{
    Guardian, GuardianClient, HostLifecycleResult, apply_lifecycle, serve_guardian,
};
use sandsurf_machine::GuestArchitecture;
use sandsurf_native::local::{LocalConnection, LocalListener};
use sandsurf_native::storage::object_name;
use sandsurf_protocol::*;
use sandsurf_state::{
    Approval, CatalogLimits, HostCatalog, MachineRecord, ReservationState, RuntimeJournal,
    RuntimeLimits,
};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::collections::BTreeSet;
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
// converting a still-running, identity-bound command into a client timeout.
const API_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_HOST_CONNECTIONS: usize = 64;

#[derive(Debug)]
pub enum HostError {
    Io(io::Error),
    EndpointUnavailable(io::Error),
    Json(serde_json::Error),
    State(sandsurf_state::Error),
    Control(crate::guardian::Error),
    Contract(sandsurf_protocol::Invalid),
    Artifact(crate::artifacts::ArtifactError),
    Secret(crate::secrets::SecretError),
    Snapshot(crate::snapshots::SnapshotError),
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
            Self::Artifact(error) => error.fmt(output),
            Self::Secret(error) => error.fmt(output),
            Self::Snapshot(error) => error.fmt(output),
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
impl From<crate::guardian::Error> for HostError {
    fn from(value: crate::guardian::Error) -> Self {
        Self::Control(value)
    }
}
impl From<sandsurf_protocol::Invalid> for HostError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}
impl From<crate::artifacts::ArtifactError> for HostError {
    fn from(value: crate::artifacts::ArtifactError) -> Self {
        Self::Artifact(value)
    }
}
impl From<crate::secrets::SecretError> for HostError {
    fn from(value: crate::secrets::SecretError) -> Self {
        Self::Secret(value)
    }
}
impl From<crate::snapshots::SnapshotError> for HostError {
    fn from(value: crate::snapshots::SnapshotError) -> Self {
        Self::Snapshot(value)
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
    verified_guardians: BTreeSet<MachineId>,
    artifacts: Arc<crate::artifacts::ArtifactStore>,
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
        prepare_directory(&root.join("machines"))?;
        prepare_directory(&root.join("images"))?;
        prepare_directory(&root.join("snapshots"))?;
        prepare_directory(&root.join("transfers"))?;
        let artifacts = Arc::new(crate::artifacts::ArtifactStore::open(
            &root.join("transfers"),
        )?);
        let secrets = crate::secrets::SecretAuthority::open(&root.join("secrets"))?;
        let mut service = Self {
            root: root.to_path_buf(),
            catalog,
            executable,
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            verified_guardians: BTreeSet::new(),
            artifacts,
            secrets,
        };
        service.recover_snapshot_barriers();
        service.recover_image_releases();
        Ok(service)
    }

    pub fn endpoint(&self) -> PathBuf {
        self.root.join("api")
    }

    pub fn handle(&mut self, request: HostRequest) -> HostResponse {
        match self.route(request) {
            HostDispatch::Task(task) => self.complete_task(task.execute()).unwrap_or_else(rejected),
            response => response.finish(),
        }
    }

    fn route(&mut self, request: HostRequest) -> HostDispatch {
        let result = match request {
            HostRequest::ListHostTree {
                machine_id,
                operation_id,
                after,
                maximum,
            } => Ok(HostDispatch::ArtifactRead(Box::new(DeferredArtifactRead {
                store: Arc::clone(&self.artifacts),
                request: ArtifactRead::Entries {
                    machine_id,
                    operation_id,
                    after,
                    maximum,
                },
            }))),
            HostRequest::ReadHostTreeBlob {
                machine_id,
                operation_id,
                digest,
                offset,
                maximum,
            } => Ok(HostDispatch::ArtifactRead(Box::new(DeferredArtifactRead {
                store: Arc::clone(&self.artifacts),
                request: ArtifactRead::Blob {
                    machine_id,
                    operation_id,
                    digest,
                    offset,
                    maximum,
                },
            }))),
            request @ (HostRequest::CaptureHostTree { .. }
            | HostRequest::CaptureGuestTree { .. }) => self.prepare_artifact_capture(request),
            request @ HostRequest::ApplyArtifactToHost { .. } => {
                self.prepare_artifact_apply(request)
            }
            HostRequest::DeliverSecret {
                machine_id,
                operation_id,
                expected_revision,
                delivery,
                approval_id,
            } => self.prepare_secret_delivery(
                machine_id,
                operation_id,
                expected_revision,
                delivery,
                approval_id,
            ),
            HostRequest::RevokeSecret {
                machine_id,
                operation_id,
                expected_revision,
                secret,
                terminate_recipients,
                approval_id,
            } => self.prepare_secret_revocation(
                machine_id,
                operation_id,
                expected_revision,
                secret,
                terminate_recipients,
                approval_id,
            ),
            HostRequest::DispatchGuest {
                machine_id,
                generation,
                operation_id,
                request,
            } => self
                .prepare_guest_dispatch(machine_id, generation, operation_id, request)
                .map(|request| HostDispatch::Guest(Box::new(request))),
            HostRequest::Guest {
                machine_id,
                generation,
                request,
            } => self
                .prepare_guest_query(machine_id, generation, request)
                .map(|request| HostDispatch::Guest(Box::new(request))),
            request => match self.defer_runtime_read(&request) {
                Ok(Some(read)) => Ok(HostDispatch::Runtime(Box::new(read))),
                Ok(None) => self
                    .handle_inner(request)
                    .map(|response| HostDispatch::Ready(Box::new(response))),
                Err(error) => Err(error),
            },
        };
        result.unwrap_or_else(|error| HostDispatch::Ready(Box::new(rejected(error))))
    }

    fn prepare_guest_dispatch(
        &mut self,
        machine_id: MachineId,
        generation: Counter,
        operation_id: OperationId,
        request: GuestRequest,
    ) -> Result<DeferredGuest> {
        self.catalog.require_guest_access(&machine_id)?;
        if self.catalog.operation(&operation_id)?.is_some() {
            return Err(sandsurf_state::Error::Conflict(
                "operation identity already belongs to a host operation",
            )
            .into());
        }
        // Guest work routes to an existing machine owner. Owner creation and
        // native reconciliation belong to lifecycle/recovery, not each command
        // or PTY keystroke. A missing route is reported without replaying work.
        self.catalog.observe_activity(&machine_id, unix_millis()?)?;
        let command = GuestCommand::new(machine_id.clone(), generation, operation_id, request)?;
        Ok(DeferredGuest {
            endpoint: self.guardian_endpoint(&machine_id),
            request: DeferredGuestRequest::Dispatch(command),
        })
    }

    fn prepare_guest_query(
        &mut self,
        machine_id: MachineId,
        generation: Counter,
        request: GuestServiceRequest,
    ) -> Result<DeferredGuest> {
        if !matches!(
            request,
            GuestServiceRequest::FilesystemQuery { .. }
                | GuestServiceRequest::Operation { .. }
                | GuestServiceRequest::Process { .. }
                | GuestServiceRequest::Processes
                | GuestServiceRequest::ReadOutput { .. }
        ) {
            return Err(HostError::Invalid(
                "private guest control cannot use the application route",
            ));
        }
        if let GuestServiceRequest::FilesystemQuery { request } = &request
            && !request.is_query()
        {
            return Err(HostError::Invalid(
                "filesystem commands require execution admission",
            ));
        }
        self.catalog.require_guest_access(&machine_id)?;
        Ok(DeferredGuest {
            endpoint: self.guardian_endpoint(&machine_id),
            request: DeferredGuestRequest::Query {
                machine_id,
                generation,
                request,
            },
        })
    }

    fn defer_runtime_read(&mut self, request: &HostRequest) -> Result<Option<DeferredRuntimeRead>> {
        let (machine_id, query) = match request {
            HostRequest::ListEvents {
                machine_id,
                after,
                maximum,
            } => (
                machine_id.clone(),
                RuntimeRequest::Events {
                    after: *after,
                    maximum: *maximum,
                },
            ),
            HostRequest::GetProcess {
                machine_id,
                execution_id,
            } => (
                machine_id.clone(),
                RuntimeRequest::Process {
                    execution_id: execution_id.clone(),
                },
            ),
            HostRequest::ListProcesses { machine_id } => {
                (machine_id.clone(), RuntimeRequest::Processes)
            }
            HostRequest::GetReceipt {
                machine_id,
                execution_id,
            } => (
                machine_id.clone(),
                RuntimeRequest::Receipt {
                    execution_id: execution_id.clone(),
                },
            ),
            HostRequest::ReadEvidence {
                machine_id,
                execution_id,
                after,
                maximum,
            } => (
                machine_id.clone(),
                RuntimeRequest::ReadOutput {
                    execution_id: execution_id.clone(),
                    after: *after,
                    maximum: *maximum,
                },
            ),
            HostRequest::ReadOutputSegment {
                machine_id,
                segment_id,
                after,
                maximum,
            } => (
                machine_id.clone(),
                RuntimeRequest::ReadOutputSegment {
                    segment_id: segment_id.clone(),
                    after: *after,
                    maximum: *maximum,
                },
            ),
            HostRequest::GetOutputSegment {
                machine_id,
                segment_id,
            } => (
                machine_id.clone(),
                RuntimeRequest::OutputSegment {
                    segment_id: segment_id.clone(),
                },
            ),
            _ => return Ok(None),
        };
        self.provision_guardian(&machine_id)?;
        Ok(Some(DeferredRuntimeRead {
            endpoint: self.guardian_endpoint(&machine_id),
            machine_id,
            query,
        }))
    }

    fn handle_inner(&mut self, request: HostRequest) -> Result<HostResponse> {
        match request {
            HostRequest::Inspect => Ok(HostResponse::Inspection {
                value: self.inspect(),
            }),
            HostRequest::StopService => Ok(HostResponse::Complete),
            HostRequest::OpenEventStream { machine_id } => {
                self.provision_guardian(&machine_id)?;
                Ok(HostResponse::EventStream {
                    endpoint: self.guardian_endpoint(&machine_id),
                })
            }
            HostRequest::ListMachines { after, maximum } => {
                let records = self.catalog.machines(after.as_ref(), maximum)?;
                let mut values = Vec::with_capacity(records.len());
                for record in records {
                    values.push(self.view(record)?);
                }
                Ok(HostResponse::Machines { values })
            }
            HostRequest::GetMachine { machine_id } => {
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine does not exist"))?;
                Ok(HostResponse::Machine {
                    value: self.view(record)?,
                })
            }
            HostRequest::GetHostOperation { operation_id } => Ok(HostResponse::HostOperation {
                value: self.catalog.operation(&operation_id)?,
            }),
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
            HostRequest::ListSnapshots { after, maximum } => Ok(HostResponse::Snapshots {
                values: self.catalog.snapshots(after.as_ref(), maximum)?,
            }),
            HostRequest::GetSnapshot { snapshot_id } => Ok(HostResponse::Snapshot {
                value: self
                    .catalog
                    .snapshot(&snapshot_id)?
                    .ok_or(HostError::Invalid("snapshot does not exist"))?,
            }),
            HostRequest::CreateSnapshot {
                request,
                approval_id,
            } => {
                let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request))?;
                let historical = self.catalog.operation(&request.operation_id)?.is_some();
                if !historical {
                    self.catalog
                        .require_revision(&request.machine_id, request.expected_revision)?;
                    self.provision_guardian(&request.machine_id)?;
                    let inspection =
                        GuardianClient::new(self.guardian_endpoint(&request.machine_id))
                            .inspect(request.machine_id.clone(), None)?;
                    let Observation::Current { value: machine } = inspection.observation else {
                        return Err(HostError::Invalid(
                            "snapshot requires a current machine observation",
                        ));
                    };
                    if machine.generation != request.expected_generation
                        || machine.applied_revision != request.expected_revision
                        || !matches!(machine.state, MachineState::Running | MachineState::Paused)
                    {
                        return Err(HostError::Invalid(
                            "snapshot requires the expected running or paused generation and revision",
                        ));
                    }
                }
                let admitted = self.catalog.admit_snapshot(
                    request.clone(),
                    Approval {
                        id: approval_id,
                        request_digest: request_digest.clone(),
                    },
                )?;
                if admitted.phase == SnapshotPhase::Ready {
                    return Ok(HostResponse::Snapshot { value: admitted });
                }
                self.provision_guardian(&request.machine_id)?;
                let capture_root = self.root.join("snapshots");
                if admitted.phase == SnapshotPhase::Capturing {
                    let client = GuardianClient::new(self.guardian_endpoint(&request.machine_id));
                    match request.kind {
                        SnapshotKind::Disk => {
                            client.native_snapshot(
                                request.machine_id.clone(),
                                NativeSnapshotRequest::FinishDisk {
                                    operation_id: request.operation_id.clone(),
                                },
                            )?;
                        }
                        SnapshotKind::Full => {
                            client.native_snapshot(
                                request.machine_id.clone(),
                                NativeSnapshotRequest::FinishFull {
                                    operation_id: request.operation_id.clone(),
                                },
                            )?;
                        }
                    }
                }
                let capturing = self.catalog.begin_snapshot(&request.id, &request_digest)?;
                if let Some(captured) =
                    crate::snapshots::published_filesystem(&capture_root, &capturing)?
                {
                    return Ok(HostResponse::Snapshot {
                        value: complete_snapshot_capture(
                            &mut self.catalog,
                            &request.id,
                            &request_digest,
                            captured,
                        )?,
                    });
                }
                let client = GuardianClient::new(self.guardian_endpoint(&request.machine_id));
                let machine_root = self.machine_root(&request.machine_id);
                let (captured, finished) = match request.kind {
                    SnapshotKind::Disk => {
                        let prepared = client.native_snapshot(
                            request.machine_id.clone(),
                            NativeSnapshotRequest::PrepareDisk {
                                operation_id: request.operation_id.clone(),
                            },
                        )?;
                        if !matches!(prepared, NativeSnapshotResponse::Complete { .. }) {
                            return Err(HostError::Invalid(
                                "guardian did not establish the native disk capture boundary",
                            ));
                        }
                        let captured = crate::snapshots::capture_filesystem(
                            &capture_root,
                            &capturing,
                            &machine_root.join("disks").join(system_disk_name()),
                        );
                        let finished = client
                            .native_snapshot(
                                request.machine_id.clone(),
                                NativeSnapshotRequest::FinishDisk {
                                    operation_id: request.operation_id.clone(),
                                },
                            )
                            .map(|response| {
                                matches!(response, NativeSnapshotResponse::Complete { .. })
                            });
                        (captured, finished)
                    }
                    SnapshotKind::Full => {
                        let prepared = client.native_snapshot(
                            request.machine_id.clone(),
                            NativeSnapshotRequest::PrepareFull {
                                snapshot_id: request.id.clone(),
                                operation_id: request.operation_id.clone(),
                            },
                        )?;
                        let NativeSnapshotResponse::Prepared { capture, processes } = prepared
                        else {
                            return Err(HostError::Invalid(
                                "guardian did not establish a full capture boundary",
                            ));
                        };
                        let captured = crate::snapshots::capture_full(
                            &capture_root,
                            &capturing,
                            &machine_root.join("disks").join(system_disk_name()),
                            &machine_root
                                .join("guardian/full-captures")
                                .join(object_name(request.operation_id.as_str())),
                            capture,
                            processes,
                        );
                        let finished = client
                            .native_snapshot(
                                request.machine_id.clone(),
                                NativeSnapshotRequest::FinishFull {
                                    operation_id: request.operation_id.clone(),
                                },
                            )
                            .map(|response| {
                                matches!(response, NativeSnapshotResponse::Complete { .. })
                            });
                        (captured, finished)
                    }
                };
                let captured = captured?;
                if !finished? {
                    return Err(HostError::Invalid(
                        "guardian did not release the snapshot capture boundary",
                    ));
                }
                Ok(HostResponse::Snapshot {
                    value: complete_snapshot_capture(
                        &mut self.catalog,
                        &request.id,
                        &request_digest,
                        captured,
                    )?,
                })
            }
            HostRequest::ImportOci {
                source,
                recipe,
                platform,
                operation_id,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Image,
                    &(
                        "sandsurf-import-oci-v2",
                        &source,
                        &recipe,
                        &platform,
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
                    crate::images::OciBuildInput {
                        source: &source,
                        recipe: &recipe,
                        platform: &platform,
                    },
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
            HostRequest::ImportNativeImage {
                manifest_path,
                manifest_digest,
                operation_id,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Image,
                    &(
                        "sandsurf-import-native-image-v1",
                        &manifest_path,
                        &manifest_digest,
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
                let image = crate::images::import_native(
                    &self.root,
                    &manifest_path,
                    &manifest_digest,
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
            HostRequest::PublishSnapshotImage {
                snapshot_id,
                allow_sensitive,
                operation_id,
                approval_id,
            } => {
                let snapshot = self
                    .catalog
                    .snapshot(&snapshot_id)?
                    .ok_or(HostError::Invalid("image snapshot does not exist"))?;
                let request_digest = digest(
                    Domain::Image,
                    &(
                        "sandsurf-publish-snapshot-image-v2",
                        &snapshot_id,
                        allow_sensitive,
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
                let image = crate::images::publish_snapshot(
                    &self.root,
                    &snapshot,
                    allow_sensitive,
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
            HostRequest::CaptureHostTree { .. } | HostRequest::CaptureGuestTree { .. } => {
                Err(HostError::Invalid(
                    "artifact capture requires owner admission and worker completion",
                ))
            }
            HostRequest::ListHostTree { .. } | HostRequest::ReadHostTreeBlob { .. } => Err(
                HostError::Invalid("artifact observations run outside the catalog owner"),
            ),
            HostRequest::ApplyArtifactToHost { .. } => Err(HostError::Invalid(
                "artifact publication runs outside the catalog owner",
            )),
            HostRequest::CreateMachine {
                machine_id,
                image_digest,
                resources,
                execution_defaults,
                lifetime,
                operation_id,
                approval_id,
            } => {
                #[cfg(target_os = "linux")]
                let native_config = crate::linux::prepare_config(
                    &self.root,
                    &self.executable,
                    &machine_id,
                    &image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "macos")]
                let native_config = crate::apple::prepare_config(
                    &self.root,
                    &self.executable,
                    &machine_id,
                    &image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "windows")]
                let native_config = crate::windows::prepare_config(
                    &self.root,
                    &self.executable,
                    &machine_id,
                    &image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "linux")]
                let image_defaults = crate::linux::execution_defaults(&self.root, &image_digest)?;
                #[cfg(target_os = "macos")]
                let image_defaults = crate::apple::execution_defaults(&self.root, &image_digest)?;
                #[cfg(target_os = "windows")]
                let image_defaults = crate::windows::execution_defaults(&self.root, &image_digest)?;
                let approval = Approval {
                    id: approval_id,
                    request_digest: digest(
                        Domain::Machine,
                        &(
                            &machine_id,
                            &image_digest,
                            &resources,
                            &execution_defaults,
                            &lifetime,
                            &operation_id,
                        ),
                    )?,
                };
                self.catalog.create_machine(
                    sandsurf_state::MachineAdmission {
                        id: machine_id.clone(),
                        image: image_digest,
                        resources,
                        defaults: execution_defaults,
                        image_defaults,
                        lifetime,
                        operation: operation_id.clone(),
                    },
                    approval,
                )?;
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                self.provision_guardian_with_config(&machine_id, Some(&native_config))?;
                let endpoint = self.guardian_endpoint(&machine_id);
                let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &operation_id)?;
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid(
                        "created machine disappeared from catalog",
                    ))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    machine: self.view(record)?,
                })
            }
            HostRequest::ForkMachine {
                machine_id,
                snapshot_id,
                resources,
                lifetime,
                operation_id,
                approval_id,
            } => {
                let snapshot = self
                    .catalog
                    .snapshot(&snapshot_id)?
                    .ok_or(HostError::Invalid("fork snapshot does not exist"))?;
                if snapshot.phase != SnapshotPhase::Ready {
                    return Err(HostError::Invalid("fork snapshot is not ready"));
                }
                #[cfg(target_os = "linux")]
                let native_config = crate::linux::prepare_config(
                    &self.root,
                    &self.executable,
                    &machine_id,
                    &snapshot.image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "macos")]
                let native_config = crate::apple::prepare_config(
                    &self.root,
                    &self.executable,
                    &machine_id,
                    &snapshot.image_digest,
                    &resources,
                )?;
                #[cfg(target_os = "windows")]
                let native_config = crate::windows::prepare_config(
                    &self.root,
                    &self.executable,
                    &machine_id,
                    &snapshot.image_digest,
                    &resources,
                )?;
                let request_digest = digest(
                    Domain::Snapshot,
                    &(
                        "sandsurf-filesystem-fork-v1",
                        &snapshot_id,
                        &machine_id,
                        &resources,
                        &lifetime,
                        &operation_id,
                    ),
                )?;
                let previously_admitted = self.catalog.operation(&operation_id)?.is_some();
                let intent = self.catalog.create_machine_from_snapshot(
                    machine_id.clone(),
                    &snapshot_id,
                    resources,
                    lifetime,
                    operation_id.clone(),
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                let machine_root = self.machine_root(&machine_id);
                prepare_directory(&machine_root)?;
                let disks = machine_root.join("disks");
                prepare_directory(&disks)?;
                let system_disk = disks.join(system_disk_name());
                // The guardian creates a blank mutable disk when none exists.
                // A new fork must install its captured disk before the guardian
                // is allowed to open that VM. An interrupted pre-launch copy is
                // verified and resumed by the same exact snapshot identity.
                let materialized_before_owner = !system_disk.exists();
                if materialized_before_owner {
                    crate::snapshots::materialize_fork(
                        &self.root.join("snapshots"),
                        &snapshot,
                        &system_disk,
                    )?;
                }
                #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                self.provision_guardian_with_config(&machine_id, Some(&native_config))?;
                let endpoint = self.guardian_endpoint(&machine_id);
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
                        crate::snapshots::materialize_fork(
                            &self.root.join("snapshots"),
                            &snapshot,
                            &system_disk,
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
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("forked machine disappeared"))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    machine: self.view(record)?,
                })
            }
            HostRequest::RollbackFilesystem {
                machine_id,
                snapshot_id,
                operation_id,
                expected_revision,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Snapshot,
                    &(
                        "sandsurf-filesystem-rollback-v1",
                        &machine_id,
                        &snapshot_id,
                        &operation_id,
                        expected_revision,
                    ),
                )?;
                if self.catalog.operation(&operation_id)?.is_none() {
                    self.catalog
                        .require_revision(&machine_id, expected_revision)?;
                }
                let admitted = self.catalog.admit_rollback(
                    &machine_id,
                    &snapshot_id,
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
                self.provision_guardian(&machine_id)?;
                let inspection = GuardianClient::new(self.guardian_endpoint(&machine_id))
                    .inspect(machine_id.clone(), None)?;
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
                let snapshot = self
                    .catalog
                    .snapshot(&snapshot_id)?
                    .ok_or(HostError::Invalid("rollback snapshot disappeared"))?;
                let evidence = crate::snapshots::rollback(
                    &self.root.join("snapshots"),
                    &snapshot,
                    &self
                        .machine_root(&machine_id)
                        .join("disks")
                        .join(system_disk_name()),
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
                machine_id,
                operation_id,
                expected_revision,
                desired,
                approval_id,
            } => {
                self.require_revision_for_new_host_operation(
                    &machine_id,
                    &operation_id,
                    expected_revision,
                )?;
                let approval = Approval {
                    id: approval_id,
                    request_digest: digest(
                        Domain::Operation,
                        &(&machine_id, &operation_id, expected_revision, desired),
                    )?,
                };
                let intent = self.catalog.request_lifecycle(
                    &machine_id,
                    operation_id.clone(),
                    expected_revision,
                    desired,
                    approval,
                )?;
                self.provision_guardian(&machine_id)?;
                let endpoint = self.guardian_endpoint(&machine_id);
                let lifecycle = self.apply_lifecycle_intent(&intent, endpoint)?;
                if desired == DesiredState::Running && lifecycle.completed_intent.is_some() {
                    self.catalog.observe_activity(&machine_id, unix_millis()?)?;
                }
                if desired == DesiredState::Destroyed && lifecycle.completed_intent.is_some() {
                    self.retire_machine_storage(&machine_id)?;
                }
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine disappeared from catalog"))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    machine: self.view(record)?,
                })
            }
            HostRequest::SetNetworkPolicy {
                machine_id,
                operation_id,
                expected_revision,
                policy,
                approval_id,
            } => {
                policy.validate()?;
                self.require_revision_for_new_host_operation(
                    &machine_id,
                    &operation_id,
                    expected_revision,
                )?;
                let request_digest = digest(
                    Domain::Network,
                    &(
                        "sandsurf-network-policy-change-v1",
                        &machine_id,
                        &operation_id,
                        expected_revision,
                        &policy,
                    ),
                )?;
                let mut configuration = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine does not exist"))?
                    .runtime_configuration;
                configuration.network = policy;
                let operation = self.catalog.set_runtime_configuration(
                    &machine_id,
                    &operation_id,
                    expected_revision,
                    configuration,
                    request_digest.clone(),
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration_if_current(&machine_id, operation.revision)?;
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine disappeared from catalog"))?;
                Ok(HostResponse::Configuration {
                    revision: operation.revision,
                    machine: self.view(record)?,
                })
            }
            HostRequest::SetExposure {
                machine_id,
                operation_id,
                expected_revision,
                exposure_id,
                mut spec,
                active,
                approval_id,
            } => {
                self.require_revision_for_new_host_operation(
                    &machine_id,
                    &operation_id,
                    expected_revision,
                )?;
                let requested_spec = spec.clone();
                let request_digest = digest(
                    Domain::Exposure,
                    &(
                        "sandsurf-port-exposure-v1",
                        &machine_id,
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
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine does not exist"))?
                    .runtime_configuration;
                let existing = configuration
                    .exposures
                    .iter()
                    .position(|value| value.id == exposure_id);
                let bound_port = active.then_some(spec.host_port);
                let exposure = Exposure {
                    id: exposure_id,
                    machine_id: machine_id.clone(),
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
                    &machine_id,
                    &operation_id,
                    expected_revision,
                    configuration,
                    request_digest.clone(),
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration_if_current(&machine_id, operation.revision)?;
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
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine disappeared from catalog"))?;
                Ok(HostResponse::Exposure {
                    exposure,
                    machine: self.view(record)?,
                })
            }
            HostRequest::PutSecret {
                secret_id,
                version,
                bytes,
                operation_id,
                approval_id,
            } => {
                let commitment = self.secrets.commitment(&secret_id, &version, &bytes)?;
                let secret = SecretVersion {
                    id: secret_id.clone(),
                    version: version.clone(),
                    bytes: counter(bytes.len() as u64),
                };
                let request_digest = digest(
                    Domain::Secret,
                    &(
                        "sandsurf-put-secret-v2",
                        &secret_id,
                        &version,
                        &commitment,
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
                    let stored = self.secrets.put(secret_id, version, &bytes)?;
                    self.catalog
                        .complete_secret_put(&operation_id, &request_digest, &stored)?;
                }
                Ok(HostResponse::Secret { secret })
            }
            HostRequest::DeliverSecret { .. } | HostRequest::RevokeSecret { .. } => Err(
                HostError::Invalid("secret authority operations require host task admission"),
            ),
            HostRequest::UpdateResources {
                machine_id,
                operation_id,
                expected_revision,
                resources,
                approval_id,
            } => {
                self.provision_guardian(&machine_id)?;
                let validated = GuardianClient::new(self.guardian_endpoint(&machine_id)).runtime(
                    machine_id.clone(),
                    RuntimeRequest::ValidateResources {
                        resources: resources.clone(),
                    },
                )?;
                if !matches!(validated, RuntimeResponse::Complete) {
                    return Err(HostError::Invalid(
                        "native resource validation returned an unexpected response",
                    ));
                }
                self.require_revision_for_new_host_operation(
                    &machine_id,
                    &operation_id,
                    expected_revision,
                )?;
                let request_digest = digest(
                    Domain::Authority,
                    &(
                        "sandsurf-machine-resources-v1",
                        &machine_id,
                        &operation_id,
                        expected_revision,
                        &resources,
                    ),
                )?;
                let operation = self.catalog.update_resources(
                    &machine_id,
                    &operation_id,
                    expected_revision,
                    resources,
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.apply_configuration_if_current(&machine_id, operation.revision)?;
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine disappeared from catalog"))?;
                Ok(HostResponse::Configuration {
                    revision: operation.revision,
                    machine: self.view(record)?,
                })
            }
            HostRequest::GetUsage { machine_id } => {
                self.provision_guardian(&machine_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&machine_id));
                let response = client.runtime(machine_id.clone(), RuntimeRequest::Usage)?;
                let RuntimeResponse::Usage {
                    generation,
                    mut usage,
                } = response
                else {
                    return Err(HostError::Invalid(
                        "native resource accounting is unavailable",
                    ));
                };
                let storage =
                    sandsurf_native::storage_usage::tree_usage(&self.machine_root(&machine_id))?;
                usage.disk_logical_bytes = Counter::try_from(storage.logical_bytes)?;
                usage.disk_allocated_bytes = Counter::try_from(storage.allocated_bytes)?;
                Ok(HostResponse::Usage {
                    usage: self.catalog.observe_usage(&machine_id, generation, usage)?,
                })
            }
            HostRequest::DispatchGuest { .. } | HostRequest::Guest { .. } => Err(
                HostError::Invalid("guest I/O must leave the catalog owner after admission"),
            ),
            HostRequest::GetOperation {
                machine_id,
                operation_id,
            } => {
                if let Some(value) = self.catalog.operation(&operation_id)? {
                    if value.machine_id() != Some(&machine_id) {
                        return Err(HostError::Invalid(
                            "host operation belongs to another authority scope",
                        ));
                    }
                    return Ok(HostResponse::HostOperation { value: Some(value) });
                }
                self.provision_guardian(&machine_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&machine_id))
                        .runtime(machine_id, RuntimeRequest::Operation { operation_id })?,
                })
            }
            request @ (HostRequest::ListEvents { .. }
            | HostRequest::GetProcess { .. }
            | HostRequest::ListProcesses { .. }
            | HostRequest::GetReceipt { .. }
            | HostRequest::ReadEvidence { .. }
            | HostRequest::GetOutputSegment { .. }
            | HostRequest::ReadOutputSegment { .. }) => self
                .defer_runtime_read(&request)?
                .ok_or(HostError::Invalid("runtime read route is unavailable"))?
                .execute(),
            HostRequest::AcknowledgeReceipt {
                machine_id,
                operation_id,
                execution_id,
                receipt_digest,
            } => {
                self.provision_guardian(&machine_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&machine_id));
                let prior = runtime_operation(&client, &machine_id, &operation_id)?;
                match prior {
                    Some(RuntimeOperationRecord::ReceiptAcknowledgement {
                        operation_id: old_operation,
                        execution_id: old_process,
                        receipt_digest: old_receipt,
                    }) if old_operation == operation_id
                        && old_process == execution_id
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
                Ok(HostResponse::Runtime {
                    response: client.runtime(
                        machine_id,
                        RuntimeRequest::AcknowledgeReceipt {
                            operation_id,
                            execution_id,
                            receipt_digest,
                        },
                    )?,
                })
            }
            HostRequest::SealOutput {
                machine_id,
                operation_id,
                execution_id,
                generation,
                expected,
                segment_id,
            } => {
                self.provision_guardian(&machine_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&machine_id));
                Ok(HostResponse::Runtime {
                    response: client.runtime(
                        machine_id,
                        RuntimeRequest::SealOutput {
                            operation_id,
                            execution_id,
                            generation,
                            expected,
                            segment_id,
                        },
                    )?,
                })
            }
            HostRequest::ReleaseEvidence {
                machine_id,
                execution_id,
                request,
                loss_approval_id,
            } => {
                self.provision_guardian(&machine_id)?;
                let client = GuardianClient::new(self.guardian_endpoint(&machine_id));
                let prior = runtime_operation(&client, &machine_id, &request.operation_id)?;
                match prior {
                    Some(RuntimeOperationRecord::EvidenceRelease {
                        execution_id: old_process,
                        request: old_request,
                        status,
                    }) if old_process == execution_id && old_request == request => {
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
                match (&request.disposition, loss_approval_id) {
                    (ReleaseDisposition::AuthorizedLoss { authorization }, Some(approval_id))
                        if *authorization == approval_id =>
                    {
                        let authorized = self.catalog.authorize_output_loss(
                            &machine_id,
                            &execution_id,
                            &request.receipt_digest,
                            &request.output,
                            Approval {
                                id: approval_id,
                                request_digest: digest(
                                    Domain::Release,
                                    &(
                                        &machine_id,
                                        &execution_id,
                                        &request.receipt_digest,
                                        &request.output,
                                        "loss",
                                    ),
                                )?,
                            },
                        )?;
                        client.runtime(
                            machine_id.clone(),
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
                        machine_id,
                        RuntimeRequest::Release {
                            execution_id,
                            request,
                        },
                    )?,
                })
            }
            HostRequest::CleanupReleasedEvidence {
                machine_id,
                execution_id,
                request_digest,
            } => {
                self.provision_guardian(&machine_id)?;
                Ok(HostResponse::Runtime {
                    response: GuardianClient::new(self.guardian_endpoint(&machine_id)).runtime(
                        machine_id,
                        RuntimeRequest::CleanupReleased {
                            execution_id,
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
            guest_power: sandsurf_machine::guest_power_capabilities(),
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
        let inspection = client.inspect(intent.machine_id.clone(), None)?;
        let current = match inspection.observation {
            Observation::Current { value } => Some(value),
            Observation::Unavailable { .. } => None,
        };
        match (intent.desired, current.as_ref().map(|value| value.state)) {
            (DesiredState::Suspended, Some(_)) => {
                self.suspend_with_full_snapshot(intent, endpoint, current.as_ref().unwrap())
            }
            (DesiredState::Running, Some(MachineState::Suspended)) => {
                self.restore_suspended_snapshot(intent, endpoint, current.as_ref().unwrap())
            }
            _ => Ok(apply_lifecycle(
                &mut self.catalog,
                endpoint,
                &intent.operation_id,
            )?),
        }
    }

    fn suspend_with_full_snapshot(
        &mut self,
        intent: &LifecycleIntent,
        endpoint: PathBuf,
        current: &MachineObservation,
    ) -> Result<HostLifecycleResult> {
        let (snapshot_id, capture_operation_id) = suspension_identities(intent)?;
        if current.state == MachineState::Suspended {
            let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &intent.operation_id)?;
            if lifecycle.completed_intent.is_some() {
                let snapshot = self
                    .catalog
                    .snapshot(&snapshot_id)?
                    .ok_or(HostError::Invalid(
                        "suspended machine has no lifecycle snapshot",
                    ))?;
                let manifest = snapshot.manifest_digest.as_ref().ok_or(HostError::Invalid(
                    "suspension snapshot has no committed manifest",
                ))?;
                self.catalog.record_suspension(
                    &intent.machine_id,
                    &intent.operation_id,
                    &snapshot_id,
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
        let request = SnapshotRequest {
            id: snapshot_id.clone(),
            operation_id: capture_operation_id.clone(),
            machine_id: intent.machine_id.clone(),
            expected_generation: current.generation,
            expected_revision: current.applied_revision,
            kind: SnapshotKind::Full,
            parent: None,
        };
        let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request))?;
        let admitted = self
            .catalog
            .admit_suspension_snapshot(request.clone(), &intent.operation_id)?;
        let snapshot = if admitted.phase == SnapshotPhase::Ready {
            admitted
        } else {
            let capturing = self.catalog.begin_snapshot(&snapshot_id, &request_digest)?;
            if let Some(captured) =
                crate::snapshots::published_filesystem(&self.root.join("snapshots"), &capturing)?
            {
                complete_snapshot_capture(
                    &mut self.catalog,
                    &snapshot_id,
                    &request_digest,
                    captured,
                )?
            } else {
                let client = GuardianClient::new(endpoint.clone());
                let prepared = client.native_snapshot(
                    intent.machine_id.clone(),
                    NativeSnapshotRequest::PrepareFull {
                        snapshot_id: snapshot_id.clone(),
                        operation_id: capture_operation_id.clone(),
                    },
                )?;
                let NativeSnapshotResponse::Prepared { capture, processes } = prepared else {
                    return Err(HostError::Invalid(
                        "guardian did not establish the suspension capture boundary",
                    ));
                };
                let machine_root = self.machine_root(&intent.machine_id);
                let captured = crate::snapshots::capture_full(
                    &self.root.join("snapshots"),
                    &capturing,
                    &machine_root.join("disks").join(system_disk_name()),
                    &machine_root
                        .join("guardian/full-captures")
                        .join(object_name(capture_operation_id.as_str())),
                    capture,
                    processes,
                )?;
                complete_snapshot_capture(
                    &mut self.catalog,
                    &snapshot_id,
                    &request_digest,
                    captured,
                )?
            }
        };
        let manifest_digest = snapshot.manifest_digest.clone().ok_or(HostError::Invalid(
            "suspension snapshot has no committed manifest",
        ))?;
        if !matches!(
            GuardianClient::new(endpoint.clone()).native_snapshot(
                intent.machine_id.clone(),
                NativeSnapshotRequest::CommitSuspend {
                    operation_id: capture_operation_id,
                    manifest_digest: manifest_digest.clone(),
                },
            )?,
            NativeSnapshotResponse::Complete { .. }
        ) {
            return Err(HostError::Invalid(
                "guardian did not commit the suspension snapshot",
            ));
        }
        let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &intent.operation_id)?;
        if lifecycle.completed_intent.is_some() {
            self.catalog.record_suspension(
                &intent.machine_id,
                &intent.operation_id,
                &snapshot_id,
                &manifest_digest,
            )?;
        }
        Ok(lifecycle)
    }

    fn restore_suspended_snapshot(
        &mut self,
        intent: &LifecycleIntent,
        endpoint: PathBuf,
        current: &MachineObservation,
    ) -> Result<HostLifecycleResult> {
        let suspension = self
            .catalog
            .suspension(&intent.machine_id)?
            .ok_or(HostError::Invalid(
                "suspended machine has no committed restore snapshot",
            ))?;
        let snapshot = self
            .catalog
            .snapshot(&suspension.snapshot_id)?
            .ok_or(HostError::Invalid("restore snapshot does not exist"))?;
        let full = snapshot
            .full
            .clone()
            .ok_or(HostError::Invalid("restore snapshot has no machine state"))?;
        let system_disk = SnapshotArtifact {
            digest: snapshot
                .system_disk_digest
                .clone()
                .ok_or(HostError::Invalid("restore snapshot has no defaults disk"))?,
            bytes: snapshot.system_disk_bytes,
        };
        if current.applied_revision.next()? != intent.revision {
            return Err(HostError::Invalid(
                "restore does not follow the suspended configuration revision",
            ));
        }
        if !matches!(
            GuardianClient::new(endpoint.clone()).native_snapshot(
                intent.machine_id.clone(),
                NativeSnapshotRequest::StageRestore {
                    snapshot_id: suspension.snapshot_id.clone(),
                    manifest_digest: suspension.manifest_digest.clone(),
                    system_disk,
                    expected: Box::new(full),
                },
            )?,
            NativeSnapshotResponse::Complete { .. }
        ) {
            return Err(HostError::Invalid(
                "guardian did not stage the suspended machine restore",
            ));
        }
        let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &intent.operation_id)?;
        if lifecycle.completed_intent.is_some() {
            self.catalog
                .clear_suspension(&intent.machine_id, &suspension.snapshot_id)?;
        }
        Ok(lifecycle)
    }

    fn recover_snapshot_barriers(&mut self) {
        let mut after = None;
        loop {
            let Ok(values) = self.catalog.snapshots(
                after.as_ref(),
                Counter::try_from(256).expect("constant is positive"),
            ) else {
                return;
            };
            if values.is_empty() {
                return;
            }
            for snapshot in &values {
                if snapshot.phase != SnapshotPhase::Capturing
                    || snapshot.request.kind != SnapshotKind::Disk
                {
                    continue;
                }
                let machine = snapshot.request.machine_id.clone();
                if self.provision_guardian(&machine).is_ok() {
                    let _ = GuardianClient::new(self.guardian_endpoint(&machine)).native_snapshot(
                        machine,
                        NativeSnapshotRequest::FinishDisk {
                            operation_id: snapshot.request.operation_id.clone(),
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

    fn prepare_secret_delivery(
        &mut self,
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        delivery: SecretDelivery,
        approval_id: CommitmentId,
    ) -> Result<HostDispatch> {
        let request_digest = digest(
            Domain::Secret,
            &(
                "sandsurf-deliver-secret-v2",
                &machine_id,
                &operation_id,
                expected_revision,
                &delivery,
            ),
        )?;
        let record = self.catalog.admit_secret_delivery(
            sandsurf_state::SecretDeliveryRecord {
                machine_id: machine_id.clone(),
                operation_id: operation_id.clone(),
                request_digest: request_digest.clone(),
                delivery: delivery.clone(),
                disclosure: SecretDisclosure::NotSent,
                revoked: false,
                revocation_operation: None,
            },
            expected_revision,
            Approval {
                id: approval_id,
                request_digest: request_digest.clone(),
            },
        )?;
        if record.disclosure != SecretDisclosure::NotSent || record.revoked {
            return Ok(HostDispatch::Ready(Box::new(
                HostResponse::SecretDelivery { delivery: record },
            )));
        }
        let bytes = self
            .secrets
            .read(&delivery.secret.id, &delivery.secret.version)?;
        if bytes.len() as u64 != delivery.secret.bytes.get() {
            return Err(HostError::Invalid("approved secret version length changed"));
        }
        self.provision_guardian(&machine_id)?;
        let record = self
            .catalog
            .begin_secret_disclosure(&operation_id, &request_digest)?;
        Ok(HostDispatch::Task(Box::new(HostTask::SecretDelivery {
            endpoint: self.guardian_endpoint(&machine_id),
            record,
            bytes: Zeroizing::new(bytes),
        })))
    }

    fn prepare_secret_revocation(
        &mut self,
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        secret: SecretVersion,
        terminate_recipients: bool,
        approval_id: CommitmentId,
    ) -> Result<HostDispatch> {
        if secret.bytes == Counter::ZERO || secret.bytes.get() > 1024 * 1024 {
            return Err(HostError::Invalid("secret version size is invalid"));
        }
        let request_digest = digest(
            Domain::Secret,
            &(
                "sandsurf-revoke-secret-v1",
                &machine_id,
                &operation_id,
                expected_revision,
                &secret,
                terminate_recipients,
            ),
        )?;
        let record = self.catalog.admit_secret_revocation(
            sandsurf_state::SecretRevocationAdmission {
                machine_id,
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
        if record.guest_cleanup_report.is_some()
            || record.deliveries.is_empty()
            || self.provision_guardian(&record.machine_id).is_err()
        {
            return Ok(HostDispatch::Ready(Box::new(
                HostResponse::SecretRevocation { revocation: record },
            )));
        }
        Ok(HostDispatch::Task(Box::new(HostTask::SecretCleanup {
            endpoint: self.guardian_endpoint(&record.machine_id),
            record,
        })))
    }

    fn prepare_artifact_capture(&mut self, request: HostRequest) -> Result<HostDispatch> {
        let (machine_id, operation_id, revision, request_digest, request) = match request {
            HostRequest::CaptureHostTree {
                machine_id,
                operation_id,
                expected_revision,
                source,
                exclusions,
                maximum_bytes,
                approval_id,
            } => {
                let binding = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-host-tree-capture-admission-v1",
                        &machine_id,
                        &operation_id,
                        expected_revision,
                        &source,
                        &exclusions,
                        maximum_bytes,
                    ),
                )?;
                (
                    machine_id,
                    operation_id,
                    expected_revision,
                    binding,
                    ArtifactCapture::Host {
                        source,
                        exclusions,
                        maximum_bytes,
                        approval_id,
                    },
                )
            }
            HostRequest::CaptureGuestTree {
                machine_id,
                source,
                operation_id,
                expected_generation,
                expected_revision,
                maximum_bytes,
            } => {
                let binding = digest(
                    Domain::Transfer,
                    &(
                        "sandsurf-guest-tree-capture-v2",
                        &source,
                        &machine_id,
                        &operation_id,
                        expected_generation,
                        expected_revision,
                        maximum_bytes,
                    ),
                )?;
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("capture machine is missing"))?;
                if maximum_bytes > record.resources.disk_bytes {
                    return Err(HostError::Invalid(
                        "capture bound exceeds the machine disk budget",
                    ));
                }
                let endpoint = self.guardian_endpoint(&machine_id);
                (
                    machine_id,
                    operation_id,
                    expected_revision,
                    binding,
                    ArtifactCapture::Guest {
                        source,
                        maximum_bytes,
                        generation: expected_generation,
                        revision: expected_revision,
                        endpoint,
                    },
                )
            }
            _ => return Err(HostError::Invalid("request is not an artifact capture")),
        };
        self.require_revision_for_new_host_operation(&machine_id, &operation_id, revision)?;
        let approval = match &request {
            ArtifactCapture::Host { approval_id, .. } => Some(Approval {
                id: approval_id.clone(),
                request_digest: request_digest.clone(),
            }),
            ArtifactCapture::Guest { .. } => None,
        };
        let operation = self.catalog.admit_transfer_operation(
            operation_id,
            machine_id,
            request_digest,
            approval,
        )?;
        Ok(HostDispatch::Task(Box::new(HostTask::ArtifactCapture {
            store: Arc::clone(&self.artifacts),
            operation,
            request,
        })))
    }

    fn prepare_artifact_apply(&mut self, request: HostRequest) -> Result<HostDispatch> {
        let HostRequest::ApplyArtifactToHost {
            machine_id,
            artifact_id,
            operation_id,
            destination,
            change_set,
            approval_id,
        } = request
        else {
            return Err(HostError::Invalid("request is not artifact publication"));
        };
        let request_digest = digest(
            Domain::Transfer,
            &(
                "sandsurf-artifact-apply-admission-v1",
                &machine_id,
                &artifact_id,
                &operation_id,
                &destination,
                &change_set,
            ),
        )?;
        let operation = self.catalog.admit_transfer_operation(
            operation_id,
            machine_id,
            request_digest.clone(),
            Some(Approval {
                id: approval_id.clone(),
                request_digest,
            }),
        )?;
        Ok(HostDispatch::Task(Box::new(HostTask::ArtifactApply {
            store: Arc::clone(&self.artifacts),
            operation,
            artifact_id,
            destination,
            change_set,
            approval_id,
        })))
    }

    fn complete_task(&mut self, completion: HostTaskCompletion) -> Result<HostResponse> {
        match completion {
            HostTaskCompletion::ArtifactTransfer { operation, result } => {
                let response = *result?;
                self.catalog.complete_transfer_operation(
                    &operation.operation_id,
                    &operation.request_digest,
                )?;
                Ok(response)
            }
            HostTaskCompletion::SecretDelivery {
                record,
                reported_received,
            } => {
                let delivery = if reported_received {
                    self.catalog
                        .complete_secret_delivery(&record.operation_id, &record.request_digest)?
                } else {
                    // A transport failure never proves non-disclosure or justifies replay.
                    self.catalog
                        .secret_deliveries(&record.machine_id)?
                        .into_iter()
                        .find(|delivery| delivery.operation_id == record.operation_id)
                        .ok_or(HostError::Invalid("admitted secret delivery is missing"))?
                };
                Ok(HostResponse::SecretDelivery { delivery })
            }
            HostTaskCompletion::SecretCleanup { record, report } => {
                let revocation = match report {
                    Some(report) => self.catalog.record_secret_cleanup_report(
                        &record.operation_id,
                        &record.request_digest,
                        report,
                    )?,
                    None => self
                        .catalog
                        .secret_revocations(&record.machine_id)?
                        .into_iter()
                        .find(|revocation| revocation.operation_id == record.operation_id)
                        .ok_or(HostError::Invalid("admitted secret revocation is missing"))?,
                };
                Ok(HostResponse::SecretRevocation { revocation })
            }
        }
    }

    fn provision_guardian(&mut self, machine: &MachineId) -> Result<()> {
        if self.catalog.machine(machine)?.is_some_and(|record| {
            record.latest_intent.desired == DesiredState::Destroyed
                && record.latest_intent.completion.is_some()
        }) {
            return self.provision_guardian_inner(machine);
        }
        #[cfg(target_os = "linux")]
        return self.provision_guardian_with_config(machine, None);
        #[cfg(target_os = "macos")]
        return self.provision_guardian_with_config(machine, None);
        #[cfg(target_os = "windows")]
        return self.provision_guardian_with_config(machine, None);
    }

    #[cfg(target_os = "linux")]
    fn provision_guardian_with_config(
        &mut self,
        machine: &MachineId,
        config: Option<&crate::linux::LinuxGuardianConfig>,
    ) -> Result<()> {
        let root = self.machine_root(machine);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let config_path = root.join("guardian/config.json");
        if let Some(config) = config {
            crate::linux::write_config(&config_path, config)?;
            self.verified_guardians.insert(machine.clone());
        } else if !self.verified_guardians.contains(machine) {
            crate::linux::read_config(&config_path, machine)?;
            self.verified_guardians.insert(machine.clone());
        }
        self.provision_guardian_inner(machine)
    }

    #[cfg(target_os = "macos")]
    fn provision_guardian_with_config(
        &mut self,
        machine: &MachineId,
        config: Option<&crate::apple::AppleGuardianConfig>,
    ) -> Result<()> {
        let root = self.machine_root(machine);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let config_path = root.join("guardian/config.json");
        if let Some(config) = config {
            crate::apple::write_config(&config_path, config)?;
            self.verified_guardians.insert(machine.clone());
        } else if !self.verified_guardians.contains(machine) {
            crate::apple::read_config(&config_path, machine)?;
            self.verified_guardians.insert(machine.clone());
        }
        self.provision_guardian_inner(machine)
    }

    #[cfg(target_os = "windows")]
    fn provision_guardian_with_config(
        &mut self,
        machine: &MachineId,
        config: Option<&crate::windows::WindowsGuardianConfig>,
    ) -> Result<()> {
        let root = self.machine_root(machine);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let config_path = root.join("guardian/config.json");
        if let Some(config) = config {
            crate::windows::write_config(&config_path, config)?;
            self.verified_guardians.insert(machine.clone());
        } else if !self.verified_guardians.contains(machine) {
            crate::windows::read_config(&config_path, machine)?;
            self.verified_guardians.insert(machine.clone());
        }
        self.provision_guardian_inner(machine)
    }

    fn provision_guardian_inner(&self, machine: &MachineId) -> Result<()> {
        let root = self.machine_root(machine);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        prepare_directory(&root.join("disks"))?;
        prepare_directory(&root.join("output"))?;
        let runtime = root.join("runtime");
        if !runtime.exists() {
            let resources = self
                .catalog
                .machine(machine)?
                .ok_or(HostError::Invalid("machine is missing from host authority"))?
                .resources;
            RuntimeJournal::create(
                &runtime,
                machine.clone(),
                runtime_limits(&resources),
                self.catalog.authority_binding().clone(),
            )?;
        }
        let endpoint = self.guardian_endpoint(machine);
        match GuardianClient::new(endpoint.clone()).owner_identity(machine.clone()) {
            Ok(_) => return Ok(()),
            Err(crate::guardian::Error::Io(error))
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
            .arg("--machine")
            .arg(machine.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(guardian_log))
            .spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if GuardianClient::new(endpoint.clone())
                .owner_identity(machine.clone())
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

    fn view(&mut self, record: MachineRecord) -> Result<MachineView> {
        let (machine, management) = match GuardianClient::new(self.guardian_endpoint(&record.id))
            .inspect(record.id.clone(), None)
        {
            Ok(value) => (value.observation, value.management),
            Err(_) => (
                Observation::Unavailable { last_known: None },
                Observation::Unavailable { last_known: None },
            ),
        };
        Ok(MachineView {
            known_sensitive: record.known_sensitive,
            execution_defaults: record.execution_defaults,
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
            management,
        })
    }

    fn apply_configuration(&mut self, machine: &MachineId, revision: Counter) -> Result<()> {
        self.provision_guardian(machine)?;
        let authorization = self.catalog.authorize_configuration(machine, revision)?;
        let operation =
            GuardianClient::new(self.guardian_endpoint(machine)).configure(authorization)?;
        if operation.delivery != Delivery::Applied || operation.command.revision != revision {
            return Err(HostError::Invalid(
                "guardian did not apply the host configuration revision",
            ));
        }
        Ok(())
    }

    fn require_revision_for_new_host_operation(
        &self,
        machine: &MachineId,
        operation: &OperationId,
        expected_revision: Counter,
    ) -> Result<()> {
        if self.catalog.operation(operation)?.is_none() {
            self.catalog.require_revision(machine, expected_revision)?;
        }
        Ok(())
    }

    fn apply_configuration_if_current(
        &mut self,
        machine: &MachineId,
        operation_revision: Counter,
    ) -> Result<()> {
        let current = self
            .catalog
            .machine(machine)?
            .ok_or(HostError::Invalid("machine does not exist"))?
            .configuration_revision;
        if operation_revision > current {
            return Err(HostError::Invalid(
                "configuration operation is ahead of host authority",
            ));
        }
        if operation_revision == current {
            self.apply_configuration(machine, current)?;
        }
        Ok(())
    }

    fn reconcile_configuration(&mut self, record: &MachineRecord) -> Result<()> {
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
        self.apply_configuration(&record.id, record.configuration_revision)
    }

    /// Reconcile unfinished lifecycle work and enforce only policies that were
    /// admitted with Machine creation/fork. Policy decisions update host
    /// lifecycle intent; the guardian still exclusively records whether the
    /// machine transition occurred.
    fn reconcile_lifetime_policies(&mut self) -> Result<()> {
        let now = unix_millis()?;
        let mut after = None;
        loop {
            let records = self.catalog.machines(after.as_ref(), counter(256))?;
            if records.is_empty() {
                break;
            }
            after = records.last().map(|record| record.id.clone());
            for record in records {
                let id = record.id.clone();
                if let Err(error) = self.reconcile_machine(record, now) {
                    // A machine's native failure or interrupted operation is
                    // not permission to starve other machines' host decisions.
                    eprintln!(
                        "sandsurf machine {} reconciliation deferred: {error}",
                        id.as_str()
                    );
                }
            }
            if after.is_none() {
                break;
            }
        }
        Ok(())
    }

    fn reconcile_machine(&mut self, mut record: MachineRecord, now: Counter) -> Result<()> {
        if record.latest_intent.desired == DesiredState::Destroyed
            && record.latest_intent.completion.is_some()
        {
            return self.retire_machine_storage(&record.id);
        }
        if record.reservation == ReservationState::Released {
            return Ok(());
        }
        // Host intent changes without claiming that native delivery succeeded.
        if let Some(expires) = record.lifetime.expires_at_unix_millis
            && now >= expires
        {
            let desired = match record.lifetime.expiration_action {
                ExpirationAction::Stop => DesiredState::Stopped,
                ExpirationAction::Destroy => DesiredState::Destroyed,
            };
            if record.latest_intent.desired != desired
                && record.latest_intent.desired != DesiredState::Destroyed
            {
                return self.apply_policy_lifecycle(record, desired, "expiration");
            }
            if record.latest_intent.completion.is_none()
                && record.latest_intent.revision == record.configuration_revision
            {
                self.provision_guardian(&record.id)?;
                self.apply_lifecycle_intent(
                    &record.latest_intent,
                    self.guardian_endpoint(&record.id),
                )?;
            }
            return Ok(());
        }
        if record.latest_intent.completion.is_none()
            && record.latest_intent.revision == record.configuration_revision
        {
            self.provision_guardian(&record.id)?;
            self.apply_lifecycle_intent(&record.latest_intent, self.guardian_endpoint(&record.id))?;
            record = self.catalog.machine(&record.id)?.ok_or(HostError::Invalid(
                "machine disappeared during reconciliation",
            ))?;
            if record.latest_intent.completion.is_none() {
                return Ok(());
            }
        }
        self.reconcile_configuration(&record)
    }

    fn apply_policy_lifecycle(
        &mut self,
        record: MachineRecord,
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

    fn machine_root(&self, machine: &MachineId) -> PathBuf {
        self.root
            .join("machines")
            .join(object_name(machine.as_str()))
    }

    fn retire_machine_storage(&mut self, machine: &MachineId) -> Result<()> {
        let record = self
            .catalog
            .machine(machine)?
            .ok_or(HostError::Invalid("machine is missing"))?;
        if record.latest_intent.desired != DesiredState::Destroyed
            || record.latest_intent.completion.is_none()
        {
            return Err(HostError::Invalid(
                "disk retirement requires confirmed native destruction",
            ));
        }
        crate::storage::retire(
            &self
                .machine_root(machine)
                .join("disks")
                .join(system_disk_name()),
            record.resources.disk_bytes.get(),
            {
                #[cfg(windows)]
                {
                    crate::storage::DiskFormat::Vhdx
                }
                #[cfg(not(windows))]
                {
                    crate::storage::DiskFormat::Raw
                }
            },
        )?;
        self.catalog.release_retired_storage(machine)?;
        Ok(())
    }

    fn guardian_endpoint(&self, machine: &MachineId) -> PathBuf {
        self.machine_root(machine).join("guardian")
    }
}

pub fn serve_host(root: &Path, executable: PathBuf) -> Result<()> {
    let service = HostService::open(root, executable)?;
    let listener = LocalListener::bind(&service.endpoint())?;
    serve_host_owned(service, listener)
}

fn serve_host_owned(mut service: HostService, listener: LocalListener) -> Result<()> {
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
                        let parsed = parse_host_request(frame).and_then(|mut wire| {
                            let data = if let Some(metadata) = wire.descriptor()? {
                                Some(receive_binary(
                                    &mut crate::ipc_frames::LocalFrameChannel {
                                        connection: &mut connection,
                                        timeout: API_TIMEOUT,
                                    },
                                    metadata,
                                    MAX_RPC_DATA_BYTES,
                                )?)
                            } else {
                                None
                            };
                            Ok(wire.assemble(data)?)
                        });
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
                            let written = {
                                let response = match dispatch {
                                    HostDispatch::Task(task) => {
                                        let completion = task.execute();
                                        let (reply, committed) = mpsc::channel();
                                        if sender
                                            .send(HostIngress::TaskComplete {
                                                completion: Box::new(completion),
                                                reply,
                                            })
                                            .is_err()
                                        {
                                            return;
                                        }
                                        let Ok(response) = committed.recv() else {
                                            return;
                                        };
                                        response
                                    }
                                    dispatch => dispatch.finish(),
                                };
                                write_host_response(&mut connection, sequence, response).is_ok()
                            };
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
        let mut next_reconciliation = std::time::Instant::now() + Duration::from_secs(1);
        let result = loop {
            if std::time::Instant::now() >= next_reconciliation {
                if let Err(error) = service.reconcile_lifetime_policies() {
                    eprintln!("sandsurf host reconciliation deferred: {error}");
                }
                next_reconciliation = std::time::Instant::now() + Duration::from_secs(1);
            }
            match receiver.recv_timeout(
                next_reconciliation.saturating_duration_since(std::time::Instant::now()),
            ) {
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
                Ok(HostIngress::TaskComplete { completion, reply }) => {
                    let _ = reply.send(service.complete_task(*completion).unwrap_or_else(rejected));
                }
                Ok(HostIngress::Failed(error)) => break Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
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
    TaskComplete {
        completion: Box<HostTaskCompletion>,
        reply: mpsc::Sender<HostResponse>,
    },
    Failed(io::Error),
}

enum HostDispatch {
    ArtifactRead(Box<DeferredArtifactRead>),
    Ready(Box<HostResponse>),
    Runtime(Box<DeferredRuntimeRead>),
    Guest(Box<DeferredGuest>),
    Task(Box<HostTask>),
}

impl HostDispatch {
    fn finish(self) -> HostResponse {
        match self {
            Self::Ready(response) => *response,
            Self::ArtifactRead(read) => read.execute().unwrap_or_else(rejected),
            Self::Runtime(read) => (*read).execute().unwrap_or_else(rejected),
            Self::Guest(guest) => (*guest).execute().unwrap_or_else(rejected),
            Self::Task(_) => rejected(HostError::Invalid(
                "host task completion requires its catalog owner",
            )),
        }
    }
}

/// Immutable admitted effects run away from the catalog writer. Only owner
/// completion may change durable host state; workers never receive the catalog.
enum HostTask {
    ArtifactCapture {
        store: Arc<crate::artifacts::ArtifactStore>,
        operation: sandsurf_state::HostTransferOperation,
        request: ArtifactCapture,
    },
    ArtifactApply {
        store: Arc<crate::artifacts::ArtifactStore>,
        operation: sandsurf_state::HostTransferOperation,
        artifact_id: OperationId,
        destination: PathBuf,
        change_set: crate::api::HostChangeSet,
        approval_id: CommitmentId,
    },
    SecretDelivery {
        endpoint: PathBuf,
        record: sandsurf_state::SecretDeliveryRecord,
        bytes: Zeroizing<Vec<u8>>,
    },
    SecretCleanup {
        endpoint: PathBuf,
        record: sandsurf_state::SecretRevocationRecord,
    },
}
enum HostTaskCompletion {
    ArtifactTransfer {
        operation: sandsurf_state::HostTransferOperation,
        result: Result<Box<HostResponse>>,
    },
    SecretDelivery {
        record: sandsurf_state::SecretDeliveryRecord,
        reported_received: bool,
    },
    SecretCleanup {
        record: sandsurf_state::SecretRevocationRecord,
        report: Option<SecretCleanupReport>,
    },
}
impl HostTask {
    fn execute(self) -> HostTaskCompletion {
        match self {
            Self::ArtifactCapture {
                store,
                operation,
                request,
            } => {
                let result = request
                    .execute(&store, &operation)
                    .map(|capture| Box::new(HostResponse::HostTreeCapture { capture }));
                HostTaskCompletion::ArtifactTransfer { operation, result }
            }
            Self::ArtifactApply {
                store,
                operation,
                artifact_id,
                destination,
                change_set,
                approval_id,
            } => {
                let result = store
                    .apply(
                        operation.machine_id.clone(),
                        artifact_id,
                        operation.operation_id.clone(),
                        &destination,
                        change_set,
                        approval_id,
                    )
                    .map(|report| Box::new(HostResponse::HostApply { report }))
                    .map_err(HostError::from);
                HostTaskCompletion::ArtifactTransfer { operation, result }
            }
            Self::SecretDelivery {
                endpoint,
                record,
                bytes,
            } => {
                let response = GuardianClient::new(endpoint).guest(
                    record.machine_id.clone(),
                    GuestServiceRequest::InstallSecret {
                        operation_id: record.operation_id.clone(),
                        delivery: record.delivery.clone(),
                        bytes: bytes.to_vec(),
                    },
                );
                HostTaskCompletion::SecretDelivery {
                    record,
                    reported_received: matches!(
                        response,
                        Ok(GuestServiceResponse::SecretInstalled { .. })
                    ),
                }
            }
            Self::SecretCleanup { endpoint, record } => {
                let client = GuardianClient::new(endpoint);
                let report = match client.inspect(record.machine_id.clone(), None) {
                    Ok(inspection)
                        if matches!(
                            inspection.observation,
                            Observation::Current {
                                value: MachineObservation {
                                    state: MachineState::Running,
                                    ..
                                }
                            }
                        ) =>
                    {
                        match client.guest(
                            record.machine_id.clone(),
                            GuestServiceRequest::RevokeSecret {
                                operation_id: record.operation_id.clone(),
                                secret_id: record.secret.id.clone(),
                                version: record.secret.version.clone(),
                                deliveries: record.deliveries.clone(),
                                terminate_recipients: record.terminate_recipients,
                            },
                        ) {
                            Ok(GuestServiceResponse::SecretCleanupReported { report }) => {
                                Some(report)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                HostTaskCompletion::SecretCleanup { record, report }
            }
        }
    }
}

struct DeferredArtifactRead {
    store: Arc<crate::artifacts::ArtifactStore>,
    request: ArtifactRead,
}
enum ArtifactRead {
    Entries {
        machine_id: MachineId,
        operation_id: OperationId,
        after: Counter,
        maximum: Counter,
    },
    Blob {
        machine_id: MachineId,
        operation_id: OperationId,
        digest: Digest,
        offset: Counter,
        maximum: u32,
    },
}
impl DeferredArtifactRead {
    fn execute(self) -> Result<HostResponse> {
        match self.request {
            ArtifactRead::Entries {
                machine_id,
                operation_id,
                after,
                maximum,
            } => {
                let (capture, entries, next) =
                    self.store
                        .capture_entries(&machine_id, &operation_id, after, maximum)?;
                Ok(HostResponse::HostTreeEntries {
                    capture,
                    entries,
                    next,
                })
            }
            ArtifactRead::Blob {
                machine_id,
                operation_id,
                digest,
                offset,
                maximum,
            } => {
                let (bytes, eof) = self.store.read_capture_blob(
                    &machine_id,
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
        }
    }
}

enum ArtifactCapture {
    Host {
        source: PathBuf,
        exclusions: Vec<String>,
        maximum_bytes: Counter,
        approval_id: CommitmentId,
    },
    Guest {
        source: GuestPath,
        maximum_bytes: Counter,
        generation: Counter,
        revision: Counter,
        endpoint: PathBuf,
    },
}
impl ArtifactCapture {
    fn execute(
        self,
        store: &crate::artifacts::ArtifactStore,
        operation: &sandsurf_state::HostTransferOperation,
    ) -> Result<crate::api::HostTreeCapture> {
        let machine = &operation.machine_id;
        match self {
            Self::Host {
                source,
                exclusions,
                maximum_bytes,
                approval_id,
            } => Ok(store.capture(
                machine.clone(),
                operation.operation_id.clone(),
                &source,
                &exclusions,
                maximum_bytes,
                approval_id,
            )?),
            Self::Guest {
                source,
                maximum_bytes,
                generation,
                revision,
                endpoint,
            } => {
                if let Some(capture) = store.existing_guest_capture(
                    machine,
                    &operation.operation_id,
                    &operation.request_digest,
                )? {
                    return Ok(capture);
                }
                if operation.applied {
                    return Err(HostError::Invalid(
                        "completed capture has no published artifact",
                    ));
                }
                let client = GuardianClient::new(endpoint);
                let inspection = client.inspect(machine.clone(), None)?;
                if !matches!(inspection.observation, Observation::Current { value } if value.generation == generation && value.applied_revision == revision && value.state == MachineState::Running)
                {
                    return Err(HostError::Invalid(
                        "capture requires the expected running generation and revision",
                    ));
                }
                Ok(store.capture_guest(
                    machine.clone(),
                    operation.operation_id.clone(),
                    operation.request_digest.clone(),
                    source,
                    maximum_bytes,
                    |request| match client.query_guest(
                        machine.clone(),
                        generation,
                        GuestServiceRequest::FilesystemQuery { request },
                    ) {
                        Ok(GuestServiceResponse::File { response }) => Ok(response),
                        Ok(GuestServiceResponse::Error { code, message }) => Err(
                            crate::artifacts::ArtifactError::Guest(format!("{code}: {message}")),
                        ),
                        Ok(_) => Err(crate::artifacts::ArtifactError::Invalid(
                            "guest capture returned the wrong response",
                        )),
                        Err(error) => {
                            Err(crate::artifacts::ArtifactError::Guest(error.to_string()))
                        }
                    },
                )?)
            }
        }
    }
}

struct DeferredGuest {
    endpoint: PathBuf,
    request: DeferredGuestRequest,
}
enum DeferredGuestRequest {
    Dispatch(GuestCommand),
    Query {
        machine_id: MachineId,
        generation: Counter,
        request: GuestServiceRequest,
    },
}
impl DeferredGuest {
    fn execute(self) -> Result<HostResponse> {
        let client = GuardianClient::new(self.endpoint);
        match self.request {
            DeferredGuestRequest::Dispatch(command) => Ok(HostResponse::Dispatch {
                operation: client.dispatch(command)?,
            }),
            DeferredGuestRequest::Query {
                machine_id,
                generation,
                request,
            } => Ok(HostResponse::Guest {
                response: client.query_guest(machine_id, generation, request)?,
            }),
        }
    }
}

struct DeferredRuntimeRead {
    endpoint: PathBuf,
    machine_id: MachineId,
    query: RuntimeRequest,
}

impl DeferredRuntimeRead {
    fn execute(self) -> Result<HostResponse> {
        Ok(HostResponse::Runtime {
            response: GuardianClient::new(self.endpoint).runtime(self.machine_id, self.query)?,
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

pub fn serve_machine_guardian(root: &Path, machine: MachineId) -> Result<()> {
    let machine_root = root.join("machines").join(object_name(machine.as_str()));
    let journal = RuntimeJournal::open(&machine_root.join("runtime"), &machine)?;
    if journal
        .last_observation()?
        .is_some_and(|value| value.value().state == MachineState::Destroyed)
    {
        #[cfg(target_os = "linux")]
        let mut guardian = Guardian::<crate::linux::LinuxGuardianEffect>::retained(journal)?;
        #[cfg(target_os = "macos")]
        let mut guardian = Guardian::<crate::apple::AppleGuardianEffect>::retained(journal)?;
        #[cfg(target_os = "windows")]
        let mut guardian = Guardian::<crate::windows::WindowsGuardianEffect>::retained(journal)?;
        serve_guardian(&machine_root.join("guardian"), &mut guardian)?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let config =
            crate::linux::read_config(&machine_root.join("guardian/config.json"), &machine)?;
        let effect = crate::linux::LinuxGuardianEffect::open(&machine_root, config)?;
        let mut guardian = Guardian::new(journal, effect);
        serve_guardian(&machine_root.join("guardian"), &mut guardian)?;
    }
    #[cfg(target_os = "macos")]
    {
        let config =
            crate::apple::read_config(&machine_root.join("guardian/config.json"), &machine)?;
        let effect = crate::apple::AppleGuardianEffect::open(&machine_root, config)?;
        let mut guardian = Guardian::new(journal, effect);
        serve_guardian(&machine_root.join("guardian"), &mut guardian)?;
    }
    #[cfg(target_os = "windows")]
    {
        let config =
            crate::windows::read_config(&machine_root.join("guardian/config.json"), &machine)?;
        let effect = crate::windows::WindowsGuardianEffect::open(&machine_root, config)?;
        let mut guardian = Guardian::new(journal, effect);
        serve_guardian(&machine_root.join("guardian"), &mut guardian)?;
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
    let (wire, bytes) = RequestEnvelope::split(request)?;
    let payload = serde_json::to_vec(&(HOST_API_VERSION, wire))?;
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
    if let Some(bytes) = bytes {
        send_binary(
            &mut crate::ipc_frames::LocalFrameChannel {
                connection: &mut connection,
                timeout: API_TIMEOUT,
            },
            bytes,
        )?;
    }
    let frame = connection
        .read_frame(API_TIMEOUT)?
        .ok_or(HostError::Invalid("host closed without a response"))?;
    let mut response = parse_host_response(frame)?;
    if let Some(metadata) = response.binary_descriptor()? {
        let bytes = receive_binary(
            &mut crate::ipc_frames::LocalFrameChannel {
                connection: &mut connection,
                timeout: API_TIMEOUT,
            },
            &metadata,
            MAX_RPC_DATA_BYTES,
        )?;
        response = response.with_wire_bytes(bytes)?;
    }
    if stopping && connection.read_frame(Duration::from_secs(10))?.is_some() {
        return Err(HostError::Invalid(
            "host sent data after its terminal response",
        ));
    }
    Ok(response)
}

fn parse_host_request(frame: Frame) -> Result<RequestEnvelope<HostRequest>> {
    require_frame(&frame)?;
    let (version, request): (u16, RequestEnvelope<HostRequest>) =
        serde_json::from_slice(&frame.payload)?;
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

fn write_host_response(
    connection: &mut LocalConnection,
    sequence: Counter,
    response: HostResponse,
) -> Result<()> {
    let (response, bytes) = match response.into_wire_parts() {
        Ok(parts) => parts,
        Err(error) => (rejected(error.into()), None),
    };
    let frame = match host_response_frame(sequence, &response) {
        Ok(frame) => frame,
        Err(error) => {
            connection.write_frame(
                &host_response_frame(sequence, &rejected(error))?,
                API_TIMEOUT,
            )?;
            return Ok(());
        }
    };
    connection.write_frame(&frame, API_TIMEOUT)?;
    if let Some(bytes) = bytes {
        send_binary(
            &mut crate::ipc_frames::LocalFrameChannel {
                connection,
                timeout: API_TIMEOUT,
            },
            bytes,
        )?;
    }
    Ok(())
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
        usage_records: counter(1_000_000),
        image_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
        resources: Resources {
            vcpus: counter(4096),
            memory_mib: counter(4 * 1024 * 1024),
            disk_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
            output_bytes: counter(1024 * 1024 * 1024 * 1024),
            managed_executions: counter(1_000_000),
        },
    }
}

fn runtime_limits(resources: &Resources) -> RuntimeLimits {
    RuntimeLimits {
        identities: counter(1_000_000),
        managed_executions: resources.managed_executions,
        operations: counter(1_000_000),
        observations: counter(1_000_000),
        events: counter(20_000_000),
        chunks: counter(10_000_000),
        output_segments: counter(1_000_000),
        output_bytes: resources.output_bytes,
    }
}

fn counter(value: u64) -> Counter {
    Counter::try_from(value).expect("static host bound is a safe integer")
}

fn unix_millis() -> Result<Counter> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HostError::Invalid("host wall clock is before the Unix generation"))?
        .as_millis();
    let millis = u64::try_from(millis)
        .map_err(|_| HostError::Invalid("host wall clock exceeds the counter range"))?;
    Ok(Counter::try_from(millis)?)
}

fn complete_snapshot_capture(
    catalog: &mut HostCatalog,
    id: &SnapshotId,
    request_digest: &Digest,
    captured: crate::snapshots::CaptureResult,
) -> Result<Snapshot> {
    match captured.full {
        Some(full) => Ok(catalog.complete_full_snapshot(
            id,
            request_digest,
            captured.disk_digest,
            captured.manifest_digest,
            SnapshotConsistency::Machine,
            full,
        )?),
        None => Ok(catalog.complete_snapshot(
            id,
            request_digest,
            captured.disk_digest,
            captured.manifest_digest,
            SnapshotConsistency::Crash,
        )?),
    }
}

fn suspension_identities(intent: &LifecycleIntent) -> Result<(SnapshotId, OperationId)> {
    let identity = digest(
        Domain::Snapshot,
        &(
            "sandsurf-suspension-identities-v1",
            &intent.machine_id,
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

fn runtime_operation(
    client: &GuardianClient,
    machine: &MachineId,
    operation: &OperationId,
) -> Result<Option<RuntimeOperationRecord>> {
    match client.runtime(
        machine.clone(),
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
fn system_disk_name() -> &'static str {
    "system.vhdx"
}

#[cfg(not(target_os = "windows"))]
fn system_disk_name() -> &'static str {
    "system.ext4"
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
        HostError::Artifact(crate::artifacts::ArtifactError::Conflict(_)) => "conflict",
        HostError::Artifact(crate::artifacts::ArtifactError::Capacity(_)) => "capacity",
        HostError::Artifact(_) => "artifact",
        HostError::Secret(crate::secrets::SecretError::Conflict(_)) => "conflict",
        HostError::Secret(crate::secrets::SecretError::Invalid(_)) => "protocol",
        HostError::Secret(_) => "secret",
        HostError::Snapshot(crate::snapshots::SnapshotError::Invalid(_)) => "conflict",
        HostError::Snapshot(_) => "snapshot",
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

#[cfg(any(unix, windows))]
fn prepare_directory(path: &Path) -> Result<()> {
    sandsurf_native::local::ensure_private_directory(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    fn admit_machine(
        service: &mut HostService,
        name: &str,
        lifetime: MachineLifetime,
    ) -> MachineId {
        let machine: MachineId = name.try_into().unwrap();
        let create: OperationId = format!("create-{name}").try_into().unwrap();
        let image = bytes_digest(b"seed");
        let resources = Resources {
            vcpus: Counter::ONE,
            memory_mib: 128_u64.try_into().unwrap(),
            disk_bytes: 1_000_000_u64.try_into().unwrap(),
            output_bytes: 1_000_000_u64.try_into().unwrap(),
            managed_executions: 8_u64.try_into().unwrap(),
        };
        let defaults = ExecutionDefaults::default();
        let request_digest = digest(
            Domain::Machine,
            &(&machine, &image, &resources, &defaults, &lifetime, &create),
        )
        .unwrap();
        service
            .catalog
            .create_machine(
                sandsurf_state::MachineAdmission {
                    id: machine.clone(),
                    image,
                    resources,
                    defaults,
                    image_defaults: ExecutionDefaults::default(),
                    lifetime,
                    operation: create,
                },
                Approval {
                    id: format!("approve-{name}").try_into().unwrap(),
                    request_digest,
                },
            )
            .unwrap();
        machine
    }

    #[test]
    fn ordinary_guest_routes_neither_provision_an_owner_nor_require_native_inspection() {
        let root = std::env::temp_dir().join(format!(
            "ssroute-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());

        let request = GuestRequest::WriteInput {
            execution_id: "process".try_into().unwrap(),
            terminal_lease_id: None,
            bytes: vec![1],
        };
        let dispatch = service
            .prepare_guest_dispatch(
                machine.clone(),
                Counter::ONE,
                "input".try_into().unwrap(),
                request,
            )
            .unwrap();
        let query = service
            .prepare_guest_query(
                machine.clone(),
                Counter::ONE,
                GuestServiceRequest::Process {
                    execution_id: "process".try_into().unwrap(),
                },
            )
            .unwrap();
        assert_eq!(dispatch.endpoint, service.guardian_endpoint(&machine));
        assert_eq!(query.endpoint, dispatch.endpoint);
        assert!(
            !service.machine_root(&machine).exists(),
            "ordinary I/O created machine ownership state"
        );
        assert!(
            matches!(
                HostDispatch::Guest(Box::new(dispatch)).finish(),
                HostResponse::Rejected { .. }
            ),
            "absence must be explicit, not owner creation"
        );
        assert!(!service.machine_root(&machine).exists());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn broken_native_ownership_cannot_starve_another_machines_expiration_intent() {
        let root = std::env::temp_dir().join(format!(
            "sspolicy-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        let broken = admit_machine(&mut service, "a-broken", MachineLifetime::default());
        let expired = admit_machine(
            &mut service,
            "z-expired",
            MachineLifetime {
                expires_at_unix_millis: Some(Counter::ONE),
                expiration_action: ExpirationAction::Stop,
            },
        );
        service.reconcile_lifetime_policies().unwrap();
        assert_eq!(
            service
                .catalog
                .machine(&broken)
                .unwrap()
                .unwrap()
                .latest_intent
                .desired,
            DesiredState::Running
        );
        let expired = service.catalog.machine(&expired).unwrap().unwrap();
        assert_eq!(expired.latest_intent.desired, DesiredState::Stopped);
        assert!(
            expired.latest_intent.completion.is_none(),
            "a host decision is not native completion"
        );
        assert_eq!(expired.reservation, ReservationState::Held);
        assert!(matches!(
            service.view(expired).unwrap().machine,
            Observation::Unavailable { last_known: None }
        ));
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn continuous_api_traffic_does_not_postpone_expiration_reconciliation() {
        let parent = if cfg!(target_os = "macos") {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let root = parent.join(format!(
            "sstimer-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        let machine = admit_machine(
            &mut service,
            "expiring",
            MachineLifetime {
                expires_at_unix_millis: Some(unix_millis().unwrap().checked_add(1000).unwrap()),
                expiration_action: ExpirationAction::Stop,
            },
        );
        drop(service);
        let serving = root.clone();
        let server = thread::spawn(move || serve_host(&serving, serving.join("absent-executable")));
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        let observed = loop {
            match host_call(
                &root,
                HostRequest::GetMachine {
                    machine_id: machine.clone(),
                },
            ) {
                Ok(HostResponse::Machine { value })
                    if value.lifecycle_intent.desired == DesiredState::Stopped =>
                {
                    assert!(value.lifecycle_intent.completion.is_none());
                    break true;
                }
                Ok(HostResponse::Machine { .. }) => {}
                Err(HostError::EndpointUnavailable(_)) => {}
                response => panic!("unexpected timer fixture response: {response:?}"),
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            // Keep gaps below the old one-second idle-only timer, without
            // saturating the machine or relying on a performance threshold.
            thread::sleep(Duration::from_millis(20));
        };
        host_call(&root, HostRequest::StopService).unwrap();
        server.join().unwrap().unwrap();
        fs::remove_dir_all(root).unwrap();
        assert!(
            observed,
            "continuous client traffic starved host expiration intent"
        );
    }

    #[test]
    fn oversized_response_is_reported_instead_of_closing_the_connection() {
        let oversized = HostResponse::Rejected {
            category: "fixture".into(),
            message: "x".repeat(MAX_CONTROL_BYTES),
        };
        let error = host_response_frame(Counter::ONE, &oversized).unwrap_err();
        let frame = host_response_frame(Counter::ONE, &rejected(error)).unwrap();
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
        // Fixture admission/publication is not the behavior under test. Complete
        // it explicitly before measuring whether an idle connection blocks the
        // production serving loop; do not infer readiness from a timing window.
        let service = HostService::open(&root, std::env::current_exe().unwrap()).unwrap();
        let endpoint = service.endpoint();
        let listener = LocalListener::bind(&endpoint).unwrap();
        let server = thread::spawn(move || serve_host_owned(service, listener));
        let idle = LocalConnection::connect(&endpoint, Duration::from_secs(3)).unwrap();
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
}
