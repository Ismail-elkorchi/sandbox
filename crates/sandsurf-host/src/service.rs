use crate::api::{
    HOST_API_VERSION, HostInspection, HostRequest, HostResponse, MachineView, ReservationView,
};
use crate::guardian::{Guardian, GuardianClient, LifecycleEvidence, LifecyclePlan, serve_guardian};
use sandsurf_machine::GuestArchitecture;
use sandsurf_native::local::{LocalConnection, LocalListener};
use sandsurf_native::storage::object_name;
use sandsurf_protocol::*;
use sandsurf_state::{
    Approval, CatalogLimits, HostCatalog, MachineRecord, ReservationState, RuntimeJournal,
    RuntimeLimits,
};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
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

#[cfg(target_os = "linux")]
type NativeGuardianConfig = crate::linux::LinuxGuardianConfig;
#[cfg(any(target_os = "macos", windows))]
type NativeGuardianConfig = crate::qemu::QemuGuardianConfig;

fn verify_machine_inputs(
    root: &Path,
    executable: &Path,
    machine: &MachineId,
    image: &Digest,
    resources: &Resources,
) -> Result<MachineInputs> {
    #[cfg(target_os = "linux")]
    let configuration = crate::linux::prepare_config(root, executable, machine, image, resources)?;
    #[cfg(any(target_os = "macos", windows))]
    let configuration = crate::qemu::prepare_config(root, executable, machine, image, resources)?;
    let verified = crate::images::resolve_native_image(root, image)?;
    let defaults = verified.manifest.system.defaults;
    Ok(MachineInputs {
        configuration,
        defaults: ExecutionDefaults {
            environment: defaults.environment,
            user: defaults.user,
            working_directory: defaults.working_directory,
        },
        clone_profile: verified.manifest.system.clone_profile,
    })
}

struct MachineInputs {
    configuration: NativeGuardianConfig,
    defaults: ExecutionDefaults,
    clone_profile: sandsurf_image::identity::CloneProfile,
}

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
    #[cfg(any(target_os = "macos", windows))]
    Qemu(crate::qemu::QemuError),
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
            #[cfg(any(target_os = "macos", windows))]
            Self::Qemu(error) => error.fmt(output),
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
#[cfg(any(target_os = "macos", windows))]
impl From<crate::qemu::QemuError> for HostError {
    fn from(value: crate::qemu::QemuError) -> Self {
        Self::Qemu(value)
    }
}

pub type Result<T> = std::result::Result<T, HostError>;

struct HostService {
    root: PathBuf,
    catalog: HostCatalog,
    executable: PathBuf,
    artifacts: Arc<crate::artifacts::ArtifactStore>,
    secrets: crate::secrets::SecretAuthority,
}

impl HostService {
    fn open(root: &Path, executable: PathBuf) -> Result<Self> {
        prepare_directory(root)?;
        let catalog_path = root.join("catalog");
        let catalog = if catalog_path.exists() {
            HostCatalog::open(&catalog_path)?
        } else {
            let host_id = random_id("host")?
                .try_into()
                .map_err(|_| HostError::Invalid("host identity generation failed"))?;
            HostCatalog::create(&catalog_path, host_id, catalog_limits(root)?)?
        };
        prepare_directory(&root.join("api"))?;
        prepare_directory(&root.join("machines"))?;
        prepare_directory(&root.join("images"))?;
        prepare_directory(&root.join("transfers"))?;
        let artifacts = Arc::new(crate::artifacts::ArtifactStore::open(
            &root.join("transfers"),
        )?);
        let secrets = crate::secrets::SecretAuthority::open(&root.join("secrets"))?;
        let mut service = Self {
            root: root.to_path_buf(),
            catalog,
            executable,
            artifacts,
            secrets,
        };
        service.recover_image_releases();
        Ok(service)
    }

    fn endpoint(&self) -> PathBuf {
        self.root.join("api")
    }

    #[cfg(test)]
    fn handle(&mut self, request: HostRequest) -> HostResponse {
        let mut dispatch = self.route(request);
        loop {
            dispatch = match dispatch {
                HostDispatch::Task(task) => match self.complete_task(task.execute()) {
                    Ok(dispatch) => dispatch,
                    Err(error) => return rejected(error),
                },
                response => return response.finish(),
            };
        }
    }

    fn route(&mut self, request: HostRequest) -> HostDispatch {
        let result = match request {
            HostRequest::CreateSnapshot {
                request,
                approval_id,
            } => self.prepare_snapshot(request, approval_id),
            request @ (HostRequest::CreateMachine { .. } | HostRequest::ForkMachine { .. }) => {
                self.prepare_machine_inputs(request)
            }
            request @ HostRequest::Lifecycle { .. } => self.prepare_lifecycle_request(request),
            HostRequest::GetMachine { machine_id } => self
                .catalog
                .machine(&machine_id)
                .map_err(HostError::from)
                .and_then(|record| {
                    let record = record.ok_or(HostError::Invalid("machine does not exist"))?;
                    Ok(HostDispatch::MachineView(Box::new(DeferredMachineView {
                        root: self.root.clone(),
                        record,
                        operation: None,
                    })))
                }),
            HostRequest::ListMachines { after, maximum } => self
                .catalog
                .machines(after.as_ref(), maximum)
                .map_err(HostError::from)
                .map(|records| {
                    HostDispatch::MachineViews(Box::new(DeferredMachineViews {
                        root: self.root.clone(),
                        records,
                    }))
                }),
            HostRequest::OpenObservationStream { machine_id } => self
                .prepare_guardian_inner(&machine_id)
                .map(|provision| HostDispatch::ObservationEndpoint(Box::new(provision))),
            HostRequest::GetUsage { machine_id } => self
                .prepare_guardian_inner(&machine_id)
                .map(|provision| HostDispatch::Task(Box::new(HostTask::Usage { provision }))),
            request @ (HostRequest::ImportOci { .. }
            | HostRequest::ImportNativeImage { .. }
            | HostRequest::PublishSnapshotImage { .. }) => self.prepare_image(request),
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

    fn prepare_snapshot(
        &mut self,
        request: sandsurf_protocol::SnapshotRequest,
        approval_id: CommitmentId,
    ) -> Result<HostDispatch> {
        let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request))?;
        let historical = self.catalog.operation(&request.operation_id)?.is_some();
        if !historical {
            self.catalog
                .require_revision(&request.machine_id, request.expected_revision)?;
            self.provision_guardian(&request.machine_id)?;
            let inspection = GuardianClient::new(self.guardian_endpoint(&request.machine_id))
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
            return Ok(HostDispatch::Ready(Box::new(HostResponse::Snapshot {
                value: admitted,
            })));
        }
        // A completed opaque input remains finishable after native destruction.
        // Only a retained native pause owner, or missing capture input, requires
        // a machine attachment. Record presence is not completion evidence.
        if crate::capture::CaptureBoundary::read(&self.machine_root(&request.machine_id))?.is_some()
            || !crate::snapshots::has_capture_record(
                &crate::snapshots::root(&self.root, &admitted),
                &admitted,
            )?
        {
            self.provision_guardian(&request.machine_id)?;
        }
        let capturing = self.catalog.begin_snapshot(&request.id, &request_digest)?;
        Ok(HostDispatch::Task(Box::new(HostTask::Snapshot {
            root: self.root.clone(),
            executable: self.executable.clone(),
            endpoint: self.guardian_endpoint(&request.machine_id),
            capturing: Box::new(capturing),
        })))
    }

    fn prepare_machine_inputs(&self, request: HostRequest) -> Result<HostDispatch> {
        let image = match &request {
            HostRequest::CreateMachine { image_digest, .. } => image_digest.clone(),
            HostRequest::ForkMachine { snapshot_id, .. } => {
                let snapshot = self
                    .catalog
                    .snapshot(snapshot_id)?
                    .ok_or(HostError::Invalid("fork snapshot does not exist"))?;
                if snapshot.phase != SnapshotPhase::Ready {
                    return Err(HostError::Invalid("fork snapshot is not ready"));
                }
                snapshot.image_digest
            }
            _ => return Err(HostError::Invalid("invalid machine input request")),
        };
        self.catalog
            .image(&image)?
            .ok_or(HostError::Invalid("machine image has not been admitted"))?;
        Ok(HostDispatch::Task(Box::new(HostTask::MachineInputs {
            root: self.root.clone(),
            executable: self.executable.clone(),
            image,
            request: Box::new(request),
        })))
    }

    fn admit_machine_inputs(
        &mut self,
        request: HostRequest,
        inputs: MachineInputs,
    ) -> Result<HostDispatch> {
        if let HostRequest::CreateMachine {
            machine_id,
            image_digest,
            resources,
            execution_defaults,
            lifetime,
            operation_id,
            approval_id,
        } = request
        {
            self.catalog
                .image(&image_digest)?
                .ok_or(HostError::Invalid("machine image is no longer admitted"))?;
            let request_digest = digest(
                Domain::Machine,
                &(
                    &machine_id,
                    &image_digest,
                    &resources,
                    &execution_defaults,
                    &lifetime,
                    &operation_id,
                ),
            )?;
            self.catalog.create_machine(
                sandsurf_state::MachineAdmission {
                    id: machine_id.clone(),
                    image: image_digest,
                    resources,
                    defaults: execution_defaults,
                    image_defaults: inputs.defaults,
                    lifetime,
                    operation: operation_id.clone(),
                },
                Approval {
                    id: approval_id,
                    request_digest,
                },
            )?;
            let provision =
                self.prepare_guardian_with_config(&machine_id, &inputs.configuration)?;
            return Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
                machine_id,
                provision,
                effect: LifecycleEffect::ordinary(LifecyclePlan::admit(
                    &self.catalog,
                    &operation_id,
                )?),
            })));
        }
        self.admit_fork(request, inputs)
    }

    fn admit_fork(&mut self, request: HostRequest, inputs: MachineInputs) -> Result<HostDispatch> {
        let HostRequest::ForkMachine {
            machine_id,
            snapshot_id,
            resources,
            lifetime,
            operation_id,
            approval_id,
        } = request
        else {
            return Err(HostError::Invalid("invalid fork admission request"));
        };
        let snapshot = self
            .catalog
            .snapshot(&snapshot_id)?
            .ok_or(HostError::Invalid("fork snapshot does not exist"))?;
        if snapshot.phase != SnapshotPhase::Ready {
            return Err(HostError::Invalid("fork snapshot is not ready"));
        }
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
        self.catalog.create_machine_from_snapshot(
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
        let provision = self.prepare_guardian_with_config(&machine_id, &inputs.configuration)?;
        let fork = self
            .catalog
            .fork(&machine_id)?
            .ok_or(HostError::Invalid("fork admission disappeared"))?;
        if fork.materialized_disk.is_some() {
            return Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
                machine_id,
                provision,
                effect: LifecycleEffect::ordinary(LifecyclePlan::admit(
                    &self.catalog,
                    &operation_id,
                )?),
            })));
        }
        Ok(HostDispatch::Task(Box::new(HostTask::Fork {
            root: self.root.clone(),
            executable: self.executable.clone(),
            snapshot: Box::new(snapshot),
            record: fork,
            clone_profile: Some(inputs.clone_profile),
            provision,
            continuation: operation_id,
        })))
    }

    fn prepare_image(&mut self, request: HostRequest) -> Result<HostDispatch> {
        sandsurf_native::volume::inspect(&self.root)?;
        match request {
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
                        "sandsurf-import-oci-v1",
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
                    return Ok(HostDispatch::Ready(Box::new(HostResponse::ImageImport {
                        operation: admitted,
                    })));
                }
                self.catalog
                    .image(&recipe.boot_image_digest)?
                    .ok_or(HostError::Invalid("OCI boot image has not been admitted"))?;
                Ok(HostDispatch::Task(Box::new(HostTask::Image {
                    root: self.root.clone(),
                    executable: self.executable.clone(),
                    job: crate::image_worker::Job {
                        operation: operation_id,
                        request_digest,
                        build: crate::image_worker::Build::Oci {
                            source,
                            recipe,
                            platform,
                        },
                    },
                })))
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
                    return Ok(HostDispatch::Ready(Box::new(HostResponse::ImageImport {
                        operation: admitted,
                    })));
                }
                Ok(HostDispatch::Task(Box::new(HostTask::Image {
                    root: self.root.clone(),
                    executable: self.executable.clone(),
                    job: crate::image_worker::Job {
                        operation: operation_id,
                        request_digest,
                        build: crate::image_worker::Build::Native {
                            manifest_path,
                            manifest_digest,
                        },
                    },
                })))
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
                        "sandsurf-publish-snapshot-image-v1",
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
                    return Ok(HostDispatch::Ready(Box::new(HostResponse::ImageImport {
                        operation: admitted,
                    })));
                }
                Ok(HostDispatch::Task(Box::new(HostTask::Image {
                    root: self.root.clone(),
                    executable: self.executable.clone(),
                    job: crate::image_worker::Job {
                        operation: operation_id,
                        request_digest,
                        build: crate::image_worker::Build::PublishSnapshot {
                            snapshot: Box::new(snapshot),
                            allow_sensitive,
                        },
                    },
                })))
            }
            _ => Err(HostError::Invalid("request is not an image operation")),
        }
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
            HostRequest::ReadConsole {
                machine_id,
                generation,
                after,
                maximum,
            } => (
                machine_id.clone(),
                RuntimeRequest::ReadConsole {
                    generation: *generation,
                    after: *after,
                    maximum: *maximum,
                },
            ),
            HostRequest::WriteConsole {
                machine_id,
                generation,
                bytes,
            } => (
                machine_id.clone(),
                RuntimeRequest::WriteConsole {
                    generation: *generation,
                    bytes: bytes.clone(),
                },
            ),
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
        let provision = self.prepare_guardian_inner(&machine_id)?;
        Ok(Some(DeferredRuntimeRead {
            endpoint: self.guardian_endpoint(&machine_id),
            machine_id,
            query,
            provision,
        }))
    }

    fn handle_inner(&mut self, request: HostRequest) -> Result<HostResponse> {
        match request {
            HostRequest::Inspect => Ok(HostResponse::Inspection {
                value: self.inspect(),
            }),
            HostRequest::StopService => Ok(HostResponse::Complete),
            HostRequest::OpenObservationStream { .. }
            | HostRequest::ListMachines { .. }
            | HostRequest::GetMachine { .. } => Err(HostError::Invalid(
                "native observations run outside the catalog owner",
            )),
            HostRequest::GetHostOperation { operation_id } => {
                self.recover_image_import(&operation_id)?;
                Ok(HostResponse::HostOperation {
                    value: self.catalog.operation(&operation_id)?,
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
            HostRequest::GetImageImport { operation_id } => {
                self.recover_image_import(&operation_id)?;
                Ok(HostResponse::ImageImport {
                    operation: self
                        .catalog
                        .image_import(&operation_id)?
                        .ok_or(HostError::Invalid("image import operation does not exist"))?,
                })
            }
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
            HostRequest::CreateSnapshot { .. } => {
                Err(HostError::Invalid("snapshot requires deferred admission"))
            }
            HostRequest::ImportOci { .. }
            | HostRequest::ImportNativeImage { .. }
            | HostRequest::PublishSnapshotImage { .. } => Err(HostError::Invalid(
                "image operation requires deferred worker admission",
            )),
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
            HostRequest::CreateMachine { .. } | HostRequest::ForkMachine { .. } => {
                Err(HostError::Invalid(
                    "machine creation requires catalog admission and deferred native effects",
                ))
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
                    &crate::snapshots::root(&self.root, &snapshot),
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
            HostRequest::Lifecycle { .. } => Err(HostError::Invalid(
                "lifecycle requires deferred native effects",
            )),
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
                        "sandsurf-put-secret-v1",
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
                let response = GuardianClient::new(self.guardian_endpoint(&machine_id)).runtime(
                    machine_id.clone(),
                    RuntimeRequest::AssessResources {
                        resources: resources.clone(),
                    },
                )?;
                let RuntimeResponse::ResourceAssessment { assessment } = response else {
                    return Err(HostError::Invalid("native resource assessment unavailable"));
                };
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
                Ok(HostResponse::ResourceUpdate {
                    revision: operation.revision,
                    machine: self.view(record)?,
                    assessment,
                })
            }
            HostRequest::AssessResources {
                machine_id,
                resources,
            } => {
                self.provision_guardian(&machine_id)?;
                let response = GuardianClient::new(self.guardian_endpoint(&machine_id))
                    .runtime(machine_id, RuntimeRequest::AssessResources { resources })?;
                let RuntimeResponse::ResourceAssessment { assessment } = response else {
                    return Err(HostError::Invalid("native resource assessment unavailable"));
                };
                Ok(HostResponse::ResourceAssessment { assessment })
            }
            HostRequest::GetUsage { .. } => Err(HostError::Invalid(
                "resource sampling requires deferred observation",
            )),
            HostRequest::ReadConsole { .. } | HostRequest::WriteConsole { .. } => Err(
                HostError::Invalid("native console I/O requires deferred guardian routing"),
            ),
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
        let network_egress = sandsurf_network::egress_capability();
        let (qualification_records, qualification_issues) =
            match crate::qualification::inspect(&self.root) {
                Ok(records) => (records, Vec::new()),
                Err(error) => (
                    Vec::new(),
                    vec![format!("retained native evidence unavailable: {error}")],
                ),
            };
        let engine = if cfg!(target_os = "macos") {
            VmEngine::QemuHvf
        } else if cfg!(target_os = "windows") {
            VmEngine::QemuWhpx
        } else {
            VmEngine::Firecracker
        };
        let reason = if qualification_records.is_empty() {
            format!(
                "{} driver has no retained real-hardware qualification for this exact build/configuration",
                std::env::consts::OS
            )
        } else {
            "qualification is scoped to the exact configurations and mechanisms in qualificationRecords; no blanket platform qualification is implied".into()
        };
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
            full_state: {
                #[cfg(any(target_os = "macos", windows))]
                {
                    sandsurf_machine::qemu_driver::full_state_capability()
                }
                #[cfg(not(any(target_os = "macos", windows)))]
                {
                    Capability::Supported {
                        qualification: Qualification::Unqualified {
                            reasons: vec![reason],
                        },
                    }
                }
            },
            images: { crate::images::qualification() },
            image_workers: crate::image_worker::capability(&self.root),
            resources: crate::resources::capabilities(&self.root, &network_egress),
            network_egress,
            qualification_records,
            qualification_issues,
            guest_power: sandsurf_machine::guest_power_capabilities(),
            console: sandsurf_machine::native_console_capability(),
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

    fn prepare_lifecycle_request(&mut self, request: HostRequest) -> Result<HostDispatch> {
        let HostRequest::Lifecycle {
            machine_id,
            operation_id,
            expected_revision,
            desired,
            approval_id,
        } = request
        else {
            return Err(HostError::Invalid("invalid lifecycle admission"));
        };
        self.require_revision_for_new_host_operation(
            &machine_id,
            &operation_id,
            expected_revision,
        )?;
        let request_digest = digest(
            Domain::Operation,
            &(&machine_id, &operation_id, expected_revision, desired),
        )?;
        let intent = self.catalog.request_lifecycle(
            &machine_id,
            operation_id,
            expected_revision,
            desired,
            Approval {
                id: approval_id,
                request_digest,
            },
        )?;
        self.prepare_lifecycle_intent(intent)
    }

    fn prepare_lifecycle_intent(&mut self, intent: LifecycleIntent) -> Result<HostDispatch> {
        let intent = self
            .catalog
            .intent(&intent.operation_id)?
            .ok_or(HostError::Invalid("lifecycle admission disappeared"))?;
        if intent.completion.is_none() && intent.desired == DesiredState::Running {
            let config = self
                .machine_root(&intent.machine_id)
                .join("guardian/config.json");
            if !config.exists() {
                let record = self
                    .catalog
                    .machine(&intent.machine_id)?
                    .ok_or(HostError::Invalid("machine bootstrap is missing"))?;
                return Ok(HostDispatch::Task(Box::new(HostTask::MachineBootstrap {
                    root: self.root.clone(),
                    executable: self.executable.clone(),
                    record: Box::new(record),
                    intent,
                })));
            }
            if let Some(fork) = self.catalog.fork(&intent.machine_id)?
                && fork.materialized_disk.is_none()
            {
                let snapshot = self
                    .catalog
                    .snapshot(&fork.snapshot_id)?
                    .ok_or(HostError::Invalid("fork recovery snapshot is missing"))?;
                let provision = self.prepare_guardian_inner(&intent.machine_id)?;
                return Ok(HostDispatch::Task(Box::new(HostTask::Fork {
                    root: self.root.clone(),
                    executable: self.executable.clone(),
                    snapshot: Box::new(snapshot),
                    record: fork,
                    clone_profile: None,
                    provision,
                    continuation: intent.operation_id,
                })));
            }
        }
        let provision = self.prepare_guardian_inner(&intent.machine_id)?;
        if intent.completion.is_none()
            && matches!(
                intent.desired,
                DesiredState::Running | DesiredState::Suspended
            )
        {
            return Ok(HostDispatch::Task(Box::new(HostTask::LifecycleInspect {
                intent,
                provision,
            })));
        }
        let plan = LifecyclePlan::admit(&self.catalog, &intent.operation_id)?;
        Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
            machine_id: intent.machine_id,
            provision,
            effect: LifecycleEffect::ordinary(plan),
        })))
    }

    fn prepare_lifecycle_effect(
        &mut self,
        intent: LifecycleIntent,
        provision: GuardianProvision,
        inspection: GuardianInspection,
    ) -> Result<HostDispatch> {
        let intent = self
            .catalog
            .intent(&intent.operation_id)?
            .ok_or(HostError::Invalid("lifecycle admission disappeared"))?;
        let plan = LifecyclePlan::admit(&self.catalog, &intent.operation_id)?;
        if intent.completion.is_some() {
            return Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
                machine_id: intent.machine_id,
                provision,
                effect: LifecycleEffect::ordinary(plan),
            })));
        }
        let current = match inspection.observation {
            Observation::Current { value } => Some(value),
            Observation::Unavailable { .. } => None,
        };
        if intent.desired == DesiredState::Suspended {
            let current =
                current.ok_or(HostError::Invalid("suspend requires a native observation"))?;
            let (snapshot_id, operation_id) = suspension_identities(&intent)?;
            if current.state == MachineState::Suspended {
                let snapshot = self
                    .catalog
                    .snapshot(&snapshot_id)?
                    .ok_or(HostError::Invalid(
                        "suspended machine has no lifecycle snapshot",
                    ))?;
                let manifest_digest = snapshot
                    .manifest_digest
                    .ok_or(HostError::Invalid("suspension manifest is missing"))?;
                return Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
                    machine_id: intent.machine_id,
                    provision,
                    effect: Box::new(LifecycleEffect {
                        plan,
                        prepare: None,
                        custody: None,
                        post: LifecyclePost::Suspend {
                            snapshot_id,
                            manifest_digest,
                        },
                    }),
                })));
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
                operation_id,
                machine_id: intent.machine_id.clone(),
                expected_generation: current.generation,
                expected_revision: current.applied_revision,
                kind: SnapshotKind::Full,
                parent: None,
            };
            let admitted = self
                .catalog
                .admit_suspension_snapshot(request, &intent.operation_id)?;
            let capturing = if admitted.phase == SnapshotPhase::Ready {
                admitted
            } else {
                self.catalog
                    .begin_snapshot(&snapshot_id, &admitted.request_digest)?
            };
            return Ok(HostDispatch::Task(Box::new(HostTask::SuspendCapture {
                root: self.root.clone(),
                intent,
                provision,
                capturing: Box::new(capturing),
            })));
        }
        let mut effect = LifecycleEffect::ordinary(plan);
        if intent.desired == DesiredState::Running
            && let Some(current) = current
            && current.state == MachineState::Suspended
        {
            if current.applied_revision.next()? != intent.revision {
                return Err(HostError::Invalid(
                    "restore does not follow the suspended revision",
                ));
            }
            let suspension =
                self.catalog
                    .suspension(&intent.machine_id)?
                    .ok_or(HostError::Invalid(
                        "suspended machine has no committed restore snapshot",
                    ))?;
            let snapshot = self
                .catalog
                .snapshot(&suspension.snapshot_id)?
                .ok_or(HostError::Invalid("restore snapshot is missing"))?;
            let full = snapshot
                .full
                .ok_or(HostError::Invalid("restore snapshot has no machine state"))?;
            effect.prepare = Some(NativeSnapshotRequest::StageRestore {
                snapshot_id: suspension.snapshot_id.clone(),
                manifest_digest: suspension.manifest_digest,
                system_disk: SnapshotArtifact {
                    digest: snapshot
                        .system_disk_digest
                        .ok_or(HostError::Invalid("restore snapshot has no system disk"))?,
                    bytes: snapshot.system_disk_bytes,
                },
                expected: Box::new(full),
            });
            effect.post = LifecyclePost::Restore {
                snapshot_id: suspension.snapshot_id,
            };
        }
        Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
            machine_id: intent.machine_id,
            provision,
            effect,
        })))
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
                "sandsurf-deliver-secret-v1",
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
                        "sandsurf-guest-tree-capture-v1",
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
                if maximum_bytes > record.runtime_configuration.resources.disk_bytes {
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

    fn recover_image_import(&mut self, operation: &OperationId) -> Result<()> {
        if let Some(admitted) = self.catalog.image_import(operation)?
            && admitted.phase == sandsurf_state::ImageImportPhase::Admitted
            && let Some(image) =
                crate::image_worker::completed(&self.root, operation, &admitted.request_digest)?
        {
            self.catalog
                .complete_image_import(operation, &admitted.request_digest, image)?;
        }
        Ok(())
    }

    fn complete_task(&mut self, completion: HostTaskCompletion) -> Result<HostDispatch> {
        match completion {
            HostTaskCompletion::MachineInputs { request, result } => {
                self.admit_machine_inputs(*request, result?)
            }
            HostTaskCompletion::MachineBootstrap { intent, result } => {
                let inputs = result?;
                self.prepare_guardian_with_config(&intent.machine_id, &inputs.configuration)?;
                self.prepare_lifecycle_intent(intent)
            }
            HostTaskCompletion::LifecycleInspect {
                intent,
                provision,
                result,
            } => self.prepare_lifecycle_effect(intent, provision, (*result)?),
            HostTaskCompletion::SuspendCapture {
                intent,
                provision,
                capturing,
                result,
            } => {
                let (captured, custody) = result?;
                let snapshot = complete_snapshot_capture(
                    &mut self.catalog,
                    &capturing.request.id,
                    &capturing.request_digest,
                    captured,
                )?;
                let manifest_digest = snapshot.manifest_digest.ok_or(HostError::Invalid(
                    "suspension snapshot has no committed manifest",
                ))?;
                let effect = LifecycleEffect {
                    plan: LifecyclePlan::admit(&self.catalog, &intent.operation_id)?,
                    prepare: Some(NativeSnapshotRequest::CommitSuspend {
                        operation_id: capturing.request.operation_id,
                        manifest_digest: manifest_digest.clone(),
                    }),
                    post: LifecyclePost::Suspend {
                        snapshot_id: snapshot.request.id,
                        manifest_digest,
                    },
                    custody: Some(custody),
                };
                Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
                    machine_id: intent.machine_id,
                    provision,
                    effect: Box::new(effect),
                })))
            }
            HostTaskCompletion::Lifecycle {
                machine_id,
                result,
                post,
                custody: _custody,
            } => {
                let lifecycle = result?.complete(&mut self.catalog)?;
                if let Some(intent) = &lifecycle.completed_intent {
                    match post {
                        LifecyclePost::None => {}
                        LifecyclePost::Suspend {
                            snapshot_id,
                            manifest_digest,
                        } => {
                            self.catalog.record_suspension(
                                &machine_id,
                                &intent.operation_id,
                                &snapshot_id,
                                &manifest_digest,
                            )?;
                        }
                        LifecyclePost::Restore { snapshot_id } => {
                            if self.catalog.suspension(&machine_id)?.is_some() {
                                self.catalog.clear_suspension(&machine_id, &snapshot_id)?;
                            }
                        }
                    }
                    if intent.desired == DesiredState::Running {
                        self.catalog.observe_activity(&machine_id, unix_millis()?)?;
                    }
                    if intent.desired == DesiredState::Destroyed {
                        self.retire_machine_storage(&machine_id)?;
                    }
                }
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine disappeared before completion"))?;
                Ok(HostDispatch::MachineView(Box::new(DeferredMachineView {
                    root: self.root.clone(),
                    record,
                    operation: Some(lifecycle.guardian_operation),
                })))
            }
            HostTaskCompletion::Fork {
                record,
                provision,
                result,
                continuation,
            } => {
                self.catalog.complete_fork_materialization(
                    &record.machine_id,
                    &record.operation_id,
                    &record.request_digest,
                    result?,
                )?;
                Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
                    machine_id: record.machine_id,
                    provision,
                    effect: LifecycleEffect::ordinary(LifecyclePlan::admit(
                        &self.catalog,
                        &continuation,
                    )?),
                })))
            }
            completion => self
                .complete_task_response(completion)
                .map(|response| HostDispatch::Ready(Box::new(response))),
        }
    }

    fn complete_task_response(&mut self, completion: HostTaskCompletion) -> Result<HostResponse> {
        match completion {
            HostTaskCompletion::Usage { machine_id, result } => {
                let (generation, usage) = result?;
                Ok(HostResponse::Usage {
                    usage: self.catalog.observe_usage(&machine_id, generation, usage)?,
                })
            }
            HostTaskCompletion::Configuration { result }
            | HostTaskCompletion::CaptureRecovery { result } => {
                result?;
                Ok(HostResponse::Complete)
            }
            HostTaskCompletion::MachineInputs { .. }
            | HostTaskCompletion::MachineBootstrap { .. }
            | HostTaskCompletion::LifecycleInspect { .. }
            | HostTaskCompletion::SuspendCapture { .. }
            | HostTaskCompletion::Lifecycle { .. }
            | HostTaskCompletion::Fork { .. } => Err(HostError::Invalid(
                "machine effects require staged completion",
            )),
            HostTaskCompletion::Snapshot {
                snapshot_id,
                request_digest,
                result,
            } => Ok(HostResponse::Snapshot {
                value: complete_snapshot_capture(
                    &mut self.catalog,
                    &snapshot_id,
                    &request_digest,
                    result?,
                )?,
            }),
            HostTaskCompletion::Image {
                operation,
                request_digest,
                result,
            } => Ok(HostResponse::ImageImport {
                operation: self.catalog.complete_image_import(
                    &operation,
                    &request_digest,
                    result?,
                )?,
            }),
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
        self.prepare_guardian_inner(machine)?.execute()
    }

    fn prepare_guardian_with_config(
        &self,
        machine: &MachineId,
        config: &NativeGuardianConfig,
    ) -> Result<GuardianProvision> {
        let root = self.machine_root(machine);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let path = root.join("guardian/config.json");
        #[cfg(target_os = "linux")]
        crate::linux::write_config(&path, config)?;
        #[cfg(any(target_os = "macos", windows))]
        crate::qemu::write_config(&path, config)?;
        self.prepare_guardian_inner(machine)
    }

    fn prepare_guardian_inner(&self, machine: &MachineId) -> Result<GuardianProvision> {
        let root = self.machine_root(machine);
        #[cfg(target_os = "linux")]
        crate::resources::require_machine_storage(
            &self.root,
            machine,
            &self
                .catalog
                .machine(machine)?
                .ok_or(HostError::Invalid("machine is missing from host authority"))?
                .runtime_configuration
                .resources,
        )?;
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
                .runtime_configuration
                .resources;
            RuntimeJournal::create(
                &runtime,
                machine.clone(),
                runtime_limits(&resources),
                self.catalog.authority_binding().clone(),
            )?;
        }
        Ok(GuardianProvision {
            host_root: self.root.clone(),
            machine: machine.clone(),
        })
    }

    fn view(&mut self, record: MachineRecord) -> Result<MachineView> {
        observe_machine(&self.root, record)
    }

    fn apply_configuration(&mut self, machine: &MachineId, revision: Counter) -> Result<()> {
        let provision = self.prepare_guardian_inner(machine)?;
        let authorization = self.catalog.authorize_configuration(machine, revision)?;
        perform_configuration(&provision, authorization)
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

    /// Admit host policy changes on the sole writer; native reconciliation
    /// uses the same detached tasks as SDK requests.
    fn reconcile_lifetime_policies(&mut self) -> Result<Vec<(MachineId, HostDispatch)>> {
        let now = unix_millis()?;
        let mut work = Vec::new();
        let mut after_snapshot = None;
        loop {
            let snapshots = self
                .catalog
                .snapshots(after_snapshot.as_ref(), counter(256))?;
            if snapshots.is_empty() {
                break;
            }
            after_snapshot = snapshots.last().map(|snapshot| snapshot.request.id.clone());
            for snapshot in snapshots {
                if snapshot.phase != SnapshotPhase::Capturing
                    || snapshot.request.kind != SnapshotKind::Disk
                {
                    continue;
                }
                let machine = &snapshot.request.machine_id;
                let prepare = (|| -> Result<Option<GuardianProvision>> {
                    if crate::capture::CaptureBoundary::read(&self.machine_root(machine))?
                        .is_some_and(|boundary| {
                            boundary.operation_id == snapshot.request.operation_id
                        })
                    {
                        return self.prepare_guardian_inner(machine).map(Some);
                    }
                    Ok(None)
                })();
                match prepare {
                    Ok(Some(provision)) => work.push((
                        machine.clone(),
                        HostDispatch::Task(Box::new(HostTask::CaptureRecovery {
                            provision,
                            snapshot: Box::new(snapshot),
                        })),
                    )),
                    Ok(None) => {}
                    Err(error) => eprintln!("sandsurf capture recovery deferred: {error}"),
                }
            }
        }
        let mut after = None;
        loop {
            let records = self.catalog.machines(after.as_ref(), counter(256))?;
            if records.is_empty() {
                break;
            }
            after = records.last().map(|record| record.id.clone());
            for record in records {
                let id = record.id.clone();
                match self.reconcile_machine(record, now) {
                    Ok(Some(dispatch)) => work.push((id, dispatch)),
                    Ok(None) => {}
                    Err(error) => eprintln!(
                        "sandsurf machine {} reconciliation deferred: {error}",
                        id.as_str()
                    ),
                }
            }
        }
        Ok(work)
    }

    fn reconcile_machine(
        &mut self,
        record: MachineRecord,
        now: Counter,
    ) -> Result<Option<HostDispatch>> {
        if record.reservation == ReservationState::Released {
            return Ok(None);
        }
        if record.latest_intent.desired == DesiredState::Destroyed
            && record.latest_intent.completion.is_some()
        {
            self.retire_machine_storage(&record.id)?;
            return Ok(None);
        }
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
                return self
                    .prepare_policy_lifecycle(record, desired, "expiration")
                    .map(Some);
            }
        }
        if record.latest_intent.completion.is_none()
            && record.latest_intent.revision == record.configuration_revision
        {
            return self
                .prepare_lifecycle_intent(record.latest_intent)
                .map(Some);
        }
        if record.latest_intent.desired == DesiredState::Destroyed {
            return Ok(None);
        }
        Ok(Some(HostDispatch::Task(Box::new(
            HostTask::Configuration {
                provision: self.prepare_guardian_inner(&record.id)?,
                authorization: self
                    .catalog
                    .authorize_configuration(&record.id, record.configuration_revision)?,
            },
        ))))
    }

    fn prepare_policy_lifecycle(
        &mut self,
        record: MachineRecord,
        desired: DesiredState,
        reason: &str,
    ) -> Result<HostDispatch> {
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
        self.prepare_lifecycle_intent(intent)
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
            record.runtime_configuration.resources.disk_bytes.get(),
        )?;
        self.catalog.release_retired_storage(machine)?;
        Ok(())
    }

    fn guardian_endpoint(&self, machine: &MachineId) -> PathBuf {
        self.machine_root(machine).join("guardian")
    }
}

fn perform_configuration(
    provision: &GuardianProvision,
    authorization: AuthorizedConfiguration,
) -> Result<()> {
    provision.execute()?;
    let command = authorization.statement.command.clone();
    let operation = GuardianClient::new(provision.endpoint()).configure(authorization)?;
    if operation.delivery != Delivery::Applied || operation.command != command {
        return Err(HostError::Invalid(
            "guardian did not apply the host configuration revision",
        ));
    }
    Ok(())
}

enum LifecyclePost {
    None,
    Suspend {
        snapshot_id: SnapshotId,
        manifest_digest: Digest,
    },
    Restore {
        snapshot_id: SnapshotId,
    },
}

struct LifecycleEffect {
    plan: LifecyclePlan,
    prepare: Option<NativeSnapshotRequest>,
    post: LifecyclePost,
    // The native capture task remains exclusively owned across catalog
    // completion and CommitSuspend. It is never replaced by a record reference.
    custody: Option<fs::File>,
}

impl LifecycleEffect {
    fn ordinary(plan: LifecyclePlan) -> Box<Self> {
        Box::new(Self {
            plan,
            prepare: None,
            post: LifecyclePost::None,
            custody: None,
        })
    }
}

struct GuardianProvision {
    host_root: PathBuf,
    machine: MachineId,
}

impl GuardianProvision {
    fn endpoint(&self) -> PathBuf {
        self.host_root
            .join("machines")
            .join(object_name(self.machine.as_str()))
            .join("guardian")
    }

    fn execute(&self) -> Result<()> {
        let machine = &self.machine;
        let root = self
            .host_root
            .join("machines")
            .join(object_name(machine.as_str()));
        let endpoint = root.join("guardian");
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
        crate::supervision::call(
            &self.host_root,
            crate::supervision::Request::Ensure {
                machine: machine.clone(),
            },
        )
        .map_err(|error| {
            HostError::GuardianStartup(format!(
                "independent guardian supervisor is unavailable: {error}"
            ))
        })?;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if GuardianClient::new(endpoint.clone())
                .owner_identity(machine.clone())
                .is_ok()
            {
                return Ok(());
            }
            crate::supervision::call(
                &self.host_root,
                crate::supervision::Request::Check {
                    machine: machine.clone(),
                },
            )
            .map_err(|error| {
                HostError::GuardianStartup(format!(
                    "guardian launch failed: {error}; inspect {}",
                    root.join("guardian/guardian.log").display()
                ))
            })?;
            if std::time::Instant::now() >= deadline {
                return Err(HostError::GuardianStartup(format!(
                    "guardian did not become reachable; inspect {}",
                    root.join("guardian/guardian.log").display()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn observe_machine(host_root: &Path, record: MachineRecord) -> Result<MachineView> {
    let machine_root = host_root
        .join("machines")
        .join(object_name(record.id.as_str()));
    let storage = crate::storage::inspect(&machine_root.join("disks/system.ext4"));
    let (machine, management) =
        match GuardianClient::new(machine_root.join("guardian")).inspect(record.id.clone(), None) {
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
        runtime_configuration: record.runtime_configuration,
        configuration_revision: record.configuration_revision,
        reservation: match record.reservation {
            ReservationState::Held => ReservationView::Held,
            ReservationState::Released => ReservationView::Released,
        },
        lifecycle_intent: record.latest_intent,
        machine,
        management,
        storage,
    })
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
        let reconciliation_sender = sender.clone();
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
                                let Some(dispatch) = execute_host_tasks(dispatch, &sender) else {
                                    return;
                                };
                                let response = dispatch.finish();
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
        // Scheduling only: no cached observations, grants or lifecycle facts.
        // Crash recovery derives the work again from the catalog.
        let mut reconciliations = BTreeSet::new();
        let result = loop {
            if std::time::Instant::now() >= next_reconciliation {
                match service.reconcile_lifetime_policies() {
                    Ok(work) => {
                        for (machine, dispatch) in work {
                            if reconciliations.len() >= MAX_HOST_CONNECTIONS / 2
                                || reconciliations.contains(&machine)
                            {
                                continue;
                            }
                            let sender = reconciliation_sender.clone();
                            let identity = machine.clone();
                            match std::thread::Builder::new().name("sandsurf-host-reconcile".into()).spawn(move || {
                            if let Some(HostDispatch::Ready(response)) = execute_host_tasks(dispatch, &sender)
                                && let HostResponse::Rejected { message, .. } = *response
                            {
                                eprintln!("sandsurf machine {} reconciliation deferred: {message}", identity.as_str());
                            }
                            let _ = sender.send(HostIngress::Reconciled(identity));
                        }) {
                            Ok(_) => { reconciliations.insert(machine); }
                            Err(error) => eprintln!("sandsurf reconciliation worker unavailable: {error}"),
                        }
                        }
                    }
                    Err(error) => eprintln!("sandsurf host reconciliation deferred: {error}"),
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
                    let _ =
                        reply.send(service.complete_task(*completion).unwrap_or_else(|error| {
                            HostDispatch::Ready(Box::new(rejected(error)))
                        }));
                }
                Ok(HostIngress::Reconciled(machine)) => {
                    reconciliations.remove(&machine);
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

/// Both API clients and recovery workers execute the same admitted task chain.
/// They return every durable completion to the one catalog owner.
fn execute_host_tasks(
    mut dispatch: HostDispatch,
    sender: &mpsc::SyncSender<HostIngress>,
) -> Option<HostDispatch> {
    loop {
        dispatch = match dispatch {
            HostDispatch::Task(task) => {
                let completion = task.execute();
                let (reply, committed) = mpsc::channel();
                sender
                    .send(HostIngress::TaskComplete {
                        completion: Box::new(completion),
                        reply,
                    })
                    .ok()?;
                committed.recv().ok()?
            }
            dispatch => return Some(dispatch),
        };
    }
}

enum HostIngress {
    Reconciled(MachineId),
    Request {
        parsed: Box<Result<HostRequest>>,
        reply: mpsc::Sender<HostDispatch>,
        delivered: mpsc::Receiver<()>,
    },
    TaskComplete {
        completion: Box<HostTaskCompletion>,
        reply: mpsc::Sender<HostDispatch>,
    },
    Failed(io::Error),
}

enum HostDispatch {
    ArtifactRead(Box<DeferredArtifactRead>),
    Ready(Box<HostResponse>),
    Runtime(Box<DeferredRuntimeRead>),
    Guest(Box<DeferredGuest>),
    Task(Box<HostTask>),
    MachineView(Box<DeferredMachineView>),
    MachineViews(Box<DeferredMachineViews>),
    ObservationEndpoint(Box<GuardianProvision>),
}

struct DeferredMachineViews {
    root: PathBuf,
    records: Vec<MachineRecord>,
}

impl DeferredMachineViews {
    fn execute(self) -> Result<HostResponse> {
        Ok(HostResponse::Machines {
            values: self
                .records
                .into_iter()
                .map(|record| observe_machine(&self.root, record))
                .collect::<Result<_>>()?,
        })
    }
}

struct DeferredMachineView {
    root: PathBuf,
    record: MachineRecord,
    operation: Option<LifecycleOperation>,
}

impl DeferredMachineView {
    fn execute(self) -> Result<HostResponse> {
        let value = observe_machine(&self.root, self.record)?;
        Ok(match self.operation {
            Some(operation) => HostResponse::Lifecycle {
                operation,
                machine: Box::new(value),
            },
            None => HostResponse::Machine { value },
        })
    }
}

impl HostDispatch {
    fn finish(self) -> HostResponse {
        match self {
            Self::Ready(response) => *response,
            Self::ArtifactRead(read) => read.execute().unwrap_or_else(rejected),
            Self::Runtime(read) => (*read).execute().unwrap_or_else(rejected),
            Self::Guest(guest) => (*guest).execute().unwrap_or_else(rejected),
            Self::MachineView(view) => view.execute().unwrap_or_else(rejected),
            Self::MachineViews(views) => views.execute().unwrap_or_else(rejected),
            Self::ObservationEndpoint(provision) => provision
                .execute()
                .map(|()| HostResponse::ObservationStream {
                    endpoint: provision.endpoint(),
                })
                .unwrap_or_else(rejected),
            Self::Task(_) => rejected(HostError::Invalid(
                "host task completion requires its catalog owner",
            )),
        }
    }
}

/// Immutable admitted effects run away from the catalog writer. Only owner
/// completion may change durable host state; workers never receive the catalog.
fn capture_snapshot(
    root: &Path,
    executable: &Path,
    endpoint: &Path,
    capturing: &sandsurf_protocol::Snapshot,
) -> Result<crate::snapshots::CaptureResult> {
    let request = &capturing.request;
    let capture_root = crate::snapshots::root(root, capturing);
    crate::snapshots::private_directory(&capture_root)?;
    let _custody = sandsurf_native::storage::disk_lease(&capture_root.join(format!(
        ".{}.task.lock",
        object_name(request.operation_id.as_str())
    )))?;
    let machine_root = root
        .join("machines")
        .join(object_name(request.machine_id.as_str()));
    if crate::capture::CaptureBoundary::require(&machine_root, &request.operation_id)?.is_some() {
        let client = GuardianClient::new(endpoint.to_path_buf());
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
    if let Some(captured) = crate::snapshots::published_filesystem(&capture_root, capturing)? {
        return Ok(captured);
    }
    let client = GuardianClient::new(endpoint.to_path_buf());
    let (captured, finished) = match request.kind {
        SnapshotKind::Disk => {
            // The catalog owns images; snapshot bytes belong to a
            // separate machine volume. Verify before acquiring the
            // pause boundary, never infer an image store from it.
            crate::images::resolve_native_image(root, &capturing.image_digest)?;
            if !crate::snapshots::prepared_filesystem(&capture_root, capturing)? {
                let prepared = client.native_snapshot(
                    request.machine_id.clone(),
                    NativeSnapshotRequest::PrepareDisk {
                        operation_id: request.operation_id.clone(),
                        expected_generation: request.expected_generation,
                        expected_revision: request.expected_revision,
                    },
                )?;
                if !matches!(prepared, NativeSnapshotResponse::Complete { .. }) {
                    return Err(HostError::Invalid(
                        "guardian did not establish the native disk capture boundary",
                    ));
                }
                let captured = crate::snapshots::prepare_filesystem(
                    &capture_root,
                    capturing,
                    &machine_root.join("disks").join(system_disk_name()),
                );
                let finished = client
                    .native_snapshot(
                        request.machine_id.clone(),
                        NativeSnapshotRequest::FinishDisk {
                            operation_id: request.operation_id.clone(),
                        },
                    )
                    .map(|response| matches!(response, NativeSnapshotResponse::Complete { .. }));
                // Native pause protects only the opaque disk copy.
                // Filesystem parsing runs after release, against the
                // durably published input, in the shared worker pool.
                captured?;
                if !finished? {
                    return Err(HostError::Invalid(
                        "guardian did not release disk copy boundary",
                    ));
                }
            }
            let captured = crate::image_worker::finish_disk_snapshot(root, executable, capturing)?;
            (Ok(captured), Ok(true))
        }
        SnapshotKind::Full => {
            let captured = capture_full_state(root, endpoint, capturing);
            let finished = client
                .native_snapshot(
                    request.machine_id.clone(),
                    NativeSnapshotRequest::FinishFull {
                        operation_id: request.operation_id.clone(),
                    },
                )
                .map(|response| matches!(response, NativeSnapshotResponse::Complete { .. }));
            (captured, finished)
        }
    };
    let captured = captured?;
    if !finished? {
        return Err(HostError::Invalid(
            "guardian did not release the snapshot capture boundary",
        ));
    }
    Ok(captured)
}

fn capture_full_state(
    root: &Path,
    endpoint: &Path,
    capturing: &Snapshot,
) -> Result<crate::snapshots::CaptureResult> {
    let request = &capturing.request;
    let client = GuardianClient::new(endpoint.to_path_buf());
    let prepared = client.native_snapshot(
        request.machine_id.clone(),
        NativeSnapshotRequest::PrepareFull {
            snapshot_id: request.id.clone(),
            operation_id: request.operation_id.clone(),
            expected_generation: request.expected_generation,
            expected_revision: request.expected_revision,
        },
    )?;
    let NativeSnapshotResponse::Prepared { capture } = prepared else {
        return Err(HostError::Invalid(
            "guardian did not establish a full capture boundary",
        ));
    };
    let machine_root = root
        .join("machines")
        .join(object_name(request.machine_id.as_str()));
    Ok(crate::snapshots::capture_full(
        &crate::snapshots::root(root, capturing),
        capturing,
        &machine_root.join("disks").join(system_disk_name()),
        &machine_root
            .join("guardian/full-captures")
            .join(object_name(request.operation_id.as_str())),
        capture,
    )?)
}

enum HostTask {
    CaptureRecovery {
        provision: GuardianProvision,
        snapshot: Box<Snapshot>,
    },
    Usage {
        provision: GuardianProvision,
    },
    Configuration {
        provision: GuardianProvision,
        authorization: AuthorizedConfiguration,
    },
    MachineBootstrap {
        root: PathBuf,
        executable: PathBuf,
        record: Box<MachineRecord>,
        intent: LifecycleIntent,
    },
    LifecycleInspect {
        intent: LifecycleIntent,
        provision: GuardianProvision,
    },
    SuspendCapture {
        root: PathBuf,
        intent: LifecycleIntent,
        provision: GuardianProvision,
        capturing: Box<Snapshot>,
    },
    MachineInputs {
        root: PathBuf,
        executable: PathBuf,
        image: Digest,
        request: Box<HostRequest>,
    },
    Lifecycle {
        machine_id: MachineId,
        provision: GuardianProvision,
        effect: Box<LifecycleEffect>,
    },
    Fork {
        root: PathBuf,
        executable: PathBuf,
        snapshot: Box<Snapshot>,
        record: sandsurf_state::ForkRecord,
        clone_profile: Option<sandsurf_image::identity::CloneProfile>,
        provision: GuardianProvision,
        continuation: OperationId,
    },
    Snapshot {
        root: PathBuf,
        executable: PathBuf,
        endpoint: PathBuf,
        capturing: Box<sandsurf_protocol::Snapshot>,
    },
    Image {
        root: PathBuf,
        executable: PathBuf,
        job: crate::image_worker::Job,
    },
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
    CaptureRecovery {
        result: Result<()>,
    },
    Usage {
        machine_id: MachineId,
        result: Result<(Counter, ResourceUsage)>,
    },
    Configuration {
        result: Result<()>,
    },
    MachineBootstrap {
        intent: LifecycleIntent,
        result: Result<MachineInputs>,
    },
    LifecycleInspect {
        intent: LifecycleIntent,
        provision: GuardianProvision,
        result: Box<Result<GuardianInspection>>,
    },
    SuspendCapture {
        intent: LifecycleIntent,
        provision: GuardianProvision,
        capturing: Box<Snapshot>,
        result: Result<(crate::snapshots::CaptureResult, fs::File)>,
    },
    Fork {
        record: sandsurf_state::ForkRecord,
        provision: GuardianProvision,
        result: Result<Digest>,
        continuation: OperationId,
    },
    MachineInputs {
        request: Box<HostRequest>,
        result: Result<MachineInputs>,
    },
    Lifecycle {
        machine_id: MachineId,
        result: Result<LifecycleEvidence>,
        post: LifecyclePost,
        custody: Option<fs::File>,
    },
    Snapshot {
        snapshot_id: sandsurf_protocol::SnapshotId,
        request_digest: Digest,
        result: Result<crate::snapshots::CaptureResult>,
    },
    Image {
        operation: OperationId,
        request_digest: Digest,
        result: Result<sandsurf_state::ImageRecord>,
    },
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
            Self::CaptureRecovery {
                provision,
                snapshot,
            } => {
                let result = (|| {
                    let capture_root = crate::snapshots::root(&provision.host_root, &snapshot);
                    crate::snapshots::private_directory(&capture_root)?;
                    let _custody =
                        sandsurf_native::storage::disk_lease(&capture_root.join(format!(
                            ".{}.task.lock",
                            object_name(snapshot.request.operation_id.as_str()),
                        )))?;
                    provision.execute()?;
                    let response = GuardianClient::new(provision.endpoint()).native_snapshot(
                        snapshot.request.machine_id,
                        NativeSnapshotRequest::FinishDisk {
                            operation_id: snapshot.request.operation_id,
                        },
                    )?;
                    if !matches!(response, NativeSnapshotResponse::Complete { .. }) {
                        return Err(HostError::Invalid(
                            "guardian did not release interrupted disk capture",
                        ));
                    }
                    Ok(())
                })();
                HostTaskCompletion::CaptureRecovery { result }
            }
            Self::Usage { provision } => {
                let result = (|| {
                    provision.execute()?;
                    let response = GuardianClient::new(provision.endpoint())
                        .runtime(provision.machine.clone(), RuntimeRequest::Usage)?;
                    let RuntimeResponse::Usage {
                        generation,
                        mut usage,
                    } = response
                    else {
                        return Err(HostError::Invalid(
                            "native resource accounting is unavailable",
                        ));
                    };
                    let storage = sandsurf_native::storage_usage::tree_usage(
                        &provision
                            .host_root
                            .join("machines")
                            .join(object_name(provision.machine.as_str())),
                    )?;
                    usage.disk_logical_bytes = Counter::try_from(storage.logical_bytes)?;
                    usage.disk_allocated_bytes = Counter::try_from(storage.allocated_bytes)?;
                    usage.provenance.storage = MeasurementSource::HostFilesystem;
                    Ok((generation, usage))
                })();
                HostTaskCompletion::Usage {
                    machine_id: provision.machine,
                    result,
                }
            }
            Self::Configuration {
                provision,
                authorization,
            } => HostTaskCompletion::Configuration {
                result: perform_configuration(&provision, authorization),
            },
            Self::MachineBootstrap {
                root,
                executable,
                record,
                intent,
            } => {
                let result = verify_machine_inputs(
                    &root,
                    &executable,
                    &record.id,
                    &record.image_digest,
                    &record.runtime_configuration.resources,
                );
                HostTaskCompletion::MachineBootstrap { intent, result }
            }
            Self::LifecycleInspect { intent, provision } => {
                let result = provision.execute().and_then(|()| {
                    GuardianClient::new(provision.endpoint())
                        .inspect(intent.machine_id.clone(), None)
                        .map_err(HostError::from)
                });
                HostTaskCompletion::LifecycleInspect {
                    intent,
                    provision,
                    result: Box::new(result),
                }
            }
            Self::SuspendCapture {
                root,
                intent,
                provision,
                capturing,
            } => {
                let result = (|| {
                    let capture_root = crate::snapshots::root(&root, &capturing);
                    crate::snapshots::private_directory(&capture_root)?;
                    let custody =
                        sandsurf_native::storage::disk_lease(&capture_root.join(format!(
                            ".{}.task.lock",
                            object_name(capturing.request.operation_id.as_str()),
                        )))?;
                    let captured =
                        match crate::snapshots::published_filesystem(&capture_root, &capturing)? {
                            Some(captured) => captured,
                            None => capture_full_state(&root, &provision.endpoint(), &capturing)?,
                        };
                    Ok((captured, custody))
                })();
                HostTaskCompletion::SuspendCapture {
                    intent,
                    provision,
                    capturing,
                    result,
                }
            }
            Self::MachineInputs {
                root,
                executable,
                image,
                request,
            } => {
                let result = (|| {
                    let (machine, resources) = match &*request {
                        HostRequest::CreateMachine {
                            machine_id,
                            resources,
                            ..
                        }
                        | HostRequest::ForkMachine {
                            machine_id,
                            resources,
                            ..
                        } => (machine_id, resources),
                        _ => return Err(HostError::Invalid("invalid machine inputs")),
                    };
                    verify_machine_inputs(&root, &executable, machine, &image, resources)
                })();
                HostTaskCompletion::MachineInputs { request, result }
            }
            Self::Lifecycle {
                machine_id,
                provision,
                effect,
            } => {
                let LifecycleEffect {
                    plan,
                    prepare,
                    post,
                    custody,
                } = *effect;
                let result = (|| {
                    provision.execute()?;
                    if let Some(request) = prepare
                        && !matches!(
                            GuardianClient::new(provision.endpoint())
                                .native_snapshot(machine_id.clone(), request,)?,
                            NativeSnapshotResponse::Complete { .. }
                        )
                    {
                        return Err(HostError::Invalid(
                            "guardian did not complete lifecycle preparation",
                        ));
                    }
                    Ok(plan.execute(provision.endpoint())?)
                })();
                HostTaskCompletion::Lifecycle {
                    machine_id,
                    result,
                    post,
                    custody,
                }
            }
            Self::Fork {
                root,
                executable,
                snapshot,
                record,
                clone_profile,
                provision,
                continuation,
            } => {
                let result = (|| {
                    let machine_root = root
                        .join("machines")
                        .join(object_name(record.machine_id.as_str()));
                    let _custody =
                        sandsurf_native::storage::disk_lease(&machine_root.join(format!(
                            ".{}.initialization.lock",
                            object_name(record.operation_id.as_str())
                        )))?;
                    let clone_profile = match clone_profile {
                        Some(profile) => profile,
                        None => {
                            crate::images::resolve_native_image(&root, &snapshot.image_digest)?
                                .manifest
                                .system
                                .clone_profile
                        }
                    };
                    crate::image_worker::materialize_fork(
                        &root,
                        &executable,
                        &snapshot,
                        &record.machine_id,
                        clone_profile,
                        &record.operation_id,
                    )
                })();
                HostTaskCompletion::Fork {
                    record,
                    provision,
                    result,
                    continuation,
                }
            }
            Self::Snapshot {
                root,
                executable,
                endpoint,
                capturing,
            } => HostTaskCompletion::Snapshot {
                snapshot_id: capturing.request.id.clone(),
                request_digest: capturing.request_digest.clone(),
                result: capture_snapshot(&root, &executable, &endpoint, &capturing),
            },
            Self::Image {
                root,
                executable,
                job,
            } => HostTaskCompletion::Image {
                operation: job.operation.clone(),
                request_digest: job.request_digest.clone(),
                result: crate::image_worker::execute(&root, &executable, job),
            },
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
    provision: GuardianProvision,
}

impl DeferredRuntimeRead {
    fn execute(self) -> Result<HostResponse> {
        self.provision.execute()?;
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
        #[cfg(any(target_os = "macos", windows))]
        let mut guardian = Guardian::<crate::qemu::QemuGuardianEffect>::retained(journal)?;
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
    #[cfg(any(target_os = "macos", windows))]
    {
        let config =
            crate::qemu::read_config(&machine_root.join("guardian/config.json"), &machine)?;
        let effect = crate::qemu::QemuGuardianEffect::open(&machine_root, config)?;
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

fn catalog_limits(root: &Path) -> Result<CatalogLimits> {
    let available_storage = sandsurf_native::capacity::available_storage_bytes(root)?;
    let physical = available_storage / 4 * 3;
    let memory_mib = sandsurf_native::capacity::available_memory_bytes()?
        .checked_sub(
            sandsurf_native::service_pool::ServicePool::Api.memory_bytes()
                + sandsurf_native::service_pool::ServicePool::Supervisor.memory_bytes()
                + sandsurf_native::service_pool::ServicePool::Images.memory_bytes(),
        )
        .ok_or(HostError::Invalid(
            "host memory cannot reserve shared service pools",
        ))?
        / (1024 * 1024)
        / 4
        * 3;
    let cpus = std::thread::available_parallelism()?.get() as u64;
    Ok(CatalogLimits {
        identities: counter(4096),
        operations: counter(1_000_000),
        usage_records: counter(1_000_000),
        // The other half covers isolated publication staging and the catalog.
        // Machine volumes are independently bounded, never charged here.
        image_bytes: Counter::try_from(physical / 2)?,
        cpu_quota_micros: Counter::try_from(cpus * 100_000)?,
        host_memory_bytes: Counter::try_from(memory_mib * 1024 * 1024)?,
    })
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

fn system_disk_name() -> &'static str {
    "system.ext4"
}

fn error_category(error: &HostError) -> &'static str {
    // Mechanism refusal is not transport failure, even when carried through a
    // platform adapter. Clients must not reconnect/retry an unsupported path.
    let native_io = match error {
        HostError::Io(error) | HostError::Image(crate::images::ImageBuildError::Io(error)) => {
            Some(error)
        }
        #[cfg(target_os = "linux")]
        HostError::Linux(crate::linux::LinuxError::Io(error)) => Some(error),
        #[cfg(any(target_os = "macos", windows))]
        HostError::Qemu(crate::qemu::QemuError::Io(error)) => Some(error),
        _ => None,
    };
    if native_io.is_some_and(|error| error.kind() == io::ErrorKind::Unsupported) {
        return "unsupported";
    }
    match error {
        HostError::Io(_) | HostError::EndpointUnavailable(_) => "transport",
        HostError::Json(_) | HostError::Contract(_) | HostError::Invalid(_) => "protocol",
        #[cfg(target_os = "linux")]
        HostError::Linux(_) => "native",
        #[cfg(any(target_os = "macos", windows))]
        HostError::Qemu(_) => "native",
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

    fn intent_service(root: &Path) -> HostService {
        // These tests admit catalog intents, never real VM workers. Their
        // capacity is an explicit fixture input, not a measurement of whatever
        // RAM/CPU remains on a concurrently building native CI runner.
        prepare_directory(root).unwrap();
        let limits = CatalogLimits {
            identities: counter(32),
            operations: counter(128),
            usage_records: counter(128),
            image_bytes: counter(64 * 1024 * 1024),
            cpu_quota_micros: counter(400000),
            host_memory_bytes: counter(4 * 1024 * 1024 * 1024),
        };
        HostCatalog::create(
            &root.join("catalog"),
            "intent-fixture".try_into().unwrap(),
            limits,
        )
        .unwrap();
        HostService::open(root, root.join("absent-executable")).unwrap()
    }

    #[test]
    fn mechanism_refusal_is_not_transport_failure() {
        let unsupported =
            || io::Error::new(io::ErrorKind::Unsupported, "operator volume unavailable");
        assert_eq!(error_category(&HostError::Io(unsupported())), "unsupported");
        assert_eq!(
            error_category(&HostError::Image(crate::images::ImageBuildError::Io(
                unsupported()
            ))),
            "unsupported"
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            error_category(&HostError::Linux(crate::linux::LinuxError::Io(
                unsupported()
            ))),
            "unsupported"
        );
        assert_eq!(
            error_category(&HostError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker interrupted"
            ))),
            "transport"
        );
    }

    fn admit_machine(
        service: &mut HostService,
        name: &str,
        lifetime: MachineLifetime,
    ) -> MachineId {
        let machine: MachineId = name.try_into().unwrap();
        let create: OperationId = format!("create-{name}").try_into().unwrap();
        let image = bytes_digest(b"seed");
        if service.catalog.image(&image).unwrap().is_none() {
            let operation: OperationId = "import-seed".try_into().unwrap();
            let request = bytes_digest(b"import-seed");
            service
                .catalog
                .admit_image_import(
                    operation.clone(),
                    request.clone(),
                    Approval {
                        id: "approve-import-seed".try_into().unwrap(),
                        request_digest: request.clone(),
                    },
                )
                .unwrap();
            service
                .catalog
                .complete_image_import(
                    &operation,
                    &request,
                    sandsurf_state::ImageRecord {
                        digest: image.clone(),
                        source_digest: image.clone(),
                        platform: "linux".into(),
                        architecture: "amd64".into(),
                        logical_bytes: Counter::ONE,
                        storage_bytes: Counter::ONE,
                        provenance_digest: image.clone(),
                        sensitive: false,
                    },
                )
                .unwrap();
        }
        let resources = Resources::from_geometry(
            Counter::ONE,
            128_u64.try_into().unwrap(),
            1_000_000_u64.try_into().unwrap(),
            1_000_000_u64.try_into().unwrap(),
            8_u64.try_into().unwrap(),
        )
        .expect("static resource envelope");
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
    fn duplicate_snapshot_tasks_cannot_release_an_active_capture_boundary() {
        let root = std::env::temp_dir().join(format!(
            "sssnap-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        let request = sandsurf_protocol::SnapshotRequest {
            id: "snapshot".try_into().unwrap(),
            operation_id: "capture".try_into().unwrap(),
            machine_id: machine.clone(),
            expected_generation: Counter::ONE,
            expected_revision: Counter::ONE,
            kind: SnapshotKind::Disk,
            parent: None,
        };
        let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request)).unwrap();
        service
            .catalog
            .admit_snapshot(
                request.clone(),
                Approval {
                    id: "approve-capture".try_into().unwrap(),
                    request_digest: request_digest.clone(),
                },
            )
            .unwrap();
        let capturing = service
            .catalog
            .begin_snapshot(&request.id, &request_digest)
            .unwrap();
        prepare_directory(&service.root.join("machines")).unwrap();
        prepare_directory(&service.machine_root(&machine)).unwrap();
        let capture_root = crate::snapshots::root(&root, &capturing);
        prepare_directory(&capture_root).unwrap();
        let custody = sandsurf_native::storage::disk_lease(&capture_root.join(format!(
            ".{}.task.lock",
            object_name(request.operation_id.as_str())
        )))
        .unwrap();
        let task = HostTask::Snapshot {
            root: root.clone(),
            executable: service.executable.clone(),
            endpoint: root.join("absent-native-owner"),
            capturing: Box::new(capturing.clone()),
        };
        let completion = task.execute();
        assert!(
            matches!(&completion, HostTaskCompletion::Snapshot { result: Err(HostError::Io(error)), .. } if error.kind() == io::ErrorKind::WouldBlock),
            "custody must be acquired before recovery can send FinishDisk to the native owner"
        );
        assert!(service.complete_task(completion).is_err());
        let recovery = HostTask::CaptureRecovery {
            provision: GuardianProvision {
                host_root: root.clone(),
                machine: machine.clone(),
            },
            snapshot: Box::new(capturing),
        }
        .execute();
        assert!(
            matches!(recovery, HostTaskCompletion::CaptureRecovery {
            result: Err(HostError::Io(error)),
        } if error.kind() == io::ErrorKind::WouldBlock),
            "background recovery must not release a live capture worker's native pause"
        );
        assert_eq!(
            service
                .catalog
                .snapshot(&request.id)
                .unwrap()
                .unwrap()
                .phase,
            SnapshotPhase::Capturing
        );
        assert!(matches!(
            service.handle(HostRequest::ListMachines {
                after: None,
                maximum: counter(16)
            }),
            HostResponse::Machines { .. }
        ));
        drop(custody);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn machine_input_verification_is_detached_and_cannot_admit_partial_authority() {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!("ssmi-{:x}", u64::from_le_bytes(nonce)));
        let mut service = intent_service(&root);
        let existing = admit_machine(&mut service, "seed-owner", MachineLifetime::default());
        let seed = service.catalog.machine(&existing).unwrap().unwrap();
        let new_machine: MachineId = "new-machine".try_into().unwrap();
        let operation: OperationId = "create-new-machine".try_into().unwrap();
        let HostDispatch::Task(task) = service.route(HostRequest::CreateMachine {
            machine_id: new_machine.clone(),
            image_digest: seed.image_digest,
            resources: seed.runtime_configuration.resources,
            execution_defaults: ExecutionDefaults::default(),
            lifetime: MachineLifetime::default(),
            operation_id: operation.clone(),
            approval_id: "approve-new-machine".try_into().unwrap(),
        }) else {
            panic!("native input verification ran on the catalog owner");
        };
        let worker = thread::spawn(move || task.execute());
        assert!(matches!(
            service.handle(HostRequest::ListImages {
                after: None,
                maximum: counter(16)
            }),
            HostResponse::Images { .. }
        ));
        assert!(service.catalog.machine(&new_machine).unwrap().is_none());
        assert!(service.catalog.operation(&operation).unwrap().is_none());
        // This fixture deliberately has no usable native seed/volume/toolchain.
        assert!(service.complete_task(worker.join().unwrap()).is_err());
        assert!(service.catalog.machine(&new_machine).unwrap().is_none());
        assert!(service.catalog.operation(&operation).unwrap().is_none());
        assert!(
            !service
                .machine_root(&new_machine)
                .join("guardian/config.json")
                .exists()
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn blocked_native_inspection_leaves_the_catalog_and_other_clients_available() {
        let parent = if cfg!(target_os = "macos") {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = parent.join(format!("ssv-{:x}", u64::from_le_bytes(nonce)));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "observed", MachineLifetime::default());
        prepare_directory(&service.machine_root(&machine)).unwrap();
        let endpoint = service.guardian_endpoint(&machine);
        prepare_directory(&endpoint).unwrap();
        let listener = LocalListener::bind(&endpoint).unwrap();
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let native = thread::spawn(move || {
            let mut connection = listener.accept(Duration::from_secs(10)).unwrap();
            assert!(
                connection
                    .read_frame(Duration::from_secs(5))
                    .unwrap()
                    .is_some()
            );
            entered.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(10)).unwrap();
            // Response loss must yield unavailable observation, not a new owner.
            drop(connection);
        });
        drop(service);
        let serving = root.clone();
        let host = thread::spawn(move || serve_host(&serving, serving.join("absent-executable")));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if host_call(
                &root,
                HostRequest::ListImages {
                    after: None,
                    maximum: counter(16),
                },
            )
            .is_ok()
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        let reading = root.clone();
        let identity = machine.clone();
        let reader = thread::spawn(move || {
            host_call(
                &reading,
                HostRequest::GetMachine {
                    machine_id: identity,
                },
            )
        });
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            host_call(
                &root,
                HostRequest::ListImages {
                    after: None,
                    maximum: counter(16)
                }
            )
            .unwrap(),
            HostResponse::Images { .. }
        ));
        release.send(()).unwrap();
        native.join().unwrap();
        assert!(
            matches!(reader.join().unwrap().unwrap(), HostResponse::Machine { value }
            if value.id == machine && matches!(value.machine, Observation::Unavailable { .. }))
        );
        host_call(&root, HostRequest::StopService).unwrap();
        host.join().unwrap().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ordinary_guest_routes_neither_provision_an_owner_nor_require_native_inspection() {
        let root = std::env::temp_dir().join(format!(
            "ssroute-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
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
        let mut service = intent_service(&root);
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
        let mut service = intent_service(&root);
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
