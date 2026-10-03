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

/// Volatile scheduling position only. Every visit rereads canonical authority;
/// restarting a host merely restarts the bounded sweep.
#[derive(Default)]
struct ReconciliationCursor {
    after_machine: Option<MachineId>,
    after_snapshot: Option<SnapshotId>,
    next_domain: usize,
    after_image: Option<OperationId>,
    after_import: Option<OperationId>,
    after_candidate: Option<OperationId>,
    after_snapshot_release: Option<OperationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ReconciliationIdentity {
    Machine(MachineId),
    Image(OperationId),
    SnapshotRelease(OperationId),
}
impl fmt::Display for ReconciliationIdentity {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Machine(id) => write!(output, "machine {}", id.as_str()),
            Self::Image(id) => write!(output, "image operation {}", id.as_str()),
            Self::SnapshotRelease(id) => write!(output, "snapshot release {}", id.as_str()),
        }
    }
}

#[derive(Clone, Copy)]
enum ImageLookupReply {
    HostOperation,
    ImageImport,
}

struct HostService {
    root: PathBuf,
    catalog: HostCatalog,
    executable: PathBuf,
    artifacts: Arc<crate::artifacts::ArtifactStore>,
    secrets: Arc<crate::secrets::SecretAuthority>,
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
        let secrets = Arc::new(crate::secrets::SecretAuthority::open(
            &root.join("secrets"),
        )?);
        let service = Self {
            root: root.to_path_buf(),
            catalog,
            executable,
            artifacts,
            secrets,
        };
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
            request @ HostRequest::PutSecret { .. } => self.prepare_secret_put(request),
            HostRequest::Inspect => Ok(HostDispatch::Inspection {
                root: self.root.clone(),
                host_id: self.catalog.host_id().as_str().into(),
            }),
            HostRequest::GetHostOperation { operation_id } => {
                self.prepare_image_lookup(operation_id, ImageLookupReply::HostOperation)
            }
            HostRequest::GetImageImport { operation_id } => {
                self.prepare_image_lookup(operation_id, ImageLookupReply::ImageImport)
            }
            HostRequest::CancelImageImport {
                operation_id,
                expected_request,
            } => self
                .catalog
                .cancel_image_import(&operation_id, &expected_request)
                .map_err(HostError::from)
                .and_then(|record| self.prepare_image_materialization(record)),
            request @ HostRequest::ReleaseImage { .. } => self.prepare_image_release(request),
            HostRequest::ReleaseSnapshot {
                snapshot_id,
                operation_id,
                approval_id,
            } => self.admit_snapshot_release(snapshot_id, operation_id, approval_id),
            HostRequest::CreateSnapshot {
                request,
                approval_id,
            } => self.prepare_snapshot(request, approval_id),
            request @ (HostRequest::CreateMachine { .. } | HostRequest::ForkMachine { .. }) => {
                self.prepare_machine_inputs(request)
            }
            request @ HostRequest::Lifecycle { .. } => self.prepare_lifecycle_request(request),
            request @ HostRequest::RollbackFilesystem { .. } => {
                self.prepare_rollback_request(request)
            }
            request @ (HostRequest::SetNetworkPolicy { .. } | HostRequest::SetExposure { .. }) => {
                self.prepare_configuration_request(request)
            }
            request @ (HostRequest::UpdateResources { .. }
            | HostRequest::AssessResources { .. }) => self.prepare_resource_assessment(request),
            HostRequest::GetMachine { machine_id } => self
                .catalog
                .machine(&machine_id)
                .map_err(HostError::from)
                .and_then(|record| {
                    let record = record.ok_or(HostError::Invalid("machine does not exist"))?;
                    Ok(HostDispatch::MachineView(Box::new(DeferredMachineView {
                        root: self.root.clone(),
                        record,
                        reply: MachineViewReply::Machine,
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
            request @ HostRequest::ReleaseEvidence { .. } => self.prepare_evidence_release(request),
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
            request => match self.prepare_runtime_request(&request) {
                Ok(Some(read)) => Ok(HostDispatch::Runtime(Box::new(read))),
                Ok(None) => self
                    .handle_inner(request)
                    .map(|response| HostDispatch::Ready(Box::new(response))),
                Err(error) => Err(error),
            },
        };
        result.unwrap_or_else(|error| HostDispatch::Ready(Box::new(rejected(error))))
    }

    fn prepare_rollback_request(&mut self, request: HostRequest) -> Result<HostDispatch> {
        match request {
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
                    return Ok(HostDispatch::Ready(Box::new(HostResponse::Rollback {
                        value: admitted,
                    })));
                }
                self.prepare_rollback_effect(admitted)
            }
            _ => Err(HostError::Invalid("not a disk rollback request")),
        }
    }

    fn prepare_rollback_effect(&self, record: RollbackRecord) -> Result<HostDispatch> {
        let snapshot = self
            .catalog
            .snapshot(&record.snapshot_id)?
            .ok_or(HostError::Invalid("rollback snapshot disappeared"))?;
        Ok(HostDispatch::Task(Box::new(HostTask::Rollback {
            provision: self.prepare_guardian_inner(&record.machine_id)?,
            record,
            snapshot: Box::new(snapshot),
        })))
    }

    fn prepare_configuration_request(&mut self, request: HostRequest) -> Result<HostDispatch> {
        match request {
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
                self.prepare_configuration_effect(
                    &machine_id,
                    operation.revision,
                    MachineViewReply::Configuration {
                        revision: operation.revision,
                    },
                )
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
                let exposure = operation
                    .configuration
                    .exposures
                    .iter()
                    .find(|value| value.id == exposure.id)
                    .cloned()
                    .ok_or(HostError::Invalid(
                        "committed exposure is missing from its configuration",
                    ))?;
                self.prepare_configuration_effect(
                    &machine_id,
                    operation.revision,
                    MachineViewReply::Exposure { exposure },
                )
            }
            _ => Err(HostError::Invalid("not a configuration request")),
        }
    }

    fn prepare_resource_assessment(&self, request: HostRequest) -> Result<HostDispatch> {
        let (machine_id, resources, update) = match request {
            HostRequest::AssessResources {
                machine_id,
                resources,
            } => (machine_id, resources, None),
            HostRequest::UpdateResources {
                machine_id,
                operation_id,
                expected_revision,
                resources,
                approval_id,
            } => {
                self.require_revision_for_new_host_operation(
                    &machine_id,
                    &operation_id,
                    expected_revision,
                )?;
                (
                    machine_id,
                    resources,
                    Some(ResourceUpdateAdmission {
                        operation_id,
                        expected_revision,
                        approval_id,
                    }),
                )
            }
            _ => return Err(HostError::Invalid("not a resource assessment request")),
        };
        resources.validate()?;
        Ok(HostDispatch::Task(Box::new(HostTask::ResourceAssessment {
            provision: self.prepare_guardian_inner(&machine_id)?,
            resources,
            update,
        })))
    }

    fn prepare_configuration_effect(
        &self,
        machine: &MachineId,
        revision: Counter,
        reply: MachineViewReply,
    ) -> Result<HostDispatch> {
        let record = self
            .catalog
            .machine(machine)?
            .ok_or(HostError::Invalid("machine does not exist"))?;
        if revision > record.configuration_revision {
            return Err(HostError::Invalid(
                "configuration operation is ahead of host authority",
            ));
        }
        // Historical observations never reinstall superseded authority.
        if revision < record.configuration_revision {
            return Ok(HostDispatch::MachineView(Box::new(DeferredMachineView {
                root: self.root.clone(),
                record,
                reply,
            })));
        }
        Ok(HostDispatch::Task(Box::new(HostTask::Configuration {
            provision: self.prepare_guardian_inner(machine)?,
            authorization: self.catalog.authorize_configuration(machine, revision)?,
            reply: Some(Box::new(reply)),
        })))
    }

    fn prepare_snapshot(
        &mut self,
        request: SnapshotRequest,
        approval_id: CommitmentId,
    ) -> Result<HostDispatch> {
        if self.catalog.operation(&request.operation_id)?.is_none() {
            self.catalog
                .require_revision(&request.machine_id, request.expected_revision)?;
            return Ok(HostDispatch::Task(Box::new(HostTask::SnapshotInspect {
                provision: self.prepare_guardian_inner(&request.machine_id)?,
                request: Box::new(request),
                approval_id,
            })));
        }
        self.admit_snapshot_request(request, approval_id)
    }

    fn admit_snapshot_request(
        &mut self,
        request: SnapshotRequest,
        approval_id: CommitmentId,
    ) -> Result<HostDispatch> {
        let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request))?;
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
        let provision =
            if crate::capture::CaptureBoundary::read(&self.machine_root(&request.machine_id))?
                .is_some()
                || !crate::snapshots::has_capture_record(
                    &crate::snapshots::root(&self.root, &admitted),
                    &admitted,
                )?
            {
                Some(self.prepare_guardian_inner(&request.machine_id)?)
            } else {
                None
            };
        let capturing = self.catalog.begin_snapshot(&request.id, &request_digest)?;
        Ok(HostDispatch::Task(Box::new(HostTask::Snapshot {
            root: self.root.clone(),
            executable: self.executable.clone(),
            endpoint: self.guardian_endpoint(&request.machine_id),
            capturing: Box::new(capturing),
            provision,
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
        let (operation_id, approval_id, input) = match request {
            HostRequest::ImportOci {
                source,
                recipe,
                platform,
                operation_id,
                approval_id,
            } => (
                operation_id,
                approval_id,
                sandsurf_state::ImageImportInput::Oci {
                    source,
                    recipe,
                    platform,
                },
            ),
            HostRequest::ImportNativeImage {
                manifest_path,
                manifest_digest,
                operation_id,
                approval_id,
            } => (
                operation_id,
                approval_id,
                sandsurf_state::ImageImportInput::Native {
                    manifest_path,
                    manifest_digest,
                },
            ),
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
                (
                    operation_id,
                    approval_id,
                    sandsurf_state::ImageImportInput::PublishSnapshot {
                        snapshot: Box::new(snapshot),
                        allow_sensitive,
                    },
                )
            }
            _ => return Err(HostError::Invalid("request is not an image operation")),
        };
        let request_digest = input.request_digest(&operation_id)?;
        let admitted = self.catalog.admit_image_import(
            operation_id,
            input,
            Approval {
                id: approval_id,
                request_digest,
            },
        )?;
        if admitted.phase == sandsurf_state::ImageImportPhase::Published {
            return Ok(HostDispatch::Ready(Box::new(HostResponse::ImageImport {
                operation: admitted,
            })));
        }
        self.prepare_image_materialization(admitted)
    }

    fn prepare_image_materialization(
        &self,
        record: sandsurf_state::ImageImportRecord,
    ) -> Result<HostDispatch> {
        match record.phase {
            sandsurf_state::ImageImportPhase::Cancelling => {
                return Ok(HostDispatch::Task(Box::new(HostTask::ImageCancel {
                    root: self.root.clone(),
                    record,
                    reply: ImageLookupReply::ImageImport,
                })));
            }
            sandsurf_state::ImageImportPhase::Cancelled
            | sandsurf_state::ImageImportPhase::Published => {
                return Ok(HostDispatch::Ready(Box::new(HostResponse::ImageImport {
                    operation: record,
                })));
            }
            sandsurf_state::ImageImportPhase::Admitted
            | sandsurf_state::ImageImportPhase::Prepared => {}
        }
        if record.phase == sandsurf_state::ImageImportPhase::Prepared {
            return Ok(self.prepare_image_publication(record, ImageLookupReply::ImageImport));
        }
        let input = self
            .catalog
            .image_import_input(&record.operation_id)?
            .ok_or(HostError::Invalid(
                "image admission has no executable input",
            ))?;
        if input.request_digest(&record.operation_id)? != record.request_digest {
            return Err(HostError::Invalid("image admission input binding changed"));
        }
        Ok(HostDispatch::Task(Box::new(HostTask::Image {
            root: self.root.clone(),
            executable: self.executable.clone(),
            job: crate::image_worker::Job {
                operation: record.operation_id,
                request_digest: record.request_digest,
                build: crate::image_worker::Build::Image { input },
            },
        })))
    }

    fn prepare_image_publication(
        &self,
        record: sandsurf_state::ImageImportRecord,
        reply: ImageLookupReply,
    ) -> HostDispatch {
        HostDispatch::Task(Box::new(HostTask::ImagePublish {
            root: self.root.clone(),
            record,
            reply,
        }))
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

    fn prepare_runtime_request(
        &mut self,
        request: &HostRequest,
    ) -> Result<Option<DeferredRuntimeRequest>> {
        let (machine_id, query) = match request {
            HostRequest::GetOperation {
                machine_id,
                operation_id,
            } => {
                if self.catalog.operation(operation_id)?.is_some() {
                    return Ok(None);
                }
                (
                    machine_id.clone(),
                    RuntimeRequest::Operation {
                        operation_id: operation_id.clone(),
                    },
                )
            }
            HostRequest::AcknowledgeReceipt {
                machine_id,
                operation_id,
                execution_id,
                receipt_digest,
            } => (
                machine_id.clone(),
                RuntimeRequest::AcknowledgeReceipt {
                    operation_id: operation_id.clone(),
                    execution_id: execution_id.clone(),
                    receipt_digest: receipt_digest.clone(),
                },
            ),
            HostRequest::SealOutput {
                machine_id,
                operation_id,
                execution_id,
                generation,
                expected,
                segment_id,
            } => (
                machine_id.clone(),
                RuntimeRequest::SealOutput {
                    operation_id: operation_id.clone(),
                    execution_id: execution_id.clone(),
                    generation: *generation,
                    expected: expected.clone(),
                    segment_id: segment_id.clone(),
                },
            ),
            HostRequest::CleanupReleasedEvidence {
                machine_id,
                execution_id,
                request_digest,
            } => (
                machine_id.clone(),
                RuntimeRequest::CleanupReleased {
                    execution_id: execution_id.clone(),
                    request_digest: request_digest.clone(),
                },
            ),

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
        Ok(Some(DeferredRuntimeRequest {
            endpoint: self.guardian_endpoint(&machine_id),
            machine_id,
            request: query,
            loss: None,
            provision,
        }))
    }

    fn prepare_evidence_release(&mut self, request: HostRequest) -> Result<HostDispatch> {
        let HostRequest::ReleaseEvidence {
            machine_id,
            execution_id,
            request,
            loss_approval_id,
        } = request
        else {
            return Err(HostError::Invalid("not an output release request"));
        };
        let loss = match (&request.disposition, loss_approval_id) {
            (ReleaseDisposition::AuthorizedLoss { authorization }, Some(id))
                if *authorization == id =>
            {
                Some(self.catalog.authorize_output_loss(
                    &machine_id,
                    &execution_id,
                    &request.receipt_digest,
                    &request.output,
                    Approval {
                        id,
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
                )?)
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
            (_, None) => None,
        };
        Ok(HostDispatch::Runtime(Box::new(DeferredRuntimeRequest {
            endpoint: self.guardian_endpoint(&machine_id),
            provision: self.prepare_guardian_inner(&machine_id)?,
            machine_id,
            request: RuntimeRequest::Release {
                execution_id,
                request,
            },
            loss,
        })))
    }

    fn handle_inner(&mut self, request: HostRequest) -> Result<HostResponse> {
        match request {
            HostRequest::Inspect => Err(HostError::Invalid(
                "host inspection requires detached observation",
            )),
            HostRequest::StopService => Ok(HostResponse::Complete),
            HostRequest::OpenObservationStream { .. }
            | HostRequest::ListMachines { .. }
            | HostRequest::GetMachine { .. } => Err(HostError::Invalid(
                "native observations run outside the catalog owner",
            )),
            HostRequest::GetHostOperation { .. }
            | HostRequest::GetImageImport { .. }
            | HostRequest::CancelImageImport { .. }
            | HostRequest::ReleaseImage { .. } => Err(HostError::Invalid(
                "image verification and cleanup require detached effects",
            )),
            HostRequest::ReleaseSnapshot { .. } => Err(HostError::Invalid(
                "snapshot release requires detached cleanup",
            )),
            HostRequest::ListImages { after, maximum } => Ok(HostResponse::Images {
                values: self.catalog.images(after.as_ref(), maximum)?,
            }),
            HostRequest::GetImage { digest } => Ok(HostResponse::Image {
                value: self
                    .catalog
                    .image(&digest)?
                    .ok_or(HostError::Invalid("image does not exist"))?,
            }),
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
            HostRequest::RollbackFilesystem { .. } => Err(HostError::Invalid(
                "disk replacement requires deferred native custody",
            )),
            HostRequest::Lifecycle { .. } => Err(HostError::Invalid(
                "lifecycle requires deferred native effects",
            )),
            HostRequest::SetNetworkPolicy { .. } | HostRequest::SetExposure { .. } => Err(
                HostError::Invalid("configuration changes require deferred native effects"),
            ),
            HostRequest::PutSecret { .. } => Err(HostError::Invalid(
                "secret storage publication requires deferred effects",
            )),
            HostRequest::DeliverSecret { .. } | HostRequest::RevokeSecret { .. } => Err(
                HostError::Invalid("secret authority operations require host task admission"),
            ),
            HostRequest::UpdateResources { .. } | HostRequest::AssessResources { .. } => Err(
                HostError::Invalid("resource assessment requires deferred native observation"),
            ),
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
                Err(HostError::Invalid(
                    "runtime operation lookup requires deferred guardian routing",
                ))
            }
            HostRequest::ListEvents { .. }
            | HostRequest::GetProcess { .. }
            | HostRequest::ListProcesses { .. }
            | HostRequest::GetReceipt { .. }
            | HostRequest::ReadEvidence { .. }
            | HostRequest::GetOutputSegment { .. }
            | HostRequest::ReadOutputSegment { .. }
            | HostRequest::AcknowledgeReceipt { .. }
            | HostRequest::SealOutput { .. }
            | HostRequest::ReleaseEvidence { .. }
            | HostRequest::CleanupReleasedEvidence { .. } => Err(HostError::Invalid(
                "runtime journal requests require deferred guardian routing",
            )),
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
        if intent.completion.is_none()
            && intent.desired == DesiredState::Running
            && let Some(fork) = self.catalog.fork(&intent.machine_id)?
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
                return Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
                    machine_id: intent.machine_id,
                    provision,
                    effect: Box::new(LifecycleEffect {
                        plan,
                        prepare: None,
                        custody: None,
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
        }
        Ok(HostDispatch::Task(Box::new(HostTask::Lifecycle {
            machine_id: intent.machine_id,
            provision,
            effect,
        })))
    }

    fn prepare_image_release(&mut self, request: HostRequest) -> Result<HostDispatch> {
        let HostRequest::ReleaseImage {
            digest: image_digest,
            operation_id,
            approval_id,
        } = request
        else {
            return Err(HostError::Invalid("not an image release request"));
        };
        let request_digest = digest(
            Domain::Image,
            &("sandsurf-release-image-v1", &operation_id, &image_digest),
        )?;
        let record = self.catalog.release_image(
            operation_id,
            image_digest,
            Approval {
                id: approval_id,
                request_digest,
            },
        )?;
        if !record.cleanup_pending {
            return Ok(HostDispatch::Ready(Box::new(HostResponse::ImageRelease {
                operation: record,
            })));
        }
        Ok(HostDispatch::Task(Box::new(HostTask::ImageCleanup {
            root: self.root.clone(),
            record,
            reply: true,
        })))
    }

    fn admit_snapshot_release(
        &mut self,
        snapshot_id: SnapshotId,
        operation_id: OperationId,
        approval_id: CommitmentId,
    ) -> Result<HostDispatch> {
        let request_digest = digest(
            Domain::Snapshot,
            &("sandsurf-release-snapshot-v1", &operation_id, &snapshot_id),
        )?;
        let record = self.catalog.release_snapshot(
            operation_id,
            snapshot_id,
            Approval {
                id: approval_id,
                request_digest,
            },
        )?;
        self.prepare_snapshot_release(record, true)
    }

    fn prepare_snapshot_release(
        &self,
        record: sandsurf_state::SnapshotReleaseRecord,
        reply: bool,
    ) -> Result<HostDispatch> {
        if !record.cleanup_pending {
            return Ok(HostDispatch::Ready(Box::new(
                HostResponse::SnapshotRelease { operation: record },
            )));
        }
        let snapshot = self
            .catalog
            .snapshot(&record.snapshot_id)?
            .ok_or(HostError::Invalid(
                "snapshot release lost its ownership record",
            ))?;
        let provision =
            if crate::capture::CaptureBoundary::read(&self.machine_root(&record.machine_id))?
                .is_some_and(|boundary| boundary.operation_id == snapshot.request.operation_id)
            {
                Some(self.prepare_guardian_inner(&record.machine_id)?)
            } else {
                None
            };
        Ok(HostDispatch::Task(Box::new(HostTask::SnapshotCleanup {
            root: self.root.clone(),
            endpoint: self.guardian_endpoint(&record.machine_id),
            provision,
            snapshot: Box::new(snapshot),
            record,
            reply,
        })))
    }

    fn prepare_image_lookup(
        &self,
        operation: OperationId,
        reply: ImageLookupReply,
    ) -> Result<HostDispatch> {
        if let Some(record) = self.catalog.image_import(&operation)? {
            match record.phase {
                sandsurf_state::ImageImportPhase::Cancelling => {
                    return Ok(HostDispatch::Task(Box::new(HostTask::ImageCancel {
                        root: self.root.clone(),
                        record,
                        reply,
                    })));
                }
                sandsurf_state::ImageImportPhase::Admitted
                | sandsurf_state::ImageImportPhase::Prepared => {
                    return Ok(HostDispatch::Task(Box::new(HostTask::ImageInspect {
                        root: self.root.clone(),
                        record,
                        reply,
                    })));
                }
                sandsurf_state::ImageImportPhase::Published
                | sandsurf_state::ImageImportPhase::Cancelled => {}
            }
        }
        Ok(HostDispatch::Ready(Box::new(
            self.image_lookup_response(&operation, reply)?,
        )))
    }

    fn image_lookup_response(
        &self,
        operation: &OperationId,
        reply: ImageLookupReply,
    ) -> Result<HostResponse> {
        Ok(match reply {
            ImageLookupReply::HostOperation => HostResponse::HostOperation {
                value: self.catalog.operation(operation)?,
            },
            ImageLookupReply::ImageImport => HostResponse::ImageImport {
                operation: self
                    .catalog
                    .image_import(operation)?
                    .ok_or(HostError::Invalid("image import operation does not exist"))?,
            },
        })
    }

    fn prepare_secret_put(&mut self, request: HostRequest) -> Result<HostDispatch> {
        match request {
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
                if operation.applied {
                    return Ok(HostDispatch::Ready(Box::new(HostResponse::Secret {
                        secret,
                    })));
                }
                Ok(HostDispatch::Task(Box::new(HostTask::SecretPut {
                    store: Arc::clone(&self.secrets),
                    record: operation,
                    bytes: Zeroizing::new(bytes),
                })))
            }
            _ => Err(HostError::Invalid("not a secret storage request")),
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
            sandsurf_state::SecretDeliveryAdmission {
                machine_id: machine_id.clone(),
                operation_id: operation_id.clone(),
                request_digest: request_digest.clone(),
                delivery: delivery.clone(),
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
        Ok(HostDispatch::Task(Box::new(HostTask::SecretPrepare {
            provision: self.prepare_guardian_inner(&machine_id)?,
            record,
            store: Arc::clone(&self.secrets),
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
        if record.guest_cleanup_report.is_some() || record.deliveries.is_empty() {
            return Ok(HostDispatch::Ready(Box::new(
                HostResponse::SecretRevocation { revocation: record },
            )));
        }
        // Host revocation has committed even when native/guest cleanup cannot
        // run. Provisioning remains a best-effort, detached observation.
        let provision = self.prepare_guardian_inner(&record.machine_id);
        Ok(HostDispatch::Task(Box::new(HostTask::SecretCleanup {
            endpoint: self.guardian_endpoint(&record.machine_id),
            provision,
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

    fn complete_task(&mut self, completion: HostTaskCompletion) -> Result<HostDispatch> {
        match completion {
            HostTaskCompletion::ImageCancel {
                record,
                reply,
                result,
            } => {
                let current =
                    self.catalog
                        .image_import(&record.operation_id)?
                        .ok_or(HostError::Invalid(
                            "image cancellation admission disappeared",
                        ))?;
                if current.request_digest != record.request_digest {
                    return Err(HostError::Invalid(
                        "image cancellation admission binding changed",
                    ));
                }
                match result {
                    Ok(_custody) => {
                        self.catalog.complete_image_cancellation(
                            &record.operation_id,
                            &record.request_digest,
                        )?;
                    }
                    Err(HostError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(HostError::Image(crate::images::ImageBuildError::Io(error)))
                        if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
                Ok(HostDispatch::Ready(Box::new(
                    self.image_lookup_response(&record.operation_id, reply)?,
                )))
            }
            HostTaskCompletion::Image {
                operation,
                request_digest,
                result,
            } => {
                let current = self
                    .catalog
                    .image_import(&operation)?
                    .ok_or(HostError::Invalid(
                        "image materialization admission disappeared",
                    ))?;
                if current.request_digest != request_digest {
                    return Err(HostError::Invalid(
                        "image materialization admission binding changed",
                    ));
                }
                if matches!(
                    current.phase,
                    sandsurf_state::ImageImportPhase::Cancelling
                        | sandsurf_state::ImageImportPhase::Cancelled
                ) {
                    return self.prepare_image_materialization(current);
                }
                let record =
                    self.catalog
                        .prepare_image_import(&operation, &request_digest, result?)?;
                if record.phase == sandsurf_state::ImageImportPhase::Published {
                    Ok(HostDispatch::Ready(Box::new(self.image_lookup_response(
                        &operation,
                        ImageLookupReply::ImageImport,
                    )?)))
                } else {
                    Ok(self.prepare_image_publication(record, ImageLookupReply::ImageImport))
                }
            }
            HostTaskCompletion::ImageInspect {
                record,
                reply,
                result,
            } => {
                let current = self
                    .catalog
                    .image_import(&record.operation_id)?
                    .ok_or(HostError::Invalid("image lookup admission disappeared"))?;
                if current.request_digest != record.request_digest {
                    return Err(HostError::Invalid("image lookup binding changed"));
                }
                if matches!(
                    current.phase,
                    sandsurf_state::ImageImportPhase::Published
                        | sandsurf_state::ImageImportPhase::Cancelling
                        | sandsurf_state::ImageImportPhase::Cancelled
                ) {
                    return Ok(HostDispatch::Ready(Box::new(
                        self.image_lookup_response(&record.operation_id, reply)?,
                    )));
                }
                if let Some(image) = result? {
                    let record = self.catalog.prepare_image_import(
                        &record.operation_id,
                        &record.request_digest,
                        image,
                    )?;
                    if record.phase == sandsurf_state::ImageImportPhase::Published {
                        Ok(HostDispatch::Ready(Box::new(
                            self.image_lookup_response(&record.operation_id, reply)?,
                        )))
                    } else {
                        Ok(self.prepare_image_publication(record, reply))
                    }
                } else {
                    Ok(HostDispatch::Ready(Box::new(
                        self.image_lookup_response(&record.operation_id, reply)?,
                    )))
                }
            }
            HostTaskCompletion::ImagePublish {
                record,
                reply,
                result,
            } => {
                let custody = result?;
                let record = self.catalog.complete_image_import(
                    &record.operation_id,
                    &record.request_digest,
                    record.image.clone().ok_or(HostError::Invalid(
                        "image publication has no reserved candidate",
                    ))?,
                )?;
                drop(custody);
                Ok(HostDispatch::Task(Box::new(
                    HostTask::ImageCandidateCleanup {
                        root: self.root.clone(),
                        record,
                        reply: Some(reply),
                    },
                )))
            }
            HostTaskCompletion::SecretPrepare {
                provision,
                record,
                result,
            } => {
                let bytes = result?;
                // The sole catalog owner fences revocation and duplicate
                // preparations before disclosing bytes to any guest channel.
                let record = self
                    .catalog
                    .begin_secret_disclosure(&record.operation_id, &record.request_digest)?;
                Ok(HostDispatch::Task(Box::new(HostTask::SecretDelivery {
                    endpoint: provision.endpoint(),
                    record,
                    bytes,
                })))
            }
            HostTaskCompletion::StorageRetire {
                machine_id,
                reply,
                result,
            } => {
                result?;
                self.catalog.release_retired_storage(&machine_id)?;
                match reply {
                    None => Ok(HostDispatch::Ready(Box::new(HostResponse::Complete))),
                    Some(reply) => {
                        let record = self
                            .catalog
                            .machine(&machine_id)?
                            .ok_or(HostError::Invalid("retired machine disappeared"))?;
                        Ok(HostDispatch::MachineView(Box::new(DeferredMachineView {
                            root: self.root.clone(),
                            record,
                            reply: *reply,
                        })))
                    }
                }
            }
            HostTaskCompletion::SnapshotInspect {
                request,
                approval_id,
                result,
            } => {
                if self.catalog.operation(&request.operation_id)?.is_some() {
                    return self.admit_snapshot_request(*request, approval_id);
                }
                let inspection = (*result)?;
                // The pre-admission inspection is not a catalog revision grant.
                self.catalog
                    .require_revision(&request.machine_id, request.expected_revision)?;
                let Observation::Current { value: machine } = inspection.observation else {
                    return Err(HostError::Invalid(
                        "snapshot requires a current machine observation",
                    ));
                };
                if inspection.machine_id != request.machine_id
                    || machine.machine_id != request.machine_id
                    || machine.generation != request.expected_generation
                    || machine.applied_revision != request.expected_revision
                    || !matches!(machine.state, MachineState::Running | MachineState::Paused)
                {
                    return Err(HostError::Invalid(
                        "snapshot requires the expected running or paused generation and revision",
                    ));
                }

                self.admit_snapshot_request(*request, approval_id)
            }
            HostTaskCompletion::Configuration {
                machine_id,
                reply,
                result,
            } => {
                result?;
                match reply {
                    None => Ok(HostDispatch::Ready(Box::new(HostResponse::Complete))),
                    Some(reply) => {
                        let record =
                            self.catalog
                                .machine(&machine_id)?
                                .ok_or(HostError::Invalid(
                                    "machine disappeared before configuration response",
                                ))?;
                        Ok(HostDispatch::MachineView(Box::new(DeferredMachineView {
                            root: self.root.clone(),
                            record,
                            reply: *reply,
                        })))
                    }
                }
            }
            HostTaskCompletion::ResourceAssessment {
                machine_id,
                resources,
                update,
                result,
            } => {
                let assessment = result?;
                let Some(update) = update else {
                    return Ok(HostDispatch::Ready(Box::new(
                        HostResponse::ResourceAssessment { assessment },
                    )));
                };
                // Native validation is an observation, not authority. The catalog
                // rechecks the revision, approval, identity and total reservation.
                self.require_revision_for_new_host_operation(
                    &machine_id,
                    &update.operation_id,
                    update.expected_revision,
                )?;
                let request_digest = digest(
                    Domain::Authority,
                    &(
                        "sandsurf-machine-resources-v1",
                        &machine_id,
                        &update.operation_id,
                        update.expected_revision,
                        &resources,
                    ),
                )?;
                let operation = self.catalog.update_resources(
                    &machine_id,
                    &update.operation_id,
                    update.expected_revision,
                    resources,
                    Approval {
                        id: update.approval_id,
                        request_digest,
                    },
                )?;
                self.prepare_configuration_effect(
                    &machine_id,
                    operation.revision,
                    MachineViewReply::ResourceUpdate {
                        revision: operation.revision,
                        assessment,
                    },
                )
            }
            HostTaskCompletion::MachineInputs { request, result } => {
                self.admit_machine_inputs(*request, result?)
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
                custody: _custody,
            } => {
                let lifecycle = result?.complete(&mut self.catalog)?;
                if let Some(intent) = &lifecycle.completed_intent {
                    if intent.desired == DesiredState::Running {
                        self.catalog.observe_activity(&machine_id, unix_millis()?)?;
                    }
                    if intent.desired == DesiredState::Destroyed {
                        return self.prepare_storage_retirement(
                            &machine_id,
                            Some(Box::new(MachineViewReply::Lifecycle {
                                operation: Box::new(lifecycle.guardian_operation),
                            })),
                        );
                    }
                }
                let record = self
                    .catalog
                    .machine(&machine_id)?
                    .ok_or(HostError::Invalid("machine disappeared before completion"))?;
                Ok(HostDispatch::MachineView(Box::new(DeferredMachineView {
                    root: self.root.clone(),
                    record,
                    reply: MachineViewReply::Lifecycle {
                        operation: Box::new(lifecycle.guardian_operation),
                    },
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
            HostTaskCompletion::SecretPut { record, result } => {
                let secret = result?;
                self.catalog.complete_secret_put(
                    &record.operation_id,
                    &record.request_digest,
                    &secret,
                )?;
                Ok(HostResponse::Secret { secret })
            }
            HostTaskCompletion::ImageCleanup {
                record,
                reply,
                result,
            } => {
                result?;
                let operation = self
                    .catalog
                    .complete_image_release(&record.operation_id, &record.request_digest)?;
                Ok(if reply {
                    HostResponse::ImageRelease { operation }
                } else {
                    HostResponse::Complete
                })
            }
            HostTaskCompletion::SnapshotCleanup {
                record,
                reply,
                result,
            } => {
                let operation = match result {
                    Ok(()) => self
                        .catalog
                        .complete_snapshot_release(&record.operation_id, &record.request_digest)?,
                    Err(HostError::Snapshot(crate::snapshots::SnapshotError::Io(error)))
                        if error.kind() == io::ErrorKind::WouldBlock =>
                    {
                        record
                    }
                    Err(error) => return Err(error),
                };
                Ok(if reply {
                    HostResponse::SnapshotRelease { operation }
                } else {
                    HostResponse::Complete
                })
            }
            HostTaskCompletion::ImageCandidateCleanup {
                record,
                reply,
                result,
            } => {
                match result {
                    Ok(()) => self.catalog.complete_image_candidate_cleanup(
                        &record.operation_id,
                        &record.request_digest,
                    )?,
                    Err(HostError::Image(crate::images::ImageBuildError::Io(error)))
                        if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
                match reply {
                    Some(reply) => self.image_lookup_response(&record.operation_id, reply),
                    None => Ok(HostResponse::Complete),
                }
            }
            HostTaskCompletion::Rollback { record, result } => Ok(HostResponse::Rollback {
                value: self.catalog.complete_rollback(
                    &record.operation_id,
                    &record.request_digest,
                    result?,
                )?,
            }),
            HostTaskCompletion::Usage { machine_id, result } => {
                let (generation, usage) = result?;
                Ok(HostResponse::Usage {
                    usage: self.catalog.observe_usage(&machine_id, generation, usage)?,
                })
            }
            HostTaskCompletion::SecretPrepare { .. }
            | HostTaskCompletion::StorageRetire { .. }
            | HostTaskCompletion::SnapshotInspect { .. }
            | HostTaskCompletion::Configuration { .. }
            | HostTaskCompletion::ResourceAssessment { .. }
            | HostTaskCompletion::MachineInputs { .. }
            | HostTaskCompletion::LifecycleInspect { .. }
            | HostTaskCompletion::SuspendCapture { .. }
            | HostTaskCompletion::Lifecycle { .. }
            | HostTaskCompletion::Fork { .. }
            | HostTaskCompletion::Image { .. }
            | HostTaskCompletion::ImagePublish { .. }
            | HostTaskCompletion::ImageCancel { .. }
            | HostTaskCompletion::ImageInspect { .. } => Err(HostError::Invalid(
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
                    match self.catalog.operation(&record.operation_id)? {
                        Some(sandsurf_state::HostOperationRecord::SecretDelivery(current))
                            if current.machine_id == record.machine_id
                                && current.request_digest == record.request_digest =>
                        {
                            current
                        }
                        _ => return Err(HostError::Invalid("admitted secret delivery is missing")),
                    }
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
                    None => match self.catalog.operation(&record.operation_id)? {
                        Some(sandsurf_state::HostOperationRecord::SecretRevocation(current))
                            if current.machine_id == record.machine_id
                                && current.request_digest == record.request_digest =>
                        {
                            current
                        }
                        _ => {
                            return Err(HostError::Invalid(
                                "admitted secret revocation is missing",
                            ));
                        }
                    },
                };
                Ok(HostResponse::SecretRevocation { revocation })
            }
        }
    }

    fn prepare_guardian_with_config(
        &self,
        machine: &MachineId,
        config: &NativeGuardianConfig,
    ) -> Result<GuardianProvision> {
        let mut provision = self.prepare_guardian_inner(machine)?;
        provision
            .initialization
            .as_mut()
            .expect("catalog provisioning has inputs")
            .configuration = Some(Box::new(config.clone()));
        Ok(provision)
    }

    fn prepare_guardian_inner(&self, machine: &MachineId) -> Result<GuardianProvision> {
        let record = self
            .catalog
            .machine(machine)?
            .ok_or(HostError::Invalid("machine is missing from host authority"))?;
        Ok(GuardianProvision {
            host_root: self.root.clone(),
            machine: machine.clone(),
            initialization: Some(GuardianInitialization {
                executable: self.executable.clone(),
                record: Box::new(record),
                binding: self.catalog.authority_binding().clone(),
                configuration: None,
            }),
        })
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

    /// Bounded, rotating authority visits. Neither retained history nor a busy
    /// early machine may cause every sweep to start over at the first identity.
    fn reconcile_lifetime_policies(
        &mut self,
        cursor: &mut ReconciliationCursor,
        busy: &BTreeSet<ReconciliationIdentity>,
        slots: usize,
    ) -> Result<Vec<(ReconciliationIdentity, HostDispatch)>> {
        let slots = slots.min(MAX_HOST_CONNECTIONS / 2);
        if slots == 0 {
            return Ok(Vec::new());
        }
        let now = unix_millis()?;
        let mut work = Vec::new();
        // Rotate the first domain so a single free slot cannot starve either
        // snapshot publication, lifecycle policy or independently owned images.
        let first = cursor.next_domain;
        cursor.next_domain = (first + 1) % 6;
        for offset in 0..6 {
            match (first + offset) % 6 {
                0 => self.reconcile_snapshot_page(cursor, busy, slots, &mut work)?,
                1 => self.reconcile_machine_page(cursor, busy, slots, now, &mut work)?,
                2 => self.reconcile_image_page(cursor, busy, slots, &mut work)?,
                3 => self.reconcile_import_page(cursor, busy, slots, &mut work)?,
                4 => self.reconcile_snapshot_release_page(cursor, busy, slots, &mut work)?,
                5 => self.reconcile_candidate_page(cursor, busy, slots, &mut work)?,
                _ => unreachable!(),
            }
        }
        Ok(work)
    }

    fn reconcile_machine_page(
        &mut self,
        cursor: &mut ReconciliationCursor,
        busy: &BTreeSet<ReconciliationIdentity>,
        slots: usize,
        now: Counter,
        work: &mut Vec<(ReconciliationIdentity, HostDispatch)>,
    ) -> Result<()> {
        let remaining = slots.saturating_sub(work.len());
        if remaining == 0 {
            return Ok(());
        }
        let records = self
            .catalog
            .active_machines(cursor.after_machine.as_ref(), counter(remaining as u64))?;
        let at_end = records.is_empty();
        for record in records {
            let id = record.id.clone();
            cursor.after_machine = Some(id.clone());
            let identity = ReconciliationIdentity::Machine(id.clone());
            if busy.contains(&identity) || work.iter().any(|(key, _)| *key == identity) {
                continue;
            }
            match self.reconcile_machine(record, now) {
                Ok(Some(dispatch)) => work.push((identity, dispatch)),
                Ok(None) => {}
                Err(error) => eprintln!(
                    "sandsurf machine {} reconciliation deferred: {error}",
                    id.as_str(),
                ),
            }
        }
        if at_end {
            cursor.after_machine = None;
        }
        Ok(())
    }

    fn reconcile_snapshot_page(
        &self,
        cursor: &mut ReconciliationCursor,
        busy: &BTreeSet<ReconciliationIdentity>,
        slots: usize,
        work: &mut Vec<(ReconciliationIdentity, HostDispatch)>,
    ) -> Result<()> {
        let remaining = slots.saturating_sub(work.len());
        if remaining == 0 {
            return Ok(());
        }
        let snapshots = self
            .catalog
            .capturing_disk_snapshots(cursor.after_snapshot.as_ref(), counter(remaining as u64))?;
        let at_end = snapshots.is_empty();
        for snapshot in snapshots {
            cursor.after_snapshot = Some(snapshot.request.id.clone());
            let machine = snapshot.request.machine_id.clone();
            let identity = ReconciliationIdentity::Machine(machine);
            if busy.contains(&identity) || work.iter().any(|(key, _)| *key == identity) {
                continue;
            }
            // Reuse the complete capture transaction, not a separate pause-only
            // repair path. Its lease prevents releasing an active capture and
            // its immutable prepared input permits finishing after restart.
            match self.prepare_snapshot_recovery(snapshot) {
                Ok(dispatch) => work.push((identity, dispatch)),
                Err(error) => eprintln!("sandsurf snapshot recovery deferred: {error}"),
            }
        }
        if at_end {
            cursor.after_snapshot = None;
        }
        Ok(())
    }

    fn reconcile_import_page(
        &self,
        cursor: &mut ReconciliationCursor,
        busy: &BTreeSet<ReconciliationIdentity>,
        slots: usize,
        work: &mut Vec<(ReconciliationIdentity, HostDispatch)>,
    ) -> Result<()> {
        let remaining = slots.saturating_sub(work.len());
        if remaining == 0 {
            return Ok(());
        }
        let records = self
            .catalog
            .pending_image_imports(cursor.after_import.as_ref(), counter(remaining as u64))?;
        let at_end = records.is_empty();
        for record in records {
            cursor.after_import = Some(record.operation_id.clone());
            let identity = ReconciliationIdentity::Image(record.operation_id.clone());
            if busy.contains(&identity) {
                continue;
            }
            match self.prepare_image_materialization(record) {
                Ok(dispatch) => work.push((identity, dispatch)),
                Err(error) => {
                    eprintln!("sandsurf image materialization recovery deferred: {error}")
                }
            }
        }
        if at_end {
            cursor.after_import = None;
        }
        Ok(())
    }

    fn reconcile_image_page(
        &self,
        cursor: &mut ReconciliationCursor,
        busy: &BTreeSet<ReconciliationIdentity>,
        slots: usize,
        work: &mut Vec<(ReconciliationIdentity, HostDispatch)>,
    ) -> Result<()> {
        let remaining = slots.saturating_sub(work.len());
        if remaining == 0 {
            return Ok(());
        }
        let releases = self
            .catalog
            .pending_image_releases(cursor.after_image.as_ref(), counter(remaining as u64))?;
        let at_end = releases.is_empty();
        for record in releases {
            cursor.after_image = Some(record.operation_id.clone());
            let identity = ReconciliationIdentity::Image(record.operation_id.clone());
            if busy.contains(&identity) {
                continue;
            }
            work.push((
                identity,
                HostDispatch::Task(Box::new(HostTask::ImageCleanup {
                    root: self.root.clone(),
                    record,
                    reply: false,
                })),
            ));
        }
        if at_end {
            cursor.after_image = None;
        }
        Ok(())
    }

    fn reconcile_candidate_page(
        &self,
        cursor: &mut ReconciliationCursor,
        busy: &BTreeSet<ReconciliationIdentity>,
        slots: usize,
        work: &mut Vec<(ReconciliationIdentity, HostDispatch)>,
    ) -> Result<()> {
        let remaining = slots.saturating_sub(work.len());
        if remaining == 0 {
            return Ok(());
        }
        let records = self.catalog.pending_image_candidate_cleanup(
            cursor.after_candidate.as_ref(),
            counter(remaining as u64),
        )?;
        let at_end = records.is_empty();
        for record in records {
            cursor.after_candidate = Some(record.operation_id.clone());
            let identity = ReconciliationIdentity::Image(record.operation_id.clone());
            if busy.contains(&identity) || work.iter().any(|(key, _)| *key == identity) {
                continue;
            }
            work.push((
                identity,
                HostDispatch::Task(Box::new(HostTask::ImageCandidateCleanup {
                    root: self.root.clone(),
                    record,
                    reply: None,
                })),
            ));
        }
        if at_end {
            cursor.after_candidate = None;
        }
        Ok(())
    }

    fn prepare_snapshot_recovery(&self, snapshot: Snapshot) -> Result<HostDispatch> {
        // Admission already binds an existing generation and machine-owned
        // storage. Re-reading that storage envelope is not a second recovery
        // authority, and finalizing published bytes needs no live VM owner.
        let provision = GuardianProvision {
            host_root: self.root.clone(),
            machine: snapshot.request.machine_id.clone(),
            initialization: None,
        };
        Ok(HostDispatch::Task(Box::new(HostTask::Snapshot {
            root: self.root.clone(),
            executable: self.executable.clone(),
            endpoint: provision.endpoint(),
            capturing: Box::new(snapshot),
            provision: Some(provision),
        })))
    }

    fn reconcile_snapshot_release_page(
        &self,
        cursor: &mut ReconciliationCursor,
        busy: &BTreeSet<ReconciliationIdentity>,
        slots: usize,
        work: &mut Vec<(ReconciliationIdentity, HostDispatch)>,
    ) -> Result<()> {
        let remaining = slots.saturating_sub(work.len());
        if remaining == 0 {
            return Ok(());
        }
        let records = self.catalog.pending_snapshot_releases(
            cursor.after_snapshot_release.as_ref(),
            counter(remaining as u64),
        )?;
        let at_end = records.is_empty();
        for record in records {
            cursor.after_snapshot_release = Some(record.operation_id.clone());
            let identity = ReconciliationIdentity::SnapshotRelease(record.operation_id.clone());
            if busy.contains(&identity) {
                continue;
            }
            match self.prepare_snapshot_release(record, false) {
                Ok(dispatch) => work.push((identity, dispatch)),
                Err(error) => eprintln!("sandsurf snapshot retirement recovery deferred: {error}"),
            }
        }
        if at_end {
            cursor.after_snapshot_release = None;
        }
        Ok(())
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
            return self.prepare_storage_retirement(&record.id, None).map(Some);
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
        if record.latest_intent.desired != DesiredState::Destroyed
            && let Some(rollback) = self.catalog.pending_rollback(&record.id)?
        {
            return self.prepare_rollback_effect(rollback).map(Some);
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
                reply: None,
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

    fn prepare_storage_retirement(
        &self,
        machine: &MachineId,
        reply: Option<Box<MachineViewReply>>,
    ) -> Result<HostDispatch> {
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
        Ok(HostDispatch::Task(Box::new(HostTask::StorageRetire {
            machine_id: machine.clone(),
            disk: self
                .machine_root(machine)
                .join("disks")
                .join(system_disk_name()),
            disk_bytes: record.runtime_configuration.resources.disk_bytes,
            reply,
        })))
    }

    fn guardian_endpoint(&self, machine: &MachineId) -> PathBuf {
        self.machine_root(machine).join("guardian")
    }
}

fn inspect_host(root: &Path, host_id: String) -> HostInspection {
    let network_egress = sandsurf_network::egress_capability();
    let (qualification_records, qualification_issues) = match crate::qualification::inspect(root) {
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
        host_id,
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
        image_workers: crate::image_worker::capability(root),
        resources: crate::resources::capabilities(root, &network_egress),
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

struct LifecycleEffect {
    plan: LifecyclePlan,
    prepare: Option<NativeSnapshotRequest>,
    // The native capture task remains exclusively owned across catalog
    // completion and CommitSuspend. It is never replaced by a record reference.
    custody: Option<crate::snapshots::CaptureCustody>,
}

impl LifecycleEffect {
    fn ordinary(plan: LifecyclePlan) -> Box<Self> {
        Box::new(Self {
            plan,
            prepare: None,
            custody: None,
        })
    }
}

struct GuardianProvision {
    host_root: PathBuf,
    machine: MachineId,
    initialization: Option<GuardianInitialization>,
}

/// Immutable admitted inputs for filesystem materialization. This task has no
/// catalog writer or permission to change authority/lifecycle intent.
struct GuardianInitialization {
    executable: PathBuf,
    record: Box<MachineRecord>,
    binding: AuthorityBinding,
    configuration: Option<Box<NativeGuardianConfig>>,
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
        if let Some(initialization) = &self.initialization {
            self.initialize(initialization, &root)?;
        }
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

    fn initialize(&self, inputs: &GuardianInitialization, root: &Path) -> Result<()> {
        let resources = &inputs.record.runtime_configuration.resources;
        crate::resources::require_machine_storage(&self.host_root, &self.machine, resources)?;
        prepare_directory(root)?;
        // All initialization workers serialize on this exact storage object;
        // an interrupted worker cannot leave a published partial journal.
        let _custody = sandsurf_native::storage::disk_lease(&root.join(".initialize.lock"))?;
        prepare_directory(&root.join("guardian"))?;
        prepare_directory(&root.join("disks"))?;
        prepare_directory(&root.join("output"))?;
        let config_path = root.join("guardian/config.json");
        match fs::symlink_metadata(&config_path) {
            Ok(_) => {
                // Published configuration is immutable. The native owner
                // verifies its artifacts when attaching; never rematerialize
                // or overwrite it from a later mutable resource envelope.
                if let Some(config) = &inputs.configuration {
                    write_guardian_configuration(&config_path, config)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let prepared;
                let config = match &inputs.configuration {
                    Some(config) => &**config,
                    None => {
                        prepared = verify_machine_inputs(
                            &self.host_root,
                            &inputs.executable,
                            &self.machine,
                            &inputs.record.image_digest,
                            resources,
                        )?;
                        &prepared.configuration
                    }
                };
                write_guardian_configuration(&config_path, config)?;
            }
            Err(error) => return Err(error.into()),
        }
        let runtime = root.join("runtime");
        match fs::symlink_metadata(&runtime) {
            Ok(_) => {
                // Do not open a live writer merely to provision an attachment.
                // If a native owner is present, its authenticated identity is
                // the next step; otherwise open validates the whole journal.
                if GuardianClient::new(self.endpoint())
                    .owner_identity(self.machine.clone())
                    .is_err()
                {
                    let journal = RuntimeJournal::open(&runtime, &self.machine)?;
                    if journal.authority_binding() != &inputs.binding {
                        return Err(HostError::Invalid("guardian authority binding differs"));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                RuntimeJournal::create(
                    &runtime,
                    self.machine.clone(),
                    runtime_limits(resources),
                    inputs.binding.clone(),
                )?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

fn write_guardian_configuration(path: &Path, config: &NativeGuardianConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    crate::linux::write_config(path, config)?;
    #[cfg(any(target_os = "macos", windows))]
    crate::qemu::write_config(path, config)?;
    Ok(())
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
        let mut reconciliation_cursor = ReconciliationCursor::default();
        let result = loop {
            if std::time::Instant::now() >= next_reconciliation {
                match service.reconcile_lifetime_policies(
                    &mut reconciliation_cursor,
                    &reconciliations,
                    (MAX_HOST_CONNECTIONS / 2).saturating_sub(reconciliations.len()),
                ) {
                    Ok(work) => {
                        for (machine, dispatch) in work {
                            if reconciliations.len() >= MAX_HOST_CONNECTIONS / 2
                                || reconciliations.contains(&machine)
                            {
                                continue;
                            }
                            let sender = reconciliation_sender.clone();
                            let identity = machine.clone();
                            match std::thread::Builder::new()
                                .name("sandsurf-host-reconcile".into())
                                .spawn(move || {
                                    if let Some(HostDispatch::Ready(response)) =
                                        execute_host_tasks(dispatch, &sender)
                                        && let HostResponse::Rejected { message, .. } = *response
                                    {
                                        eprintln!(
                                            "sandsurf {identity} reconciliation deferred: {message}"
                                        );
                                    }
                                    let _ = sender.send(HostIngress::Reconciled(identity));
                                }) {
                                Ok(_) => {
                                    reconciliations.insert(machine);
                                }
                                Err(error) => {
                                    eprintln!("sandsurf reconciliation worker unavailable: {error}")
                                }
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
    Reconciled(ReconciliationIdentity),
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
    Inspection { root: PathBuf, host_id: String },
    ArtifactRead(Box<DeferredArtifactRead>),
    Ready(Box<HostResponse>),
    Runtime(Box<DeferredRuntimeRequest>),
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
        let mut page = ControlPage::default();
        for record in self.records {
            if !page.push(observe_machine(&self.root, record)?)? {
                break;
            }
        }
        Ok(HostResponse::Machines {
            values: page.into_values(),
        })
    }
}

enum MachineViewReply {
    Machine,
    Lifecycle {
        operation: Box<LifecycleOperation>,
    },
    Configuration {
        revision: Counter,
    },
    Exposure {
        exposure: Exposure,
    },
    ResourceUpdate {
        revision: Counter,
        assessment: ResourceChangeAssessment,
    },
}
struct ResourceUpdateAdmission {
    operation_id: OperationId,
    expected_revision: Counter,
    approval_id: CommitmentId,
}
struct DeferredMachineView {
    root: PathBuf,
    record: MachineRecord,
    reply: MachineViewReply,
}

impl DeferredMachineView {
    fn execute(self) -> Result<HostResponse> {
        let value = observe_machine(&self.root, self.record)?;
        Ok(match self.reply {
            MachineViewReply::Lifecycle { operation } => HostResponse::Lifecycle {
                operation: *operation,
                machine: Box::new(value),
            },
            MachineViewReply::Machine => HostResponse::Machine { value },
            MachineViewReply::Configuration { revision } => HostResponse::Configuration {
                revision,
                machine: value,
            },
            MachineViewReply::Exposure { exposure } => HostResponse::Exposure {
                exposure,
                machine: value,
            },
            MachineViewReply::ResourceUpdate {
                revision,
                assessment,
            } => HostResponse::ResourceUpdate {
                revision,
                assessment,
                machine: value,
            },
        })
    }
}

impl HostDispatch {
    fn finish(self) -> HostResponse {
        match self {
            Self::Inspection { root, host_id } => HostResponse::Inspection {
                value: inspect_host(&root, host_id),
            },
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
fn finish_retired_capture(
    root: &Path,
    endpoint: &Path,
    snapshot: &Snapshot,
    provision: Option<&GuardianProvision>,
) -> Result<()> {
    let machine_root = root
        .join("machines")
        .join(object_name(snapshot.request.machine_id.as_str()));
    let Some(boundary) = crate::capture::CaptureBoundary::read(&machine_root)? else {
        return Ok(());
    };
    if boundary.operation_id != snapshot.request.operation_id {
        return Ok(()); // A different capture's pause is not ours to release.
    }
    if let Some(provision) = provision {
        provision.execute()?;
    }
    let operation_id = snapshot.request.operation_id.clone();
    let request = match snapshot.request.kind {
        SnapshotKind::Disk => NativeSnapshotRequest::FinishDisk { operation_id },
        SnapshotKind::Full => NativeSnapshotRequest::FinishFull { operation_id },
    };
    let response = GuardianClient::new(endpoint.to_path_buf())
        .native_snapshot(snapshot.request.machine_id.clone(), request)?;
    if !matches!(response, NativeSnapshotResponse::Complete { .. })
        || crate::capture::CaptureBoundary::read(&machine_root)?
            .is_some_and(|boundary| boundary.operation_id == snapshot.request.operation_id)
    {
        return Err(HostError::Invalid(
            "retired capture still owns a native boundary",
        ));
    }
    Ok(())
}

fn capture_snapshot(
    root: &Path,
    executable: &Path,
    endpoint: &Path,
    capturing: &sandsurf_protocol::Snapshot,
    provision: Option<&GuardianProvision>,
) -> Result<crate::snapshots::CaptureResult> {
    let request = &capturing.request;
    let capture_root = crate::snapshots::root(root, capturing);
    let _custody = crate::snapshots::capture_custody(&capture_root, capturing)?;
    let machine_root = root
        .join("machines")
        .join(object_name(request.machine_id.as_str()));
    if crate::capture::CaptureBoundary::require(&machine_root, &request.operation_id)?.is_some() {
        if let Some(provision) = provision {
            provision.execute()?;
        }
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
                if let Some(provision) = provision {
                    provision.execute()?;
                }
                let prepared = client.native_snapshot(
                    request.machine_id.clone(),
                    NativeSnapshotRequest::PrepareDisk {
                        snapshot_id: request.id.clone(),
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
            if let Some(provision) = provision {
                provision.execute()?;
            }
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
    ImageCancel {
        root: PathBuf,
        record: sandsurf_state::ImageImportRecord,
        reply: ImageLookupReply,
    },
    ImageCandidateCleanup {
        root: PathBuf,
        record: sandsurf_state::ImageImportRecord,
        reply: Option<ImageLookupReply>,
    },
    ImagePublish {
        root: PathBuf,
        record: sandsurf_state::ImageImportRecord,
        reply: ImageLookupReply,
    },
    SnapshotCleanup {
        root: PathBuf,
        endpoint: PathBuf,
        provision: Option<GuardianProvision>,
        snapshot: Box<Snapshot>,
        record: sandsurf_state::SnapshotReleaseRecord,
        reply: bool,
    },
    ImageCleanup {
        root: PathBuf,
        record: sandsurf_state::ImageReleaseRecord,
        reply: bool,
    },
    ImageInspect {
        root: PathBuf,
        record: sandsurf_state::ImageImportRecord,
        reply: ImageLookupReply,
    },
    Rollback {
        provision: GuardianProvision,
        record: RollbackRecord,
        snapshot: Box<Snapshot>,
    },
    StorageRetire {
        machine_id: MachineId,
        disk: PathBuf,
        disk_bytes: Counter,
        reply: Option<Box<MachineViewReply>>,
    },
    Usage {
        provision: GuardianProvision,
    },
    Configuration {
        provision: GuardianProvision,
        authorization: AuthorizedConfiguration,
        reply: Option<Box<MachineViewReply>>,
    },
    ResourceAssessment {
        provision: GuardianProvision,
        resources: Resources,
        update: Option<ResourceUpdateAdmission>,
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
    SnapshotInspect {
        provision: GuardianProvision,
        request: Box<SnapshotRequest>,
        approval_id: CommitmentId,
    },
    Snapshot {
        root: PathBuf,
        executable: PathBuf,
        endpoint: PathBuf,
        capturing: Box<sandsurf_protocol::Snapshot>,
        provision: Option<GuardianProvision>,
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
    SecretPut {
        store: Arc<crate::secrets::SecretAuthority>,
        record: sandsurf_state::SecretPutRecord,
        bytes: Zeroizing<Vec<u8>>,
    },
    SecretPrepare {
        provision: GuardianProvision,
        record: sandsurf_state::SecretDeliveryRecord,
        store: Arc<crate::secrets::SecretAuthority>,
    },
    SecretDelivery {
        endpoint: PathBuf,
        record: sandsurf_state::SecretDeliveryRecord,
        bytes: Zeroizing<Vec<u8>>,
    },
    SecretCleanup {
        endpoint: PathBuf,
        provision: Result<GuardianProvision>,
        record: sandsurf_state::SecretRevocationRecord,
    },
}
enum HostTaskCompletion {
    ImageCancel {
        record: sandsurf_state::ImageImportRecord,
        reply: ImageLookupReply,
        result: Result<crate::image_worker::CancellationCustody>,
    },
    ImageCandidateCleanup {
        record: sandsurf_state::ImageImportRecord,
        reply: Option<ImageLookupReply>,
        result: Result<()>,
    },
    ImagePublish {
        record: sandsurf_state::ImageImportRecord,
        reply: ImageLookupReply,
        result: Result<crate::images::PublicationCustody>,
    },
    SnapshotCleanup {
        record: sandsurf_state::SnapshotReleaseRecord,
        reply: bool,
        result: Result<()>,
    },
    ImageCleanup {
        record: sandsurf_state::ImageReleaseRecord,
        reply: bool,
        result: Result<()>,
    },
    ImageInspect {
        record: sandsurf_state::ImageImportRecord,
        reply: ImageLookupReply,
        result: Result<Option<sandsurf_state::ImageRecord>>,
    },
    Rollback {
        record: RollbackRecord,
        result: Result<Digest>,
    },
    StorageRetire {
        machine_id: MachineId,
        reply: Option<Box<MachineViewReply>>,
        result: Result<()>,
    },
    Usage {
        machine_id: MachineId,
        result: Result<(Counter, ResourceUsage)>,
    },
    Configuration {
        machine_id: MachineId,
        reply: Option<Box<MachineViewReply>>,
        result: Result<()>,
    },
    ResourceAssessment {
        machine_id: MachineId,
        resources: Resources,
        update: Option<ResourceUpdateAdmission>,
        result: Result<ResourceChangeAssessment>,
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
        result: Result<(
            crate::snapshots::CaptureResult,
            crate::snapshots::CaptureCustody,
        )>,
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
        custody: Option<crate::snapshots::CaptureCustody>,
    },
    SnapshotInspect {
        request: Box<SnapshotRequest>,
        approval_id: CommitmentId,
        result: Box<Result<GuardianInspection>>,
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
    SecretPut {
        record: sandsurf_state::SecretPutRecord,
        result: Result<SecretVersion>,
    },
    SecretPrepare {
        provision: GuardianProvision,
        record: sandsurf_state::SecretDeliveryRecord,
        result: Result<Zeroizing<Vec<u8>>>,
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
            Self::ImageCancel {
                root,
                record,
                reply,
            } => {
                let result = crate::image_worker::cancel(
                    &root,
                    &record.operation_id,
                    &record.request_digest,
                );
                HostTaskCompletion::ImageCancel {
                    record,
                    reply,
                    result,
                }
            }
            Self::ImageCandidateCleanup {
                root,
                record,
                reply,
            } => {
                let result = record
                    .image
                    .as_ref()
                    .ok_or(HostError::Invalid(
                        "image cleanup has no published candidate",
                    ))
                    .and_then(|image| {
                        crate::images::reclaim_candidate(
                            &root,
                            &record.operation_id,
                            &record.request_digest,
                            image,
                        )
                        .map_err(HostError::from)
                    });
                HostTaskCompletion::ImageCandidateCleanup {
                    record,
                    reply,
                    result,
                }
            }
            Self::ImagePublish {
                root,
                record,
                reply,
            } => {
                let result = record
                    .image
                    .as_ref()
                    .ok_or(HostError::Invalid(
                        "image publication has no reserved candidate",
                    ))
                    .and_then(|image| {
                        crate::images::publish_candidate(
                            &root,
                            &record.operation_id,
                            &record.request_digest,
                            image,
                        )
                        .map_err(HostError::from)
                    });
                HostTaskCompletion::ImagePublish {
                    record,
                    reply,
                    result,
                }
            }
            Self::SnapshotCleanup {
                root,
                endpoint,
                provision,
                snapshot,
                record,
                reply,
            } => {
                let result = crate::snapshots::cleanup(&root, &snapshot, &record, || {
                    finish_retired_capture(&root, &endpoint, &snapshot, provision.as_ref())
                        .map_err(|error| io::Error::other(error.to_string()))
                })
                .map_err(HostError::from);
                HostTaskCompletion::SnapshotCleanup {
                    record,
                    reply,
                    result,
                }
            }
            Self::ImageCleanup {
                root,
                record,
                reply,
            } => {
                let result =
                    crate::images::cleanup(&root, &record.image_digest).map_err(HostError::from);
                HostTaskCompletion::ImageCleanup {
                    record,
                    reply,
                    result,
                }
            }
            Self::ImageInspect {
                root,
                record,
                reply,
            } => {
                let result =
                    crate::images::completed(&root, &record.operation_id, &record.request_digest)
                        .map_err(HostError::from);
                HostTaskCompletion::ImageInspect {
                    record,
                    reply,
                    result,
                }
            }
            Self::Rollback {
                provision,
                record,
                snapshot,
            } => {
                let result = (|| {
                    provision.execute()?;
                    let inspection = GuardianClient::new(provision.endpoint())
                        .inspect(record.machine_id.clone(), None)?;
                    if inspection.machine_id != record.machine_id
                        || !matches!(
                            inspection.observation, Observation::Current {
                                value: MachineObservation { ref machine_id, state: MachineState::Stopped, .. }
                            } if *machine_id == record.machine_id
                        )
                    {
                        return Err(HostError::Invalid(
                            "disk rollback requires a confirmed stopped machine",
                        ));
                    }
                    // Observed stop is necessary but insufficient: replacement
                    // takes the storage owner's exclusive attachment lease too.
                    Ok(crate::snapshots::rollback(
                        &crate::snapshots::root(&provision.host_root, &snapshot),
                        &snapshot,
                        &provision
                            .host_root
                            .join("machines")
                            .join(object_name(record.machine_id.as_str()))
                            .join("disks")
                            .join(system_disk_name()),
                        &record.operation_id,
                    )?)
                })();
                HostTaskCompletion::Rollback { record, result }
            }
            Self::StorageRetire {
                machine_id,
                disk,
                disk_bytes,
                reply,
            } => {
                let result =
                    crate::storage::retire(&disk, disk_bytes.get()).map_err(HostError::from);
                HostTaskCompletion::StorageRetire {
                    machine_id,
                    reply,
                    result,
                }
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
                reply,
            } => {
                let result = perform_configuration(&provision, authorization);
                HostTaskCompletion::Configuration {
                    machine_id: provision.machine,
                    reply,
                    result,
                }
            }
            Self::ResourceAssessment {
                provision,
                resources,
                update,
            } => {
                let result = (|| {
                    provision.execute()?;
                    let client = GuardianClient::new(provision.endpoint());
                    let response = client.runtime(
                        provision.machine.clone(),
                        if update.is_some() {
                            RuntimeRequest::ValidateResources {
                                resources: resources.clone(),
                            }
                        } else {
                            RuntimeRequest::AssessResources {
                                resources: resources.clone(),
                            }
                        },
                    )?;
                    let RuntimeResponse::ResourceAssessment { assessment } = response else {
                        return Err(HostError::Invalid("native resource assessment unavailable"));
                    };
                    Ok(assessment)
                })();
                HostTaskCompletion::ResourceAssessment {
                    machine_id: provision.machine,
                    resources,
                    update,
                    result,
                }
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
                    let custody = crate::snapshots::capture_custody(&capture_root, &capturing)?;
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
            Self::SnapshotInspect {
                provision,
                request,
                approval_id,
            } => {
                let result = provision.execute().and_then(|()| {
                    GuardianClient::new(provision.endpoint())
                        .inspect(request.machine_id.clone(), None)
                        .map_err(HostError::from)
                });
                HostTaskCompletion::SnapshotInspect {
                    request,
                    approval_id,
                    result: Box::new(result),
                }
            }
            Self::Snapshot {
                root,
                executable,
                endpoint,
                capturing,
                provision,
            } => HostTaskCompletion::Snapshot {
                snapshot_id: capturing.request.id.clone(),
                request_digest: capturing.request_digest.clone(),
                result: capture_snapshot(
                    &root,
                    &executable,
                    &endpoint,
                    &capturing,
                    provision.as_ref(),
                ),
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
            Self::SecretPut {
                store,
                record,
                bytes,
            } => {
                let result = store
                    .put(
                        record.secret.id.clone(),
                        record.secret.version.clone(),
                        &bytes,
                    )
                    .map_err(HostError::from);
                HostTaskCompletion::SecretPut { record, result }
            }
            Self::SecretPrepare {
                provision,
                record,
                store,
            } => {
                let result = (|| {
                    let bytes = Zeroizing::new(
                        store.read(&record.delivery.secret.id, &record.delivery.secret.version)?,
                    );
                    if bytes.len() as u64 != record.delivery.secret.bytes.get() {
                        return Err(HostError::Invalid("approved secret version length changed"));
                    }
                    provision.execute()?;
                    Ok(bytes)
                })();
                HostTaskCompletion::SecretPrepare {
                    provision,
                    record,
                    result,
                }
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
            Self::SecretCleanup {
                endpoint,
                provision,
                record,
            } => {
                let client = GuardianClient::new(endpoint);
                let inspection = provision
                    .and_then(|provision| provision.execute())
                    .and_then(|()| {
                        client
                            .inspect(record.machine_id.clone(), None)
                            .map_err(HostError::from)
                    });
                let report = match inspection {
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

struct DeferredRuntimeRequest {
    endpoint: PathBuf,
    machine_id: MachineId,
    request: RuntimeRequest,
    loss: Option<AuthorizedLoss>,
    provision: GuardianProvision,
}

impl DeferredRuntimeRequest {
    fn execute(self) -> Result<HostResponse> {
        self.provision.execute()?;
        let client = GuardianClient::new(self.endpoint);
        if let Some(authorization) = self.loss {
            let response = client.runtime(
                self.machine_id.clone(),
                RuntimeRequest::RecordLoss { authorization },
            )?;
            if !matches!(response, RuntimeResponse::Complete) {
                return Err(HostError::Invalid(
                    "guardian did not acknowledge host loss authority",
                ));
            }
        }
        Ok(HostResponse::Runtime {
            response: client.runtime(self.machine_id, self.request)?,
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
        admit_machine_with_defaults(service, name, lifetime, ExecutionDefaults::default())
    }

    fn admit_machine_with_defaults(
        service: &mut HostService,
        name: &str,
        lifetime: MachineLifetime,
        defaults: ExecutionDefaults,
    ) -> MachineId {
        let machine: MachineId = name.try_into().unwrap();
        let create: OperationId = format!("create-{name}").try_into().unwrap();
        let image = bytes_digest(b"seed");
        if service.catalog.image(&image).unwrap().is_none() {
            let operation: OperationId = "import-seed".try_into().unwrap();
            let input = sandsurf_state::ImageImportInput::Native {
                manifest_path: service.root.join("seed-manifest.json"),
                manifest_digest: image.clone(),
            };
            let request = input.request_digest(&operation).unwrap();
            service
                .catalog
                .admit_image_import(
                    operation.clone(),
                    input,
                    Approval {
                        id: "approve-import-seed".try_into().unwrap(),
                        request_digest: request.clone(),
                    },
                )
                .unwrap();
            let candidate = sandsurf_state::ImageRecord {
                digest: image.clone(),
                source_digest: image.clone(),
                platform: "linux".into(),
                architecture: "amd64".into(),
                logical_bytes: Counter::ONE,
                storage_bytes: Counter::ONE,
                provenance_digest: image.clone(),
                sensitive: false,
            };
            service
                .catalog
                .prepare_image_import(&operation, &request, candidate.clone())
                .unwrap();
            service
                .catalog
                .complete_image_import(&operation, &request, candidate)
                .unwrap();
        }
        let resources = Resources::from_geometry(
            Counter::ONE,
            128_u64.try_into().unwrap(),
            1_048_576_u64.try_into().unwrap(),
            1_000_000_u64.try_into().unwrap(),
            8_u64.try_into().unwrap(),
        )
        .expect("static resource envelope");
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
    fn secret_publication_changes_store_then_completes_only_on_catalog_owner() {
        let root = std::env::temp_dir().join(format!(
            "sssecret-store-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get(),
        ));
        let mut service = intent_service(&root);
        let id: SecretId = "credential".try_into().unwrap();
        let version: SecretVersionId = "version".try_into().unwrap();
        let operation: OperationId = "put".try_into().unwrap();
        let request = HostRequest::PutSecret {
            secret_id: id.clone(),
            version: version.clone(),
            bytes: b"protected".to_vec(),
            operation_id: operation.clone(),
            approval_id: "approve-put".try_into().unwrap(),
        };
        let HostDispatch::Task(task) = service.route(request.clone()) else {
            panic!("secret publication ran on the catalog writer");
        };
        assert!(service.secrets.read(&id, &version).is_err());
        assert!(matches!(service.catalog.operation(&operation).unwrap(),
            Some(sandsurf_state::HostOperationRecord::SecretPut(record)) if !record.applied));
        let completion = task.execute();
        assert_eq!(service.secrets.read(&id, &version).unwrap(), b"protected");
        assert!(matches!(service.catalog.operation(&operation).unwrap(),
            Some(sandsurf_state::HostOperationRecord::SecretPut(record)) if !record.applied));
        service.complete_task(completion).unwrap();
        assert!(matches!(service.catalog.operation(&operation).unwrap(),
            Some(sandsurf_state::HostOperationRecord::SecretPut(record)) if record.applied));
        assert!(
            matches!(service.route(request), HostDispatch::Ready(response)
            if matches!(response.as_ref(), HostResponse::Secret { secret } if secret.id == id && secret.version == version))
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn secret_preparation_does_not_disclose_and_catalog_completion_fences_duplicate_or_revoked_delivery()
     {
        let root = std::env::temp_dir().join(format!(
            "sssecret-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        let secret = SecretVersion {
            id: "credential".try_into().unwrap(),
            version: "opaque-version".try_into().unwrap(),
            bytes: counter(6),
        };
        let delivery = |id: &str| sandsurf_state::SecretDeliveryAdmission {
            operation_id: id.try_into().unwrap(),
            machine_id: machine.clone(),
            request_digest: bytes_digest(id.as_bytes()),
            delivery: SecretDelivery {
                secret: secret.clone(),
                destination: SecretDestination::File {
                    path: "/run/credential".try_into().unwrap(),
                    mode: 0o600,
                },
                lifetime: SecretLifetime::UntilRevoked,
                execution_id: None,
            },
        };
        let mut admit = |record: sandsurf_state::SecretDeliveryAdmission| {
            service
                .catalog
                .admit_secret_delivery(
                    record.clone(),
                    Counter::ONE,
                    Approval {
                        id: format!("approve-{}", record.operation_id.as_str())
                            .try_into()
                            .unwrap(),
                        request_digest: record.request_digest.clone(),
                    },
                )
                .unwrap()
        };
        let first = admit(delivery("deliver"));
        let revoked = admit(delivery("deliver-after-revocation"));
        let completion = |record, result: Result<()>| HostTaskCompletion::SecretPrepare {
            provision: GuardianProvision {
                host_root: root.clone(),
                machine: machine.clone(),
                initialization: None,
            },
            record,
            result: result.map(|()| Zeroizing::new(b"secret".to_vec())),
        };
        assert!(
            service
                .complete_task(completion(
                    first.clone(),
                    Err(HostError::Invalid("native unavailable"))
                ))
                .is_err()
        );
        for operation in [&first.operation_id, &revoked.operation_id] {
            assert!(matches!(service.catalog.operation(operation).unwrap(),
                Some(sandsurf_state::HostOperationRecord::SecretDelivery(record))
                    if record.disclosure == SecretDisclosure::NotSent));
        }
        assert!(
            !service
                .catalog
                .machine(&machine)
                .unwrap()
                .unwrap()
                .known_sensitive
        );
        let HostDispatch::Task(task) = service
            .complete_task(completion(first.clone(), Ok(())))
            .unwrap()
        else {
            panic!("secret disclosure did not return to a detached worker");
        };
        assert!(matches!(*task, HostTask::SecretDelivery { .. }));
        drop(task); // An interrupted dispatch cannot be sent again by a second preparation.
        assert!(service.complete_task(completion(first, Ok(()))).is_err());
        assert!(
            service
                .catalog
                .machine(&machine)
                .unwrap()
                .unwrap()
                .known_sensitive
        );
        service
            .catalog
            .admit_secret_revocation(
                sandsurf_state::SecretRevocationAdmission {
                    machine_id: machine.clone(),
                    operation_id: "revoke".try_into().unwrap(),
                    expected_revision: Counter::ONE,
                    secret,
                    terminate_recipients: false,
                    request_digest: bytes_digest(b"revoke"),
                },
                Approval {
                    id: "approve-revoke".try_into().unwrap(),
                    request_digest: bytes_digest(b"revoke"),
                },
            )
            .unwrap();
        assert!(
            service
                .complete_task(completion(revoked.clone(), Ok(())))
                .is_err()
        );
        assert!(
            matches!(service.catalog.operation(&revoked.operation_id).unwrap(),
            Some(sandsurf_state::HostOperationRecord::SecretDelivery(record))
                if record.revoked && record.disclosure == SecretDisclosure::NotSent)
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_resource_validation_cannot_admit_a_superseded_host_revision() {
        let root = std::env::temp_dir().join(format!(
            "ssresource-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        let resources = service
            .catalog
            .machine(&machine)
            .unwrap()
            .unwrap()
            .runtime_configuration
            .resources;
        let operation: OperationId = "resource-update".try_into().unwrap();
        // Another host decision wins while the native worker is assessing.
        service
            .catalog
            .request_lifecycle(
                &machine,
                "stop".try_into().unwrap(),
                Counter::ONE,
                DesiredState::Stopped,
                Approval {
                    id: "approve-stop".try_into().unwrap(),
                    request_digest: digest(
                        Domain::Operation,
                        &(
                            &machine,
                            OperationId::try_from("stop").unwrap(),
                            Counter::ONE,
                            DesiredState::Stopped,
                        ),
                    )
                    .unwrap(),
                },
            )
            .unwrap();
        let completion = HostTaskCompletion::ResourceAssessment {
            machine_id: machine.clone(),
            resources,
            update: Some(ResourceUpdateAdmission {
                operation_id: operation.clone(),
                expected_revision: Counter::ONE,
                approval_id: "approve-resource-update".try_into().unwrap(),
            }),
            result: Ok(ResourceChangeAssessment {
                mode: ResourceChangeMode::Live,
                reasons: vec![],
            }),
        };
        assert!(service.complete_task(completion).is_err());
        assert!(service.catalog.operation(&operation).unwrap().is_none());
        let record = service.catalog.machine(&machine).unwrap().unwrap();
        assert_eq!(record.configuration_revision, Counter::ONE.next().unwrap());
        assert_eq!(record.latest_intent.desired, DesiredState::Stopped);
        assert!(!service.machine_root(&machine).exists());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn historical_network_retry_does_not_install_old_authority_or_contact_native_ownership() {
        let root = std::env::temp_dir().join(format!(
            "ssnetwork-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        let operation: OperationId = "configure".try_into().unwrap();
        let policy = NetworkPolicy::default();
        let request_digest = digest(
            Domain::Network,
            &(
                "sandsurf-network-policy-change-v1",
                &machine,
                &operation,
                Counter::ONE,
                &policy,
            ),
        )
        .unwrap();
        let configuration = service
            .catalog
            .machine(&machine)
            .unwrap()
            .unwrap()
            .runtime_configuration;
        let admission = service
            .catalog
            .set_runtime_configuration(
                &machine,
                &operation,
                Counter::ONE,
                configuration,
                request_digest.clone(),
                Approval {
                    id: "approve-configure".try_into().unwrap(),
                    request_digest,
                },
            )
            .unwrap();
        service
            .catalog
            .request_lifecycle(
                &machine,
                "stop".try_into().unwrap(),
                admission.revision,
                DesiredState::Stopped,
                Approval {
                    id: "approve-stop".try_into().unwrap(),
                    request_digest: digest(
                        Domain::Operation,
                        &(
                            &machine,
                            OperationId::try_from("stop").unwrap(),
                            admission.revision,
                            DesiredState::Stopped,
                        ),
                    )
                    .unwrap(),
                },
            )
            .unwrap();
        let HostDispatch::MachineView(view) = service.route(HostRequest::SetNetworkPolicy {
            machine_id: machine.clone(),
            operation_id: operation,
            expected_revision: Counter::ONE,
            policy,
            approval_id: "approve-configure".try_into().unwrap(),
        }) else {
            panic!("historical configuration was dispatched to the native owner");
        };
        assert_eq!(
            view.record.configuration_revision,
            admission.revision.next().unwrap()
        );
        assert!(
            matches!(view.reply, MachineViewReply::Configuration { revision } if revision == admission.revision)
        );
        assert!(!service.machine_root(&machine).exists());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_or_cross_machine_snapshot_inspection_cannot_reserve_capture_authority() {
        let root = std::env::temp_dir().join(format!(
            "sssnapshot-inspect-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        let request = SnapshotRequest {
            id: "snapshot".try_into().unwrap(),
            operation_id: "capture".try_into().unwrap(),
            machine_id: machine.clone(),
            expected_generation: Counter::ONE,
            expected_revision: Counter::ONE,
            kind: SnapshotKind::Disk,
            parent: None,
        };
        let inspection = |identity: MachineId| GuardianInspection {
            machine_id: identity.clone(),
            observation: Observation::Current {
                value: MachineObservation {
                    machine_id: identity,
                    generation: Counter::ONE,
                    sequence: Counter::ONE,
                    state: MachineState::Running,
                    applied_revision: Counter::ONE,
                    cause: ObservationCause::Native {},
                    evidence_digest: bytes_digest(b"native"),
                },
            },
            management: Observation::Unavailable { last_known: None },
            operation: None,
            lifecycle_operation: None,
            configuration_operation: None,
        };
        let completion = |identity| HostTaskCompletion::SnapshotInspect {
            request: Box::new(request.clone()),
            approval_id: "approve-capture".try_into().unwrap(),
            result: Box::new(Ok(inspection(identity))),
        };
        assert!(
            service
                .complete_task(completion("other".try_into().unwrap()))
                .is_err()
        );
        assert!(service.catalog.snapshot(&request.id).unwrap().is_none());
        service
            .catalog
            .request_lifecycle(
                &machine,
                "stop".try_into().unwrap(),
                Counter::ONE,
                DesiredState::Stopped,
                Approval {
                    id: "approve-stop".try_into().unwrap(),
                    request_digest: digest(
                        Domain::Operation,
                        &(
                            &machine,
                            OperationId::try_from("stop").unwrap(),
                            Counter::ONE,
                            DesiredState::Stopped,
                        ),
                    )
                    .unwrap(),
                },
            )
            .unwrap();
        assert!(service.complete_task(completion(machine)).is_err());
        assert!(service.catalog.snapshot(&request.id).unwrap().is_none());
        assert!(
            service
                .catalog
                .operation(&request.operation_id)
                .unwrap()
                .is_none()
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
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
            provision: None,
        };
        let completion = task.execute();
        assert!(
            matches!(&completion, HostTaskCompletion::Snapshot { result: Err(HostError::Snapshot(crate::snapshots::SnapshotError::Io(error))), .. } if error.kind() == io::ErrorKind::WouldBlock),
            "custody must be acquired before recovery can send FinishDisk to the native owner"
        );
        assert!(service.complete_task(completion).is_err());
        let HostDispatch::Task(recovery) = service.prepare_snapshot_recovery(capturing).unwrap()
        else {
            panic!("capture recovery must use the canonical capture task");
        };
        let recovery = recovery.execute();
        assert!(
            matches!(recovery, HostTaskCompletion::Snapshot {
                result: Err(HostError::Snapshot(crate::snapshots::SnapshotError::Io(error))), ..
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
    fn guardian_provisioning_is_a_detached_materialization_plan_and_reopens_from_authority() {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("ssprovision-{:x}", u64::from_le_bytes(nonce)));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "computer", MachineLifetime::default());
        let machine_root = service.machine_root(&machine);
        let provision = service.prepare_guardian_inner(&machine).unwrap();
        assert!(
            !machine_root.exists(),
            "preparation performed filesystem effects on the catalog owner"
        );
        let inputs = provision.initialization.as_ref().unwrap();
        let record = service.catalog.machine(&machine).unwrap().unwrap();
        assert_eq!(inputs.record.id, machine);
        assert_eq!(inputs.record.image_digest, record.image_digest);
        assert_eq!(&inputs.binding, service.catalog.authority_binding());
        let operation = record.latest_intent.operation_id;
        drop(provision);
        drop(service); // admitted identity survives a host restart before any effects
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        let intent = service.catalog.intent(&operation).unwrap().unwrap();
        let HostDispatch::Task(task) = service.prepare_lifecycle_intent(intent).unwrap() else {
            panic!("recovery must enqueue admitted initialization, not run it inline");
        };
        assert!(
            matches!(&*task, HostTask::LifecycleInspect { provision, .. }
            if provision.initialization.is_some())
        );
        assert!(!machine_root.exists());
        let completion = task.execute();
        // The fixture has no image/native storage. Its refusal belongs to the
        // worker and cannot fabricate native completion or remove admission.
        assert!(service.complete_task(completion).is_err());
        assert!(
            service
                .catalog
                .intent(&operation)
                .unwrap()
                .unwrap()
                .completion
                .is_none()
        );
        assert!(matches!(
            service.handle(HostRequest::ListImages {
                after: None,
                maximum: Counter::ONE
            }),
            HostResponse::Images { .. }
        ));
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
    fn image_candidate_ownership_recovers_each_handoff_without_rebuilding_or_retaining_duplicates()
    {
        let fixture = crate::images::native_import_tests::Fixture::new();
        let mut service = intent_service(&fixture.root);
        let operation: OperationId = "candidate-handoff".try_into().unwrap();
        let input = sandsurf_state::ImageImportInput::Native {
            manifest_path: fixture.manifest.clone(),
            manifest_digest: fixture.digest.clone(),
        };
        let request = input.request_digest(&operation).unwrap();
        service
            .catalog
            .admit_image_import(
                operation.clone(),
                input,
                Approval {
                    id: "approve-candidate-handoff".try_into().unwrap(),
                    request_digest: request.clone(),
                },
            )
            .unwrap();
        let image = crate::images::import_native(
            &fixture.root,
            &fixture.manifest,
            &fixture.digest,
            &operation,
            &request,
        )
        .unwrap();
        let shared = fixture.root.join("images").join(image.digest.as_str());
        let stage = fixture
            .root
            .join("images/imports")
            .join(object_name(operation.as_str()));
        assert!(!shared.exists());
        fs::remove_dir_all(fixture.manifest.parent().unwrap()).unwrap();
        let dispatch = service
            .complete_task(HostTaskCompletion::Image {
                operation: operation.clone(),
                request_digest: request.clone(),
                result: Ok(image.clone()),
            })
            .unwrap();
        assert!(matches!(dispatch, HostDispatch::Task(_)));
        assert!(service.catalog.image(&image.digest).unwrap().is_none());
        drop(dispatch);
        drop(service);
        let service =
            HostService::open(&fixture.root, fixture.root.join("absent-executable")).unwrap();
        let prepared = service.catalog.image_import(&operation).unwrap().unwrap();
        assert_eq!(prepared.phase, sandsurf_state::ImageImportPhase::Prepared);
        let HostDispatch::Task(task) = service
            .prepare_image_materialization(prepared.clone())
            .unwrap()
        else {
            panic!("prepared publication was not detached");
        };
        let completion = task.execute();
        assert!(shared.exists());
        assert!(service.catalog.image(&image.digest).unwrap().is_none());
        assert!(
            crate::images::cleanup(&fixture.root, &image.digest).is_err(),
            "original publication custody must exclude retirement"
        );
        drop(completion); // publication happened, but no catalog commit
        drop(service);
        let mut service =
            HostService::open(&fixture.root, fixture.root.join("absent-executable")).unwrap();
        let prepared = service.catalog.image_import(&operation).unwrap().unwrap();
        let HostDispatch::Task(task) = service
            .prepare_image_materialization(prepared.clone())
            .unwrap()
        else {
            panic!("interrupted publication was not recovered");
        };
        let cleanup = service.complete_task(task.execute()).unwrap();
        assert_eq!(
            service.catalog.image(&image.digest).unwrap(),
            Some(image.clone())
        );
        assert_eq!(
            service
                .catalog
                .pending_image_candidate_cleanup(None, counter(1))
                .unwrap()
                .len(),
            1
        );
        assert!(stage.join("candidate").exists());
        drop(cleanup); // ownership committed, reclamation interrupted
        drop(service);
        let mut service =
            HostService::open(&fixture.root, fixture.root.join("absent-executable")).unwrap();
        assert!(matches!(
            service
                .prepare_image_lookup(operation.clone(), ImageLookupReply::ImageImport)
                .unwrap(),
            HostDispatch::Ready(_)
        ));
        let reader = sandsurf_native::storage::read_lease(
            &fixture
                .root
                .join("images/imports")
                .join(format!(".owner-{}", object_name(operation.as_str()))),
        )
        .unwrap();
        let HostDispatch::Ready(_) = service
            .complete_task(
                HostTask::ImageCandidateCleanup {
                    root: fixture.root.clone(),
                    record: service.catalog.image_import(&operation).unwrap().unwrap(),
                    reply: Some(ImageLookupReply::ImageImport),
                }
                .execute(),
            )
            .unwrap()
        else {
            panic!("a busy reader cannot undo publication");
        };
        assert!(stage.join("candidate").exists());
        assert_eq!(
            service
                .catalog
                .pending_image_candidate_cleanup(None, counter(1))
                .unwrap()
                .len(),
            1
        );
        drop(reader);
        // A partial byte cleanup must resume from committed ownership, not
        // demand a second verification of the already-transferred originals.
        fs::remove_file(
            stage
                .join("candidate")
                .join(image.digest.as_str())
                .join("system.ext4"),
        )
        .unwrap();
        let mut work = Vec::new();
        service
            .reconcile_candidate_page(
                &mut ReconciliationCursor::default(),
                &BTreeSet::new(),
                1,
                &mut work,
            )
            .unwrap();
        let (_, HostDispatch::Task(task)) = work.pop().unwrap() else {
            panic!("candidate cleanup was not recovered");
        };
        assert!(matches!(
            service.complete_task(task.execute()).unwrap(),
            HostDispatch::Ready(_)
        ));
        assert!(!stage.join("candidate").exists());
        assert!(stage.join("result.json").exists());
        assert!(
            service
                .catalog
                .pending_image_candidate_cleanup(None, counter(1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fs::read(shared.join("system.ext4")).unwrap(),
            b"opaque-system-seed"
        );
        assert!(matches!(
            service
                .complete_task(HostTaskCompletion::ImageInspect {
                    record: prepared,
                    reply: ImageLookupReply::HostOperation,
                    result: Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "candidate reclaimed after inspection admission"
                    )
                    .into()),
                })
                .unwrap(),
            HostDispatch::Ready(_)
        ));
        // A late, exact worker response is an observation of the committed
        // publication, not authorization to recreate a reclaimed candidate.
        assert!(matches!(
            service
                .complete_task(HostTaskCompletion::Image {
                    operation,
                    request_digest: request,
                    result: Ok(image),
                })
                .unwrap(),
            HostDispatch::Ready(_)
        ));
        assert!(!stage.join("candidate").exists());
        drop(service);
    }

    #[test]
    fn image_recovery_has_bounded_rotating_visits_and_busy_work_cannot_starve_later_recipes() {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("ssimage-sweep-{:x}", u64::from_le_bytes(nonce)));
        let mut service = intent_service(&root);
        admit_machine(&mut service, "busy-machine", MachineLifetime::default());
        for label in ["a-build", "b-build", "c-build"] {
            let operation: OperationId = label.try_into().unwrap();
            let input = sandsurf_state::ImageImportInput::Native {
                manifest_path: root.join(format!("{label}.json")),
                manifest_digest: bytes_digest(label.as_bytes()),
            };
            let request_digest = input.request_digest(&operation).unwrap();
            service
                .catalog
                .admit_image_import(
                    operation,
                    input,
                    Approval {
                        id: format!("approve-{label}").try_into().unwrap(),
                        request_digest,
                    },
                )
                .unwrap();
        }
        let mut cursor = ReconciliationCursor::default();
        let busy = BTreeSet::from([ReconciliationIdentity::Image("a-build".try_into().unwrap())]);
        assert!(
            service
                .reconcile_lifetime_policies(&mut cursor, &busy, 0)
                .unwrap()
                .is_empty()
        );
        assert!(cursor.after_import.is_none());
        let mut visited = BTreeSet::new();
        for _ in 0..12 {
            let work = service
                .reconcile_lifetime_policies(&mut cursor, &busy, 1)
                .unwrap();
            assert!(work.len() <= 1);
            for (identity, _) in work {
                visited.insert(identity);
            }
        }
        assert!(visited.contains(&ReconciliationIdentity::Machine(
            "busy-machine".try_into().unwrap()
        )));
        assert!(visited.contains(&ReconciliationIdentity::Image(
            "b-build".try_into().unwrap()
        )));
        assert!(visited.contains(&ReconciliationIdentity::Image(
            "c-build".try_into().unwrap()
        )));
        assert!(!visited.contains(&ReconciliationIdentity::Image(
            "a-build".try_into().unwrap()
        )));
        assert!(!root.join("image-workers").exists());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn admitted_image_recipe_recovers_before_worker_publication_without_source_io_on_owner() {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("ssimage-admission-{:x}", u64::from_le_bytes(nonce)));
        let mut service = intent_service(&root);
        let operation: OperationId = "image".try_into().unwrap();
        let input = sandsurf_state::ImageImportInput::Native {
            manifest_path: root.join("missing-source.json"),
            manifest_digest: bytes_digest(b"image"),
        };
        let request = HostRequest::ImportNativeImage {
            manifest_path: root.join("missing-source.json"),
            manifest_digest: bytes_digest(b"image"),
            operation_id: operation.clone(),
            approval_id: "approved-image".try_into().unwrap(),
        };
        let HostDispatch::Task(task) = service.route(request) else {
            panic!("image admission must enqueue source work")
        };
        assert!(
            matches!(&*task, HostTask::Image { job, .. } if job.operation == operation
            && matches!(&job.build, crate::image_worker::Build::Image { input: admitted } if admitted == &input))
        );
        assert!(!root.join("image-workers").exists());
        drop(task);
        drop(service);
        let service = HostService::open(&root, root.join("absent-executable")).unwrap();
        let mut cursor = ReconciliationCursor::default();
        let mut work = Vec::new();
        service
            .reconcile_import_page(&mut cursor, &BTreeSet::new(), 1, &mut work)
            .unwrap();
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].0, ReconciliationIdentity::Image(operation.clone()));
        let HostDispatch::Task(task) = &work[0].1 else {
            panic!("recovery must dispatch the same materializer")
        };
        assert!(
            matches!(&**task, HostTask::Image { job, .. } if job.operation == operation
            && job.request_digest == input.request_digest(&operation).unwrap()
            && matches!(&job.build, crate::image_worker::Build::Image { input: retained } if retained == &input))
        );
        assert!(!root.join("image-workers").exists());
        assert_eq!(
            service
                .catalog
                .image_import(&operation)
                .unwrap()
                .unwrap()
                .phase,
            sandsurf_state::ImageImportPhase::Admitted
        );
        drop(work);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn image_lookup_reads_bytes_off_owner_and_absence_never_completes_admission() {
        let root = std::env::temp_dir().join(format!(
            "ssimage-query-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get(),
        ));
        let mut service = intent_service(&root);
        let operation: OperationId = "import".try_into().unwrap();
        let input = sandsurf_state::ImageImportInput::Native {
            manifest_path: root.join("source-manifest.json"),
            manifest_digest: bytes_digest(b"image input"),
        };
        let request_digest = input.request_digest(&operation).unwrap();
        let admitted = service
            .catalog
            .admit_image_import(
                operation.clone(),
                input,
                Approval {
                    id: "approve-import".try_into().unwrap(),
                    request_digest,
                },
            )
            .unwrap();
        for request in [
            HostRequest::GetHostOperation {
                operation_id: operation.clone(),
            },
            HostRequest::GetImageImport {
                operation_id: operation.clone(),
            },
        ] {
            let HostDispatch::Task(task) = service.route(request) else {
                panic!("verification cannot run while the catalog handles a lookup");
            };
            assert!(matches!(&*task, HostTask::ImageInspect { record, .. } if *record == admitted));
            let completion = task.execute();
            service.complete_task(completion).unwrap();
            assert_eq!(
                service.catalog.image_import(&operation).unwrap(),
                Some(admitted.clone())
            );
        }
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn image_cancellation_recovers_original_custody_and_never_adopts_late_results() {
        use std::io::Write;
        let root = std::env::temp_dir().join(format!(
            "ssimage-cancel-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let operation: OperationId = "interrupted-import".try_into().unwrap();
        let input = sandsurf_state::ImageImportInput::Native {
            manifest_path: root.join("external-manifest.json"),
            manifest_digest: bytes_digest(b"source"),
        };
        let request = input.request_digest(&operation).unwrap();
        service
            .catalog
            .admit_image_import(
                operation.clone(),
                input.clone(),
                Approval {
                    id: "approve-import".try_into().unwrap(),
                    request_digest: request.clone(),
                },
            )
            .unwrap();
        prepare_directory(&root.join("image-workers")).unwrap();
        let worker = root
            .join("image-workers")
            .join(object_name(operation.as_str()));
        prepare_directory(&worker).unwrap();
        crate::image_records::publish(
            &worker.join("job.json"),
            &crate::image_worker::Job {
                operation: operation.clone(),
                request_digest: request.clone(),
                build: crate::image_worker::Build::Image { input },
            },
        )
        .unwrap();
        let writer =
            Arc::new(sandsurf_native::storage::disk_lease(&worker.join(".owner")).unwrap());
        let surviving_native_owner = writer.clone();
        let stage = root
            .join("images/imports")
            .join(object_name(operation.as_str()));
        prepare_directory(&root.join("images/imports")).unwrap();
        prepare_directory(&stage).unwrap();
        crate::image_records::publish(
            &stage.join("request.json"),
            &serde_json::json!({ "requestDigest": request }),
        )
        .unwrap();
        let candidate = stage.join("candidate");
        prepare_directory(&candidate).unwrap();
        let mut disk =
            sandsurf_native::local::create_private_file(&candidate.join("private-disk")).unwrap();
        disk.write_all(b"interrupted bytes").unwrap();
        disk.sync_all().unwrap();
        drop(disk);
        let cancellation = HostRequest::CancelImageImport {
            operation_id: operation.clone(),
            expected_request: request.clone(),
        };
        assert!(
            matches!(service.handle(cancellation), HostResponse::ImageImport { operation: record }
            if record.phase == sandsurf_state::ImageImportPhase::Cancelling)
        );
        assert_eq!(
            fs::read(candidate.join("private-disk")).unwrap(),
            b"interrupted bytes"
        );
        assert!(worker.join("cancel.json").exists());
        drop(writer);
        assert!(
            matches!(service.handle(HostRequest::GetImageImport { operation_id: operation.clone() }),
            HostResponse::ImageImport { operation: record } if record.phase == sandsurf_state::ImageImportPhase::Cancelling)
        );
        assert!(
            candidate.exists(),
            "a controller exit cannot release a surviving original VMM's bytes"
        );
        drop(surviving_native_owner);
        let HostDispatch::Task(task) = service.route(HostRequest::GetImageImport {
            operation_id: operation.clone(),
        }) else {
            panic!("cleanup was not detached");
        };
        let completion = task.execute();
        assert!(matches!(
            &completion,
            HostTaskCompletion::ImageCancel { result: Ok(_), .. }
        ));
        assert!(!candidate.exists());
        assert!(
            sandsurf_native::storage::disk_lease(&worker.join(".owner")).is_err(),
            "cleanup custody must survive until catalog completion"
        );
        drop(completion); // Interrupted after physical cleanup, before catalog commit.
        drop(service);
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        let mut work = Vec::new();
        service
            .reconcile_import_page(
                &mut ReconciliationCursor::default(),
                &BTreeSet::new(),
                1,
                &mut work,
            )
            .unwrap();
        let (_, HostDispatch::Task(task)) = work.pop().unwrap() else {
            panic!("cancel recovery was not detached");
        };
        assert!(matches!(&*task, HostTask::ImageCancel { .. }));
        assert!(
            matches!(service.complete_task(task.execute()).unwrap().finish(), HostResponse::ImageImport { operation: record }
            if record.phase == sandsurf_state::ImageImportPhase::Cancelled)
        );
        let late = HostTaskCompletion::Image {
            operation: operation.clone(),
            request_digest: request.clone(),
            result: Err(HostError::Invalid("late worker failure")),
        };
        assert!(
            matches!(service.complete_task(late).unwrap().finish(), HostResponse::ImageImport { operation: record }
            if record.phase == sandsurf_state::ImageImportPhase::Cancelled)
        );
        assert!(matches!(
            service.route(HostRequest::GetHostOperation {
                operation_id: operation.clone()
            }),
            HostDispatch::Ready(_)
        ));
        assert!(
            service
                .catalog
                .pending_image_imports(None, counter(1))
                .unwrap()
                .is_empty()
        );
        assert!(
            worker.join("job.json").exists() && worker.join("cancel.json").exists(),
            "immutable replay fences are not discarded with private bytes"
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn image_retirement_reopens_without_deleting_and_recovers_through_catalog_completion() {
        let root = std::env::temp_dir().join(format!(
            "ssimage-cleanup-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get(),
        ));
        let mut service = intent_service(&root);
        let image = bytes_digest(b"retired image");
        let import: OperationId = "import".try_into().unwrap();
        let input = sandsurf_state::ImageImportInput::Native {
            manifest_path: root.join("source-manifest.json"),
            manifest_digest: image.clone(),
        };
        let request_digest = input.request_digest(&import).unwrap();
        service
            .catalog
            .admit_image_import(
                import.clone(),
                input,
                Approval {
                    id: "approve-import".try_into().unwrap(),
                    request_digest: request_digest.clone(),
                },
            )
            .unwrap();
        let candidate = sandsurf_state::ImageRecord {
            digest: image.clone(),
            source_digest: image.clone(),
            platform: "linux".into(),
            architecture: "amd64".into(),
            logical_bytes: Counter::ONE,
            storage_bytes: Counter::ONE,
            provenance_digest: image.clone(),
            sensitive: false,
        };
        service
            .catalog
            .prepare_image_import(&import, &request_digest, candidate.clone())
            .unwrap();
        service
            .catalog
            .complete_image_import(&import, &request_digest, candidate)
            .unwrap();
        let bytes = root.join("images").join(image.as_str());
        prepare_directory(&bytes).unwrap();
        fs::write(
            bytes.join("owned-payload"),
            b"retain until admitted deletion",
        )
        .unwrap();
        let operation: OperationId = "release".try_into().unwrap();
        let HostDispatch::Task(task) = service.route(HostRequest::ReleaseImage {
            digest: image.clone(),
            operation_id: operation.clone(),
            approval_id: "approve-release".try_into().unwrap(),
        }) else {
            panic!("image deletion must not run on the catalog writer");
        };
        assert!(bytes.exists());
        assert_eq!(
            service
                .catalog
                .pending_image_releases(None, counter(1))
                .unwrap()
                .len(),
            1
        );
        drop(task); // client/host dies after durable admission, before deletion
        drop(service);
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        assert!(
            bytes.exists(),
            "host startup ran cleanup before serving requests"
        );
        let mut cursor = ReconciliationCursor::default();
        let work = service
            .reconcile_lifetime_policies(&mut cursor, &BTreeSet::new(), 1)
            .unwrap();
        assert_eq!(work.len(), 1);
        let (identity, HostDispatch::Task(task)) = work.into_iter().next().unwrap() else {
            panic!("recovery must run the same admitted image cleanup task");
        };
        assert_eq!(identity, ReconciliationIdentity::Image(operation.clone()));
        let completion = task.execute();
        assert!(!bytes.exists());
        assert_eq!(
            service
                .catalog
                .pending_image_releases(None, counter(1))
                .unwrap()
                .len(),
            1,
            "storage effects are not catalog completion"
        );
        assert!(matches!(
            service.complete_task(completion).unwrap(),
            HostDispatch::Ready(_)
        ));
        assert!(
            service
                .catalog
                .pending_image_releases(None, counter(1))
                .unwrap()
                .is_empty()
        );
        assert!(
            matches!(service.handle(HostRequest::GetHostOperation { operation_id: operation }),
            HostResponse::HostOperation { value: Some(sandsurf_state::HostOperationRecord::ImageRelease(record)) }
                if !record.cleanup_pending && record.image_digest == image)
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_reconciliation_visits_later_machines_and_does_not_advance_without_capacity() {
        let root = std::env::temp_dir().join(format!(
            "ssfair-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get(),
        ));
        prepare_directory(&root).unwrap();
        HostCatalog::create(
            &root.join("catalog"),
            "fair-fixture".try_into().unwrap(),
            CatalogLimits {
                identities: counter(40),
                operations: counter(128),
                usage_records: counter(128),
                image_bytes: counter(64 * 1024 * 1024),
                cpu_quota_micros: counter(4_000_000),
                host_memory_bytes: counter(40 * 1024 * 1024 * 1024),
            },
        )
        .unwrap();
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        for index in 0..33 {
            admit_machine(
                &mut service,
                &format!("box-{index:02}"),
                MachineLifetime {
                    expires_at_unix_millis: (index == 32).then_some(Counter::ONE),
                    expiration_action: ExpirationAction::Stop,
                },
            );
        }
        let mut cursor = ReconciliationCursor::default();
        let busy = BTreeSet::new();
        let first = service
            .reconcile_lifetime_policies(&mut cursor, &busy, 32)
            .unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(cursor.after_machine.as_ref().unwrap().as_str(), "box-31");
        let expired: MachineId = "box-32".try_into().unwrap();
        assert_eq!(
            service
                .catalog
                .machine(&expired)
                .unwrap()
                .unwrap()
                .latest_intent
                .desired,
            DesiredState::Running
        );
        let before = cursor.after_machine.clone();
        assert!(
            service
                .reconcile_lifetime_policies(&mut cursor, &busy, 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            cursor.after_machine, before,
            "capacity loss skipped unvisited authority"
        );
        let busy = first.into_iter().map(|(id, _)| id).collect();
        let second = service
            .reconcile_lifetime_policies(&mut cursor, &busy, 1)
            .unwrap();
        // This authority-only fixture intentionally has no operator volume:
        // native task preparation may refuse, but the later expiration must
        // still be visited and durably admitted rather than starved.
        assert!(second.len() <= 1);
        if let Some((identity, _)) = second.first() {
            assert_eq!(identity, &ReconciliationIdentity::Machine(expired.clone()));
        }
        let record = service.catalog.machine(&expired).unwrap().unwrap();
        assert_eq!(record.latest_intent.desired, DesiredState::Stopped);
        assert!(record.latest_intent.completion.is_none());
        assert_eq!(record.reservation, ReservationState::Held);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_retirement_recovers_after_disconnect_and_busy_readers_never_complete_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "sssnapret-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        let request = SnapshotRequest {
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
                    id: "approve-snapshot".try_into().unwrap(),
                    request_digest: request_digest.clone(),
                },
            )
            .unwrap();
        service
            .catalog
            .begin_snapshot(&request.id, &request_digest)
            .unwrap();
        let snapshot = service
            .catalog
            .complete_snapshot(
                &request.id,
                &request_digest,
                bytes_digest(b"disk"),
                bytes_digest(b"manifest"),
                SnapshotConsistency::Crash,
            )
            .unwrap();
        prepare_directory(&root.join("machines")).unwrap();
        prepare_directory(&root.join("machines").join(object_name(machine.as_str()))).unwrap();
        let snapshots = crate::snapshots::root(&root, &snapshot);
        prepare_directory(&snapshots).unwrap();
        let payload = snapshots.join(object_name(request.id.as_str()));
        prepare_directory(&payload).unwrap();
        std::io::Write::write_all(
            &mut sandsurf_native::local::create_private_file(&payload.join("system.ext4")).unwrap(),
            b"disk",
        )
        .unwrap();
        let original = crate::snapshots::retain_input(&snapshots, &request.id).unwrap();
        let operation: OperationId = "release-snapshot".try_into().unwrap();
        let HostDispatch::Task(task) = service.route(HostRequest::ReleaseSnapshot {
            snapshot_id: request.id.clone(),
            operation_id: operation.clone(),
            approval_id: "approve-release".try_into().unwrap(),
        }) else {
            panic!("snapshot deletion ran on catalog owner");
        };
        assert!(payload.exists());
        let HostDispatch::Ready(response) = service.complete_task(task.execute()).unwrap() else {
            panic!("busy retirement must return its durable operation");
        };
        assert!(
            matches!(*response, HostResponse::SnapshotRelease { operation: record } if record.cleanup_pending)
        );
        assert!(payload.exists());
        drop(service); // committed retirement, no filesystem mutation
        let mut service = HostService::open(&root, root.join("absent-executable")).unwrap();
        assert!(payload.exists());
        assert_eq!(
            service
                .catalog
                .snapshot(&request.id)
                .unwrap()
                .unwrap()
                .phase,
            SnapshotPhase::Retiring
        );
        drop(original);
        let mut cursor = ReconciliationCursor {
            next_domain: 4,
            ..Default::default()
        };
        let work = service
            .reconcile_lifetime_policies(&mut cursor, &BTreeSet::new(), 1)
            .unwrap();
        let (identity, HostDispatch::Task(task)) = work.into_iter().next().unwrap() else {
            panic!("retirement must recover through its original task");
        };
        assert_eq!(
            identity,
            ReconciliationIdentity::SnapshotRelease(operation.clone())
        );
        let completion = task.execute();
        assert!(
            matches!(
                &completion,
                HostTaskCompletion::SnapshotCleanup { result: Ok(()), .. }
            ),
            "recovered snapshot retirement must finish physical cleanup"
        );
        assert!(!payload.exists());
        assert_eq!(
            service
                .catalog
                .snapshot(&request.id)
                .unwrap()
                .unwrap()
                .phase,
            SnapshotPhase::Retiring,
            "file deletion cannot commit catalog authority"
        );
        service.complete_task(completion).unwrap();
        assert_eq!(
            service
                .catalog
                .snapshot(&request.id)
                .unwrap()
                .unwrap()
                .phase,
            SnapshotPhase::Released
        );
        assert!(
            service
                .catalog
                .pending_snapshot_releases(None, Counter::ONE)
                .unwrap()
                .is_empty()
        );
        assert!(
            matches!(service.handle(HostRequest::GetHostOperation { operation_id: operation }), HostResponse::HostOperation { value: Some(sandsurf_state::HostOperationRecord::SnapshotRelease(record)) } if !record.cleanup_pending)
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn single_slot_reconciliation_alternates_snapshot_completion_and_machine_policy() {
        let root = std::env::temp_dir().join(format!(
            "ssdomains-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get(),
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        let request = SnapshotRequest {
            id: "snapshot".try_into().unwrap(),
            operation_id: "capture".try_into().unwrap(),
            machine_id: machine,
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
        service
            .catalog
            .begin_snapshot(&request.id, &request_digest)
            .unwrap();
        let mut cursor = ReconciliationCursor::default();
        let busy = BTreeSet::new();
        let first = service
            .reconcile_lifetime_policies(&mut cursor, &busy, 1)
            .unwrap();
        assert_eq!(first.len(), 1);
        assert!(matches!(&first[0].1, HostDispatch::Task(task) if matches!(
            &**task, HostTask::Snapshot { capturing, .. } if capturing.request == request
        )));
        let second = service
            .reconcile_lifetime_policies(&mut cursor, &busy, 1)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert!(matches!(&second[0].1, HostDispatch::Task(task) if matches!(
            &**task, HostTask::LifecycleInspect { .. }
        )));
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_destruction_keeps_disk_retirement_detached_and_reservation_until_completion() {
        let root = std::env::temp_dir().join(format!(
            "ssretire-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get(),
        ));
        let mut service = intent_service(&root);
        let machine = admit_machine(&mut service, "box", MachineLifetime::default());
        assert!(service.prepare_storage_retirement(&machine, None).is_err());
        let operation: OperationId = "destroy".try_into().unwrap();
        let request_digest = digest(
            Domain::Operation,
            &(&machine, &operation, Counter::ONE, DesiredState::Destroyed),
        )
        .unwrap();
        service
            .catalog
            .request_lifecycle(
                &machine,
                operation.clone(),
                Counter::ONE,
                DesiredState::Destroyed,
                Approval {
                    id: "approve-destroy".try_into().unwrap(),
                    request_digest,
                },
            )
            .unwrap();
        let record = service.catalog.machine(&machine).unwrap().unwrap();
        let mut runtime = sandsurf_state::RuntimeJournal::create(
            &root.join("observed"),
            machine.clone(),
            runtime_limits(&record.runtime_configuration.resources),
            service.catalog.authority_binding().clone(),
        )
        .unwrap();
        let mut observed = MachineObservation {
            machine_id: machine.clone(),
            generation: Counter::ONE,
            sequence: Counter::ONE,
            state: MachineState::Creating,
            applied_revision: Counter::ONE,
            cause: ObservationCause::Lifecycle {
                operation_id: "create-box".try_into().unwrap(),
            },
            evidence_digest: bytes_digest(b"native-created"),
        };
        runtime.observe(observed.clone()).unwrap();
        observed.sequence = counter(2);
        observed.state = MachineState::Destroying;
        observed.applied_revision = counter(2);
        observed.cause = ObservationCause::Lifecycle {
            operation_id: operation.clone(),
        };
        runtime.observe(observed.clone()).unwrap();
        observed.sequence = counter(3);
        observed.state = MachineState::Destroyed;
        let evidence = runtime.observe(observed).unwrap();
        service.catalog.complete_intent(&evidence).unwrap();
        let disk = service
            .machine_root(&machine)
            .join("disks")
            .join(system_disk_name());
        prepare_directory(&root.join("machines")).unwrap();
        prepare_directory(&service.machine_root(&machine)).unwrap();
        prepare_directory(disk.parent().unwrap()).unwrap();
        let HostDispatch::Task(task) = service.prepare_storage_retirement(&machine, None).unwrap()
        else {
            panic!("disk deletion must not run on the catalog writer");
        };
        assert!(!disk.with_extension("storage.json").exists());
        assert_eq!(
            service
                .catalog
                .machine(&machine)
                .unwrap()
                .unwrap()
                .reservation,
            ReservationState::Held
        );
        let completion = task.execute();
        assert_eq!(
            service
                .catalog
                .machine(&machine)
                .unwrap()
                .unwrap()
                .reservation,
            ReservationState::Held,
            "a deletion worker cannot release host authority"
        );
        assert!(matches!(
            service.complete_task(completion).unwrap(),
            HostDispatch::Ready(_)
        ));
        assert_eq!(
            service
                .catalog
                .machine(&machine)
                .unwrap()
                .unwrap()
                .reservation,
            ReservationState::Released
        );
        assert!(
            service
                .catalog
                .active_machines(None, counter(32))
                .unwrap()
                .is_empty()
        );
        assert!(service.catalog.machine(&machine).unwrap().is_some());
        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn byte_limited_recovery_pages_do_not_reset_before_later_machine_identities() {
        let root = std::env::temp_dir().join(format!(
            "ssbyte-sweep-{}-{}",
            std::process::id(),
            unix_millis().unwrap().get()
        ));
        let mut service = intent_service(&root);
        let mut identities = Vec::new();
        for name in ["a-large", "b-large", "c-large"] {
            identities.push(admit_machine_with_defaults(
                &mut service,
                name,
                MachineLifetime::default(),
                ExecutionDefaults {
                    environment: (0..3)
                        .map(|index| (format!("LARGE_{index}"), "x".repeat(64 * 1024)))
                        .collect(),
                    ..ExecutionDefaults::default()
                },
            ));
        }
        let busy = identities
            .iter()
            .cloned()
            .map(ReconciliationIdentity::Machine)
            .collect();
        let mut cursor = ReconciliationCursor::default();
        let mut work = Vec::new();
        for identity in &identities {
            service
                .reconcile_machine_page(&mut cursor, &busy, 8, Counter::ONE, &mut work)
                .unwrap();
            assert_eq!(cursor.after_machine.as_ref(), Some(identity));
            assert!(work.is_empty());
        }
        service
            .reconcile_machine_page(&mut cursor, &busy, 8, Counter::ONE, &mut work)
            .unwrap();
        assert!(cursor.after_machine.is_none());
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
        service
            .reconcile_lifetime_policies(&mut ReconciliationCursor::default(), &BTreeSet::new(), 32)
            .unwrap();
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
            observe_machine(&service.root, expired).unwrap().machine,
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
