use sandsurf_protocol::{
    CommitmentId, Counter, Digest, ExecutionDefaults, ExecutionId, GuestServiceRequest,
    GuestServiceResponse, LifecycleIntent, LifecycleOperation, MachineId, MachineLifetime,
    MachineObservation, Observation, Operation, OperationId, OutputSegmentId, Qualification,
    ReleaseRequest, Resources, RollbackRecord, RuntimeResponse, Snapshot, SnapshotId,
    SnapshotRequest, VmEngine,
};
use sandsurf_state::{
    HostOperationRecord, ImageImportRecord, ImageRecord, ImageReleaseRecord, SecretRevocationRecord,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const HOST_API_VERSION: u16 = 11;

impl sandsurf_protocol::RpcRequest for HostRequest {
    fn binary_field(&mut self) -> Option<(&mut Vec<u8>, usize)> {
        match self {
            Self::PutSecret { bytes, .. } => Some((bytes, sandsurf_protocol::MAX_RPC_DATA_BYTES)),
            Self::DispatchGuest { request, .. } => request.binary_field(),
            Self::Guest { request, .. } => request.binary_field(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostInspection {
    pub host_id: String,
    pub platform: String,
    pub architecture: String,
    pub guest_architecture: String,
    pub engine: VmEngine,
    pub lifecycle: Qualification,
    pub full_state: Qualification,
    pub images: Qualification,
    pub guest_power: sandsurf_protocol::GuestPowerCapabilities,
    pub guest_platform: String,
    /// Verified defaults image packaged for this host architecture. Source
    /// builds without packaged artifacts report `None` explicitly.
    pub default_image_digest: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OciSource {
    Layout {
        path: PathBuf,
    },
    Archive {
        path: PathBuf,
    },
    Registry {
        reference: String,
        credential: Option<sandsurf_protocol::SecretVersion>,
    },
}

/// OCI supplies an operating-system filesystem. Boot artifacts are an
/// explicit, independently verified recipe input rather than implicit state
/// inherited from whichever development image happens to ship with the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineImageRecipe {
    pub boot_image_digest: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservationView {
    Held,
    Released,
}

/// Observation of host-owned storage, not integrity of the root-controlled OS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StorageInspection {
    Current {
        phase: StoragePhase,
        format: StorageFormat,
        capacity_bytes: u64,
        operation_id: Option<OperationId>,
        payload: StoragePayload,
    },
    Unavailable {
        reason: StorageUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoragePhase {
    Preparing,
    Published,
    Attached,
    Replacing,
    Retiring,
    Retired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageFormat {
    Raw,
    Vhdx,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageUnavailableReason {
    OwnershipMissing,
    OwnershipInvalid,
    AccessUnavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StoragePayload {
    Present { file_bytes: u64 },
    CapacityMismatch { file_bytes: u64 },
    Missing,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineView {
    pub id: MachineId,
    pub image_digest: Digest,
    pub resources: Resources,
    pub runtime_configuration: sandsurf_protocol::RuntimeConfiguration,
    pub configuration_revision: Counter,
    pub reservation: ReservationView,
    pub known_sensitive: bool,
    pub lifecycle_intent: LifecycleIntent,
    pub machine: Observation<MachineObservation>,
    pub management: Observation<sandsurf_protocol::GuestManagementReport>,
    pub storage: StorageInspection,
    pub execution_defaults: ExecutionDefaults,
    pub lifetime: MachineLifetime,
    pub last_activity_unix_millis: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostTreeEntryKind {
    Directory,
    File,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTreeEntry {
    pub path: String,
    pub kind: HostTreeEntryKind,
    pub mode: u32,
    pub size: Counter,
    pub digest: Option<Digest>,
    pub target: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTreeCapture {
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub request_digest: Digest,
    pub manifest_digest: Digest,
    pub entries: Counter,
    pub bytes: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostTreeChange {
    Upsert { entry: HostTreeEntry },
    Delete { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostChangeSet {
    pub base_manifest_digest: Digest,
    pub base: Vec<HostTreeEntry>,
    pub changes: Vec<HostTreeChange>,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostApplyReport {
    pub operation_id: OperationId,
    pub change_set_digest: Digest,
    pub applied: Counter,
    pub recovered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostRequest {
    Inspect,
    StopService,
    ListMachines {
        after: Option<MachineId>,
        maximum: Counter,
    },
    GetMachine {
        machine_id: MachineId,
    },
    OpenEventStream {
        machine_id: MachineId,
    },
    GetHostOperation {
        operation_id: OperationId,
    },
    ListImages {
        after: Option<Digest>,
        maximum: Counter,
    },
    GetImage {
        digest: Digest,
    },
    GetImageImport {
        operation_id: OperationId,
    },
    ReleaseImage {
        digest: Digest,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    ListSnapshots {
        after: Option<SnapshotId>,
        maximum: Counter,
    },
    GetSnapshot {
        snapshot_id: SnapshotId,
    },
    CreateSnapshot {
        request: SnapshotRequest,
        approval_id: CommitmentId,
    },
    ImportOci {
        source: OciSource,
        recipe: MachineImageRecipe,
        platform: String,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    ImportNativeImage {
        manifest_path: PathBuf,
        manifest_digest: Digest,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    PublishSnapshotImage {
        snapshot_id: SnapshotId,
        allow_sensitive: bool,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    CaptureHostTree {
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        source: PathBuf,
        exclusions: Vec<String>,
        maximum_bytes: Counter,
        approval_id: CommitmentId,
    },
    CaptureGuestTree {
        machine_id: MachineId,
        source: sandsurf_protocol::GuestPath,
        operation_id: OperationId,
        expected_generation: Counter,
        expected_revision: Counter,
        maximum_bytes: Counter,
    },
    ListHostTree {
        machine_id: MachineId,
        operation_id: OperationId,
        after: Counter,
        maximum: Counter,
    },
    ReadHostTreeBlob {
        machine_id: MachineId,
        operation_id: OperationId,
        digest: Digest,
        offset: Counter,
        maximum: u32,
    },
    ApplyArtifactToHost {
        machine_id: MachineId,
        artifact_id: OperationId,
        operation_id: OperationId,
        destination: PathBuf,
        change_set: HostChangeSet,
        approval_id: CommitmentId,
    },
    CreateMachine {
        machine_id: MachineId,
        image_digest: Digest,
        resources: Resources,
        execution_defaults: ExecutionDefaults,
        lifetime: MachineLifetime,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    ForkMachine {
        machine_id: MachineId,
        snapshot_id: SnapshotId,
        resources: Resources,
        lifetime: MachineLifetime,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    RollbackFilesystem {
        machine_id: MachineId,
        snapshot_id: SnapshotId,
        operation_id: OperationId,
        expected_revision: Counter,
        approval_id: CommitmentId,
    },
    Lifecycle {
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        desired: sandsurf_protocol::DesiredState,
        approval_id: CommitmentId,
    },
    SetNetworkPolicy {
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        policy: sandsurf_protocol::NetworkPolicy,
        approval_id: CommitmentId,
    },
    SetExposure {
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        exposure_id: sandsurf_protocol::ExposureId,
        spec: sandsurf_protocol::ExposureSpec,
        active: bool,
        approval_id: CommitmentId,
    },
    PutSecret {
        secret_id: sandsurf_protocol::SecretId,
        version: sandsurf_protocol::SecretVersionId,
        bytes: Vec<u8>,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    DeliverSecret {
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        delivery: sandsurf_protocol::SecretDelivery,
        approval_id: CommitmentId,
    },
    RevokeSecret {
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        secret: sandsurf_protocol::SecretVersion,
        terminate_recipients: bool,
        approval_id: CommitmentId,
    },
    UpdateResources {
        machine_id: MachineId,
        operation_id: OperationId,
        expected_revision: Counter,
        resources: Resources,
        approval_id: CommitmentId,
    },
    GetUsage {
        machine_id: MachineId,
    },
    DispatchGuest {
        machine_id: MachineId,
        generation: Counter,
        operation_id: OperationId,
        request: sandsurf_protocol::GuestRequest,
    },
    Guest {
        machine_id: MachineId,
        generation: Counter,
        request: GuestServiceRequest,
    },
    GetProcess {
        machine_id: MachineId,
        execution_id: ExecutionId,
    },
    ListProcesses {
        machine_id: MachineId,
    },
    ListEvents {
        machine_id: MachineId,
        after: Counter,
        maximum: u16,
    },
    GetOperation {
        machine_id: MachineId,
        operation_id: OperationId,
    },
    GetReceipt {
        machine_id: MachineId,
        execution_id: ExecutionId,
    },
    ReadEvidence {
        machine_id: MachineId,
        execution_id: ExecutionId,
        after: Counter,
        maximum: u32,
    },
    GetOutputSegment {
        machine_id: MachineId,
        segment_id: OutputSegmentId,
    },
    ReadOutputSegment {
        machine_id: MachineId,
        segment_id: OutputSegmentId,
        after: Counter,
        maximum: u32,
    },
    AcknowledgeReceipt {
        machine_id: MachineId,
        operation_id: OperationId,
        execution_id: ExecutionId,
        receipt_digest: Digest,
    },
    SealOutput {
        machine_id: MachineId,
        operation_id: OperationId,
        execution_id: ExecutionId,
        generation: Counter,
        expected: Option<sandsurf_protocol::OutputBoundary>,
        segment_id: OutputSegmentId,
    },
    ReleaseEvidence {
        machine_id: MachineId,
        execution_id: ExecutionId,
        request: ReleaseRequest,
        loss_approval_id: Option<CommitmentId>,
    },
    CleanupReleasedEvidence {
        machine_id: MachineId,
        execution_id: ExecutionId,
        request_digest: Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostResponse {
    Complete,
    /// Private, authenticated observer endpoint. This conveys no lifecycle or
    /// configuration authority and is never a cached machine observation.
    EventStream {
        endpoint: PathBuf,
    },
    Inspection {
        value: HostInspection,
    },
    Machines {
        values: Vec<MachineView>,
    },
    Machine {
        value: MachineView,
    },
    HostOperation {
        value: Option<HostOperationRecord>,
    },
    Images {
        values: Vec<ImageRecord>,
    },
    Image {
        value: ImageRecord,
    },
    ImageImport {
        operation: ImageImportRecord,
    },
    ImageRelease {
        operation: ImageReleaseRecord,
    },
    Snapshots {
        values: Vec<Snapshot>,
    },
    Snapshot {
        value: Snapshot,
    },
    Rollback {
        value: RollbackRecord,
    },
    HostTreeCapture {
        capture: HostTreeCapture,
    },
    HostTreeEntries {
        capture: HostTreeCapture,
        entries: Vec<HostTreeEntry>,
        next: Option<Counter>,
    },
    HostBlob {
        offset: Counter,
        bytes: Vec<u8>,
        eof: bool,
        digest: Digest,
    },
    HostBlobMetadata {
        offset: Counter,
        eof: bool,
        digest: Digest,
        chunks: Vec<sandsurf_protocol::BinaryChunk>,
    },
    HostApply {
        report: HostApplyReport,
    },
    Lifecycle {
        operation: LifecycleOperation,
        machine: MachineView,
    },
    Configuration {
        revision: Counter,
        machine: MachineView,
    },
    Exposure {
        exposure: sandsurf_protocol::Exposure,
        machine: MachineView,
    },
    Secret {
        secret: sandsurf_protocol::SecretVersion,
    },
    SecretDelivery {
        delivery: sandsurf_state::SecretDeliveryRecord,
    },
    SecretRevocation {
        revocation: SecretRevocationRecord,
    },
    Usage {
        usage: sandsurf_protocol::ResourceUsage,
    },
    Dispatch {
        operation: Operation,
    },
    Guest {
        response: GuestServiceResponse,
    },
    Runtime {
        response: RuntimeResponse,
    },
    Rejected {
        category: String,
        message: String,
    },
}

impl HostResponse {
    pub fn into_wire_parts(
        self,
    ) -> Result<sandsurf_protocol::WireParts<Self>, sandsurf_protocol::Invalid> {
        match self {
            Self::Runtime { response } => {
                let (response, bytes) = response.into_wire_parts()?;
                Ok((Self::Runtime { response }, bytes))
            }
            Self::Guest { response } => {
                let (response, bytes) = response.into_wire_parts()?;
                Ok((Self::Guest { response }, bytes))
            }
            Self::HostBlob {
                offset,
                bytes,
                eof,
                digest,
            } => {
                let bytes = if bytes.is_empty() {
                    Vec::new()
                } else {
                    vec![bytes]
                };
                let chunks = sandsurf_protocol::describe_binary(&bytes)?;
                sandsurf_protocol::validate_binary(&chunks, sandsurf_protocol::MAX_STREAM_BYTES)?;
                Ok((
                    Self::HostBlobMetadata {
                        offset,
                        eof,
                        digest,
                        chunks,
                    },
                    Some(bytes),
                ))
            }
            Self::HostBlobMetadata { .. } => {
                Err(sandsurf_protocol::Invalid("cannot originate blob metadata"))
            }
            response => Ok((response, None)),
        }
    }

    pub fn binary_descriptor(
        &self,
    ) -> Result<Option<Vec<sandsurf_protocol::BinaryChunk>>, sandsurf_protocol::Invalid> {
        match self {
            Self::Runtime { response } => response.binary_descriptor(),
            Self::Guest { response } => response.binary_descriptor(),
            Self::HostBlobMetadata { chunks, .. } => {
                sandsurf_protocol::validate_binary(chunks, sandsurf_protocol::MAX_STREAM_BYTES)?;
                Ok(Some(chunks.clone()))
            }
            Self::HostBlob { .. } => Err(sandsurf_protocol::Invalid(
                "blob bytes must use data frames",
            )),
            _ => Ok(None),
        }
    }

    pub fn with_wire_bytes(self, bytes: Vec<Vec<u8>>) -> Result<Self, sandsurf_protocol::Invalid> {
        match self {
            Self::Runtime { response } => Ok(Self::Runtime {
                response: response.with_wire_bytes(bytes)?,
            }),
            Self::Guest { response } => Ok(Self::Guest {
                response: response.with_wire_bytes(bytes)?,
            }),
            Self::HostBlobMetadata {
                offset,
                eof,
                digest,
                chunks,
            } => {
                if sandsurf_protocol::describe_binary(&bytes)? != chunks {
                    return Err(sandsurf_protocol::Invalid(
                        "blob bytes differ from metadata",
                    ));
                }
                Ok(Self::HostBlob {
                    offset,
                    bytes: bytes.into_iter().flatten().collect(),
                    eof,
                    digest,
                })
            }
            _ => Err(sandsurf_protocol::Invalid(
                "response does not describe binary data",
            )),
        }
    }
}
