use sandsurf_protocol::{
    Capability, CommitmentId, Counter, Digest, Grant, GrantId, GuestServiceRequest,
    GuestServiceResponse, LifecycleIntent, LifecycleOperation, MachineObservation, Observation,
    Operation, OperationId, PinId, ProcessId, Qualification, ReleaseRequest, Resources,
    RuntimeResponse, SandboxId, TransferId, VmEngine,
};
use sandsurf_state::{ImageImportRecord, ImageRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const HOST_API_VERSION: u16 = 1;

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
    pub guest_platform: String,
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
        credential: Option<sandsurf_protocol::SecretId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservationView {
    Held,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxView {
    pub id: SandboxId,
    pub image_digest: Digest,
    pub resources: Resources,
    pub runtime_configuration: sandsurf_protocol::RuntimeConfiguration,
    pub configuration_revision: Counter,
    pub reservation: ReservationView,
    pub lifecycle_intent: LifecycleIntent,
    pub machine: Observation<MachineObservation>,
    pub workload_defaults: WorkloadDefaultsView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadDefaultsView {
    pub environment: BTreeMap<String, String>,
    pub user: Option<String>,
    pub working_directory: Option<String>,
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
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
    pub sandbox_id: SandboxId,
    pub request_digest: Digest,
    pub manifest_digest: Digest,
    pub entries: Counter,
    pub bytes: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostBlobTransfer {
    pub id: TransferId,
    pub length: Counter,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostWorkspaceChange {
    Upsert { entry: HostTreeEntry },
    Delete { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostWorkspaceChangeSet {
    pub base_manifest_digest: Digest,
    pub base: Vec<HostTreeEntry>,
    pub changes: Vec<HostWorkspaceChange>,
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
    ListSandboxes {
        after: Option<SandboxId>,
        maximum: Counter,
    },
    GetSandbox {
        sandbox_id: SandboxId,
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
    ImportOci {
        source: OciSource,
        platform: String,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    CaptureHostTree {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        expected_revision: Counter,
        scope_digest: Digest,
        source: PathBuf,
        exclusions: Vec<String>,
        maximum_bytes: Counter,
        approval_id: CommitmentId,
    },
    ListHostTree {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        after: Counter,
        maximum: Counter,
    },
    ReadHostTreeBlob {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        digest: Digest,
        offset: Counter,
        maximum: u32,
    },
    BeginHostBlob {
        sandbox_id: SandboxId,
        expected_revision: Counter,
        scope_digest: Digest,
        transfer: HostBlobTransfer,
        approval_id: CommitmentId,
    },
    WriteHostBlob {
        sandbox_id: SandboxId,
        expected_revision: Counter,
        scope_digest: Digest,
        transfer: HostBlobTransfer,
        offset: Counter,
        bytes: Vec<u8>,
    },
    CommitHostBlob {
        sandbox_id: SandboxId,
        expected_revision: Counter,
        scope_digest: Digest,
        transfer: HostBlobTransfer,
    },
    ApplyHostWorkspace {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        expected_revision: Counter,
        scope_digest: Digest,
        destination: PathBuf,
        change_set: HostWorkspaceChangeSet,
        approval_id: CommitmentId,
    },
    CreateSandbox {
        sandbox_id: SandboxId,
        image_digest: Digest,
        resources: Resources,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    Lifecycle {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        expected_revision: Counter,
        desired: sandsurf_protocol::DesiredState,
        approval_id: CommitmentId,
    },
    SetGrant {
        sandbox_id: SandboxId,
        grant_id: GrantId,
        expected_revision: Counter,
        capability: Capability,
        scope_digest: Digest,
        revoked: bool,
        approval_id: CommitmentId,
    },
    SetNetworkPolicy {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        expected_revision: Counter,
        policy: sandsurf_protocol::NetworkPolicy,
        approval_id: CommitmentId,
    },
    SetExposure {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        expected_revision: Counter,
        exposure_id: sandsurf_protocol::ExposureId,
        spec: sandsurf_protocol::ExposureSpec,
        active: bool,
        approval_id: CommitmentId,
    },
    PutSecret {
        secret_id: sandsurf_protocol::SecretId,
        bytes: Vec<u8>,
        operation_id: OperationId,
        approval_id: CommitmentId,
    },
    DeliverSecret {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        expected_revision: Counter,
        scope_digest: Digest,
        delivery: sandsurf_protocol::SecretDelivery,
        approval_id: CommitmentId,
    },
    UpdateResources {
        sandbox_id: SandboxId,
        operation_id: OperationId,
        expected_revision: Counter,
        resources: Resources,
        live: sandsurf_protocol::LiveResourceLimits,
        approval_id: CommitmentId,
    },
    GetUsage {
        sandbox_id: SandboxId,
    },
    Workload {
        sandbox_id: SandboxId,
        epoch: Counter,
        operation_id: OperationId,
        expected_revision: Counter,
        request: sandsurf_protocol::WorkloadRequest,
        scope_digest: Digest,
    },
    Guest {
        sandbox_id: SandboxId,
        expected_revision: Counter,
        capability: Capability,
        scope_digest: Digest,
        request: GuestServiceRequest,
    },
    GetProcess {
        sandbox_id: SandboxId,
        process_id: ProcessId,
    },
    ListProcesses {
        sandbox_id: SandboxId,
    },
    GetOperation {
        sandbox_id: SandboxId,
        operation_id: OperationId,
    },
    GetReceipt {
        sandbox_id: SandboxId,
        process_id: ProcessId,
    },
    ReadEvidence {
        sandbox_id: SandboxId,
        process_id: ProcessId,
        after: Counter,
        maximum: u32,
    },
    ReadPinnedEvidence {
        sandbox_id: SandboxId,
        pin_id: PinId,
        after: Counter,
        maximum: u32,
    },
    AcknowledgeReceipt {
        sandbox_id: SandboxId,
        process_id: ProcessId,
        receipt_digest: Digest,
        expected_revision: Counter,
        scope_digest: Digest,
    },
    PinEvidence {
        sandbox_id: SandboxId,
        process_id: ProcessId,
        receipt_digest: Digest,
        pin_id: PinId,
        expected_revision: Counter,
        scope_digest: Digest,
    },
    ReleaseEvidence {
        sandbox_id: SandboxId,
        process_id: ProcessId,
        request: ReleaseRequest,
        expected_revision: Counter,
        scope_digest: Digest,
        loss_approval_id: Option<CommitmentId>,
    },
    CleanupReleasedEvidence {
        sandbox_id: SandboxId,
        process_id: ProcessId,
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
    Inspection {
        value: HostInspection,
    },
    Sandboxes {
        values: Vec<SandboxView>,
    },
    Sandbox {
        value: SandboxView,
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
    HostApply {
        report: HostApplyReport,
    },
    Lifecycle {
        operation: LifecycleOperation,
        sandbox: SandboxView,
    },
    Grant {
        grant: Grant,
    },
    Configuration {
        revision: Counter,
        sandbox: SandboxView,
    },
    Exposure {
        exposure: sandsurf_protocol::Exposure,
        sandbox: SandboxView,
    },
    Secret {
        secret: sandsurf_protocol::SecretVersion,
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
