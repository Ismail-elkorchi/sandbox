use sandsurf_protocol::{
    Capability, CommitmentId, Counter, Digest, Grant, GrantId, GuestServiceRequest,
    GuestServiceResponse, LifecycleIntent, LifecycleOperation, MachineObservation, Observation,
    Operation, OperationId, PinId, ProcessId, Qualification, ReleaseRequest, Resources,
    RuntimeResponse, SandboxId, VmEngine,
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
    Lifecycle {
        operation: LifecycleOperation,
        sandbox: SandboxView,
    },
    Grant {
        grant: Grant,
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
