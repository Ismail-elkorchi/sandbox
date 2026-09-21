use sandsurf_protocol::{
    Capability, CommitmentId, Counter, Digest, Grant, GrantId, GuestServiceRequest,
    GuestServiceResponse, LifecycleIntent, LifecycleOperation, MachineObservation, Observation,
    Operation, OperationId, Qualification, Resources, SandboxId, VmEngine,
};
use serde::{Deserialize, Serialize};

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
    Rejected {
        category: String,
        message: String,
    },
}
