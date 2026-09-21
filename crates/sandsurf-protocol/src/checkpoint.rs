use crate::{CheckpointId, Counter, Digest, OperationId, Resources, SandboxId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointKind {
    Filesystem,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointConsistency {
    Crash,
    Filesystem,
    Application,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointPhase {
    Admitted,
    Capturing,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointRequest {
    pub id: CheckpointId,
    pub operation_id: OperationId,
    pub sandbox_id: SandboxId,
    pub expected_epoch: Counter,
    pub expected_revision: Counter,
    pub kind: CheckpointKind,
    pub parent: Option<CheckpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Checkpoint {
    pub request: CheckpointRequest,
    pub request_digest: Digest,
    pub phase: CheckpointPhase,
    pub image_digest: Digest,
    pub resources: Resources,
    pub consistency: Option<CheckpointConsistency>,
    pub workload_disk_digest: Option<Digest>,
    pub workload_disk_bytes: Counter,
    pub manifest_digest: Option<Digest>,
    pub sensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackPhase {
    Admitted,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RollbackRecord {
    pub operation_id: OperationId,
    pub sandbox_id: SandboxId,
    pub checkpoint_id: CheckpointId,
    pub expected_revision: Counter,
    pub request_digest: Digest,
    pub phase: RollbackPhase,
    pub evidence_digest: Option<Digest>,
}
