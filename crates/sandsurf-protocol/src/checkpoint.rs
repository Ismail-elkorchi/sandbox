use crate::{
    CheckpointId, Counter, Digest, OperationId, OutputBoundary, ProcessSnapshot, Resources,
    SandboxId, VmEngine,
};
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
    pub full: Option<FullCheckpointMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointArtifact {
    pub digest: Digest,
    pub bytes: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointProcessWatermark {
    pub snapshot: ProcessSnapshot,
    pub output: OutputBoundary,
}

/// Engine-specific material bound into a full checkpoint. The reconnect state
/// contains protected supervisor credentials and therefore makes every full
/// capture sensitive even when no workload secret was delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FullCheckpointMetadata {
    pub engine: VmEngine,
    pub engine_version: String,
    pub architecture: String,
    pub configuration_digest: Digest,
    pub snapshot_state: CheckpointArtifact,
    /// Separate guest-memory material when the native engine emits it. Engines
    /// with an integrated saved-machine artifact leave this absent.
    pub memory: Option<CheckpointArtifact>,
    pub control_disk: CheckpointArtifact,
    pub reconnect_state: CheckpointArtifact,
    pub processes: Vec<CheckpointProcessWatermark>,
    pub generation: Digest,
    pub fork_safe: bool,
}

/// Metadata produced by the exclusive native owner before host publication.
/// Artifact names are fixed by the guardian; no guest or application path is
/// accepted at this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeFullCapture {
    pub engine: VmEngine,
    pub engine_version: String,
    pub architecture: String,
    pub configuration_digest: Digest,
    pub snapshot_state: CheckpointArtifact,
    pub memory: Option<CheckpointArtifact>,
    pub reconnect_state: CheckpointArtifact,
    pub generation: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeCheckpointRequest {
    PrepareFull {
        checkpoint_id: CheckpointId,
        operation_id: OperationId,
    },
    FinishFull {
        operation_id: OperationId,
    },
    CommitSuspend {
        operation_id: OperationId,
        manifest_digest: Digest,
    },
    StageRestore {
        checkpoint_id: CheckpointId,
        manifest_digest: Digest,
        workload_disk: CheckpointArtifact,
        expected: Box<FullCheckpointMetadata>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeCheckpointResponse {
    Prepared {
        capture: NativeFullCapture,
        processes: Vec<CheckpointProcessWatermark>,
    },
    Complete {
        evidence: Digest,
    },
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
