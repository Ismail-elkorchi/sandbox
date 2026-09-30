use crate::{
    Counter, Digest, ExecutionSnapshot, MachineId, OperationId, OutputBoundary, Resources,
    SnapshotId, SpawnRequest, VmEngine,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotKind {
    Disk,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotConsistency {
    Crash,
    Machine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotPhase {
    Admitted,
    Capturing,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotRequest {
    pub id: SnapshotId,
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub expected_generation: Counter,
    pub expected_revision: Counter,
    pub kind: SnapshotKind,
    pub parent: Option<SnapshotId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub request: SnapshotRequest,
    pub request_digest: Digest,
    pub phase: SnapshotPhase,
    pub image_digest: Digest,
    pub resources: Resources,
    pub consistency: Option<SnapshotConsistency>,
    pub system_disk_digest: Option<Digest>,
    pub system_disk_bytes: Counter,
    pub manifest_digest: Option<Digest>,
    pub sensitive: bool,
    pub full: Option<FullSnapshotMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotArtifact {
    pub digest: Digest,
    pub bytes: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedExecution {
    /// Host admission, not evidence that a particular Linux PID exists.
    pub admission: SpawnRequest,
    /// Last cooperative guest report; an admitted execution can have none.
    pub observation: Option<ExecutionSnapshot>,
    /// Actual bytes retained by the host at the native capture boundary.
    pub output: OutputBoundary,
}

/// Engine-specific material bound into a full snapshot. Reconnect credentials
/// are also available to guest root: they authenticate this machine's channel,
/// not its reports. Their inclusion makes every full capture sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FullSnapshotMetadata {
    pub engine: VmEngine,
    pub engine_version: String,
    pub architecture: String,
    pub configuration_digest: Digest,
    pub snapshot_state: SnapshotArtifact,
    /// Separate guest-memory material when the native engine emits it. Engines
    /// with an integrated saved-machine artifact leave this absent.
    pub memory: Option<SnapshotArtifact>,
    pub reconnect_state: SnapshotArtifact,
    pub executions: Vec<CapturedExecution>,
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
    /// Immutable admission membership at this capture, never reconstructed
    /// from a later runtime journal when an interrupted capture is retried.
    pub executions: Vec<CapturedExecution>,
    pub snapshot_state: SnapshotArtifact,
    pub memory: Option<SnapshotArtifact>,
    pub reconnect_state: SnapshotArtifact,
    pub generation: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeSnapshotRequest {
    PrepareDisk {
        operation_id: OperationId,
    },
    FinishDisk {
        operation_id: OperationId,
    },
    PrepareFull {
        snapshot_id: SnapshotId,
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
        snapshot_id: SnapshotId,
        manifest_digest: Digest,
        system_disk: SnapshotArtifact,
        expected: Box<FullSnapshotMetadata>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeSnapshotResponse {
    Prepared { capture: NativeFullCapture },
    Complete { evidence: Digest },
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
    pub machine_id: MachineId,
    pub snapshot_id: SnapshotId,
    pub expected_revision: Counter,
    pub request_digest: Digest,
    pub phase: RollbackPhase,
    pub evidence_digest: Option<Digest>,
}
