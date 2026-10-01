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
    /// Host admission lineage survives even without a cooperative observation.
    pub lineage: Option<crate::ExecutionLineage>,
    /// Last cooperative guest report; an admitted execution can have none.
    pub observation: Option<ExecutionSnapshot>,
    /// Actual bytes retained by the host at the native capture boundary.
    pub output: OutputBoundary,
}

impl CapturedExecution {
    /// Deterministic incarnation identity makes interrupted restore admission
    /// retryable without rewriting a spawn operation or replaying the spawn.
    pub fn restored(
        &self,
        snapshot_id: &SnapshotId,
        machine_id: &MachineId,
        generation: Counter,
    ) -> Result<(SpawnRequest, crate::ExecutionLineage), crate::Invalid> {
        if self.admission.machine_id != *machine_id || generation <= self.admission.generation {
            return Err(crate::Invalid(
                "memory restore requires the same machine and a newer generation",
            ));
        }
        self.admission.validate()?;
        self.output.validate()?;
        if self.output.final_cursor > self.admission.output_bytes {
            return Err(crate::Invalid(
                "captured output exceeds admission reservation",
            ));
        }
        if let Some(lineage) = &self.lineage {
            if lineage.source_machine_id != *machine_id
                || lineage.source_generation >= self.admission.generation
                || lineage.source_execution_id == self.admission.execution_id
            {
                return Err(crate::Invalid("captured execution lineage invalid"));
            }
            lineage.output_anchor.validate()?;
        }
        if self
            .observation
            .as_ref()
            .is_some_and(|value| value.request != self.admission || value.lineage != self.lineage)
        {
            return Err(crate::Invalid(
                "captured observation differs from admission",
            ));
        }
        let identity = crate::digest(
            crate::Domain::Snapshot,
            &(
                "execution-incarnation",
                machine_id,
                generation,
                snapshot_id,
                &self.admission.execution_id,
            ),
        )?;
        let mut request = self.admission.clone();
        request.execution_id = identity.as_str().to_owned().try_into()?;
        request.generation = generation;
        let lineage = crate::ExecutionLineage {
            logical_execution_id: self.lineage.as_ref().map_or_else(
                || self.admission.execution_id.clone(),
                |value| value.logical_execution_id.clone(),
            ),
            source_execution_id: self.admission.execution_id.clone(),
            source_machine_id: machine_id.clone(),
            source_generation: self.admission.generation,
            snapshot_id: snapshot_id.clone(),
            output_anchor: self.output.clone(),
        };
        Ok((request, lineage))
    }
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
