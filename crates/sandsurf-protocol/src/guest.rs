use crate::{
    Capability, CheckpointId, Counter, Digest, GuestPath, Mutation, OperationId, OutputBoundary,
    ProcessId, ProcessOutcome, SandboxId, SpawnRequest, Stream, TransferId, WatcherId,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileStat {
    pub kind: FileKind,
    pub size: u64,
    pub readonly: bool,
    pub modified_millis: Option<u64>,
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryEntry {
    pub name: Vec<u8>,
    pub stat: FileStat,
}

impl DirectoryEntry {
    pub fn utf8_name(&self) -> Option<&str> {
        std::str::from_utf8(&self.name).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryPage {
    pub entries: Vec<DirectoryEntry>,
    pub next: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileRevision {
    pub size: u64,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileRange {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub eof: bool,
    pub revision: FileRevision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchEventKind {
    Created,
    Modified,
    Removed,
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WatchEvent {
    pub watcher_id: WatcherId,
    pub epoch: Counter,
    pub sequence: Counter,
    pub kind: WatchEventKind,
    pub path: Option<GuestPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedChunk {
    pub cursor: Counter,
    pub stream: Stream,
    pub bytes: Vec<u8>,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedPage {
    pub after: Counter,
    pub available: Counter,
    pub chunks: Vec<RetainedChunk>,
    pub required_bytes: Option<Counter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessCompletion {
    pub outcome: ProcessOutcome,
    pub output: OutputBoundary,
    pub cleanup_digest: Digest,
    pub accounting_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProcessState {
    Running,
    Exited(ProcessCompletion),
    Unknown { evidence: Digest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessSnapshot {
    pub request: SpawnRequest,
    pub guest_pid: u32,
    pub state: ProcessState,
    #[serde(default)]
    pub lineage: Option<ProcessLineage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessLineage {
    pub source_sandbox_id: SandboxId,
    pub source_epoch: Counter,
    pub checkpoint_id: CheckpointId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuestServiceRequest {
    /// Guardian-only machine shutdown barrier. The host API never forwards
    /// this request from an application.
    PrepareStop,
    /// Guardian-only capture barrier. The workload cgroup is frozen and its
    /// persistent filesystem is synchronized before this request completes.
    PrepareFilesystemCapture {
        operation_id: OperationId,
    },
    /// Guardian-only release of an exact capture barrier.
    FinishFilesystemCapture {
        operation_id: OperationId,
    },
    /// Guardian-only restore handshake sent over the captured boot capability.
    /// The response is sealed under that old session; all later connections
    /// require the new epoch and capability.
    RebindEpoch {
        checkpoint_id: CheckpointId,
        capture_operation_id: OperationId,
        sandbox_id: SandboxId,
        previous_epoch: Counter,
        epoch: Counter,
        boot_identity: Digest,
        capability: [u8; 32],
        network_capability: [u8; 32],
        generation_seed: [u8; 32],
    },
    /// Guardian-only proof that a fresh authenticated transport is bound to
    /// the expected guest identity. This remains available while ordinary
    /// workload operations are fenced for capture/restore.
    ProbeIdentity,
    /// Guardian-only secret installation. Raw bytes are never accepted by the
    /// application guest-query route or persisted in ordinary operation logs.
    InstallSecret {
        operation_id: OperationId,
        delivery: crate::SecretDelivery,
        bytes: Vec<u8>,
    },
    RevokeSecret {
        operation_id: OperationId,
        secret_id: crate::SecretId,
        version: Digest,
        deliveries: Vec<crate::SecretDelivery>,
        terminate_recipients: bool,
    },
    ApplyResources {
        resources: crate::LiveResourceLimits,
    },
    ResourceUsage,
    Dispatch {
        mutation: Mutation,
        capability: Capability,
    },
    Process {
        process_id: ProcessId,
    },
    Processes,
    ReadOutput {
        process_id: ProcessId,
        after: Counter,
        maximum: u32,
    },
    Operation {
        operation_id: OperationId,
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
pub enum FilesystemRequest {
    Stat {
        path: GuestPath,
        follow: bool,
    },
    List {
        path: GuestPath,
        after: Option<Vec<u8>>,
        maximum: u16,
    },
    Read {
        path: GuestPath,
        offset: u64,
        maximum: u32,
    },
    Write {
        path: GuestPath,
        bytes: Vec<u8>,
        mode: u32,
        expected: FileExpectation,
    },
    BeginWrite {
        transfer: FileTransfer,
    },
    WriteChunk {
        transfer: FileTransfer,
        offset: u64,
        bytes: Vec<u8>,
    },
    CommitWrite {
        transfer: FileTransfer,
    },
    AbortWrite {
        transfer: FileTransfer,
    },
    Transaction {
        transaction: FileTransaction,
    },
    Mkdir {
        path: GuestPath,
        recursive: bool,
    },
    Rename {
        from: GuestPath,
        to: GuestPath,
    },
    Remove {
        path: GuestPath,
        recursive: bool,
    },
    Chmod {
        path: GuestPath,
        mode: u32,
    },
    Readlink {
        path: GuestPath,
    },
    Symlink {
        path: GuestPath,
        target: Vec<u8>,
    },
    Watch {
        watcher_id: WatcherId,
        epoch: Counter,
        path: GuestPath,
        recursive: bool,
    },
    PollWatch {
        watcher_id: WatcherId,
        epoch: Counter,
        maximum: u16,
    },
    Unwatch {
        watcher_id: WatcherId,
        epoch: Counter,
    },
}

impl FilesystemRequest {
    pub fn validate(&self) -> Result<(), crate::Invalid> {
        match self {
            Self::List { maximum, .. } | Self::PollWatch { maximum, .. }
                if *maximum == 0 || *maximum > 4096 =>
            {
                return Err(crate::Invalid("filesystem page bound is invalid"));
            }
            Self::Read { maximum, .. }
                if *maximum == 0 || *maximum as usize > crate::MAX_STREAM_BYTES =>
            {
                return Err(crate::Invalid("filesystem read bound is invalid"));
            }
            Self::Write { bytes, mode, .. }
                if bytes.len() > crate::MAX_STREAM_BYTES || mode & !0o7777 != 0 =>
            {
                return Err(crate::Invalid(
                    "filesystem write is oversized or has invalid mode",
                ));
            }
            Self::BeginWrite { transfer }
            | Self::CommitWrite { transfer }
            | Self::AbortWrite { transfer }
                if transfer.validate().is_err() =>
            {
                return Err(crate::Invalid("filesystem transfer is invalid"));
            }
            Self::WriteChunk {
                transfer,
                offset,
                bytes,
            } if transfer.validate().is_err()
                || bytes.is_empty()
                || bytes.len() > crate::MAX_STREAM_BYTES
                || offset
                    .checked_add(bytes.len() as u64)
                    .is_none_or(|end| end > transfer.length) =>
            {
                return Err(crate::Invalid("filesystem transfer chunk is invalid"));
            }
            Self::Transaction { transaction } if transaction.validate().is_err() => {
                return Err(crate::Invalid("filesystem transaction is invalid"));
            }
            Self::Chmod { mode, .. } if mode & !0o7777 != 0 => {
                return Err(crate::Invalid("filesystem mode is invalid"));
            }
            Self::Symlink { target, .. }
                if target.is_empty() || target.len() > 4096 || target.contains(&0) =>
            {
                return Err(crate::Invalid("symlink target is malformed"));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn required_capability(&self) -> Capability {
        match self {
            Self::Stat { .. }
            | Self::List { .. }
            | Self::Read { .. }
            | Self::Readlink { .. }
            | Self::Watch { .. }
            | Self::PollWatch { .. }
            | Self::Unwatch { .. } => Capability::ReadFiles,
            Self::Write { .. }
            | Self::BeginWrite { .. }
            | Self::WriteChunk { .. }
            | Self::CommitWrite { .. }
            | Self::AbortWrite { .. }
            | Self::Transaction { .. }
            | Self::Mkdir { .. }
            | Self::Rename { .. }
            | Self::Remove { .. }
            | Self::Chmod { .. }
            | Self::Symlink { .. } => Capability::WriteFiles,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileTransaction {
    pub id: OperationId,
    pub mutations: Vec<FileMutation>,
}

impl FileTransaction {
    pub fn validate(&self) -> Result<(), crate::Invalid> {
        if self.mutations.is_empty() || self.mutations.len() > 1024 {
            return Err(crate::Invalid(
                "filesystem transaction mutation count is invalid",
            ));
        }
        let mut bytes = 0_usize;
        let mut paths = std::collections::BTreeSet::new();
        for mutation in &self.mutations {
            let path = match mutation {
                FileMutation::Write {
                    path,
                    bytes: value,
                    mode,
                    ..
                } => {
                    bytes = bytes
                        .checked_add(value.len())
                        .ok_or(crate::Invalid("filesystem transaction is oversized"))?;
                    if *mode & !0o7777 != 0 {
                        return Err(crate::Invalid("filesystem transaction mode is invalid"));
                    }
                    path
                }
                FileMutation::Remove { path, .. } => path,
            };
            if !paths.insert(path.as_bytes()) {
                return Err(crate::Invalid(
                    "filesystem transaction repeats a destination",
                ));
            }
        }
        if bytes > crate::MAX_STREAM_BYTES {
            return Err(crate::Invalid("filesystem transaction is oversized"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FileMutation {
    Write {
        path: GuestPath,
        bytes: Vec<u8>,
        mode: u32,
        expected: FileExpectation,
    },
    Remove {
        path: GuestPath,
        expected: FileExpectation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileTransfer {
    pub id: TransferId,
    pub path: GuestPath,
    pub length: u64,
    pub digest: Digest,
    pub mode: u32,
    pub expected: FileExpectation,
}

impl FileTransfer {
    pub fn validate(&self) -> Result<(), crate::Invalid> {
        if self.length > 128 * 1024 * 1024 * 1024 || self.mode & !0o7777 != 0 {
            return Err(crate::Invalid("filesystem transfer exceeds its bound"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FileExpectation {
    Any,
    Absent,
    Matches { size: u64, digest: Digest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuestServiceResponse {
    ReadyToStop {
        evidence: Digest,
    },
    FilesystemCapturePrepared {
        evidence: Digest,
    },
    FilesystemCaptureFinished {
        evidence: Digest,
    },
    EpochRebound {
        evidence: Digest,
    },
    Identity {
        sandbox_id: SandboxId,
        epoch: Counter,
        boot_identity: Digest,
    },
    SecretInstalled {
        evidence: Digest,
    },
    SecretRevoked {
        evidence: crate::SecretRevocationEvidence,
    },
    ResourcesApplied {
        evidence: Digest,
    },
    ResourceUsage {
        usage: crate::ResourceUsage,
    },
    Effect {
        outcome: GuestEffectOutcome,
    },
    Process {
        process: Box<ProcessSnapshot>,
    },
    Processes {
        processes: Vec<ProcessSnapshot>,
    },
    Output {
        page: RetainedPage,
    },
    File {
        response: FilesystemResponse,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuestEffectOutcome {
    Applied { evidence: Digest },
    NotApplied { evidence: Digest },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FilesystemResponse {
    Stat { value: FileStat },
    List { page: DirectoryPage },
    Read { range: FileRange },
    Written { revision: FileRevision },
    Link { target: Vec<u8> },
    Watch { events: Vec<WatchEvent> },
    Complete,
}
