use crate::{
    Counter, Digest, ExecutionId, ExecutionOutcome, GuestCommand, GuestPath, MachineId,
    OperationId, OutputBoundary, SnapshotId, SpawnRequest, Stream, TransferId, WatcherId,
};
use serde::{Deserialize, Serialize};

/// Reported by guest software. Authentication binds transport, not truthful
/// kernel identity or management state when the guest administrator is untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestManagementIdentity {
    pub boot_id: crate::GuestBootId,
    pub instance_id: crate::ManagementInstanceId,
}

/// Host timestamp and generation fence around a guest-controlled report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestManagementReport {
    pub generation: Counter,
    pub identity: GuestManagementIdentity,
    pub observed_unix_millis: Counter,
}

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
    pub observation: FileReadObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileRangeMetadata {
    pub offset: u64,
    pub eof: bool,
    pub observation: FileReadObservation,
    pub chunks: Vec<crate::BinaryChunk>,
}

impl FileRange {
    pub fn into_binary_parts(self) -> Result<(FileRangeMetadata, Vec<Vec<u8>>), crate::Invalid> {
        if self.bytes.len() > crate::MAX_STREAM_BYTES {
            return Err(crate::Invalid("file range exceeds its byte bound"));
        }
        let bytes = if self.bytes.is_empty() {
            Vec::new()
        } else {
            vec![self.bytes]
        };
        let metadata = FileRangeMetadata {
            offset: self.offset,
            eof: self.eof,
            observation: self.observation,
            chunks: crate::describe_binary(&bytes)?,
        };
        metadata.validate()?;
        Ok((metadata, bytes))
    }
}
impl FileRangeMetadata {
    pub fn validate(&self) -> Result<usize, crate::Invalid> {
        let length = crate::validate_binary(&self.chunks, crate::MAX_STREAM_BYTES)?;
        let end = self
            .offset
            .checked_add(length as u64)
            .ok_or(crate::Invalid("file range overflow"))?;
        if end > self.observation.size
            || self.eof != (end == self.observation.size)
            || (length == 0 && !self.eof)
        {
            return Err(crate::Invalid("file range coverage is invalid"));
        }
        Ok(length)
    }
    pub fn with_binary_parts(self, bytes: Vec<Vec<u8>>) -> Result<FileRange, crate::Invalid> {
        self.validate()?;
        if crate::describe_binary(&bytes)? != self.chunks {
            return Err(crate::Invalid("file data differs from metadata"));
        }
        Ok(FileRange {
            offset: self.offset,
            bytes: bytes.into_iter().flatten().collect(),
            eof: self.eof,
            observation: self.observation,
        })
    }
}

/// A guest-reported metadata token for detecting changes during a live read.
/// It is not a content digest, a point-in-time snapshot, or host attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileReadObservation {
    pub size: u64,
    pub token: Digest,
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
    pub generation: Counter,
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

/// Bounded control metadata for a page whose original bytes travel in
/// authenticated, credit-limited data frames on the guest channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedChunkMetadata {
    pub cursor: Counter,
    pub stream: Stream,
    pub length: u32,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedPageMetadata {
    pub after: Counter,
    pub available: Counter,
    pub chunks: Vec<RetainedChunkMetadata>,
    pub required_bytes: Option<Counter>,
}

impl RetainedPage {
    pub fn into_binary_parts(self) -> Result<(RetainedPageMetadata, Vec<Vec<u8>>), crate::Invalid> {
        let mut chunks = Vec::with_capacity(self.chunks.len());
        let mut data = Vec::with_capacity(self.chunks.len());
        for chunk in self.chunks {
            if crate::bytes_digest(&chunk.bytes) != chunk.digest {
                return Err(crate::Invalid("retained chunk digest mismatch"));
            }
            chunks.push(RetainedChunkMetadata {
                cursor: chunk.cursor,
                stream: chunk.stream,
                length: u32::try_from(chunk.bytes.len())
                    .map_err(|_| crate::Invalid("retained chunk length overflow"))?,
                digest: chunk.digest,
            });
            data.push(chunk.bytes);
        }
        let metadata = RetainedPageMetadata {
            after: self.after,
            available: self.available,
            chunks,
            required_bytes: self.required_bytes,
        };
        metadata.validate_lengths()?;
        Ok((metadata, data))
    }
}

impl RetainedPageMetadata {
    pub fn validate_lengths(&self) -> Result<usize, crate::Invalid> {
        if self.after > self.available
            || self.chunks.len() > 256
            || (!self.chunks.is_empty() && self.required_bytes.is_some())
        {
            return Err(crate::Invalid("retained page bounds invalid"));
        }
        let mut cursor = self.after;
        let mut total = 0_usize;
        for chunk in &self.chunks {
            if chunk.cursor != cursor
                || chunk.length == 0
                || chunk.length as usize > crate::MAX_STREAM_BYTES
            {
                return Err(crate::Invalid("retained page is not contiguous"));
            }
            cursor = cursor.checked_add(u64::from(chunk.length))?;
            total = total
                .checked_add(chunk.length as usize)
                .filter(|value| *value <= crate::MAX_CONTROL_BYTES)
                .ok_or(crate::Invalid("retained page byte bound exceeded"))?;
        }
        if cursor > self.available
            || self.required_bytes.is_some_and(|value| {
                value == Counter::ZERO || value.get() > crate::MAX_STREAM_BYTES as u64
            })
        {
            return Err(crate::Invalid("retained page cursor invalid"));
        }
        Ok(total)
    }

    pub fn with_binary_parts(self, data: Vec<Vec<u8>>) -> Result<RetainedPage, crate::Invalid> {
        self.validate_lengths()?;
        if self.chunks.len() != data.len() {
            return Err(crate::Invalid("retained page chunk count mismatch"));
        }
        let chunks = self
            .chunks
            .into_iter()
            .zip(data)
            .map(|(chunk, bytes)| {
                if bytes.len() != chunk.length as usize
                    || crate::bytes_digest(&bytes) != chunk.digest
                {
                    return Err(crate::Invalid("retained page bytes mismatch"));
                }
                Ok(RetainedChunk {
                    cursor: chunk.cursor,
                    stream: chunk.stream,
                    bytes,
                    digest: chunk.digest,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RetainedPage {
            after: self.after,
            available: self.available,
            chunks,
            required_bytes: self.required_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionCompletion {
    pub outcome: ExecutionOutcome,
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
pub enum ExecutionState {
    Running,
    /// The command leader has exited. Inherited output descriptors may still
    /// belong to independent Linux processes, so capture is not yet complete.
    Draining {
        outcome: ExecutionOutcome,
        accounting_digest: Digest,
    },
    Exited(ExecutionCompletion),
    Unknown {
        evidence: Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionSnapshot {
    pub request: SpawnRequest,
    pub guest_pid: u32,
    pub state: ExecutionState,
    #[serde(default)]
    pub lineage: Option<ExecutionLineage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionLineage {
    pub source_machine_id: MachineId,
    pub source_generation: Counter,
    pub snapshot_id: SnapshotId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuestServiceRequest {
    /// Guardian-only restore handshake sent over the captured boot capability.
    /// The response is sealed under that old session; all later connections
    /// require the new generation and capability.
    RebindGeneration {
        snapshot_id: SnapshotId,
        capture_operation_id: OperationId,
        machine_id: MachineId,
        previous_generation: Counter,
        generation: Counter,
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
        version: crate::SecretVersionId,
        deliveries: Vec<crate::SecretDelivery>,
        terminate_recipients: bool,
    },
    FilesystemQuery {
        request: FilesystemRequest,
    },
    Dispatch {
        command: GuestCommand,
    },
    Process {
        execution_id: ExecutionId,
    },
    Processes,
    ReadOutput {
        execution_id: ExecutionId,
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
        generation: Counter,
        path: GuestPath,
        recursive: bool,
    },
    PollWatch {
        watcher_id: WatcherId,
        generation: Counter,
        maximum: u16,
    },
    Unwatch {
        watcher_id: WatcherId,
        generation: Counter,
    },
}

impl FilesystemRequest {
    pub(crate) fn validate_metadata(&self, length: Option<usize>) -> Result<(), crate::Invalid> {
        match (self, length) {
            (Self::Write { bytes, mode, .. }, Some(length))
                if bytes.is_empty() && length <= crate::MAX_STREAM_BYTES && mode & !0o7777 == 0 =>
            {
                Ok(())
            }
            (
                Self::WriteChunk {
                    transfer,
                    offset,
                    bytes,
                },
                Some(length),
            ) if bytes.is_empty()
                && transfer.validate().is_ok()
                && length > 0
                && length <= crate::MAX_STREAM_BYTES
                && offset
                    .checked_add(length as u64)
                    .is_some_and(|end| end <= transfer.length) =>
            {
                Ok(())
            }
            (Self::Write { .. } | Self::WriteChunk { .. }, _) => Err(crate::Invalid(
                "filesystem metadata has an invalid byte descriptor",
            )),
            (_, None) => self.validate(),
            _ => Err(crate::Invalid("filesystem metadata has unexpected bytes")),
        }
    }

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

    pub fn is_query(&self) -> bool {
        matches!(
            self,
            Self::Stat { .. }
                | Self::List { .. }
                | Self::Read { .. }
                | Self::Readlink { .. }
                | Self::PollWatch { .. }
        )
    }
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuestServiceResponse {
    GenerationRebound {
        evidence: Digest,
    },
    Identity {
        machine_id: MachineId,
        generation: Counter,
        boot_identity: Digest,
        management: GuestManagementIdentity,
    },
    SecretInstalled {
        evidence: Digest,
    },
    SecretCleanupReported {
        report: crate::SecretCleanupReport,
    },
    Effect {
        outcome: GuestEffectOutcome,
    },
    Process {
        process: Box<ExecutionSnapshot>,
    },
    Processes {
        processes: Vec<ExecutionSnapshot>,
    },
    Output {
        page: RetainedPage,
    },
    OutputMetadata {
        page: RetainedPageMetadata,
    },
    File {
        response: FilesystemResponse,
    },
    Error {
        code: String,
        message: String,
    },
}

impl GuestServiceResponse {
    pub fn into_wire_parts(self) -> Result<crate::WireParts<Self>, crate::Invalid> {
        match self {
            Self::Output { page } => {
                let (page, bytes) = page.into_binary_parts()?;
                if page.validate_lengths()? > crate::MAX_STREAM_BYTES {
                    return Err(crate::Invalid("guest output exceeds its response credit"));
                }
                Ok((Self::OutputMetadata { page }, Some(bytes)))
            }
            Self::File {
                response: FilesystemResponse::Read { range },
            } => {
                let (range, bytes) = range.into_binary_parts()?;
                Ok((
                    Self::File {
                        response: FilesystemResponse::ReadMetadata { range },
                    },
                    Some(bytes),
                ))
            }
            Self::OutputMetadata { .. }
            | Self::File {
                response: FilesystemResponse::ReadMetadata { .. },
            } => Err(crate::Invalid(
                "internal response cannot originate wire-only metadata",
            )),
            other => Ok((other, None)),
        }
    }
    pub fn binary_descriptor(&self) -> Result<Option<Vec<crate::BinaryChunk>>, crate::Invalid> {
        match self {
            Self::OutputMetadata { page } => {
                if page.validate_lengths()? > crate::MAX_STREAM_BYTES {
                    return Err(crate::Invalid("guest output exceeds its response credit"));
                }
                Ok(Some(
                    page.chunks
                        .iter()
                        .map(|chunk| crate::BinaryChunk {
                            length: chunk.length,
                            digest: chunk.digest.clone(),
                        })
                        .collect(),
                ))
            }
            Self::File {
                response: FilesystemResponse::ReadMetadata { range },
            } => {
                range.validate()?;
                Ok(Some(range.chunks.clone()))
            }
            Self::Output { .. }
            | Self::File {
                response: FilesystemResponse::Read { .. },
            } => Err(crate::Invalid("RPC bytes must use binary data frames")),
            _ => Ok(None),
        }
    }
    pub fn with_wire_bytes(self, bytes: Vec<Vec<u8>>) -> Result<Self, crate::Invalid> {
        match self {
            Self::OutputMetadata { page } => Ok(Self::Output {
                page: page.with_binary_parts(bytes)?,
            }),
            Self::File {
                response: FilesystemResponse::ReadMetadata { range },
            } => Ok(Self::File {
                response: FilesystemResponse::Read {
                    range: range.with_binary_parts(bytes)?,
                },
            }),
            _ => Err(crate::Invalid("response has no binary metadata")),
        }
    }
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
    ReadMetadata { range: FileRangeMetadata },
    Written { revision: FileRevision },
    Link { target: Vec<u8> },
    Watch { events: Vec<WatchEvent> },
    Complete,
}
