use crate::Invalid;
use serde::{Deserialize, Serialize};

macro_rules! identifier {
    ($($name:ident),+ $(,)?) => {$ (
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl TryFrom<String> for $name {
            type Error = Invalid;
            fn try_from(value: String) -> Result<Self, Invalid> {
                if value.is_empty() || value.len() > 128 ||
                    !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                    return Err(Invalid("identity must be 1..128 ASCII letters, digits, hyphens or underscores"));
                }
                Ok(Self(value))
            }
        }
        impl TryFrom<&str> for $name {
            type Error = Invalid;
            fn try_from(value: &str) -> Result<Self, Invalid> { value.to_owned().try_into() }
        }
        impl From<$name> for String { fn from(value: $name) -> Self { value.0 } }
        impl $name { pub fn as_str(&self) -> &str { &self.0 } }
    )+};
}

identifier!(
    HostId,
    MachineId,
    ExecutionId,
    OperationId,
    CommitmentId,
    StoreId,
    PinId,
    DiskId,
    TerminalId,
    SnapshotId,
    ExposureId,
    TransferId,
    ImageId,
    SecretId,
    SecretVersionId,
    GuestBootId,
    ManagementInstanceId,
    WatcherId
);

/// Byte-preserving absolute Linux path used at the guest protocol boundary.
/// TypeScript offers UTF-8 convenience constructors, but no lossy decoding is
/// performed for directory entries or symlink targets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct GuestPath(Vec<u8>);

impl TryFrom<Vec<u8>> for GuestPath {
    type Error = Invalid;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        validate_guest_path_bytes(&value)?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for GuestPath {
    type Error = Invalid;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.as_bytes().to_vec().try_into()
    }
}

impl From<GuestPath> for Vec<u8> {
    fn from(value: GuestPath) -> Self {
        value.0
    }
}

impl GuestPath {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);
impl TryFrom<String> for Digest {
    type Error = Invalid;
    fn try_from(value: String) -> Result<Self, Invalid> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Invalid("digest must be lowercase SHA-256 hex"));
        }
        Ok(Self(value))
    }
}
impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.0
    }
}
impl Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! lowercase_hex {
    ($name:ident, $bytes:literal, $message:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl TryFrom<String> for $name {
            type Error = Invalid;
            fn try_from(value: String) -> Result<Self, Invalid> {
                if value.len() != $bytes * 2
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(Invalid($message));
                }
                Ok(Self(value))
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

lowercase_hex!(
    AuthorityPublicKey,
    32,
    "authority public key must be 32-byte lowercase hex"
);
lowercase_hex!(
    AuthoritySignature,
    64,
    "authority signature must be 64-byte lowercase hex"
);

/// The wire representation is exactly representable by both JavaScript and SQLite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct Counter(u64);
impl Counter {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const MAX: u64 = 9_007_199_254_740_991;
    pub fn get(self) -> u64 {
        self.0
    }
    pub fn next(self) -> Result<Self, Invalid> {
        self.checked_add(1)
    }
    pub fn checked_add(self, amount: u64) -> Result<Self, Invalid> {
        self.0
            .checked_add(amount)
            .ok_or(Invalid("counter overflow"))?
            .try_into()
    }
}
impl TryFrom<u64> for Counter {
    type Error = Invalid;
    fn try_from(value: u64) -> Result<Self, Invalid> {
        if value > Self::MAX {
            Err(Invalid("counter exceeds safe integer range"))
        } else {
            Ok(Self(value))
        }
    }
}
impl From<Counter> for u64 {
    fn from(value: Counter) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesiredState {
    Running,
    Paused,
    Stopped,
    Suspended,
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MachineState {
    Creating,
    Starting,
    Running,
    Paused,
    Stopped,
    Suspended,
    Restoring,
    Destroying,
    Destroyed,
    Failed,
}

impl MachineState {
    pub fn satisfies(self, desired: DesiredState) -> bool {
        matches!(
            (self, desired),
            (Self::Running, DesiredState::Running)
                | (Self::Paused, DesiredState::Paused)
                | (Self::Stopped, DesiredState::Stopped)
                | (Self::Suspended, DesiredState::Suspended)
                | (Self::Destroyed, DesiredState::Destroyed)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleIntent {
    pub machine_id: MachineId,
    pub operation_id: OperationId,
    pub desired: DesiredState,
    pub revision: Counter,
    pub request_digest: Digest,
    /// An immutable reference, not a cached authoritative running/stopped flag.
    pub completion: Option<ObservationRef>,
}

/// Stable host command material. Completion is deliberately excluded because it
/// is a later host reference to guardian evidence, not part of dispatch authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleCommand {
    pub machine_id: MachineId,
    pub operation_id: OperationId,
    pub desired: DesiredState,
    pub revision: Counter,
    pub request_digest: Digest,
    /// Exact host-owned configuration for the target revision. Drivers do not
    /// reconstruct grants from cached application or captured guest state.
    pub configuration: crate::RuntimeConfiguration,
}

/// Host-issued installation of one authoritative configuration revision. This
/// is deliberately not a lifecycle request: applying a grant while stopped or
/// paused must not start, resume, or stop the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationCommand {
    pub machine_id: MachineId,
    pub operation_id: OperationId,
    pub revision: Counter,
    pub request_digest: Digest,
    /// Exact host-authored configuration installed by the guardian. It is an
    /// immutable signed snapshot, never a guardian-owned grant database.
    pub configuration: crate::RuntimeConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationRef {
    pub machine_id: MachineId,
    pub generation: Counter,
    pub sequence: Counter,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ObservationCause {
    Lifecycle {
        operation_id: OperationId,
    },
    Configuration {
        operation_id: OperationId,
    },
    /// An independently measured native fact. It cannot complete host intent.
    Native {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineObservation {
    pub machine_id: MachineId,
    pub generation: Counter,
    pub sequence: Counter,
    pub state: MachineState,
    pub applied_revision: Counter,
    pub cause: ObservationCause,
    /// Driver evidence identity; observations are written only by the exclusive guardian.
    pub evidence_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Observation<T> {
    Current {
        value: T,
    },
    Unavailable {
        #[serde(rename = "lastKnown")]
        last_known: Option<T>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestCommand {
    pub machine_id: MachineId,
    pub generation: Counter,
    pub operation_id: OperationId,
    pub request: GuestRequest,
    pub request_digest: Digest,
}

impl GuestCommand {
    pub fn new(
        machine_id: MachineId,
        generation: Counter,
        operation_id: OperationId,
        request: GuestRequest,
    ) -> Result<Self, Invalid> {
        request.validate()?;
        let request_digest = command_digest(&machine_id, generation, &operation_id, &request)?;
        Ok(Self {
            machine_id,
            generation,
            operation_id,
            request,
            request_digest,
        })
    }

    pub fn validate(&self) -> Result<(), Invalid> {
        self.validate_identity()?;
        self.request.validate()?;
        let expected = command_digest(
            &self.machine_id,
            self.generation,
            &self.operation_id,
            &self.request,
        )?;
        if self.request_digest != expected {
            return Err(Invalid("command digest does not bind its request"));
        }
        Ok(())
    }

    /// Durable admission contains metadata and byte commitments, never payloads.
    /// Only the original fully assembled command can receive a dispatch permit.
    pub fn admission(&self) -> Result<crate::RequestEnvelope<Self>, Invalid> {
        self.validate()?;
        let (admission, _) = crate::RequestEnvelope::split(self.clone())?;
        Ok(admission)
    }

    fn validate_identity(&self) -> Result<(), Invalid> {
        if self.generation == Counter::ZERO {
            return Err(Invalid("execution generation must be positive"));
        }
        if let GuestRequest::Spawn { request } = &self.request
            && (request.machine_id != self.machine_id
                || request.generation != self.generation
                || request.operation_id != self.operation_id)
        {
            return Err(Invalid("spawn identity does not match its command"));
        }
        Ok(())
    }
}

impl crate::RequestEnvelope<GuestCommand> {
    pub fn validate_admission(&mut self) -> Result<(), Invalid> {
        let length = self
            .descriptor()?
            .map(|chunks| crate::validate_binary(chunks, crate::MAX_STREAM_BYTES))
            .transpose()?;
        self.request.validate_identity()?;
        self.request.request.validate_metadata(length)?;
        let expected = command_metadata_digest(
            &self.request.machine_id,
            self.request.generation,
            &self.request.operation_id,
            &crate::RequestEnvelope {
                request: self.request.request.clone(),
                binary: self.binary.clone(),
            },
        )?;
        if self.request.request_digest != expected {
            return Err(Invalid("admission digest does not bind its metadata"));
        }
        Ok(())
    }
}

fn command_digest(
    machine_id: &MachineId,
    generation: Counter,
    operation_id: &OperationId,
    request: &GuestRequest,
) -> Result<Digest, Invalid> {
    let (metadata, _) = crate::RequestEnvelope::split(request.clone())?;
    command_metadata_digest(machine_id, generation, operation_id, &metadata)
}

fn command_metadata_digest(
    machine_id: &MachineId,
    generation: Counter,
    operation_id: &OperationId,
    request: &crate::RequestEnvelope<GuestRequest>,
) -> Result<Digest, Invalid> {
    crate::digest(
        crate::Domain::Operation,
        &(
            "sandsurf-guest-command-v2",
            machine_id,
            generation,
            operation_id,
            request,
        ),
    )
}

/// The guardian pins this host identity and verification key. It is not a grant set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBinding {
    pub host_id: HostId,
    pub key_id: Digest,
    pub public_key: AuthorityPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedLifecycleStatement {
    pub version: u16,
    pub host_id: HostId,
    pub key_id: Digest,
    pub command: LifecycleCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedLifecycle {
    pub statement: AuthorizedLifecycleStatement,
    pub signature: AuthoritySignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedConfigurationStatement {
    pub version: u16,
    pub host_id: HostId,
    pub key_id: Digest,
    pub command: ConfigurationCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedConfiguration {
    pub statement: AuthorizedConfigurationStatement,
    pub signature: AuthoritySignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationOperation {
    pub command: ConfigurationCommand,
    pub delivery: Delivery,
    pub evidence_digest: Option<Digest>,
    pub observation: Option<ObservationRef>,
}

/// Host authorization for loss of one complete receipt-bound output scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedLossStatement {
    pub version: u16,
    pub host_id: HostId,
    pub key_id: Digest,
    pub machine_id: MachineId,
    pub execution_id: ExecutionId,
    pub receipt_digest: Digest,
    pub output: OutputBoundary,
    pub approval_id: CommitmentId,
    pub request_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedLoss {
    pub statement: AuthorizedLossStatement,
    pub signature: AuthoritySignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuardianRequest {
    Inspect {
        machine_id: MachineId,
        operation_id: Option<OperationId>,
    },
    Dispatch {
        command: GuestCommand,
    },
    Transition {
        authorization: AuthorizedLifecycle,
    },
    Configure {
        authorization: AuthorizedConfiguration,
    },
    Guest {
        machine_id: MachineId,
        request: crate::GuestServiceRequest,
    },
    QueryGuest {
        machine_id: MachineId,
        generation: Counter,
        request: crate::GuestServiceRequest,
    },
    NativeSnapshot {
        machine_id: MachineId,
        request: crate::NativeSnapshotRequest,
    },
    Runtime {
        machine_id: MachineId,
        request: RuntimeRequest,
    },
    /// Read-only, credit-driven journal subscription. Subsequent credits must
    /// repeat the identity and page bound with the last delivered cursor.
    SubscribeEvents {
        machine_id: MachineId,
        after: Counter,
        maximum: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeRequest {
    /// Private endpoint identity only; says nothing about native VM power.
    OwnerIdentity {},
    ValidateResources {
        resources: Resources,
    },
    Usage,
    Events {
        after: Counter,
        maximum: u16,
    },
    Process {
        execution_id: ExecutionId,
    },
    Processes,
    Operation {
        operation_id: OperationId,
    },
    Receipt {
        execution_id: ExecutionId,
    },
    ReadOutput {
        execution_id: ExecutionId,
        after: Counter,
        maximum: u32,
    },
    AcknowledgeReceipt {
        operation_id: OperationId,
        execution_id: ExecutionId,
        receipt_digest: Digest,
    },
    Pin {
        operation_id: OperationId,
        execution_id: ExecutionId,
        receipt_digest: Digest,
        pin_id: PinId,
    },
    ReadPin {
        pin_id: PinId,
        after: Counter,
        maximum: u32,
    },
    RecordLoss {
        authorization: AuthorizedLoss,
    },
    Release {
        execution_id: ExecutionId,
        request: ReleaseRequest,
    },
    CleanupReleased {
        execution_id: ExecutionId,
        request_digest: Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceChunk {
    pub sequence: Counter,
    pub offset: Counter,
    pub stream: Stream,
    pub bytes: Vec<u8>,
    pub bytes_digest: Digest,
    pub chain_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidencePage {
    pub after: Counter,
    pub cursor: Counter,
    pub available: Counter,
    pub chunks: Vec<EvidenceChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceChunkMetadata {
    pub sequence: Counter,
    pub offset: Counter,
    pub stream: Stream,
    pub length: u32,
    pub bytes_digest: Digest,
    pub chain_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidencePageMetadata {
    pub after: Counter,
    pub cursor: Counter,
    pub available: Counter,
    pub chunks: Vec<EvidenceChunkMetadata>,
}

impl EvidencePage {
    pub fn into_binary_parts(self) -> Result<(EvidencePageMetadata, Vec<Vec<u8>>), crate::Invalid> {
        let mut metadata = Vec::with_capacity(self.chunks.len());
        let mut bytes = Vec::with_capacity(self.chunks.len());
        for chunk in self.chunks {
            if crate::bytes_digest(&chunk.bytes) != chunk.bytes_digest {
                return Err(crate::Invalid(
                    "evidence chunk bytes disagree with their digest",
                ));
            }
            metadata.push(EvidenceChunkMetadata {
                sequence: chunk.sequence,
                offset: chunk.offset,
                stream: chunk.stream,
                length: u32::try_from(chunk.bytes.len())
                    .map_err(|_| crate::Invalid("evidence chunk exceeds length range"))?,
                bytes_digest: chunk.bytes_digest,
                chain_digest: chunk.chain_digest,
            });
            bytes.push(chunk.bytes);
        }
        let page = EvidencePageMetadata {
            after: self.after,
            cursor: self.cursor,
            available: self.available,
            chunks: metadata,
        };
        page.validate_lengths()?;
        Ok((page, bytes))
    }
}

impl EvidencePageMetadata {
    pub fn validate_lengths(&self) -> Result<usize, crate::Invalid> {
        if self.after > self.cursor || self.cursor > self.available {
            return Err(crate::Invalid("evidence page cursor order is invalid"));
        }
        let mut expected = self.after.get();
        let mut total = 0usize;
        for chunk in &self.chunks {
            let length = chunk.length as usize;
            if length == 0 || length > crate::MAX_STREAM_BYTES || chunk.offset.get() != expected {
                return Err(crate::Invalid("evidence chunk metadata is invalid"));
            }
            total = total
                .checked_add(length)
                .filter(|value| *value <= crate::MAX_CONTROL_BYTES)
                .ok_or(crate::Invalid("evidence page exceeds byte bound"))?;
            expected = expected
                .checked_add(length as u64)
                .ok_or(crate::Invalid("evidence cursor overflow"))?;
        }
        if expected != self.cursor.get() {
            return Err(crate::Invalid("evidence page coverage is incomplete"));
        }
        Ok(total)
    }

    pub fn with_binary_parts(self, bytes: Vec<Vec<u8>>) -> Result<EvidencePage, crate::Invalid> {
        self.validate_lengths()?;
        if self.chunks.len() != bytes.len() {
            return Err(crate::Invalid(
                "evidence data frame count differs from metadata",
            ));
        }
        let mut chunks = Vec::with_capacity(bytes.len());
        for (chunk, bytes) in self.chunks.into_iter().zip(bytes) {
            if bytes.len() != chunk.length as usize
                || crate::bytes_digest(&bytes) != chunk.bytes_digest
            {
                return Err(crate::Invalid("evidence data frame differs from metadata"));
            }
            chunks.push(EvidenceChunk {
                sequence: chunk.sequence,
                offset: chunk.offset,
                stream: chunk.stream,
                bytes,
                bytes_digest: chunk.bytes_digest,
                chain_digest: chunk.chain_digest,
            });
        }
        Ok(EvidencePage {
            after: self.after,
            cursor: self.cursor,
            available: self.available,
            chunks,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeEventValue {
    Machine {
        observation: MachineObservation,
    },
    GuestOperation {
        operation: Operation,
    },
    LifecycleOperation {
        operation: LifecycleOperation,
    },
    ConfigurationOperation {
        operation: ConfigurationOperation,
    },
    Process {
        process: crate::ExecutionSnapshot,
    },
    Output {
        execution_id: ExecutionId,
        boundary: OutputBoundary,
    },
    Receipt {
        execution_id: ExecutionId,
        receipt_digest: Digest,
    },
    EvidenceRelease {
        execution_id: ExecutionId,
        request_digest: Digest,
        cleanup_pending: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvent {
    pub cursor: Counter,
    pub value: RuntimeEventValue,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEventPage {
    pub cursor: Counter,
    pub available: Counter,
    pub events: Vec<RuntimeEvent>,
}

/// Reserve envelope space on both private IPC and the SDK bridge. Entry count
/// alone is not a byte bound: execution observations can carry large argv/env.
pub const MAX_EVENT_PAGE_BYTES: usize = crate::MAX_CONTROL_BYTES - 1024;

/// Guest reports and host-native interruption evidence have distinct provenance.
/// Interruption never fabricates a guest exit, stream EOF, or capture receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionStatus {
    pub execution_id: ExecutionId,
    pub generation: Counter,
    pub report: Observation<crate::ExecutionSnapshot>,
    pub interruption: Option<MachineObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeResponse {
    OwnerIdentity {
        machine_id: MachineId,
    },
    Usage {
        /// Guardian journal fence for this sample. This is not a fresh power
        /// observation and does not claim that native control is reachable.
        generation: Counter,
        usage: crate::ResourceUsage,
    },
    Events {
        page: RuntimeEventPage,
    },
    Process {
        process: Box<ExecutionStatus>,
        request: crate::SpawnRequest,
    },
    Processes {
        processes: Vec<ExecutionStatus>,
    },
    Operation {
        operation: Option<RuntimeOperationRecord>,
    },
    Receipt {
        receipt: Option<Receipt>,
        digest: Option<Digest>,
    },
    Output {
        page: EvidencePage,
    },
    OutputMetadata {
        page: EvidencePageMetadata,
    },
    Release {
        status: ReleaseStatus,
    },
    Complete,
}

impl RuntimeResponse {
    pub fn into_wire_parts(self) -> Result<crate::WireParts<Self>, crate::Invalid> {
        match self {
            Self::Output { page } => {
                let (page, bytes) = page.into_binary_parts()?;
                Ok((Self::OutputMetadata { page }, Some(bytes)))
            }
            Self::OutputMetadata { .. } => Err(crate::Invalid("cannot originate output metadata")),
            response => Ok((response, None)),
        }
    }

    pub fn binary_descriptor(&self) -> Result<Option<Vec<crate::BinaryChunk>>, crate::Invalid> {
        match self {
            Self::OutputMetadata { page } => {
                page.validate_lengths()?;
                let chunks = page
                    .chunks
                    .iter()
                    .map(|chunk| crate::BinaryChunk {
                        length: chunk.length,
                        digest: chunk.bytes_digest.clone(),
                    })
                    .collect::<Vec<_>>();
                crate::validate_binary(&chunks, crate::MAX_CONTROL_BYTES)?;
                Ok(Some(chunks))
            }
            Self::Output { .. } => Err(crate::Invalid("output bytes must use data frames")),
            _ => Ok(None),
        }
    }

    pub fn with_wire_bytes(self, bytes: Vec<Vec<u8>>) -> Result<Self, crate::Invalid> {
        match self {
            Self::OutputMetadata { page } => Ok(Self::Output {
                page: page.with_binary_parts(bytes)?,
            }),
            _ => Err(crate::Invalid("response does not describe binary data")),
        }
    }
}

/// Immutable guardian-owned command history. These records support
/// reconciliation only; acknowledgement is not acceptance and none of the
/// evidence variants delegate the grant that originally admitted them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeOperationRecord {
    Guest {
        operation: Operation,
    },
    ReceiptAcknowledgement {
        operation_id: OperationId,
        execution_id: ExecutionId,
        receipt_digest: Digest,
    },
    EvidencePin {
        operation_id: OperationId,
        pin_id: PinId,
        execution_id: ExecutionId,
        receipt_digest: Digest,
    },
    EvidenceRelease {
        execution_id: ExecutionId,
        request: ReleaseRequest,
        status: ReleaseStatus,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardianInspection {
    pub machine_id: MachineId,
    pub observation: Observation<MachineObservation>,
    pub management: Observation<crate::GuestManagementReport>,
    pub operation: Option<Operation>,
    pub lifecycle_operation: Option<LifecycleOperation>,
    pub configuration_operation: Option<ConfigurationOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuardianResponse {
    Inspection {
        value: Box<GuardianInspection>,
    },
    Dispatch {
        operation: Operation,
    },
    Lifecycle {
        operation: LifecycleOperation,
    },
    Configuration {
        operation: ConfigurationOperation,
    },
    Guest {
        response: crate::GuestServiceResponse,
    },
    NativeSnapshot {
        response: crate::NativeSnapshotResponse,
    },
    Runtime {
        response: RuntimeResponse,
    },
    Rejected {
        category: String,
        message: String,
    },
}

impl GuardianResponse {
    pub fn into_wire_parts(self) -> Result<crate::WireParts<Self>, crate::Invalid> {
        match self {
            Self::Runtime { response } => {
                let (response, bytes) = response.into_wire_parts()?;
                Ok((Self::Runtime { response }, bytes))
            }
            Self::Guest { response } => {
                let (response, bytes) = response.into_wire_parts()?;
                Ok((Self::Guest { response }, bytes))
            }
            response => Ok((response, None)),
        }
    }
    pub fn binary_descriptor(&self) -> Result<Option<Vec<crate::BinaryChunk>>, crate::Invalid> {
        match self {
            Self::Runtime { response } => response.binary_descriptor(),
            Self::Guest { response } => response.binary_descriptor(),
            _ => Ok(None),
        }
    }
    pub fn with_wire_bytes(self, bytes: Vec<Vec<u8>>) -> Result<Self, crate::Invalid> {
        match self {
            Self::Runtime { response } => Ok(Self::Runtime {
                response: response.with_wire_bytes(bytes)?,
            }),
            Self::Guest { response } => Ok(Self::Guest {
                response: response.with_wire_bytes(bytes)?,
            }),
            _ => Err(crate::Invalid("response does not describe binary data")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    Admitted,
    Dispatched,
    NotApplied,
    Applied,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub admission: crate::RequestEnvelope<GuestCommand>,
    pub delivery: Delivery,
    pub evidence_digest: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleOperation {
    pub command: LifecycleCommand,
    pub delivery: Delivery,
    pub evidence_digest: Option<Digest>,
    pub observation: Option<ObservationRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    pub vcpus: Counter,
    #[serde(rename = "memoryMiB")]
    pub memory_mib: Counter,
    pub disk_bytes: Counter,
    pub output_bytes: Counter,
    pub managed_executions: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StdioMode {
    Pipes,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalSize {
    pub columns: u16,
    pub rows: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl TerminalSize {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.columns == 0 || self.rows == 0 {
            return Err(Invalid("terminal rows and columns must be positive"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpawnRequest {
    pub machine_id: MachineId,
    pub generation: Counter,
    pub execution_id: ExecutionId,
    pub operation_id: OperationId,
    pub argv: Vec<String>,
    pub cwd: String,
    pub environment: std::collections::BTreeMap<String, String>,
    pub user: Option<String>,
    pub stdio: StdioMode,
    pub terminal_size: Option<TerminalSize>,
    /// Elapsed workload time after which the supervisor terminates this
    /// process group. This is part of execution semantics, not a client wait
    /// timeout, and therefore survives client disconnects.
    /// Relative workload-active deadline. This guest-owned countdown does not
    /// advance while the VM is paused or suspended.
    pub active_deadline_millis: Option<Counter>,
    /// Absolute host wall-clock boundary. This advances while paused and is
    /// rechecked against Unix time when the workload resumes.
    pub elapsed_deadline_unix_millis: Option<Counter>,
    pub output_bytes: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuestRequest {
    Spawn {
        request: Box<SpawnRequest>,
    },
    CloseInput {
        execution_id: ExecutionId,
        terminal_lease_id: Option<TerminalId>,
    },
    WriteInput {
        execution_id: ExecutionId,
        terminal_lease_id: Option<TerminalId>,
        bytes: Vec<u8>,
    },
    AcquireTerminalInput {
        execution_id: ExecutionId,
        terminal_lease_id: TerminalId,
    },
    ReleaseTerminalInput {
        execution_id: ExecutionId,
        terminal_lease_id: TerminalId,
    },
    ResizeTerminal {
        execution_id: ExecutionId,
        size: TerminalSize,
    },
    Signal {
        execution_id: ExecutionId,
        signal: u8,
        group: bool,
    },
    Terminate {
        execution_id: ExecutionId,
        grace_millis: u32,
    },
    Filesystem {
        request: Box<crate::FilesystemRequest>,
    },
}

impl GuestRequest {
    pub(crate) fn validate_metadata(&self, length: Option<usize>) -> Result<(), Invalid> {
        match (self, length) {
            (Self::WriteInput { bytes, .. }, Some(length))
                if bytes.is_empty() && length > 0 && length <= crate::MAX_STREAM_BYTES =>
            {
                Ok(())
            }
            (Self::Filesystem { request }, length) => request.validate_metadata(length),
            (_, None) => self.validate(),
            _ => Err(Invalid("command metadata has an invalid byte descriptor")),
        }
    }

    pub fn validate(&self) -> Result<(), Invalid> {
        match self {
            Self::Spawn { request } => request.validate(),
            Self::CloseInput { .. }
            | Self::AcquireTerminalInput { .. }
            | Self::ReleaseTerminalInput { .. } => Ok(()),
            Self::WriteInput { bytes, .. } => {
                if bytes.is_empty() || bytes.len() > crate::MAX_STREAM_BYTES {
                    return Err(Invalid("input chunk is outside stream bounds"));
                }
                Ok(())
            }
            Self::ResizeTerminal { size, .. } => size.validate(),
            Self::Signal { signal, .. } => {
                if !(1..=64).contains(signal) {
                    return Err(Invalid("signal is outside the supported range"));
                }
                Ok(())
            }
            Self::Terminate { grace_millis, .. } => {
                if *grace_millis > 60_000 {
                    return Err(Invalid("termination grace exceeds 60 seconds"));
                }
                Ok(())
            }
            Self::Filesystem { request } => request.validate(),
        }
    }
}

impl SpawnRequest {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.argv.is_empty()
            || self.argv.len() > 4096
            || self
                .argv
                .iter()
                .any(|value| value.is_empty() || value.len() > 64 * 1024 || value.contains('\0'))
        {
            return Err(Invalid("argv is empty, oversized, or contains NUL"));
        }
        validate_guest_path(&self.cwd)?;
        if self.environment.len() > 4096
            || self.environment.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > 4096
                    || value.len() > 64 * 1024
                    || name.contains(['=', '\0'])
                    || value.contains('\0')
            })
        {
            return Err(Invalid("environment is oversized or malformed"));
        }
        if self
            .user
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 4096 || value.contains('\0'))
        {
            return Err(Invalid("user is empty, oversized, or contains NUL"));
        }
        match (self.stdio, self.terminal_size) {
            (StdioMode::Pipes, None) => {}
            (StdioMode::Terminal, Some(size)) => size.validate()?,
            _ => return Err(Invalid("terminal size does not match stdio mode")),
        }
        if self.output_bytes == Counter::ZERO {
            return Err(Invalid("process output reservation must be positive"));
        }
        if self
            .active_deadline_millis
            .is_some_and(|value| value == Counter::ZERO || value.get() > 30 * 24 * 60 * 60 * 1000)
        {
            return Err(Invalid(
                "active process deadline must be positive and no more than 30 days",
            ));
        }
        if self
            .elapsed_deadline_unix_millis
            .is_some_and(|value| value == Counter::ZERO)
        {
            return Err(Invalid(
                "elapsed process deadline must be a positive Unix time",
            ));
        }
        Ok(())
    }
}

fn validate_guest_path(value: &str) -> Result<(), Invalid> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') || !value.starts_with('/') {
        return Err(Invalid(
            "guest path must be absolute, bounded, and NUL-free",
        ));
    }
    Ok(())
}

fn validate_guest_path_bytes(value: &[u8]) -> Result<(), Invalid> {
    if value.is_empty() || value.len() > 4096 || value[0] != b'/' || value.contains(&0) {
        return Err(Invalid(
            "guest path bytes must be absolute, bounded, and NUL-free",
        ));
    }
    Ok(())
}
impl Resources {
    pub fn validate(&self) -> Result<(), Invalid> {
        if [
            self.vcpus,
            self.memory_mib,
            self.disk_bytes,
            self.output_bytes,
            self.managed_executions,
        ]
        .contains(&Counter::ZERO)
        {
            return Err(Invalid("resource reservations must be positive"));
        }
        Ok(())
    }
    pub fn checked_add(&self, other: &Self) -> Result<Self, Invalid> {
        Ok(Self {
            vcpus: self.vcpus.checked_add(other.vcpus.get())?,
            memory_mib: self.memory_mib.checked_add(other.memory_mib.get())?,
            disk_bytes: self.disk_bytes.checked_add(other.disk_bytes.get())?,
            output_bytes: self.output_bytes.checked_add(other.output_bytes.get())?,
            managed_executions: self
                .managed_executions
                .checked_add(other.managed_executions.get())?,
        })
    }
    pub fn within(&self, limit: &Self) -> bool {
        self.vcpus <= limit.vcpus
            && self.memory_mib <= limit.memory_mib
            && self.disk_bytes <= limit.disk_bytes
            && self.output_bytes <= limit.output_bytes
            && self.managed_executions <= limit.managed_executions
    }
    pub fn zero() -> Self {
        Self {
            vcpus: Counter::ZERO,
            memory_mib: Counter::ZERO,
            disk_bytes: Counter::ZERO,
            output_bytes: Counter::ZERO,
            managed_executions: Counter::ZERO,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stream {
    Stdout,
    Stderr,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputBoundary {
    pub final_cursor: Counter,
    pub chunks: Counter,
    pub stdout_bytes: Counter,
    pub stderr_bytes: Counter,
    pub terminal_bytes: Counter,
    pub omitted_bytes: Counter,
    pub final_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExecutionOutcome {
    Exit { code: i32 },
    Signal { signal: u32 },
    DeadlineExceeded,
    SpawnFailed { reason: Digest },
    Interrupted { evidence: Digest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub machine_id: MachineId,
    pub generation: Counter,
    pub execution_id: ExecutionId,
    pub operation_id: OperationId,
    pub request_digest: Digest,
    pub outcome: ExecutionOutcome,
    pub output: OutputBoundary,
    pub cleanup_digest: Digest,
    pub accounting_digest: Digest,
}

/// A trusted consumer's durable-store assertion, not proof that a URL contains bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureCommitment {
    pub store_id: StoreId,
    pub commitment_id: CommitmentId,
    pub manifest_digest: Digest,
    pub receipt_digest: Digest,
    pub output: OutputBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReleaseDisposition {
    CompleteCapture { commitment: CaptureCommitment },
    ContinuingRetention { pin: PinId },
    AuthorizedLoss { authorization: CommitmentId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseRequest {
    pub operation_id: OperationId,
    pub receipt_digest: Digest,
    /// The initial API releases the whole receipt's output, not selected ranges.
    pub output: OutputBoundary,
    pub disposition: ReleaseDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseStatus {
    pub request_digest: Digest,
    pub cleanup_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmEngine {
    Firecracker,
    AppleVirtualization,
    HyperV,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Qualification {
    Qualified { evidence: Digest },
    Unqualified { reasons: Vec<String> },
}

/// Implementation support and retained qualification are different facts.
/// Unsupported never means "supported but not yet tested".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Capability {
    Supported { qualification: Qualification },
    Unsupported { reasons: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestPowerCapabilities {
    pub shutdown: Capability,
    pub reboot: Capability,
}
