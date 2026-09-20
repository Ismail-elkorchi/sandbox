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
    SandboxId,
    ProcessId,
    OperationId,
    GrantId,
    CommitmentId,
    StoreId,
    PinId,
    DiskId
);

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
    pub sandbox_id: SandboxId,
    pub operation_id: OperationId,
    pub desired: DesiredState,
    pub revision: Counter,
    pub request_digest: Digest,
    /// An immutable reference, not a cached authoritative running/stopped flag.
    pub completion: Option<ObservationRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationRef {
    pub sandbox_id: SandboxId,
    pub epoch: Counter,
    pub sequence: Counter,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineObservation {
    pub sandbox_id: SandboxId,
    pub epoch: Counter,
    pub sequence: Counter,
    pub state: MachineState,
    pub applied_revision: Counter,
    pub operation_id: OperationId,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Spawn,
    ReadFiles,
    WriteFiles,
    WorkloadAdmin,
    Network,
    ExposePort,
    DeliverSecret,
    ApplyToHost,
    IncreaseResources,
    Checkpoint,
    Fork,
    ReleaseEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub id: GrantId,
    pub sandbox_id: SandboxId,
    pub capability: Capability,
    /// Binds the normalized scope, not a model-supplied policy label.
    pub scope_digest: Digest,
    pub revision: Counter,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mutation {
    pub sandbox_id: SandboxId,
    pub epoch: Counter,
    pub operation_id: OperationId,
    pub grant_id: GrantId,
    pub expected_revision: Counter,
    pub request_digest: Digest,
}

/// The guardian pins this host identity and verification key. It is not a grant set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBinding {
    pub host_id: HostId,
    pub key_id: Digest,
    pub public_key: AuthorityPublicKey,
}

/// Exact, immutable authority for one mutation. Only the host service sends this
/// over its private guardian channel; applications retain operation/grant IDs and
/// expected revisions, never this envelope as independently exercisable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedMutationStatement {
    pub version: u16,
    pub host_id: HostId,
    pub key_id: Digest,
    pub mutation: Mutation,
    pub capability: Capability,
    pub scope_digest: Digest,
    pub grant_revision: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedMutation {
    pub statement: AuthorizedMutationStatement,
    pub signature: AuthoritySignature,
}

/// Host authorization for loss of one complete receipt-bound output scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedLossStatement {
    pub version: u16,
    pub host_id: HostId,
    pub key_id: Digest,
    pub sandbox_id: SandboxId,
    pub process_id: ProcessId,
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
    pub request: Mutation,
    pub capability: Capability,
    pub delivery: Delivery,
    pub evidence_digest: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    pub vcpus: Counter,
    pub memory_mib: Counter,
    pub disk_bytes: Counter,
    pub output_bytes: Counter,
    pub processes: Counter,
}
impl Resources {
    pub fn validate(&self) -> Result<(), Invalid> {
        if [
            self.vcpus,
            self.memory_mib,
            self.disk_bytes,
            self.output_bytes,
            self.processes,
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
            processes: self.processes.checked_add(other.processes.get())?,
        })
    }
    pub fn within(&self, limit: &Self) -> bool {
        self.vcpus <= limit.vcpus
            && self.memory_mib <= limit.memory_mib
            && self.disk_bytes <= limit.disk_bytes
            && self.output_bytes <= limit.output_bytes
            && self.processes <= limit.processes
    }
    pub fn zero() -> Self {
        Self {
            vcpus: Counter::ZERO,
            memory_mib: Counter::ZERO,
            disk_bytes: Counter::ZERO,
            output_bytes: Counter::ZERO,
            processes: Counter::ZERO,
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
pub enum ProcessOutcome {
    Exit { code: i32 },
    Signal { signal: u32 },
    SpawnFailed { reason: Digest },
    Interrupted { evidence: Digest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub sandbox_id: SandboxId,
    pub epoch: Counter,
    pub process_id: ProcessId,
    pub operation_id: OperationId,
    pub request_digest: Digest,
    pub outcome: ProcessOutcome,
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
