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
    DiskId,
    TerminalId,
    CheckpointId,
    ExposureId,
    TransferId,
    ImageId,
    SecretId,
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
    pub sandbox_id: SandboxId,
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
    pub sandbox_id: SandboxId,
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
    pub sandbox_id: SandboxId,
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
    pub request: WorkloadRequest,
    pub request_digest: Digest,
}

impl Mutation {
    pub fn new(
        sandbox_id: SandboxId,
        epoch: Counter,
        operation_id: OperationId,
        grant_id: GrantId,
        expected_revision: Counter,
        request: WorkloadRequest,
    ) -> Result<Self, Invalid> {
        request.validate()?;
        let request_digest = mutation_digest(
            &sandbox_id,
            epoch,
            &operation_id,
            &grant_id,
            expected_revision,
            &request,
        )?;
        Ok(Self {
            sandbox_id,
            epoch,
            operation_id,
            grant_id,
            expected_revision,
            request,
            request_digest,
        })
    }

    pub fn validate(&self) -> Result<(), Invalid> {
        if self.epoch == Counter::ZERO || self.expected_revision == Counter::ZERO {
            return Err(Invalid("mutation epoch and revision must be positive"));
        }
        self.request.validate()?;
        if let WorkloadRequest::Spawn { request } = &self.request
            && (request.sandbox_id != self.sandbox_id
                || request.epoch != self.epoch
                || request.operation_id != self.operation_id)
        {
            return Err(Invalid("spawn identity does not match its mutation"));
        }
        let expected = mutation_digest(
            &self.sandbox_id,
            self.epoch,
            &self.operation_id,
            &self.grant_id,
            self.expected_revision,
            &self.request,
        )?;
        if self.request_digest != expected {
            return Err(Invalid("mutation digest does not bind its request"));
        }
        Ok(())
    }

    pub fn required_capability(&self) -> Capability {
        self.request.required_capability()
    }
}

impl WorkloadRequest {
    pub fn required_capability(&self) -> Capability {
        match self {
            WorkloadRequest::Spawn { request }
                if request.user.as_deref().is_some_and(is_root_user) =>
            {
                Capability::WorkloadAdmin
            }
            WorkloadRequest::Spawn { .. }
            | WorkloadRequest::WriteInput { .. }
            | WorkloadRequest::CloseInput { .. }
            | WorkloadRequest::AcquireTerminalInput { .. }
            | WorkloadRequest::ReleaseTerminalInput { .. }
            | WorkloadRequest::ResizeTerminal { .. }
            | WorkloadRequest::Signal { .. }
            | WorkloadRequest::Terminate { .. } => Capability::Spawn,
            WorkloadRequest::Filesystem { request } => request.required_capability(),
        }
    }
}

fn is_root_user(value: &str) -> bool {
    value == "root" || value == "0" || value.starts_with("0:")
}

fn mutation_digest(
    sandbox_id: &SandboxId,
    epoch: Counter,
    operation_id: &OperationId,
    grant_id: &GrantId,
    expected_revision: Counter,
    request: &WorkloadRequest,
) -> Result<Digest, Invalid> {
    crate::digest(
        crate::Domain::Operation,
        &(
            "sandsurf-workload-mutation-v1",
            sandbox_id,
            epoch,
            operation_id,
            grant_id,
            expected_revision,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GuardianRequest {
    Inspect {
        sandbox_id: SandboxId,
        operation_id: Option<OperationId>,
    },
    Dispatch {
        authorization: AuthorizedMutation,
    },
    Transition {
        authorization: AuthorizedLifecycle,
    },
    Configure {
        authorization: AuthorizedConfiguration,
    },
    Guest {
        sandbox_id: SandboxId,
        request: crate::GuestServiceRequest,
    },
    NativeCheckpoint {
        sandbox_id: SandboxId,
        request: crate::NativeCheckpointRequest,
    },
    Runtime {
        sandbox_id: SandboxId,
        request: RuntimeRequest,
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
    Events {
        after: Counter,
        maximum: u16,
    },
    Process {
        process_id: ProcessId,
    },
    Processes,
    Operation {
        operation_id: OperationId,
    },
    Receipt {
        process_id: ProcessId,
    },
    ReadOutput {
        process_id: ProcessId,
        after: Counter,
        maximum: u32,
    },
    AcknowledgeReceipt {
        operation_id: OperationId,
        process_id: ProcessId,
        receipt_digest: Digest,
    },
    Pin {
        operation_id: OperationId,
        process_id: ProcessId,
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
        process_id: ProcessId,
        request: ReleaseRequest,
    },
    CleanupReleased {
        process_id: ProcessId,
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
    WorkloadOperation {
        operation: Operation,
    },
    LifecycleOperation {
        operation: LifecycleOperation,
    },
    ConfigurationOperation {
        operation: ConfigurationOperation,
    },
    Process {
        process: crate::ProcessSnapshot,
    },
    Output {
        process_id: ProcessId,
        boundary: OutputBoundary,
    },
    Receipt {
        process_id: ProcessId,
        receipt_digest: Digest,
    },
    EvidenceRelease {
        process_id: ProcessId,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RuntimeResponse {
    Events {
        page: RuntimeEventPage,
    },
    Process {
        process: Option<Observation<crate::ProcessSnapshot>>,
    },
    Processes {
        processes: Vec<Observation<crate::ProcessSnapshot>>,
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
    Release {
        status: ReleaseStatus,
    },
    Complete,
}

/// Immutable guardian-owned mutation history. These records support
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
    Workload {
        operation: Operation,
    },
    ReceiptAcknowledgement {
        operation_id: OperationId,
        process_id: ProcessId,
        receipt_digest: Digest,
    },
    EvidencePin {
        operation_id: OperationId,
        pin_id: PinId,
        process_id: ProcessId,
        receipt_digest: Digest,
    },
    EvidenceRelease {
        process_id: ProcessId,
        request: ReleaseRequest,
        status: ReleaseStatus,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardianInspection {
    pub sandbox_id: SandboxId,
    pub observation: Observation<MachineObservation>,
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
    NativeCheckpoint {
        response: crate::NativeCheckpointResponse,
    },
    Runtime {
        response: RuntimeResponse,
    },
    Rejected {
        category: String,
        message: String,
    },
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
    pub processes: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessLifetime {
    Job,
    Sandbox,
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
    pub sandbox_id: SandboxId,
    pub epoch: Counter,
    pub process_id: ProcessId,
    pub operation_id: OperationId,
    pub argv: Vec<String>,
    pub cwd: String,
    pub environment: std::collections::BTreeMap<String, String>,
    pub user: Option<String>,
    pub stdio: StdioMode,
    pub terminal_size: Option<TerminalSize>,
    pub lifetime: ProcessLifetime,
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
pub enum WorkloadRequest {
    Spawn {
        request: Box<SpawnRequest>,
    },
    CloseInput {
        process_id: ProcessId,
        terminal_lease_id: Option<TerminalId>,
    },
    WriteInput {
        process_id: ProcessId,
        terminal_lease_id: Option<TerminalId>,
        bytes: Vec<u8>,
    },
    AcquireTerminalInput {
        process_id: ProcessId,
        terminal_lease_id: TerminalId,
    },
    ReleaseTerminalInput {
        process_id: ProcessId,
        terminal_lease_id: TerminalId,
    },
    ResizeTerminal {
        process_id: ProcessId,
        size: TerminalSize,
    },
    Signal {
        process_id: ProcessId,
        signal: u8,
        group: bool,
    },
    Terminate {
        process_id: ProcessId,
        grace_millis: u32,
    },
    Filesystem {
        request: Box<crate::FilesystemRequest>,
    },
}

impl WorkloadRequest {
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
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\0')
        || !value.starts_with('/')
        || value.split('/').any(|part| part == "..")
    {
        return Err(Invalid(
            "guest path must be absolute, bounded, and normalized",
        ));
    }
    Ok(())
}

fn validate_guest_path_bytes(value: &[u8]) -> Result<(), Invalid> {
    if value.is_empty()
        || value.len() > 4096
        || value[0] != b'/'
        || value.contains(&0)
        || (value.len() > 1 && value.ends_with(b"/"))
        || value
            .split(|byte| *byte == b'/')
            .skip(1)
            .any(|part| part.is_empty() || matches!(part, b"." | b".."))
    {
        return Err(Invalid(
            "guest path bytes must be absolute, bounded, and normalized",
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
    DeadlineExceeded,
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
