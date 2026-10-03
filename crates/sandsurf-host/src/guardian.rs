//! Guardian orchestration owned by the host service implementation.

//! Internal host/guardian control service.
//!
//! Applications talk to the host API, which remains the only grant and desired-
//! lifecycle authority. The host sends exact signed operations to a separately
//! owned guardian. The guardian pins one host key and stores observations and
//! operation outcomes, but never reconstructs or mutates a grant set.

use sandsurf_protocol::*;
use sandsurf_state::{DispatchDecision, HostCatalog, RuntimeJournal};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[path = "observation_stream.rs"]
pub(crate) mod observation_stream;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use observation_stream::ObservationStream;
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub const SERVICE_VERSION: u16 = 1;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
// Full-state VM capture/restore is synchronous at this private ownership
// boundary and can include bounded hashing of memory plus multiple disks.
// Match the host's operation bound so transport timeout never implies that an
// exact identity-bound operation stopped running.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const MAX_GUARDIAN_CONNECTIONS: usize = 32;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    State(sandsurf_state::Error),
    Protocol(&'static str),
    Rejected { category: String, message: String },
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "guardian transport: {error}"),
            Self::Json(error) => write!(output, "guardian message: {error}"),
            Self::State(error) => write!(output, "guardian journal: {error}"),
            Self::Protocol(message) | Self::Unsupported(message) => output.write_str(message),
            Self::Rejected { category, message } => {
                write!(output, "guardian rejected ({category}): {message}")
            }
        }
    }
}

impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_state::Error> for Error {
    fn from(value: sandsurf_state::Error) -> Self {
        Self::State(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// A native/guest effect returns attribution evidence and an honest delivery
/// conclusion. `Unknown` is retained when dispatch may have happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectOutcome {
    Applied(Digest),
    NotApplied(Digest),
    Unknown,
}

pub use sandsurf_machine::{MachineOutcome as LifecycleEffect, MachineTransition};

use crate::guest_worker::{ExecutionHint, GuestJob, GuestJobResult};
pub use crate::guest_worker::{ExecutionHints, GuestPoll, GuestProgress};

pub use crate::boot_preparation::{BootPreparation, PreparedBoot};
pub use crate::restore_preparation::{PreparedRestore, RestorePreparation};

pub trait GuardianEffect {
    fn staged_restore_binding(&self) -> Option<&Digest> {
        None
    }
    fn restore_preparation(
        &self,
        _snapshot_id: SnapshotId,
        _manifest_digest: Digest,
        _system_disk: SnapshotArtifact,
        _expected: FullSnapshotMetadata,
    ) -> Result<RestorePreparation> {
        Err(Error::Unsupported(
            "native full-state restore is unavailable",
        ))
    }
    fn install_prepared_restore(
        &mut self,
        _prepared: PreparedRestore,
    ) -> Result<NativeSnapshotResponse> {
        Err(Error::Unsupported(
            "native full-state restore is unavailable",
        ))
    }
    fn boot_preparation(
        &self,
        _command: &LifecycleCommand,
        _current: Option<&MachineObservation>,
    ) -> Result<Option<BootPreparation>> {
        Ok(None)
    }
    fn install_prepared_boot(&mut self, _prepared: PreparedBoot) -> Result<()> {
        Err(Error::Unsupported(
            "native owner does not consume prepared boot artifacts",
        ))
    }
    fn guest_reset_configuration(&self) -> Result<RuntimeConfiguration> {
        Err(Error::Unsupported(
            "native guest reset configuration is unavailable",
        ))
    }
    fn take_console(&mut self) -> Option<sandsurf_machine::NativeConsole> {
        None
    }
    fn take_guest_reset(&mut self) -> Option<Digest> {
        None
    }
    /// The caller has durably advanced the generation before this cold boot.
    /// Native reset is within the existing applied envelope, not new intent.
    fn recover_guest_reset(&mut self, _current: &MachineObservation) -> Result<Digest> {
        Err(Error::Unsupported(
            "native guest reset recovery is unsupported",
        ))
    }
    /// The durable capture transaction owns the pause, including uncertain
    /// native delivery. A volatile native "paused" flag is not this authority.
    fn capture_owner(&self) -> Result<Option<OperationId>>;
    fn guest_driver(&mut self) -> Box<dyn GuestDriver>;
    /// Volatile I/O coordination only; this does not decide lifecycle or grants.
    fn guest_io_admissible(&self) -> bool {
        true
    }
    fn guest_poll_allowed(&self) -> bool {
        matches!(self.capture_owner(), Ok(None))
    }
    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> LifecycleEffect;
    fn configure(
        &mut self,
        _command: &ConfigurationCommand,
        _current: &MachineObservation,
    ) -> EffectOutcome {
        EffectOutcome::NotApplied(bytes_digest(b"configuration-installation-unsupported"))
    }
    fn validate_resources(
        &self,
        _resources: &sandsurf_protocol::Resources,
        _current: &MachineObservation,
    ) -> Result<()> {
        Err(Error::Unsupported(
            "native resource reconfiguration is unsupported",
        ))
    }
    fn resource_usage(&mut self) -> Result<ResourceUsage> {
        Err(Error::Unsupported(
            "native resource accounting is not implemented",
        ))
    }
    fn resource_envelope(&self) -> Option<sandsurf_protocol::Resources> {
        None
    }
    fn assess_resources(
        &self,
        _resources: &sandsurf_protocol::Resources,
        _current: &MachineObservation,
    ) -> sandsurf_protocol::ResourceChangeAssessment {
        sandsurf_protocol::ResourceChangeAssessment {
            mode: sandsurf_protocol::ResourceChangeMode::Unsupported,
            reasons: vec!["native resource enforcement is unsupported".into()],
        }
    }
    fn native_snapshot(
        &mut self,
        _request: NativeSnapshotRequest,
        _journal: &mut RuntimeJournal,
    ) -> Result<NativeSnapshotResponse> {
        Err(Error::Unsupported(
            "native full-state snapshoting is not implemented",
        ))
    }
    fn rebind_restored_runtime(
        &mut self,
        _journal: &mut RuntimeJournal,
        _generation: Counter,
    ) -> Result<()> {
        Ok(())
    }
    /// Retire admitted integration only after native stop/destruction. This
    /// cannot be inferred from a missing management connection.
    fn retire_restore_intent(&mut self) -> Result<()> {
        Ok(())
    }
    fn observe_power(&mut self) -> Result<Option<sandsurf_machine::NativePowerObservation>>;
    /// Externally verifiable absence of a native owner after handle loss. A
    /// driver without a custody mechanism cannot turn absence into shutdown.
    fn observe_detachment(&self) -> Result<Option<Digest>> {
        Ok(None)
    }
}

/// Guest/defaults dispatch is deliberately separate from native VM ownership.
/// A defaults driver cannot report or mutate machine lifecycle state.
pub trait GuestDriver: Send {
    fn dispatch(&mut self, command: &GuestCommand) -> EffectOutcome;
    fn poll(&mut self, _hints: &ExecutionHints) -> Result<crate::guest_worker::GuestPoll> {
        Ok(crate::guest_worker::GuestPoll::default())
    }
    fn query(&mut self, _request: GuestServiceRequest) -> Result<GuestServiceResponse> {
        Err(Error::Unsupported("guest query is not implemented"))
    }
}

/// Restart only within the already applied envelope and the durably committed
/// reset generation. Guest reset cannot acquire new host lifecycle authority.
pub(crate) fn restart_after_native_reset<E: GuardianEffect>(
    effect: &mut E,
    current: &MachineObservation,
    configuration: sandsurf_protocol::RuntimeConfiguration,
) -> Result<Digest> {
    if current.state != MachineState::Starting || current.generation.get() < 2 {
        return Err(Error::Protocol(
            "native reset has no committed generation fence",
        ));
    }
    let command = reset_command(current, configuration)?;
    let previous = reset_previous(current)?;
    match effect.transition(&command, Some(&previous)) {
        LifecycleEffect::Observed(values)
            if values.last().is_some_and(|value| {
                value.generation == current.generation && value.state == MachineState::Running
            }) =>
        {
            Ok(values
                .last()
                .expect("checked reset observation")
                .evidence_digest
                .clone())
        }
        _ => Err(Error::Protocol("native guest reset recovery failed")),
    }
}

fn reset_command(
    starting: &MachineObservation,
    configuration: RuntimeConfiguration,
) -> Result<LifecycleCommand> {
    Ok(LifecycleCommand {
        machine_id: starting.machine_id.clone(),
        operation_id: OperationId::try_from(format!("native-reset-{}", starting.generation.get()))
            .map_err(|_| Error::Protocol("reset identity overflow"))?,
        desired: DesiredState::Running,
        revision: starting.applied_revision,
        request_digest: starting.evidence_digest.clone(),
        configuration,
    })
}

fn reset_previous(starting: &MachineObservation) -> Result<MachineObservation> {
    Ok(MachineObservation {
        generation: Counter::try_from(
            starting
                .generation
                .get()
                .checked_sub(1)
                .ok_or(Error::Protocol("reset generation invalid"))?,
        )
        .map_err(|_| Error::Protocol("reset generation invalid"))?,
        state: MachineState::Stopped,
        ..starting.clone()
    })
}

#[cfg(test)]
#[path = "boot_preparation_tests.rs"]
mod boot_preparation_tests;

pub struct Guardian<E> {
    journal: RuntimeJournal,
    // Native ownership ends at confirmed destruction. The durable ledger can
    // remain available without image files, virtual hardware, or a guest.
    effect: Option<E>,
    management_seen: Option<std::time::Instant>,
    execution_seen: std::collections::BTreeMap<ExecutionId, std::time::Instant>,
    console: crate::console::ConsoleStore,
    // Scheduling only. Durable operation admission and the authority fence
    // decide whether a completed offline job can ever start virtual hardware.
    offline_in_flight: bool,
    reset_pending: Option<MachineObservation>,
}

enum BootAdmission {
    Ready(GuardianResponse),
    Queued {
        input: BootPreparation,
        pending: BootPending,
    },
}

enum BootPending {
    Lifecycle(Box<AuthorizedLifecycle>),
    Reset(MachineObservation),
}

struct RestorePending {
    observation: MachineObservation,
    accepted_revision: Counter,
    input: RestorePreparation,
}
enum RestoreAdmission {
    Ready(GuardianResponse),
    Queued {
        input: RestorePreparation,
        pending: Box<RestorePending>,
    },
}

enum GuestAdmission {
    Ready(GuardianResponse),
    Queued {
        job: GuestJob,
        pending: GuestPending,
    },
}

enum GuestPending {
    Dispatch {
        operation_id: OperationId,
        request_digest: Digest,
    },
    Query {
        generation: Counter,
    },
    Poll {
        generation: Counter,
    },
}

fn rejected(error: Error) -> GuardianResponse {
    GuardianResponse::Rejected {
        category: error_category(&error).to_owned(),
        message: error.to_string(),
    }
}

impl<E: GuardianEffect> Guardian<E> {
    fn begin_restore(
        &mut self,
        machine_id: MachineId,
        request: NativeSnapshotRequest,
    ) -> Result<RestoreAdmission> {
        if &machine_id != self.journal.machine_id() {
            return Err(Error::Protocol("guardian machine identity mismatch"));
        }
        if self.offline_in_flight {
            return Err(Error::Rejected {
                category: "capacity".into(),
                message: "offline preparation is already in flight".into(),
            });
        }
        self.refresh_native_observation()?;
        let observation = self
            .journal
            .last_observation()?
            .ok_or(Error::Protocol("restore has no native machine observation"))?
            .value()
            .clone();
        if observation.state != MachineState::Suspended {
            return Err(Error::Protocol(
                "full restore requires a suspended native computer",
            ));
        }
        let accepted_revision = self.journal.accepted_revision()?;
        if accepted_revision != observation.applied_revision {
            return Err(Error::Protocol(
                "full restore requires all accepted host authority to be applied",
            ));
        }
        let NativeSnapshotRequest::StageRestore {
            snapshot_id,
            manifest_digest,
            system_disk,
            expected,
        } = request
        else {
            return Err(Error::Protocol(
                "offline restore requires a full-state input",
            ));
        };
        let input = self
            .effect
            .as_ref()
            .ok_or(Error::Unsupported("native owner is unavailable"))?
            .restore_preparation(snapshot_id, manifest_digest, system_disk, *expected)?;
        if let Some(binding) = self
            .effect
            .as_ref()
            .and_then(GuardianEffect::staged_restore_binding)
        {
            if binding != &input.binding()? {
                return Err(Error::Protocol(
                    "another prepared restore owns native custody",
                ));
            }
            return Ok(RestoreAdmission::Ready(GuardianResponse::NativeSnapshot {
                response: input.evidence()?,
            }));
        }
        let pending = Box::new(RestorePending {
            observation,
            accepted_revision,
            input: input.clone(),
        });
        self.offline_in_flight = true;
        Ok(RestoreAdmission::Queued { input, pending })
    }

    fn finish_restore(
        &mut self,
        pending: Box<RestorePending>,
        result: Result<PreparedRestore>,
    ) -> Result<GuardianResponse> {
        self.offline_in_flight = false;
        self.refresh_native_observation()?;
        if self.journal.accepted_revision()? != pending.accepted_revision
            || self
                .journal
                .last_observation()?
                .as_ref()
                .map(|value| value.value())
                != Some(&pending.observation)
        {
            return Err(Error::Protocol(
                "offline restore was superseded by native state or host authority",
            ));
        }
        let prepared = result?;
        if prepared.input != pending.input {
            return Err(Error::Protocol(
                "offline restore completion binding changed",
            ));
        }
        let response = self
            .effect
            .as_mut()
            .ok_or(Error::Unsupported("native owner is unavailable"))?
            .install_prepared_restore(prepared)?;
        Ok(GuardianResponse::NativeSnapshot { response })
    }
    pub fn new(journal: RuntimeJournal, effect: E) -> Self {
        let console = crate::console::ConsoleStore::new(journal.retention_root());
        Self {
            journal,
            effect: Some(effect),
            management_seen: None,
            execution_seen: std::collections::BTreeMap::new(),
            console,
            offline_in_flight: false,
            reset_pending: None,
        }
    }

    pub fn retained(journal: RuntimeJournal) -> Result<Self> {
        if journal
            .last_observation()?
            .is_none_or(|value| value.value().state != MachineState::Destroyed)
        {
            return Err(Error::Protocol(
                "retained evidence requires confirmed native destruction",
            ));
        }
        let console = crate::console::ConsoleStore::new(journal.retention_root());
        Ok(Self {
            journal,
            effect: None,
            management_seen: None,
            execution_seen: std::collections::BTreeMap::new(),
            console,
            offline_in_flight: false,
            reset_pending: None,
        })
    }

    fn begin_guest(&mut self, request: GuardianRequest) -> Result<GuestAdmission> {
        if self.effect.is_none() {
            return Err(Error::Unsupported(
                "destroyed machine has no guest transport",
            ));
        }
        if !self.effect.as_ref().unwrap().guest_io_admissible() {
            return Err(Error::Unsupported(
                "native capture owns the guest I/O boundary",
            ));
        }
        match request {
            GuardianRequest::Dispatch { command } => {
                self.journal.admit(command.clone())?;
                if let GuestRequest::Spawn { request } = &command.request {
                    self.journal.admit_process(
                        request.execution_id.clone(),
                        &request.operation_id,
                        request.output_bytes,
                        request.stdio == StdioMode::Terminal,
                    )?;
                }
                let pending = GuestPending::Dispatch {
                    operation_id: command.operation_id.clone(),
                    request_digest: command.request_digest.clone(),
                };
                match self.journal.begin_dispatch(command)? {
                    DispatchDecision::Reconcile(operation) => {
                        Ok(GuestAdmission::Ready(GuardianResponse::Dispatch {
                            operation,
                        }))
                    }
                    DispatchDecision::Perform(permit) => {
                        // Commit dispatch on the owner, then transfer only immutable input.
                        let job = permit.perform(|command| GuestJob::Dispatch(command.clone()));
                        Ok(GuestAdmission::Queued { job, pending })
                    }
                }
            }
            GuardianRequest::QueryGuest {
                machine_id,
                generation,
                request,
            } => {
                let current = self.journal.last_observation()?;
                if &machine_id != self.journal.machine_id()
                    || !current.is_some_and(|value| {
                        value.value().generation == generation
                            && value.value().state == MachineState::Running
                    })
                    || !matches!(
                        request,
                        GuestServiceRequest::FilesystemQuery { .. }
                            | GuestServiceRequest::Operation { .. }
                            | GuestServiceRequest::Process { .. }
                            | GuestServiceRequest::Processes
                            | GuestServiceRequest::ReadOutput { .. }
                    )
                {
                    return Err(Error::Protocol(
                        "stale generation or non-session guest query",
                    ));
                }
                Ok(GuestAdmission::Queued {
                    job: GuestJob::Query(request),
                    pending: GuestPending::Query { generation },
                })
            }
            GuardianRequest::Guest {
                machine_id,
                request,
            } => {
                if &machine_id != self.journal.machine_id()
                    || matches!(request, GuestServiceRequest::Dispatch { .. })
                {
                    return Err(Error::Protocol("unauthorized private guest request"));
                }
                let generation = self
                    .journal
                    .last_observation()?
                    .ok_or(Error::Protocol("guest machine generation is unavailable"))?
                    .value()
                    .generation;
                Ok(GuestAdmission::Queued {
                    job: GuestJob::Query(request),
                    pending: GuestPending::Query { generation },
                })
            }
            _ => Err(Error::Protocol("request is not a guest operation")),
        }
    }

    fn poll_job(&self) -> Result<Option<GuestJob>> {
        let Some(current) = self.journal.last_observation()? else {
            return Ok(None);
        };
        if current.value().state != MachineState::Running
            || !self
                .effect
                .as_ref()
                .is_some_and(|effect| effect.guest_poll_allowed())
        {
            return Ok(None);
        }
        let generation = current.value().generation;
        let mut hints = ExecutionHints::new();
        for (id, boundary) in self.journal.unsettled_execution_boundaries(generation)? {
            hints.insert(
                id,
                ExecutionHint {
                    generation,
                    boundary,
                    settled: false,
                },
            );
        }
        Ok(Some(GuestJob::Poll(hints)))
    }

    fn finish_guest(
        &mut self,
        pending: GuestPending,
        result: GuestJobResult,
    ) -> Result<Option<GuardianResponse>> {
        match (pending, result) {
            (
                GuestPending::Dispatch {
                    operation_id,
                    request_digest,
                },
                GuestJobResult::Dispatch(outcome),
            ) => {
                let (delivery, evidence) = match outcome {
                    EffectOutcome::Applied(evidence) => (Delivery::Applied, Some(evidence)),
                    EffectOutcome::NotApplied(evidence) => (Delivery::NotApplied, Some(evidence)),
                    EffectOutcome::Unknown => (Delivery::Unknown, None),
                };
                let operation = self.journal.record_delivery(
                    &operation_id,
                    &request_digest,
                    delivery,
                    evidence,
                )?;
                Ok(Some(GuardianResponse::Dispatch { operation }))
            }
            (GuestPending::Query { generation }, GuestJobResult::Query(response)) => {
                if self
                    .journal
                    .last_observation()?
                    .is_none_or(|current| current.value().generation != generation)
                {
                    return Err(Error::Protocol(
                        "guest response belongs to a superseded generation; delivery may have occurred",
                    ));
                }
                Ok(Some(GuardianResponse::Guest {
                    response: response?,
                }))
            }
            (GuestPending::Poll { generation }, GuestJobResult::Progress(progress)) => {
                if self
                    .journal
                    .last_observation()?
                    .is_none_or(|current| current.value().generation != generation)
                {
                    return Ok(None);
                }
                self.management_seen = None;
                let progress = progress?;
                if let Some(identity) = progress.identity {
                    let millis = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| Error::Protocol("host observation clock predates Unix time"))?
                        .as_millis();
                    let observed_unix_millis =
                        Counter::try_from(u64::try_from(millis).map_err(|_| {
                            Error::Protocol("management observation clock overflow")
                        })?)
                        .map_err(|_| Error::Protocol("management observation clock overflow"))?;
                    self.journal
                        .record_management_report(GuestManagementReport {
                            generation,
                            identity,
                            observed_unix_millis,
                        })?;
                    self.management_seen = Some(std::time::Instant::now());
                }
                for progress in progress.executions {
                    self.commit_guest_progress(progress)?;
                }
                Ok(None)
            }
            _ => Err(Error::Protocol(
                "guest worker result does not match its admission",
            )),
        }
    }

    fn commit_guest_progress(&mut self, progress: GuestProgress) -> Result<()> {
        let snapshot = progress.snapshot;
        if self
            .journal
            .last_observation()?
            .is_none_or(|current| current.value().generation != snapshot.request.generation)
        {
            return Ok(()); // In-flight observations never rebind a historical execution.
        }
        let id = &snapshot.request.execution_id;
        self.journal.observe_process(&snapshot)?;
        self.execution_seen
            .insert(id.clone(), std::time::Instant::now());
        let mut committed = self.journal.process_boundary(id)?;
        if let Some(page) = progress.output {
            if page.required_bytes.is_some() {
                return Err(Error::Protocol(
                    "guest output exceeds the negotiated page bound",
                ));
            }
            for chunk in page.chunks {
                if chunk.cursor != committed.final_cursor {
                    return Err(Error::Protocol("guest output is not contiguous"));
                }
                committed = self.journal.append_output(
                    id,
                    committed
                        .chunks
                        .next()
                        .map_err(|_| Error::Protocol("output cursor overflow"))?,
                    chunk.stream,
                    &chunk.bytes,
                )?;
            }
            if let ExecutionState::Exited(completion) = &snapshot.state {
                if committed == completion.output && self.journal.receipt(id)?.is_none() {
                    self.journal.publish_receipt(
                        id,
                        completion.outcome.clone(),
                        completion.cleanup_digest.clone(),
                        completion.accounting_digest.clone(),
                    )?;
                } else if committed.final_cursor >= page.available && committed != completion.output
                {
                    return Err(Error::Protocol(
                        "guest completion does not match host-captured bytes",
                    ));
                }
            }
        }
        Ok(())
    }

    fn management_observation(&self) -> Result<Observation<GuestManagementReport>> {
        let last = self.journal.last_management_report()?;
        let current = self.journal.last_observation()?;
        Ok(match last {
            Some(value)
                if self
                    .management_seen
                    .is_some_and(|seen| seen.elapsed() <= Duration::from_secs(5))
                    && current.is_some_and(|current| {
                        current.value().generation == value.generation
                            && current.value().state == MachineState::Running
                    }) =>
            {
                Observation::Current { value }
            }
            last_known => Observation::Unavailable { last_known },
        })
    }

    fn execution_is_current(&self, snapshot: &ExecutionSnapshot) -> Result<bool> {
        if matches!(snapshot.state, ExecutionState::Exited(_)) {
            return Ok(true);
        }
        Ok(matches!(
            snapshot.state,
            ExecutionState::Running | ExecutionState::Draining { .. }
        ) && self
            .execution_seen
            .get(&snapshot.request.execution_id)
            .is_some_and(|seen| seen.elapsed() <= Duration::from_secs(5))
            && self.journal.last_observation()?.is_some_and(|current| {
                current.value().generation == snapshot.request.generation
                    && current.value().state == MachineState::Running
            }))
    }

    fn execution_status(&self, id: &ExecutionId) -> Result<ExecutionStatus> {
        let generation = self.journal.execution_generation(id)?;
        let report = match self.journal.process_snapshot(id)? {
            Some(value) if self.execution_is_current(&value)? => Observation::Current { value },
            last_known => Observation::Unavailable { last_known },
        };
        Ok(ExecutionStatus {
            execution_id: id.clone(),
            generation,
            lineage: self.journal.execution_lineage(id)?,
            report,
            interruption: self.journal.execution_interruption(generation)?,
        })
    }

    pub fn handle(&mut self, request: GuardianRequest) -> GuardianResponse {
        let result = self.handle_inner(request);
        self.attach_native_console();
        match result {
            Ok(response) => response,
            Err(error) => {
                eprintln!("sandsurf guardian request rejected: {error}");
                GuardianResponse::Rejected {
                    category: error_category(&error).to_owned(),
                    message: error.to_string(),
                }
            }
        }
    }

    /// A destroyed VM no longer needs a resident owner. Its journal remains
    /// durable and can be reopened if the host later reads historical evidence.
    pub fn can_retire(&mut self) -> Result<bool> {
        Ok(!self.offline_in_flight
            && self.reset_pending.is_none()
            && self
                .journal
                .last_observation()?
                .is_some_and(|value| value.value().state == MachineState::Destroyed)
            && match self.effect.as_mut() {
                None => true,
                Some(effect) => matches!(effect.observe_power(), Ok(None)),
            })
    }

    /// Measure native hardware independently of host intent and guest health.
    /// Ordinary guest traffic uses the resulting journal fence; it does not
    /// perform a native control transaction for every command or keystroke.
    fn refresh_native_observation(&mut self) -> Result<bool> {
        let Some(current) = self
            .journal
            .last_observation()?
            .map(|value| value.value().clone())
        else {
            return Ok(false);
        };
        let Some(effect) = self.effect.as_mut() else {
            return Ok(current.state == MachineState::Destroyed);
        };
        let measured = match effect.observe_power() {
            Ok(measured) => measured,
            Err(_) => return Ok(false),
        };
        let measured = match measured {
            Some(measured) => measured,
            None => {
                if matches!(
                    current.state,
                    MachineState::Stopped
                        | MachineState::Suspended
                        | MachineState::Destroyed
                        | MachineState::Failed
                ) {
                    return Ok(true);
                }
                let evidence_digest = match effect.observe_detachment() {
                    Ok(Some(evidence)) => evidence,
                    Ok(None) | Err(_) => return Ok(false),
                };
                sandsurf_machine::NativePowerObservation {
                    // Detachment proves no computer is running, not completion
                    // of a partially dispatched destruction transaction.
                    state: if current.state == MachineState::Destroying {
                        MachineState::Failed
                    } else {
                        MachineState::Stopped
                    },
                    evidence_digest,
                }
            }
        };
        // Only a positive, consumed native reset witness can enter recovery.
        // Neither arbitrary VMM exit nor management loss reaches this branch.
        let reset = effect.take_guest_reset();
        if !matches!(
            measured.state,
            MachineState::Running
                | MachineState::Paused
                | MachineState::Stopped
                | MachineState::Failed
        ) {
            return Err(Error::Protocol(
                "native power observation is not a stable state",
            ));
        }
        if measured.state == MachineState::Paused && !matches!(effect.capture_owner(), Ok(None)) {
            // Mask only the temporary pause. A lifecycle pause which adopted
            // this same physical boundary remains a current native fact, even
            // while the capture journal is busy or unreadable.
            return Ok(current.state == MachineState::Paused);
        }
        if measured.state == MachineState::Stopped
            && current.state == MachineState::Starting
            && self.reset_pending.as_ref() == Some(&current)
        {
            return Ok(false);
        }
        if measured.state != current.state {
            self.journal.observe(MachineObservation {
                machine_id: current.machine_id.clone(),
                generation: current.generation,
                sequence: current
                    .sequence
                    .next()
                    .map_err(|_| Error::Protocol("native observation sequence overflow"))?,
                state: measured.state,
                applied_revision: current.applied_revision,
                cause: ObservationCause::Native {},
                evidence_digest: measured.evidence_digest,
            })?;
            if matches!(measured.state, MachineState::Stopped | MachineState::Failed) {
                self.management_seen = None;
                self.execution_seen.clear();
                self.console.detach();
            }
        }
        if measured.state == MachineState::Stopped
            && current.state == MachineState::Running
            && let Some(evidence) = reset
        {
            let stopped = self
                .journal
                .last_observation()?
                .ok_or(Error::Protocol("reset stop boundary missing"))?;
            let starting = MachineObservation {
                machine_id: current.machine_id,
                generation: current
                    .generation
                    .next()
                    .map_err(|_| Error::Protocol("reset generation overflow"))?,
                sequence: stopped
                    .value()
                    .sequence
                    .next()
                    .map_err(|_| Error::Protocol("reset sequence overflow"))?,
                state: MachineState::Starting,
                applied_revision: current.applied_revision,
                cause: ObservationCause::GuestReset {},
                evidence_digest: evidence,
            };
            // Commit the fence before any replacement attachment can run.
            self.journal.observe(starting.clone())?;
            // A reset advances the durable generation immediately, but offline
            // disk interpretation must never occupy the native control owner.
            self.reset_pending = Some(starting.clone());
            let command = reset_command(&starting, effect.guest_reset_configuration()?)?;
            let previous = reset_previous(&starting)?;
            if effect
                .boot_preparation(&command, Some(&previous))?
                .is_none()
            {
                self.complete_reset(starting, None)?;
            }
        }
        self.attach_native_console();
        Ok(true)
    }

    fn begin_boot(&mut self, authorization: AuthorizedLifecycle) -> Result<BootAdmission> {
        self.refresh_native_observation()?;
        let operation = self.journal.admit_lifecycle(authorization.clone())?;
        if !matches!(
            operation.delivery,
            Delivery::Admitted | Delivery::NotApplied
        ) {
            return Ok(BootAdmission::Ready(self.transition(authorization, None)?));
        }
        if let Err(error) = self.journal.validate_lifecycle_preparation(&authorization) {
            return Ok(BootAdmission::Ready(
                self.unprepared_failure(&operation.command, error.into())?,
            ));
        }
        let current = self
            .journal
            .last_observation()?
            .map(|value| value.value().clone());
        let input = self
            .effect
            .as_ref()
            .ok_or(Error::Unsupported("destroyed machine has no native owner"))?
            .boot_preparation(&operation.command, current.as_ref())?;
        let Some(input) = input else {
            return Ok(BootAdmission::Ready(self.transition(authorization, None)?));
        };
        if self.offline_in_flight {
            // An exact retry observes admission; it is not a second worker.
            // A later host revision is already fenced and may be retried once
            // the physical disk worker releases its custody.
            return Ok(BootAdmission::Ready(GuardianResponse::Lifecycle {
                operation,
            }));
        }
        self.offline_in_flight = true;
        Ok(BootAdmission::Queued {
            input,
            pending: BootPending::Lifecycle(Box::new(authorization)),
        })
    }

    fn begin_reset_boot(&mut self) -> Result<Option<(BootPreparation, BootPending)>> {
        if self.offline_in_flight {
            return Ok(None);
        }
        let Some(starting) = self.reset_pending.clone() else {
            return Ok(None);
        };
        if !self.journal.native_reset_is_current(&starting)? {
            self.reset_pending = None;
            return Ok(None);
        }
        let native = self
            .effect
            .as_ref()
            .ok_or(Error::Unsupported("native owner is unavailable"))?;
        let command = reset_command(&starting, native.guest_reset_configuration()?)?;
        let previous = reset_previous(&starting)?;
        let Some(input) = native.boot_preparation(&command, Some(&previous))? else {
            self.complete_reset(starting, None)?;
            return Ok(None);
        };
        self.offline_in_flight = true;
        Ok(Some((input, BootPending::Reset(starting))))
    }

    fn finish_boot(
        &mut self,
        pending: BootPending,
        result: Result<PreparedBoot>,
    ) -> Result<Option<GuardianResponse>> {
        self.offline_in_flight = false;
        match pending {
            BootPending::Lifecycle(authorization) => {
                let command = authorization.statement.command.clone();
                let result =
                    result.and_then(|prepared| self.transition(*authorization, Some(prepared)));
                match result {
                    Ok(response) => Ok(Some(response)),
                    Err(error) => Ok(Some(self.unprepared_failure(&command, error)?)),
                }
            }
            BootPending::Reset(starting) => {
                if !self.journal.native_reset_is_current(&starting)? {
                    self.reset_pending = None;
                    return Ok(None);
                }
                match result {
                    Ok(prepared) => self.complete_reset(starting, Some(prepared))?,
                    Err(error) => self.record_reset_completion(starting, Err(error))?,
                }
                Ok(None)
            }
        }
    }

    fn unprepared_failure(
        &mut self,
        command: &LifecycleCommand,
        error: Error,
    ) -> Result<GuardianResponse> {
        let operation = self
            .journal
            .lifecycle_operation(&command.operation_id)?
            .ok_or(Error::Protocol("prepared lifecycle admission is missing"))?;
        let operation = if operation.delivery == Delivery::Admitted {
            self.journal.record_lifecycle_delivery(
                &command.operation_id,
                &command.request_digest,
                Delivery::NotApplied,
                Some(bytes_digest(error.to_string().as_bytes())),
                None,
            )?
        } else {
            operation
        };
        Ok(GuardianResponse::Lifecycle { operation })
    }

    fn complete_reset(
        &mut self,
        starting: MachineObservation,
        prepared: Option<PreparedBoot>,
    ) -> Result<()> {
        let native = self
            .effect
            .as_mut()
            .ok_or(Error::Unsupported("native owner is unavailable"))?;
        let outcome = (|| {
            if let Some(prepared) = prepared {
                native.install_prepared_boot(prepared)?;
            }
            native.recover_guest_reset(&starting)
        })();
        self.record_reset_completion(starting, outcome)
    }

    fn record_reset_completion(
        &mut self,
        starting: MachineObservation,
        outcome: Result<Digest>,
    ) -> Result<()> {
        let (state, evidence_digest) = match outcome {
            Ok(evidence) => (MachineState::Running, evidence),
            Err(error) => (
                MachineState::Failed,
                bytes_digest(error.to_string().as_bytes()),
            ),
        };
        self.journal.observe(MachineObservation {
            sequence: starting
                .sequence
                .next()
                .map_err(|_| Error::Protocol("reset sequence overflow"))?,
            state,
            evidence_digest,
            ..starting
        })?;
        self.reset_pending = None;
        self.attach_native_console();
        Ok(())
    }

    fn transition(
        &mut self,
        authorization: AuthorizedLifecycle,
        prepared: Option<PreparedBoot>,
    ) -> Result<GuardianResponse> {
        self.refresh_native_observation()?;
        let command = authorization.statement.command.clone();
        let current = self
            .journal
            .last_observation()?
            .map(|value| value.value().clone());
        self.journal.admit_lifecycle(authorization.clone())?;
        let operation = match self.journal.begin_lifecycle(authorization)? {
            sandsurf_state::LifecycleDecision::Reconcile(operation) => {
                self.reconcile_lifecycle(operation)?
            }
            sandsurf_state::LifecycleDecision::Perform(permit) => {
                let native = self
                    .effect
                    .as_mut()
                    .ok_or(Error::Unsupported("destroyed machine has no native owner"))?;
                let outcome = permit.perform(|actual| {
                    // Running would invalidate an in-flight disk/memory copy.
                    // An authorized pause may take over the same native paused
                    // boundary; capture cleanup will preserve that public state.
                    if actual.desired == DesiredState::Running {
                        match native.capture_owner() {
                            Ok(None) => {}
                            Ok(Some(_)) => {
                                return LifecycleEffect::NotApplied(bytes_digest(
                                    b"native-capture-owns-pause-boundary",
                                ));
                            }
                            Err(_) => {
                                return LifecycleEffect::NotApplied(bytes_digest(
                                    b"native-capture-ownership-unavailable",
                                ));
                            }
                        }
                    }
                    // Forced containment must not depend on a readable
                    // capture journal; suspension verifies its own
                    // committed full-state witness in the native owner.
                    if let Some(prepared) = prepared
                        && let Err(error) = native.install_prepared_boot(prepared)
                    {
                        return LifecycleEffect::NotApplied(bytes_digest(
                            error.to_string().as_bytes(),
                        ));
                    }
                    native.transition(actual, current.as_ref())
                });
                match outcome {
                    LifecycleEffect::Observed(transitions) => {
                        if transitions.is_empty() || transitions.len() > 8 {
                            return Err(Error::Protocol(
                                "native lifecycle returned an invalid observation count",
                            ));
                        }
                        let restored_generation = if current
                            .as_ref()
                            .is_some_and(|value| value.state == MachineState::Suspended)
                            && transitions
                                .last()
                                .is_some_and(|value| value.state == MachineState::Running)
                        {
                            let generation = transitions
                                .last()
                                .expect("restored transition checked above")
                                .generation;
                            Some(generation)
                        } else {
                            None
                        };
                        let mut references = Vec::with_capacity(transitions.len());
                        for transition in transitions {
                            let sequence = match self.journal.last_observation()? {
                                Some(value) => value.value().sequence.next().map_err(|_| {
                                    Error::Protocol("guardian observation sequence overflow")
                                })?,
                                None => Counter::ONE,
                            };
                            let committed = self.journal.observe(MachineObservation {
                                machine_id: command.machine_id.clone(),
                                generation: transition.generation,
                                sequence,
                                state: transition.state,
                                applied_revision: command.revision,
                                cause: sandsurf_protocol::ObservationCause::Lifecycle {
                                    operation_id: command.operation_id.clone(),
                                },
                                evidence_digest: transition.evidence_digest,
                            })?;
                            references.push(committed.reference()?);
                        }
                        let final_observation = self.journal.last_observation()?.ok_or(
                            Error::Protocol("native lifecycle produced no committed observation"),
                        )?;
                        if !final_observation.value().state.satisfies(command.desired) {
                            return Err(Error::Protocol(
                                "native lifecycle did not establish the desired state",
                            ));
                        }
                        let evidence = digest(Domain::Operation, &references)
                            .map_err(|_| Error::Protocol("lifecycle evidence digest failed"))?;
                        let operation = self.journal.record_lifecycle_delivery(
                            &command.operation_id,
                            &command.request_digest,
                            Delivery::Applied,
                            Some(evidence),
                            Some(final_observation.reference()?),
                        )?;
                        // Native facts and lifecycle delivery have their
                        // own owner. Execution integration cannot rewind
                        // them or turn an observed running VM into unknown.
                        if let Some(generation) = restored_generation
                            && let Err(error) =
                                native.rebind_restored_runtime(&mut self.journal, generation)
                        {
                            eprintln!("sandsurf restored execution integration pending: {error}");
                        }
                        operation
                    }
                    LifecycleEffect::NotApplied(evidence) => {
                        self.journal.record_lifecycle_delivery(
                            &command.operation_id,
                            &command.request_digest,
                            Delivery::NotApplied,
                            Some(evidence),
                            None,
                        )?
                    }
                    LifecycleEffect::Unknown => self.journal.record_lifecycle_delivery(
                        &command.operation_id,
                        &command.request_digest,
                        Delivery::Unknown,
                        None,
                        None,
                    )?,
                }
            }
        };
        Ok(GuardianResponse::Lifecycle { operation })
    }

    fn attach_native_console(&mut self) {
        if let Ok(Some(current)) = self.journal.last_observation()
            && matches!(
                current.value().state,
                MachineState::Running | MachineState::Paused
            )
            && let Some(console) = self.effect.as_mut().and_then(GuardianEffect::take_console)
            && let Err(error) = self.console.attach(current.value().generation, console)
        {
            eprintln!("sandsurf native console capture unavailable: {error}");
        }
    }

    fn handle_inner(&mut self, request: GuardianRequest) -> Result<GuardianResponse> {
        match request {
            GuardianRequest::Inspect {
                machine_id,
                operation_id,
            } => {
                if &machine_id != self.journal.machine_id() {
                    return Err(Error::Protocol("guardian machine identity mismatch"));
                }
                let reachable = self.refresh_native_observation()?;
                self.reconcile_execution_integration();
                let observation = match self.journal.last_observation()? {
                    Some(value) if reachable => Observation::Current {
                        value: value.value().clone(),
                    },
                    Some(value) => Observation::Unavailable {
                        last_known: Some(value.value().clone()),
                    },
                    None => Observation::Unavailable { last_known: None },
                };
                let operation = operation_id
                    .as_ref()
                    .map(|id| self.journal.operation(id))
                    .transpose()?
                    .flatten();
                let lifecycle_operation = operation_id
                    .as_ref()
                    .map(|id| self.journal.lifecycle_operation(id))
                    .transpose()?
                    .flatten();
                let configuration_operation = operation_id
                    .as_ref()
                    .map(|id| self.journal.configuration_operation(id))
                    .transpose()?
                    .flatten();
                Ok(GuardianResponse::Inspection {
                    value: Box::new(GuardianInspection {
                        machine_id,
                        observation,
                        management: self.management_observation()?,
                        operation,
                        lifecycle_operation,
                        configuration_operation,
                    }),
                })
            }
            GuardianRequest::Dispatch { .. }
            | GuardianRequest::QueryGuest { .. }
            | GuardianRequest::Guest { .. } => Err(Error::Protocol(
                "guest requests require the independent I/O worker",
            )),
            GuardianRequest::Transition { authorization } => self.transition(authorization, None),
            GuardianRequest::Configure { authorization } => {
                let command = authorization.statement.command.clone();
                let current = self
                    .journal
                    .last_observation()?
                    .ok_or(Error::Protocol("configuration has no machine observation"))?
                    .value()
                    .clone();
                self.journal.admit_configuration(authorization.clone())?;
                let operation = match self.journal.begin_configuration(authorization)? {
                    sandsurf_state::ConfigurationDecision::Reconcile(operation) => {
                        self.reconcile_configuration(operation)?
                    }
                    sandsurf_state::ConfigurationDecision::Perform(permit) => {
                        let native = self
                            .effect
                            .as_mut()
                            .ok_or(Error::Unsupported("destroyed machine has no native owner"))?;
                        let outcome = permit.perform(|actual| native.configure(actual, &current));
                        match outcome {
                            EffectOutcome::Applied(evidence) => {
                                let sequence = current.sequence.next().map_err(|_| {
                                    Error::Protocol("observation sequence overflow")
                                })?;
                                let committed = self.journal.observe(MachineObservation {
                                    machine_id: command.machine_id.clone(),
                                    generation: current.generation,
                                    sequence,
                                    state: current.state,
                                    applied_revision: command.revision,
                                    cause: ObservationCause::Configuration {
                                        operation_id: command.operation_id.clone(),
                                    },
                                    evidence_digest: evidence.clone(),
                                })?;
                                self.journal.record_configuration_delivery(
                                    &command.operation_id,
                                    &command.request_digest,
                                    Delivery::Applied,
                                    Some(evidence),
                                    Some(committed.reference()?),
                                )?
                            }
                            EffectOutcome::NotApplied(evidence) => {
                                self.journal.record_configuration_delivery(
                                    &command.operation_id,
                                    &command.request_digest,
                                    Delivery::NotApplied,
                                    Some(evidence),
                                    None,
                                )?
                            }
                            EffectOutcome::Unknown => self.journal.record_configuration_delivery(
                                &command.operation_id,
                                &command.request_digest,
                                Delivery::Unknown,
                                None,
                                None,
                            )?,
                        }
                    }
                };
                Ok(GuardianResponse::Configuration { operation })
            }
            GuardianRequest::NativeSnapshot {
                machine_id,
                request,
            } => {
                if &machine_id != self.journal.machine_id() {
                    return Err(Error::Protocol("guardian machine identity mismatch"));
                }
                match &request {
                    NativeSnapshotRequest::StageRestore { .. } => {
                        return Err(Error::Protocol(
                            "full restore must use detached preparation",
                        ));
                    }
                    NativeSnapshotRequest::PrepareDisk {
                        expected_generation,
                        expected_revision,
                        ..
                    }
                    | NativeSnapshotRequest::PrepareFull {
                        expected_generation,
                        expected_revision,
                        ..
                    } => {
                        self.refresh_native_observation()?;
                        let current = self
                            .journal
                            .last_observation()?
                            .ok_or(Error::Protocol("capture has no native machine observation"))?;
                        if current.value().generation != *expected_generation
                            || current.value().applied_revision != *expected_revision
                            || !matches!(
                                current.value().state,
                                MachineState::Running | MachineState::Paused
                            )
                        {
                            return Err(Error::Protocol(
                                "capture generation, revision or native power changed",
                            ));
                        }
                    }
                    _ => {}
                }
                let releasing = matches!(
                    request,
                    NativeSnapshotRequest::FinishDisk { .. }
                        | NativeSnapshotRequest::FinishFull { .. }
                );
                let response = self
                    .effect
                    .as_mut()
                    .ok_or(Error::Unsupported("destroyed machine has no native owner"))?
                    .native_snapshot(request, &mut self.journal)?;
                if releasing {
                    // Releasing under newer unapplied authority deliberately
                    // does not resume an older envelope. With capture masking
                    // gone, record actual power without completing host intent.
                    self.refresh_native_observation()?;
                }
                Ok(GuardianResponse::NativeSnapshot { response })
            }
            GuardianRequest::Runtime {
                machine_id,
                request,
            } => {
                if &machine_id != self.journal.machine_id() {
                    return Err(Error::Protocol("guardian machine identity mismatch"));
                }
                let response = match request {
                    RuntimeRequest::ReadConsole {
                        generation,
                        after,
                        maximum,
                    } => RuntimeResponse::Console {
                        page: self.console.read(generation, after, maximum)?,
                    },
                    RuntimeRequest::WriteConsole { generation, bytes } => {
                        self.refresh_native_observation()?;
                        let current = self
                            .journal
                            .last_observation()?
                            .ok_or(Error::Protocol("console generation unavailable"))?;
                        if generation != current.value().generation {
                            return Err(Error::Rejected { category: "stale-generation".into(), message: "native console input belongs to an earlier execution generation".into() });
                        }
                        if current.value().state != MachineState::Running {
                            return Err(Error::Unsupported(
                                "native console input requires a running computer",
                            ));
                        }
                        RuntimeResponse::ConsoleInput {
                            accepted: self.console.write(generation, &bytes)?,
                        }
                    }
                    RuntimeRequest::OwnerIdentity {} => RuntimeResponse::OwnerIdentity {
                        machine_id: self.journal.machine_id().clone(),
                    },
                    RuntimeRequest::AssessResources { resources } => {
                        let current = self
                            .journal
                            .last_observation()?
                            .ok_or(Error::Protocol("native resource state unavailable"))?;
                        RuntimeResponse::ResourceAssessment {
                            assessment: self
                                .effect
                                .as_ref()
                                .ok_or(Error::Unsupported(
                                    "destroyed machine has no native resource owner",
                                ))?
                                .assess_resources(&resources, current.value()),
                        }
                    }
                    RuntimeRequest::ValidateResources { resources } => {
                        let current = self
                            .journal
                            .last_observation()?
                            .ok_or(Error::Protocol("native resource state is unavailable"))?;
                        self.journal.validate_resource_envelope(&resources)?;
                        let effect = self
                            .effect
                            .as_ref()
                            .ok_or(Error::Unsupported("destroyed machine has no native owner"))?;
                        effect.validate_resources(&resources, current.value())?;
                        RuntimeResponse::ResourceAssessment {
                            assessment: effect.assess_resources(&resources, current.value()),
                        }
                    }
                    RuntimeRequest::Usage => {
                        let generation = self
                            .journal
                            .last_observation()?
                            .ok_or(Error::Protocol(
                                "resource sample has no native generation fence",
                            ))?
                            .value()
                            .generation;
                        let mut usage = self
                            .effect
                            .as_mut()
                            .ok_or(Error::Unsupported("destroyed machine has no native owner"))?
                            .resource_usage()?;
                        usage.output_retained_bytes = self.journal.retained_output_bytes()?;
                        usage.executions_current = self.journal.managed_execution_slots_held()?;
                        usage.provenance.output =
                            sandsurf_protocol::MeasurementSource::HostRetention;
                        usage.provenance.executions =
                            sandsurf_protocol::MeasurementSource::HostAdmission;
                        RuntimeResponse::Usage { generation, usage }
                    }
                    RuntimeRequest::Events { after, maximum } => RuntimeResponse::Events {
                        page: self.journal.events(after, maximum)?,
                    },
                    RuntimeRequest::Process { execution_id } => {
                        let request = self.journal.process_request(&execution_id)?;
                        RuntimeResponse::Process {
                            process: Box::new(self.execution_status(&execution_id)?),
                            request,
                        }
                    }
                    RuntimeRequest::Processes => RuntimeResponse::Processes {
                        processes: self
                            .journal
                            .execution_ids()?
                            .into_iter()
                            .map(|id| self.execution_status(&id))
                            .collect::<Result<Vec<_>>>()?,
                    },
                    RuntimeRequest::Operation { operation_id } => RuntimeResponse::Operation {
                        operation: self.journal.runtime_operation(&operation_id)?,
                    },
                    RuntimeRequest::Receipt { execution_id } => {
                        let value = self.journal.receipt(&execution_id)?;
                        RuntimeResponse::Receipt {
                            receipt: value.as_ref().map(|value| value.0.clone()),
                            digest: value.map(|value| value.1),
                        }
                    }
                    RuntimeRequest::ReadOutput {
                        execution_id,
                        after,
                        maximum,
                    } => RuntimeResponse::Output {
                        page: evidence_page(self.journal.read_output(
                            &execution_id,
                            after,
                            maximum as usize,
                        )?),
                    },
                    RuntimeRequest::AcknowledgeReceipt {
                        operation_id,
                        execution_id,
                        receipt_digest,
                    } => {
                        self.journal.acknowledge_receipt(
                            &operation_id,
                            &execution_id,
                            &receipt_digest,
                        )?;
                        RuntimeResponse::Complete
                    }
                    RuntimeRequest::SealOutput {
                        operation_id,
                        execution_id,
                        generation,
                        expected,
                        segment_id,
                    } => RuntimeResponse::OutputSegment {
                        segment: self.journal.seal_output(
                            &operation_id,
                            &execution_id,
                            generation,
                            expected.as_ref(),
                            segment_id,
                        )?,
                    },
                    RuntimeRequest::OutputSegment { segment_id } => {
                        RuntimeResponse::OutputSegment {
                            segment: self.journal.output_segment(&segment_id)?,
                        }
                    }
                    RuntimeRequest::ReadOutputSegment {
                        segment_id,
                        after,
                        maximum,
                    } => RuntimeResponse::Output {
                        page: evidence_page(self.journal.read_output_segment(
                            &segment_id,
                            after,
                            maximum as usize,
                        )?),
                    },
                    RuntimeRequest::RecordLoss { authorization } => {
                        self.journal.record_loss_authorization(authorization)?;
                        RuntimeResponse::Complete
                    }
                    RuntimeRequest::Release {
                        execution_id,
                        request,
                    } => RuntimeResponse::Release {
                        status: self.journal.release(&execution_id, request)?,
                    },
                    RuntimeRequest::CleanupReleased {
                        execution_id,
                        request_digest,
                    } => RuntimeResponse::Release {
                        status: self
                            .journal
                            .cleanup_released(&execution_id, &request_digest)?,
                    },
                };
                Ok(GuardianResponse::Runtime { response })
            }
            GuardianRequest::SubscribeEvents { .. } | GuardianRequest::SubscribeConsole { .. } => {
                Err(Error::Protocol(
                    "event subscriptions require a streaming connection",
                ))
            }
        }
    }

    fn reconcile_execution_integration(&mut self) {
        let generation = match self.journal.last_observation() {
            Ok(Some(value)) if value.value().state == MachineState::Running => {
                value.value().generation
            }
            Ok(Some(value))
                if matches!(
                    value.value().state,
                    MachineState::Stopped | MachineState::Destroyed
                ) =>
            {
                if let Some(effect) = self.effect.as_mut()
                    && let Err(error) = effect.retire_restore_intent()
                {
                    eprintln!("sandsurf restore intent retirement pending: {error}");
                }
                return;
            }
            _ => return,
        };
        if !matches!(self.journal.generation_was_restored(generation), Ok(true)) {
            return;
        }
        if let Some(effect) = self.effect.as_mut()
            && let Err(error) = effect.rebind_restored_runtime(&mut self.journal, generation)
        {
            // The admitted restore intent remains durable. Neither failed
            // integration nor its retry is a new native lifecycle decision.
            eprintln!("sandsurf restored execution integration pending: {error}");
        }
    }

    fn reconcile_lifecycle(&mut self, operation: LifecycleOperation) -> Result<LifecycleOperation> {
        if matches!(operation.delivery, Delivery::Dispatched | Delivery::Unknown)
            && let Some(observed) = self.journal.last_observation()?
            && observed.value().cause
                == (ObservationCause::Lifecycle {
                    operation_id: operation.command.operation_id.clone(),
                })
            && observed.value().state.satisfies(operation.command.desired)
        {
            let reference = observed.reference()?;
            let evidence = digest(Domain::Operation, &("reconciled-lifecycle-v1", &reference))
                .map_err(|_| Error::Protocol("lifecycle evidence digest failed"))?;
            return Ok(self.journal.record_lifecycle_delivery(
                &operation.command.operation_id,
                &operation.command.request_digest,
                Delivery::Applied,
                Some(evidence),
                Some(reference),
            )?);
        }
        Ok(operation)
    }

    fn reconcile_configuration(
        &mut self,
        operation: ConfigurationOperation,
    ) -> Result<ConfigurationOperation> {
        if matches!(operation.delivery, Delivery::Dispatched | Delivery::Unknown)
            && let Some(observed) = self.journal.last_observation()?
            && observed.value().cause
                == (ObservationCause::Configuration {
                    operation_id: operation.command.operation_id.clone(),
                })
            && observed.value().applied_revision == operation.command.revision
        {
            let reference = observed.reference()?;
            let evidence = digest(
                Domain::Operation,
                &("reconciled-configuration-v1", &reference),
            )
            .map_err(|_| Error::Protocol("configuration evidence digest failed"))?;
            return Ok(self.journal.record_configuration_delivery(
                &operation.command.operation_id,
                &operation.command.request_digest,
                Delivery::Applied,
                Some(evidence),
                Some(reference),
            )?);
        }
        Ok(operation)
    }
}

fn evidence_page(value: sandsurf_state::OutputPage) -> EvidencePage {
    EvidencePage {
        after: value.after,
        cursor: value.cursor,
        available: value.available,
        chunks: value
            .chunks
            .into_iter()
            .map(|chunk| EvidenceChunk {
                sequence: chunk.sequence,
                offset: chunk.offset,
                stream: chunk.stream,
                bytes: chunk.bytes,
                bytes_digest: chunk.bytes_digest,
                chain_digest: chunk.chain_digest,
            })
            .collect(),
    }
}

fn error_category(error: &Error) -> &str {
    match error {
        Error::Io(_) => "transport",
        Error::Json(_) | Error::Protocol(_) => "protocol",
        Error::State(_) => "state",
        Error::Rejected { category, .. } => category,
        Error::Unsupported(_) => "unsupported",
    }
}

#[derive(Debug, Clone)]
pub struct GuardianClient {
    endpoint: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLifecycleResult {
    pub guardian_operation: LifecycleOperation,
    pub completed_intent: Option<LifecycleIntent>,
}

/// Immutable admission from the sole host authority. It contains no catalog,
/// signing key or authority to choose a different operation/configuration.
pub struct LifecyclePlan {
    intent: LifecycleIntent,
    authorization: Option<AuthorizedLifecycle>,
}

/// Evidence returned by an independently owned guardian. Only catalog-owner
/// completion turns it into a completed host intent.
pub struct LifecycleEvidence {
    intent: LifecycleIntent,
    operation: LifecycleOperation,
    observation: Option<MachineObservation>,
}

impl LifecyclePlan {
    pub fn admit(catalog: &HostCatalog, operation_id: &OperationId) -> Result<Self> {
        let intent = catalog
            .intent(operation_id)?
            .ok_or(Error::Protocol("lifecycle intent is missing"))?;
        let authorization = if intent.completion.is_some() {
            None
        } else {
            Some(catalog.authorize_lifecycle(operation_id)?)
        };
        Ok(Self {
            intent,
            authorization,
        })
    }

    /// Native effects and transport waits never borrow the catalog writer.
    pub fn execute(self, endpoint: PathBuf) -> Result<LifecycleEvidence> {
        let client = GuardianClient::new(endpoint);
        let intent = self.intent;
        if let Some(completion) = intent.completion.as_ref() {
            let inspection =
                client.inspect(intent.machine_id.clone(), Some(intent.operation_id.clone()))?;
            let operation = inspection.lifecycle_operation.ok_or(Error::Protocol(
                "guardian no longer retains a completed lifecycle operation",
            ))?;
            if operation.command.machine_id != intent.machine_id
                || operation.command.operation_id != intent.operation_id
                || operation.command.desired != intent.desired
                || operation.command.revision != intent.revision
                || operation.command.request_digest != intent.request_digest
                || operation.delivery != Delivery::Applied
                || operation.evidence_digest.is_none()
                || operation.observation.as_ref() != Some(completion)
            {
                return Err(Error::Protocol(
                    "guardian lifecycle history conflicts with completed host intent",
                ));
            }
            return Ok(LifecycleEvidence {
                intent,
                operation,
                observation: None,
            });
        }
        let operation = client.transition(self.authorization.ok_or(Error::Protocol(
            "pending lifecycle plan has no host authorization",
        ))?)?;
        let observation = if operation.delivery == Delivery::Applied {
            let inspection = client.inspect(
                operation.command.machine_id.clone(),
                Some(operation.command.operation_id.clone()),
            )?;
            let observation = match inspection.observation {
                Observation::Current { value } => value,
                Observation::Unavailable { .. } => {
                    return Err(Error::Protocol(
                        "applied lifecycle observation is unavailable",
                    ));
                }
            };
            if inspection.lifecycle_operation.as_ref() != Some(&operation) {
                return Err(Error::Protocol(
                    "guardian lifecycle inspection changed during completion",
                ));
            }
            Some(observation)
        } else {
            None
        };
        Ok(LifecycleEvidence {
            intent,
            operation,
            observation,
        })
    }
}

impl LifecycleEvidence {
    pub fn complete(self, catalog: &mut HostCatalog) -> Result<HostLifecycleResult> {
        let intent = catalog
            .intent(&self.intent.operation_id)?
            .ok_or(Error::Protocol(
                "lifecycle intent disappeared before completion",
            ))?;
        if intent.machine_id != self.intent.machine_id
            || intent.operation_id != self.operation.command.operation_id
            || intent.machine_id != self.operation.command.machine_id
            || intent.desired != self.operation.command.desired
            || intent.revision != self.operation.command.revision
            || intent.request_digest != self.operation.command.request_digest
        {
            return Err(Error::Protocol(
                "lifecycle evidence conflicts with host admission",
            ));
        }
        let completed_intent = if let Some(observation) = self.observation {
            Some(catalog.complete_lifecycle_operation(&self.operation, &observation)?)
        } else if self.intent.completion.is_some() {
            if intent.completion != self.intent.completion {
                return Err(Error::Protocol("completed lifecycle history changed"));
            }
            Some(intent)
        } else {
            None
        };
        Ok(HostLifecycleResult {
            guardian_operation: self.operation,
            completed_intent,
        })
    }
}

impl GuardianClient {
    pub fn new(endpoint: PathBuf) -> Self {
        Self { endpoint }
    }

    /// Reachability of the exclusive journal endpoint is not a power fact.
    pub fn owner_identity(&self, machine: MachineId) -> Result<()> {
        match self.runtime(machine.clone(), RuntimeRequest::OwnerIdentity {})? {
            RuntimeResponse::OwnerIdentity { machine_id } if machine_id == machine => Ok(()),
            _ => Err(Error::Protocol(
                "guardian returned the wrong owner identity",
            )),
        }
    }

    pub fn inspect(
        &self,
        machine_id: MachineId,
        operation_id: Option<OperationId>,
    ) -> Result<GuardianInspection> {
        match self.call(GuardianRequest::Inspect {
            machine_id,
            operation_id,
        })? {
            GuardianResponse::Inspection { value } => Ok(*value),
            GuardianResponse::Dispatch { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Lifecycle { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Configuration { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Guest { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::NativeSnapshot { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
        }
    }

    pub fn dispatch(&self, command: GuestCommand) -> Result<Operation> {
        match self.call(GuardianRequest::Dispatch { command })? {
            GuardianResponse::Dispatch { operation } => Ok(operation),
            GuardianResponse::Inspection { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Lifecycle { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Configuration { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Guest { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::NativeSnapshot { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
        }
    }

    pub fn transition(&self, authorization: AuthorizedLifecycle) -> Result<LifecycleOperation> {
        match self.call(GuardianRequest::Transition { authorization })? {
            GuardianResponse::Lifecycle { operation } => Ok(operation),
            GuardianResponse::Inspection { .. }
            | GuardianResponse::Dispatch { .. }
            | GuardianResponse::Configuration { .. }
            | GuardianResponse::Guest { .. }
            | GuardianResponse::NativeSnapshot { .. }
            | GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
        }
    }

    pub fn configure(
        &self,
        authorization: AuthorizedConfiguration,
    ) -> Result<ConfigurationOperation> {
        match self.call(GuardianRequest::Configure { authorization })? {
            GuardianResponse::Configuration { operation } => Ok(operation),
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
            GuardianResponse::Inspection { .. }
            | GuardianResponse::Dispatch { .. }
            | GuardianResponse::Lifecycle { .. }
            | GuardianResponse::Guest { .. }
            | GuardianResponse::NativeSnapshot { .. }
            | GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
        }
    }

    pub fn guest(
        &self,
        machine_id: MachineId,
        request: GuestServiceRequest,
    ) -> Result<GuestServiceResponse> {
        match self.call(GuardianRequest::Guest {
            machine_id,
            request,
        })? {
            GuardianResponse::Guest { response } => Ok(response),
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
            GuardianResponse::Inspection { .. }
            | GuardianResponse::Dispatch { .. }
            | GuardianResponse::Lifecycle { .. }
            | GuardianResponse::Configuration { .. }
            | GuardianResponse::NativeSnapshot { .. }
            | GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
        }
    }

    pub fn query_guest(
        &self,
        machine_id: MachineId,
        generation: Counter,
        request: GuestServiceRequest,
    ) -> Result<GuestServiceResponse> {
        match self.call(GuardianRequest::QueryGuest {
            machine_id,
            generation,
            request,
        })? {
            GuardianResponse::Guest { response } => Ok(response),
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
            _ => Err(Error::Protocol(
                "guardian returned the wrong guest-query response",
            )),
        }
    }

    pub fn native_snapshot(
        &self,
        machine_id: MachineId,
        request: NativeSnapshotRequest,
    ) -> Result<NativeSnapshotResponse> {
        match self.call(GuardianRequest::NativeSnapshot {
            machine_id,
            request,
        })? {
            GuardianResponse::NativeSnapshot { response } => Ok(response),
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
            GuardianResponse::Inspection { .. }
            | GuardianResponse::Dispatch { .. }
            | GuardianResponse::Lifecycle { .. }
            | GuardianResponse::Configuration { .. }
            | GuardianResponse::Guest { .. }
            | GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
        }
    }

    pub fn runtime(
        &self,
        machine_id: MachineId,
        request: RuntimeRequest,
    ) -> Result<RuntimeResponse> {
        match self.call(GuardianRequest::Runtime {
            machine_id,
            request,
        })? {
            GuardianResponse::Runtime { response } => Ok(response),
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
            GuardianResponse::Inspection { .. }
            | GuardianResponse::Dispatch { .. }
            | GuardianResponse::Lifecycle { .. }
            | GuardianResponse::Configuration { .. }
            | GuardianResponse::Guest { .. }
            | GuardianResponse::NativeSnapshot { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn call(&self, request: GuardianRequest) -> Result<GuardianResponse> {
        use sandsurf_native::local::LocalConnection;
        let mut connection = LocalConnection::connect(&self.endpoint, REQUEST_TIMEOUT)?;
        let (wire, bytes) = RequestEnvelope::split(request)
            .map_err(|_| Error::Protocol("invalid request bytes"))?;
        let frame = request_frame(&wire)?;
        connection.write_frame(&frame, REQUEST_TIMEOUT)?;
        if let Some(bytes) = bytes {
            send_binary(
                &mut crate::ipc_frames::LocalFrameChannel {
                    connection: &mut connection,
                    timeout: REQUEST_TIMEOUT,
                },
                bytes,
            )?;
        }
        let response = connection
            .read_frame(REQUEST_TIMEOUT)?
            .ok_or(Error::Protocol("guardian closed without a response"))?;
        let mut response = parse_response(response)?;
        if let Some(metadata) = response
            .binary_descriptor()
            .map_err(|_| Error::Protocol("invalid RPC metadata"))?
        {
            let bytes = receive_binary(
                &mut crate::ipc_frames::LocalFrameChannel {
                    connection: &mut connection,
                    timeout: REQUEST_TIMEOUT,
                },
                &metadata,
                MAX_RPC_DATA_BYTES,
            )?;
            response = response
                .with_wire_bytes(bytes)
                .map_err(|_| Error::Protocol("invalid RPC bytes"))?;
        }
        Ok(response)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn call(&self, _: GuardianRequest) -> Result<GuardianResponse> {
        let _ = &self.endpoint;
        Err(Error::Unsupported(
            "native guardian control transport is not implemented on this host",
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn serve_guardian<E: GuardianEffect>(
    endpoint: &Path,
    guardian: &mut Guardian<E>,
) -> Result<()> {
    use sandsurf_native::local::LocalListener;
    let listener = LocalListener::bind(endpoint)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let channel_limit = Arc::new(AtomicUsize::new(
        guardian
            .effect
            .as_ref()
            .and_then(GuardianEffect::resource_envelope)
            .map_or(MAX_GUARDIAN_CONNECTIONS, |value| {
                value.channels.get().min(MAX_GUARDIAN_CONNECTIONS as u64) as usize
            }),
    ));
    let events = Arc::clone(&guardian.console.notifications);
    events.publish(guardian.journal.event_cursor()?);
    let (sender, receiver) = mpsc::sync_channel::<GuardianIngress>(MAX_GUARDIAN_CONNECTIONS);
    let (boot_jobs, boot_queue) = mpsc::sync_channel::<OfflineWorkItem>(1);
    let boot_completions = sender.clone();
    let boot_worker = std::thread::Builder::new()
        .name("sandsurf-offline-native".into())
        .spawn(move || {
            while let Ok(item) = boot_queue.recv() {
                let completion = match item {
                    OfflineWorkItem::Boot(BootWorkItem {
                        input,
                        pending,
                        reply,
                    }) => {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            input.execute()
                        }))
                        .unwrap_or_else(|_| Err(Error::Protocol("offline boot worker panicked")));
                        GuardianIngress::BootComplete {
                            pending,
                            result,
                            reply,
                        }
                    }
                    OfflineWorkItem::Restore {
                        input,
                        pending,
                        reply,
                    } => {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            input.execute()
                        }))
                        .unwrap_or_else(|_| {
                            Err(Error::Protocol("offline restore worker panicked"))
                        });
                        GuardianIngress::RestoreComplete {
                            pending,
                            result,
                            reply,
                        }
                    }
                };
                if boot_completions.send(completion).is_err() {
                    break;
                }
            }
        })?;
    let (guest_jobs, guest_queue) = mpsc::sync_channel::<GuestWorkItem>(16);
    let completion_sender = sender.clone();
    let guest_worker = guardian
        .effect
        .as_mut()
        .map(|native| {
            let mut guest = native.guest_driver();
            std::thread::Builder::new()
                .name("sandsurf-guest-io".into())
                .spawn(move || {
                    while let Ok(GuestWorkItem {
                        job,
                        pending,
                        reply,
                    }) = guest_queue.recv()
                    {
                        let result = crate::guest_worker::execute(&mut *guest, job);
                        if completion_sender
                            .send(GuardianIngress::GuestComplete {
                                pending,
                                result,
                                reply,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                })
        })
        .transpose()?;
    let mut outstanding_guest_jobs = 0usize;
    let mut poll_in_flight = false;
    let mut last_poll = std::time::Instant::now();
    let mut last_request = std::time::Instant::now();
    std::thread::scope(|scope| {
        let stopped_accept = Arc::clone(&stopped);
        let active_accept = Arc::clone(&active);
        let limit_accept = Arc::clone(&channel_limit);
        let events_accept = Arc::clone(&events);
        let accept_worker = scope.spawn(move || {
            while !stopped_accept.load(Ordering::Acquire) {
                let connection = match listener.accept(Duration::from_secs(1)) {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(error) => {
                        let _ = sender.try_send(GuardianIngress::Failed(error));
                        return;
                    }
                };
                if active_accept.fetch_add(1, Ordering::AcqRel)
                    >= limit_accept.load(Ordering::Acquire)
                {
                    active_accept.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                let sender = sender.clone();
                let active = Arc::clone(&active_accept);
                let events = Arc::clone(&events_accept);
                let worker = std::thread::Builder::new()
                    .name("sandsurf-guardian-client".into())
                    .spawn(move || {
                        let _active = ActiveGuardianConnection(active);
                        let mut connection = connection;
                        let frame = match connection.read_frame(REQUEST_TIMEOUT) {
                            Ok(Some(frame)) => frame,
                            Ok(None) | Err(_) => return,
                        };
                        let sequence = frame.sequence;
                        let parsed = parse_request(frame).and_then(|mut wire| {
                            let metadata = wire
                                .descriptor()
                                .map_err(|_| Error::Protocol("invalid request descriptor"))?;
                            let data = if let Some(metadata) = metadata {
                                Some(receive_binary(
                                    &mut crate::ipc_frames::LocalFrameChannel {
                                        connection: &mut connection,
                                        timeout: REQUEST_TIMEOUT,
                                    },
                                    metadata,
                                    MAX_RPC_DATA_BYTES,
                                )?)
                            } else {
                                None
                            };
                            wire.assemble(data)
                                .map_err(|_| Error::Protocol("invalid request bytes"))
                        });
                        if let Ok(
                            subscription @ (GuardianRequest::SubscribeEvents { .. }
                            | GuardianRequest::SubscribeConsole { .. }),
                        ) = &parsed
                        {
                            let _ = observation_stream::serve(
                                &mut connection,
                                &sender,
                                &events,
                                subscription.clone(),
                            );
                            return;
                        }
                        let (reply, response) = mpsc::channel();
                        if sender
                            .try_send(GuardianIngress::Request {
                                parsed: Box::new(parsed),
                                reply,
                            })
                            .is_err()
                        {
                            return;
                        }
                        if let Ok(response) = response.recv() {
                            let (response, bytes) = match response.into_wire_parts() {
                                Ok(parts) => parts,
                                Err(error) => (
                                    GuardianResponse::Rejected {
                                        category: "protocol".into(),
                                        message: error.to_string(),
                                    },
                                    None,
                                ),
                            };
                            let (frame, bytes) = match response_frame(sequence, &response) {
                                Ok(frame) => (frame, bytes),
                                Err(error) => match response_frame(
                                    sequence,
                                    &GuardianResponse::Rejected {
                                        category: "protocol".into(),
                                        message: error.to_string(),
                                    },
                                ) {
                                    Ok(frame) => (frame, None),
                                    Err(_) => return,
                                },
                            };
                            // Lost transport never reverses an admitted operation.
                            if connection.write_frame(&frame, REQUEST_TIMEOUT).is_ok()
                                && let Some(bytes) = bytes
                            {
                                let _ = send_binary(
                                    &mut crate::ipc_frames::LocalFrameChannel {
                                        connection: &mut connection,
                                        timeout: REQUEST_TIMEOUT,
                                    },
                                    bytes,
                                );
                            }
                        }
                    });
                if let Err(error) = worker {
                    active_accept.fetch_sub(1, Ordering::AcqRel);
                    eprintln!("sandsurf guardian connection rejected: {error}");
                }
            }
        });
        let result = (|| loop {
            // Notification only: the journal remains the sole history owner.
            // Publish after every committed owner turn, including admission
            // paths that continue before periodic native/guest observation.
            events.publish(guardian.journal.event_cursor()?);
            let envelope = guardian
                .effect
                .as_ref()
                .and_then(GuardianEffect::resource_envelope);
            let inflight_limit = envelope
                .as_ref()
                .map_or(16, |value| value.inflight_requests.get().min(16) as usize);
            channel_limit.store(
                envelope.as_ref().map_or(MAX_GUARDIAN_CONNECTIONS, |value| {
                    value.channels.get().min(MAX_GUARDIAN_CONNECTIONS as u64) as usize
                }),
                Ordering::Release,
            );
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(GuardianIngress::Request { parsed, reply }) => {
                    last_request = std::time::Instant::now();
                    let response = match *parsed {
                        Ok(GuardianRequest::NativeSnapshot {
                            machine_id,
                            request: request @ NativeSnapshotRequest::StageRestore { .. },
                        }) => {
                            if outstanding_guest_jobs + usize::from(guardian.offline_in_flight)
                                >= inflight_limit
                            {
                                let _ = reply.send(rejected(Error::Rejected {
                                    category: "capacity".into(),
                                    message: "host in-flight resource budget exhausted".into(),
                                }));
                                continue;
                            }
                            match guardian.begin_restore(machine_id, request) {
                                Ok(RestoreAdmission::Ready(response)) => response,
                                Ok(RestoreAdmission::Queued { input, pending }) => {
                                    if let Err(error) =
                                        boot_jobs.try_send(OfflineWorkItem::Restore {
                                            input,
                                            pending,
                                            reply: reply.clone(),
                                        })
                                    {
                                        let item = match error {
                                            mpsc::TrySendError::Full(item)
                                            | mpsc::TrySendError::Disconnected(item) => item,
                                        };
                                        let OfflineWorkItem::Restore { pending, reply, .. } = item
                                        else {
                                            unreachable!()
                                        };
                                        let response = guardian
                                            .finish_restore(
                                                pending,
                                                Err(Error::Unsupported(
                                                    "offline restore queue is unavailable",
                                                )),
                                            )
                                            .unwrap_or_else(rejected);
                                        let _ = reply.send(response);
                                    }
                                    continue;
                                }
                                Err(error) => rejected(error),
                            }
                        }
                        Ok(GuardianRequest::Transition { authorization }) => {
                            match guardian.begin_boot(authorization) {
                                Ok(BootAdmission::Ready(response)) => response,
                                Ok(BootAdmission::Queued { input, pending }) => {
                                    if outstanding_guest_jobs >= inflight_limit {
                                        if let Some(response) = guardian.finish_boot(
                                            pending,
                                            Err(Error::Rejected {
                                                category: "capacity".into(),
                                                message: "host in-flight resource budget exhausted"
                                                    .into(),
                                            }),
                                        )? {
                                            let _ = reply.send(response);
                                        }
                                        continue;
                                    }
                                    queue_boot(
                                        guardian,
                                        &boot_jobs,
                                        BootWorkItem {
                                            input,
                                            pending,
                                            reply: Some(reply),
                                        },
                                    )?;
                                    continue;
                                }
                                Err(error) => rejected(error),
                            }
                        }
                        Ok(request)
                            if matches!(
                                request,
                                GuardianRequest::Dispatch { .. }
                                    | GuardianRequest::QueryGuest { .. }
                                    | GuardianRequest::Guest { .. }
                            ) =>
                        {
                            if outstanding_guest_jobs + usize::from(guardian.offline_in_flight)
                                >= inflight_limit
                            {
                                let _ = reply.send(rejected(Error::Rejected {
                                    category: "capacity".into(),
                                    message: "host in-flight resource budget exhausted".into(),
                                }));
                                continue;
                            }
                            match guardian.begin_guest(request) {
                                Ok(GuestAdmission::Ready(response)) => response,
                                Ok(GuestAdmission::Queued { job, pending }) => {
                                    match guest_jobs.try_send(GuestWorkItem {
                                        job,
                                        pending,
                                        reply: Some(reply.clone()),
                                    }) {
                                        Ok(()) => {
                                            outstanding_guest_jobs += 1;
                                            continue;
                                        }
                                        Err(error) => {
                                            let item = match error {
                                                mpsc::TrySendError::Full(item)
                                                | mpsc::TrySendError::Disconnected(item) => item,
                                            };
                                            let failure = match item.job {
                                                GuestJob::Dispatch(_) => GuestJobResult::Dispatch(
                                                    EffectOutcome::NotApplied(bytes_digest(
                                                        b"guest-io-queue-not-delivered",
                                                    )),
                                                ),
                                                GuestJob::Query(_) => {
                                                    GuestJobResult::Query(Err(Error::Unsupported(
                                                        "guest I/O queue is unavailable or full",
                                                    )))
                                                }
                                                GuestJob::Poll(_) => unreachable!(),
                                            };
                                            match guardian.finish_guest(item.pending, failure) {
                                                Ok(Some(response)) => response,
                                                Ok(None) => rejected(Error::Protocol(
                                                    "guest admission has no reply",
                                                )),
                                                Err(error) => rejected(error),
                                            }
                                        }
                                    }
                                }
                                Err(error) => rejected(error),
                            }
                        }
                        Ok(GuardianRequest::Runtime {
                            request: RuntimeRequest::ValidateResources { ref resources },
                            ..
                        }) if resources.channels.get() < active.load(Ordering::Acquire) as u64
                            || resources.inflight_requests.get()
                                < (outstanding_guest_jobs + usize::from(guardian.offline_in_flight))
                                    as u64 =>
                        {
                            rejected(Error::Rejected {
                                category: "capacity".into(),
                                message: "resource reduction excludes active channels or requests"
                                    .into(),
                            })
                        }
                        Ok(request) => {
                            let mut response = guardian.handle(request);
                            if let GuardianResponse::Runtime {
                                response: RuntimeResponse::Usage { ref mut usage, .. },
                            } = response
                            {
                                usage.channels_current = Some(
                                    Counter::try_from(active.load(Ordering::Acquire) as u64)
                                        .map_err(|_| {
                                            Error::Protocol("channel accounting overflow")
                                        })?,
                                );
                                usage.inflight_requests_current = Some(
                                    Counter::try_from(
                                        (outstanding_guest_jobs
                                            + usize::from(guardian.offline_in_flight))
                                            as u64,
                                    )
                                    .map_err(|_| Error::Protocol("request accounting overflow"))?,
                                );
                                usage.provenance.channels =
                                    sandsurf_protocol::MeasurementSource::HostAdmission;
                            }
                            response
                        }
                        Err(error) => GuardianResponse::Rejected {
                            category: error_category(&error).to_owned(),
                            message: error.to_string(),
                        },
                    };
                    let _ = reply.send(response);
                }
                Ok(GuardianIngress::GuestComplete {
                    pending,
                    result,
                    reply,
                }) => {
                    outstanding_guest_jobs = outstanding_guest_jobs.saturating_sub(1);
                    if matches!(pending, GuestPending::Poll { .. }) {
                        poll_in_flight = false;
                    }
                    match guardian.finish_guest(pending, result) {
                        Ok(Some(response)) => {
                            if let Some(reply) = reply {
                                let _ = reply.send(response);
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            if let Some(reply) = reply {
                                let _ = reply.send(rejected(error));
                            } else {
                                eprintln!("sandsurf guest observation unavailable: {error}");
                            }
                        }
                    }
                }
                Ok(GuardianIngress::BootComplete {
                    pending,
                    result,
                    reply,
                }) => match guardian.finish_boot(pending, result) {
                    Ok(Some(response)) => {
                        if let Some(reply) = reply {
                            let _ = reply.send(response);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if let Some(reply) = reply {
                            let _ = reply.send(rejected(error));
                        } else {
                            eprintln!("sandsurf native reset completion unavailable: {error}");
                        }
                    }
                },
                Ok(GuardianIngress::RestoreComplete {
                    pending,
                    result,
                    reply,
                }) => {
                    let response = guardian
                        .finish_restore(pending, result)
                        .unwrap_or_else(rejected);
                    let _ = reply.send(response);
                }
                Ok(GuardianIngress::Failed(error)) => break Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if outstanding_guest_jobs == 0
                        && last_request.elapsed() >= Duration::from_secs(3)
                        && guardian.can_retire()?
                    {
                        break Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(Error::Protocol("guardian ingress stopped unexpectedly"));
                }
            }
            if outstanding_guest_jobs < inflight_limit
                && let Some((input, pending)) = guardian.begin_reset_boot()?
            {
                queue_boot(
                    guardian,
                    &boot_jobs,
                    BootWorkItem {
                        input,
                        pending,
                        reply: None,
                    },
                )?;
            }
            if last_poll.elapsed() >= Duration::from_secs(1) {
                last_poll = std::time::Instant::now();
                guardian.refresh_native_observation()?;
                guardian.reconcile_execution_integration();
                if !poll_in_flight
                    && outstanding_guest_jobs + usize::from(guardian.offline_in_flight)
                        < inflight_limit
                    && let Some(job) = guardian.poll_job()?
                    && guest_jobs
                        .try_send(GuestWorkItem {
                            job,
                            pending: GuestPending::Poll {
                                generation: guardian
                                    .journal
                                    .last_observation()?
                                    .ok_or(Error::Protocol("poll machine generation unavailable"))?
                                    .value()
                                    .generation,
                            },
                            reply: None,
                        })
                        .is_ok()
                {
                    outstanding_guest_jobs += 1;
                    poll_in_flight = true;
                }
            }
        })();
        events.close();
        stopped.store(true, Ordering::Release);
        drop(receiver);
        accept_worker
            .join()
            .map_err(|_| Error::Protocol("guardian accept worker panicked"))?;
        drop(guest_jobs);
        drop(guest_worker); // No native handles or journal writer are owned by this thread.
        drop(boot_jobs);
        drop(boot_worker); // Immutable input only; no journal or native ownership.
        result
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
enum GuardianIngress {
    Request {
        parsed: Box<Result<GuardianRequest>>,
        reply: mpsc::Sender<GuardianResponse>,
    },
    GuestComplete {
        pending: GuestPending,
        result: GuestJobResult,
        reply: Option<mpsc::Sender<GuardianResponse>>,
    },
    BootComplete {
        pending: BootPending,
        result: Result<PreparedBoot>,
        reply: Option<mpsc::Sender<GuardianResponse>>,
    },
    RestoreComplete {
        pending: Box<RestorePending>,
        result: Result<PreparedRestore>,
        reply: mpsc::Sender<GuardianResponse>,
    },
    Failed(std::io::Error),
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct BootWorkItem {
    input: BootPreparation,
    pending: BootPending,
    reply: Option<mpsc::Sender<GuardianResponse>>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
enum OfflineWorkItem {
    Boot(BootWorkItem),
    Restore {
        input: RestorePreparation,
        pending: Box<RestorePending>,
        reply: mpsc::Sender<GuardianResponse>,
    },
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn queue_boot<E: GuardianEffect>(
    guardian: &mut Guardian<E>,
    queue: &mpsc::SyncSender<OfflineWorkItem>,
    item: BootWorkItem,
) -> Result<()> {
    if let Err(error) = queue.try_send(OfflineWorkItem::Boot(item)) {
        let item = match error {
            mpsc::TrySendError::Full(item) | mpsc::TrySendError::Disconnected(item) => item,
        };
        let OfflineWorkItem::Boot(item) = item else {
            unreachable!()
        };
        let response = guardian.finish_boot(
            item.pending,
            Err(Error::Unsupported("offline boot queue is unavailable")),
        )?;
        if let Some(reply) = item.reply
            && let Some(response) = response
        {
            let _ = reply.send(response);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct GuestWorkItem {
    job: GuestJob,
    pending: GuestPending,
    reply: Option<mpsc::Sender<GuardianResponse>>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct ActiveGuardianConnection(Arc<AtomicUsize>);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl Drop for ActiveGuardianConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn serve_guardian<E: GuardianEffect>(_: &Path, _: &mut Guardian<E>) -> Result<()> {
    Err(Error::Unsupported(
        "native guardian control transport is not implemented on this host",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn request_frame(request: &RequestEnvelope<GuardianRequest>) -> Result<Frame> {
    let payload = serde_json::to_vec(&(SERVICE_VERSION, request))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(Error::Protocol("guardian request exceeds its bound"));
    }
    Ok(Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ONE,
        authentication: [0; AUTHENTICATION_BYTES],
        payload,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn response_frame(sequence: Counter, response: &GuardianResponse) -> Result<Frame> {
    let payload = serde_json::to_vec(&(SERVICE_VERSION, response))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(Error::Protocol("guardian response exceeds its bound"));
    }
    Ok(Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence,
        authentication: [0; AUTHENTICATION_BYTES],
        payload,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_request(frame: Frame) -> Result<RequestEnvelope<GuardianRequest>> {
    require_control_frame(&frame)?;
    let (version, request): (u16, RequestEnvelope<GuardianRequest>) =
        serde_json::from_slice(&frame.payload)?;
    if version != SERVICE_VERSION {
        return Err(Error::Protocol("guardian service version mismatch"));
    }
    Ok(request)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_response(frame: Frame) -> Result<GuardianResponse> {
    require_control_frame(&frame)?;
    if frame.sequence != Counter::ONE {
        return Err(Error::Protocol("guardian response sequence mismatch"));
    }
    let (version, response): (u16, GuardianResponse) = serde_json::from_slice(&frame.payload)?;
    if version != SERVICE_VERSION {
        return Err(Error::Protocol("guardian service version mismatch"));
    }
    Ok(response)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn require_control_frame(frame: &Frame) -> Result<()> {
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence == Counter::ZERO
        || frame.authentication != [0; AUTHENTICATION_BYTES]
    {
        return Err(Error::Protocol("invalid guardian control frame"));
    }
    Ok(())
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod local_output_tests {
    use super::*;

    fn dense_response() -> GuardianResponse {
        let bytes = vec![255; MAX_STREAM_BYTES];
        let digest = bytes_digest(&bytes);
        GuardianResponse::Runtime {
            response: RuntimeResponse::Output {
                page: EvidencePage {
                    after: Counter::ZERO,
                    cursor: (bytes.len() as u64).try_into().unwrap(),
                    available: (bytes.len() as u64).try_into().unwrap(),
                    chunks: vec![EvidenceChunk {
                        sequence: Counter::ONE,
                        offset: Counter::ZERO,
                        stream: Stream::Stdout,
                        bytes,
                        bytes_digest: digest.clone(),
                        chain_digest: digest,
                    }],
                },
            },
        }
    }

    #[test]
    fn guardian_binary_response_preserves_dense_bytes() {
        let response = dense_response();
        let (wire, bytes) = response.clone().into_wire_parts().unwrap();
        let frame = response_frame(Counter::ONE, &wire).unwrap();
        assert!(frame.payload.len() < MAX_CONTROL_BYTES);
        let parsed = parse_response(frame).unwrap();
        assert_eq!(
            parsed.binary_descriptor().unwrap().unwrap()[0].length as usize,
            MAX_STREAM_BYTES
        );
        assert_eq!(parsed.with_wire_bytes(bytes.unwrap()).unwrap(), response);
    }
    #[test]
    fn guardian_binary_response_rejects_corrupt_bytes() {
        let (wire, bytes) = dense_response().into_wire_parts().unwrap();
        let mut bytes = bytes.unwrap();
        bytes[0][0] ^= 1;
        assert!(wire.with_wire_bytes(bytes).is_err());
    }
}
