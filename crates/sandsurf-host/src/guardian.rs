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
#[path = "event_stream.rs"]
mod event_stream;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use event_stream::EventStream;
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
pub const SERVICE_VERSION: u16 = 7;
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

pub trait GuardianEffect {
    /// The durable capture transaction owns the pause, including uncertain
    /// native delivery. A volatile native "paused" flag is not this authority.
    fn capture_owner(&self) -> Result<Option<OperationId>>;
    fn guest_driver(&mut self) -> Box<dyn GuestDriver>;
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
    ) -> sandsurf_state::Result<()> {
        Ok(())
    }
    fn observe_power(&mut self) -> Result<Option<sandsurf_machine::NativePowerObservation>>;
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

pub struct Guardian<E> {
    journal: RuntimeJournal,
    // Native ownership ends at confirmed destruction. The durable ledger can
    // remain available without image files, virtual hardware, or a guest.
    effect: Option<E>,
    management_seen: Option<std::time::Instant>,
    execution_seen: std::collections::BTreeMap<ExecutionId, std::time::Instant>,
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
    pub fn new(journal: RuntimeJournal, effect: E) -> Self {
        Self {
            journal,
            effect: Some(effect),
            management_seen: None,
            execution_seen: std::collections::BTreeMap::new(),
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
        Ok(Self {
            journal,
            effect: None,
            management_seen: None,
            execution_seen: std::collections::BTreeMap::new(),
        })
    }

    fn begin_guest(&mut self, request: GuardianRequest) -> Result<GuestAdmission> {
        if self.effect.is_none() {
            return Err(Error::Unsupported(
                "destroyed machine has no guest transport",
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
            report,
            interruption: self.journal.execution_interruption(generation)?,
        })
    }

    pub fn handle(&mut self, request: GuardianRequest) -> GuardianResponse {
        match self.handle_inner(request) {
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
        Ok(self
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
        let Some(measured) = measured else {
            return Ok(matches!(
                current.state,
                MachineState::Stopped
                    | MachineState::Suspended
                    | MachineState::Destroyed
                    | MachineState::Failed
            ));
        };
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
            // Capture owns this temporary pause; it is not public pause intent.
            return Ok(false);
        }
        if measured.state != current.state {
            self.journal.observe(MachineObservation {
                machine_id: current.machine_id,
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
            }
        }
        Ok(true)
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
            GuardianRequest::Transition { authorization } => {
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
                            if matches!(
                                actual.desired,
                                DesiredState::Running | DesiredState::Paused
                            ) {
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
                            native.transition(actual, current.as_ref())
                        });
                        match outcome {
                            LifecycleEffect::Observed(transitions) => {
                                if transitions.is_empty() || transitions.len() > 8 {
                                    return Err(Error::Protocol(
                                        "native lifecycle returned an invalid observation count",
                                    ));
                                }
                                if current
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
                                    native
                                        .rebind_restored_runtime(&mut self.journal, generation)?;
                                }
                                let mut references = Vec::with_capacity(transitions.len());
                                for transition in transitions {
                                    let sequence = match self.journal.last_observation()? {
                                        Some(value) => {
                                            value.value().sequence.next().map_err(|_| {
                                                Error::Protocol(
                                                    "guardian observation sequence overflow",
                                                )
                                            })?
                                        }
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
                                let final_observation =
                                    self.journal.last_observation()?.ok_or(Error::Protocol(
                                        "native lifecycle produced no committed observation",
                                    ))?;
                                if !final_observation.value().state.satisfies(command.desired) {
                                    return Err(Error::Protocol(
                                        "native lifecycle did not establish the desired state",
                                    ));
                                }
                                let evidence =
                                    digest(Domain::Operation, &references).map_err(|_| {
                                        Error::Protocol("lifecycle evidence digest failed")
                                    })?;
                                self.journal.record_lifecycle_delivery(
                                    &command.operation_id,
                                    &command.request_digest,
                                    Delivery::Applied,
                                    Some(evidence),
                                    Some(final_observation.reference()?),
                                )?
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
                let response = self
                    .effect
                    .as_mut()
                    .ok_or(Error::Unsupported("destroyed machine has no native owner"))?
                    .native_snapshot(request, &mut self.journal)?;
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
                    RuntimeRequest::OwnerIdentity {} => RuntimeResponse::OwnerIdentity {
                        machine_id: self.journal.machine_id().clone(),
                    },
                    RuntimeRequest::ValidateResources { resources } => {
                        let current = self
                            .journal
                            .last_observation()?
                            .ok_or(Error::Protocol("native resource state is unavailable"))?;
                        self.journal.validate_resource_envelope(&resources)?;
                        self.effect
                            .as_ref()
                            .ok_or(Error::Unsupported("destroyed machine has no native owner"))?
                            .validate_resources(&resources, current.value())?;
                        RuntimeResponse::Complete
                    }
                    RuntimeRequest::Usage => {
                        let mut usage = self
                            .effect
                            .as_mut()
                            .ok_or(Error::Unsupported("destroyed machine has no native owner"))?
                            .resource_usage()?;
                        usage.output_retained_bytes = self.journal.retained_output_bytes()?;
                        usage.executions_current = Counter::try_from(
                            self.journal
                                .process_snapshots()?
                                .iter()
                                .filter(|execution| {
                                    matches!(
                                        execution.state,
                                        ExecutionState::Running | ExecutionState::Draining { .. }
                                    )
                                })
                                .count() as u64,
                        )
                        .map_err(|_| Error::Protocol("execution accounting overflow"))?;
                        RuntimeResponse::Usage { usage }
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
                    RuntimeRequest::Pin {
                        operation_id,
                        execution_id,
                        receipt_digest,
                        pin_id,
                    } => {
                        self.journal
                            .pin(&operation_id, &execution_id, &receipt_digest, pin_id)?;
                        RuntimeResponse::Complete
                    }
                    RuntimeRequest::ReadPin {
                        pin_id,
                        after,
                        maximum,
                    } => RuntimeResponse::Output {
                        page: evidence_page(self.journal.read_pin(
                            &pin_id,
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
            GuardianRequest::SubscribeEvents { .. } => Err(Error::Protocol(
                "event subscriptions require a streaming connection",
            )),
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

/// Trusted host-side routing. Application requests contain identities and
/// expected revisions; this link creates the signed envelope and sends it
/// directly to the guardian without returning it to the application.
pub struct HostGuardianLink<'host> {
    catalog: &'host HostCatalog,
    guardian: GuardianClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLifecycleResult {
    pub guardian_operation: LifecycleOperation,
    pub completed_intent: Option<LifecycleIntent>,
}

/// Route one already-authorized host intent, then commit only guardian evidence
/// that establishes its postcondition. Ambiguous/not-applied delivery leaves the
/// host intent pending and returns the guardian operation unchanged.
pub fn apply_lifecycle(
    catalog: &mut HostCatalog,
    endpoint: PathBuf,
    operation_id: &OperationId,
) -> Result<HostLifecycleResult> {
    let client = GuardianClient::new(endpoint);
    if let Some(intent) = catalog.intent(operation_id)?
        && let Some(completion) = intent.completion.as_ref()
    {
        let inspection = client.inspect(intent.machine_id.clone(), Some(operation_id.clone()))?;
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
        return Ok(HostLifecycleResult {
            guardian_operation: operation,
            completed_intent: Some(intent),
        });
    }
    let authorization = catalog.authorize_lifecycle(operation_id)?;
    let operation = client.transition(authorization)?;
    let completed_intent = if operation.delivery == Delivery::Applied {
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
        Some(catalog.complete_lifecycle_operation(&operation, &observation)?)
    } else {
        None
    };
    Ok(HostLifecycleResult {
        guardian_operation: operation,
        completed_intent,
    })
}

impl<'host> HostGuardianLink<'host> {
    pub fn new(catalog: &'host HostCatalog, endpoint: PathBuf) -> Self {
        Self {
            catalog,
            guardian: GuardianClient::new(endpoint),
        }
    }

    pub fn transition(&self, operation_id: &OperationId) -> Result<LifecycleOperation> {
        let authorization = self.catalog.authorize_lifecycle(operation_id)?;
        self.guardian.transition(authorization)
    }

    pub fn inspect(
        &self,
        machine_id: MachineId,
        operation_id: Option<OperationId>,
    ) -> Result<GuardianInspection> {
        self.guardian.inspect(machine_id, operation_id)
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
    let events = Arc::new(event_stream::EventSignal::new(
        guardian.journal.event_cursor()?,
    ));
    let (sender, receiver) = mpsc::sync_channel::<GuardianIngress>(MAX_GUARDIAN_CONNECTIONS);
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
                if active_accept.fetch_add(1, Ordering::AcqRel) >= MAX_GUARDIAN_CONNECTIONS {
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
                        if let Ok(GuardianRequest::SubscribeEvents {
                            machine_id,
                            after,
                            maximum,
                        }) = &parsed
                        {
                            let _ = event_stream::serve(
                                &mut connection,
                                &sender,
                                &events,
                                machine_id.clone(),
                                *after,
                                *maximum,
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
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(GuardianIngress::Request { parsed, reply }) => {
                    last_request = std::time::Instant::now();
                    let response = match *parsed {
                        Ok(request)
                            if matches!(
                                request,
                                GuardianRequest::Dispatch { .. }
                                    | GuardianRequest::QueryGuest { .. }
                                    | GuardianRequest::Guest { .. }
                            ) =>
                        {
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
                        Ok(request) => guardian.handle(request),
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
            if last_poll.elapsed() >= Duration::from_secs(1) {
                last_poll = std::time::Instant::now();
                guardian.refresh_native_observation()?;
                if !poll_in_flight
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
    Failed(std::io::Error),
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
