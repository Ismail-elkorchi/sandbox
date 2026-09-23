#![deny(unsafe_code)]

//! Internal host/guardian control service.
//!
//! Applications talk to the host API, which remains the only grant and desired-
//! lifecycle authority. The host sends exact signed operations to a separately
//! owned guardian. The guardian pins one host key and stores observations and
//! operation outcomes, but never reconstructs or mutates a grant set.

use sandsurf_protocol::*;
use sandsurf_state::{DispatchDecision, HostCatalog, RuntimeJournal};
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
const SERVICE_VERSION: u16 = 3;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const OUTPUT_DATA_STREAM: u32 = 1;
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

pub trait GuardianEffect {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome;
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
    fn reconcile(&mut self, _journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        Ok(())
    }
    fn query(&mut self, _request: GuestServiceRequest) -> Result<GuestServiceResponse> {
        Err(Error::Unsupported("guest query is not implemented"))
    }
    fn native_checkpoint(
        &mut self,
        _request: NativeCheckpointRequest,
        _journal: &mut RuntimeJournal,
    ) -> Result<NativeCheckpointResponse> {
        Err(Error::Unsupported(
            "native full-state checkpointing is not implemented",
        ))
    }
    fn rebind_restored_runtime(
        &mut self,
        _journal: &mut RuntimeJournal,
        _epoch: Counter,
    ) -> sandsurf_state::Result<()> {
        Ok(())
    }
    /// Reports whether a last committed live-machine observation is currently
    /// backed by this guardian's exclusive native owner. It is not a lifecycle
    /// transition and cannot manufacture a stopped/failed observation.
    fn live_observation_reachable(&mut self) -> bool {
        true
    }
}

/// Guest/workload dispatch is deliberately separate from native VM ownership.
/// A workload driver cannot report or mutate machine lifecycle state.
pub trait WorkloadDriver {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome;
    fn reconcile(&mut self, _journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        Ok(())
    }
    fn query(&mut self, _request: GuestServiceRequest) -> Result<GuestServiceResponse> {
        Err(Error::Unsupported("guest query is not implemented"))
    }
}

/// Standard guardian effect composition. This exposes capabilities without
/// imposing an application workflow: lifecycle and workload operations remain
/// independently addressable through their own durable operation identities.
pub struct NativeGuardianEffect<M, W> {
    machine: M,
    workload: W,
}

impl<M, W> NativeGuardianEffect<M, W> {
    pub fn new(machine: M, workload: W) -> Self {
        Self { machine, workload }
    }

    pub fn machine(&self) -> &M {
        &self.machine
    }

    pub fn workload(&self) -> &W {
        &self.workload
    }
}

impl<M: sandsurf_machine::MachineDriver, W: WorkloadDriver> GuardianEffect
    for NativeGuardianEffect<M, W>
{
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        self.workload.dispatch(mutation, capability)
    }

    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> LifecycleEffect {
        sandsurf_machine::apply_lifecycle(&mut self.machine, command, current)
    }

    fn configure(
        &mut self,
        command: &ConfigurationCommand,
        current: &MachineObservation,
    ) -> EffectOutcome {
        match self.machine.configure(command, current) {
            sandsurf_machine::ConfigurationOutcome::Applied(evidence) => {
                EffectOutcome::Applied(evidence)
            }
            sandsurf_machine::ConfigurationOutcome::NotApplied(evidence) => {
                EffectOutcome::NotApplied(evidence)
            }
            sandsurf_machine::ConfigurationOutcome::Unknown => EffectOutcome::Unknown,
        }
    }

    fn reconcile(&mut self, journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        self.workload.reconcile(journal)
    }

    fn query(&mut self, request: GuestServiceRequest) -> Result<GuestServiceResponse> {
        self.workload.query(request)
    }
}

pub struct Guardian<E> {
    journal: RuntimeJournal,
    effect: E,
}

impl<E: GuardianEffect> Guardian<E> {
    pub fn new(journal: RuntimeJournal, effect: E) -> Self {
        Self { journal, effect }
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

    /// Pull guest-owned process/output progress into the guardian journal even
    /// when no host request is arriving.  The guest replay spool remains the
    /// source until each byte and its terminal evidence have committed here.
    pub fn reconcile(&mut self) -> Result<()> {
        self.effect.reconcile(&mut self.journal)?;
        Ok(())
    }

    /// A destroyed VM no longer needs a resident owner. Its journal remains
    /// durable and can be reopened if the host later reads historical evidence.
    pub fn can_retire(&mut self) -> Result<bool> {
        Ok(self
            .journal
            .last_observation()?
            .is_some_and(|value| value.value().state == MachineState::Destroyed)
            && !self.effect.live_observation_reachable())
    }

    fn handle_inner(&mut self, request: GuardianRequest) -> Result<GuardianResponse> {
        self.effect.reconcile(&mut self.journal)?;
        match request {
            GuardianRequest::Inspect {
                sandbox_id,
                operation_id,
            } => {
                if &sandbox_id != self.journal.sandbox_id() {
                    return Err(Error::Protocol("guardian sandbox identity mismatch"));
                }
                let observation = match self.journal.last_observation()? {
                    Some(value)
                        if !matches!(
                            value.value().state,
                            MachineState::Running | MachineState::Paused
                        ) || self.effect.live_observation_reachable() =>
                    {
                        Observation::Current {
                            value: value.value().clone(),
                        }
                    }
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
                        sandbox_id,
                        observation,
                        operation,
                        lifecycle_operation,
                        configuration_operation,
                    }),
                })
            }
            GuardianRequest::Dispatch { authorization } => {
                let operation_id = authorization.statement.mutation.operation_id.clone();
                let request_digest = authorization.statement.mutation.request_digest.clone();
                self.journal.admit(authorization.clone())?;
                if let WorkloadRequest::Spawn { request } =
                    &authorization.statement.mutation.request
                {
                    self.journal.admit_process(
                        request.process_id.clone(),
                        &request.operation_id,
                        request.output_bytes,
                        request.stdio == StdioMode::Terminal,
                    )?;
                }
                let operation = match self.journal.begin_dispatch(authorization)? {
                    DispatchDecision::Reconcile(operation) => operation,
                    DispatchDecision::Perform(permit) => {
                        let outcome = permit.perform(|mutation, capability| {
                            self.effect.dispatch(mutation, *capability)
                        });
                        match outcome {
                            EffectOutcome::Applied(evidence) => self.journal.record_delivery(
                                &operation_id,
                                &request_digest,
                                Delivery::Applied,
                                Some(evidence),
                            ),
                            EffectOutcome::NotApplied(evidence) => self.journal.record_delivery(
                                &operation_id,
                                &request_digest,
                                Delivery::NotApplied,
                                Some(evidence),
                            ),
                            EffectOutcome::Unknown => self.journal.record_delivery(
                                &operation_id,
                                &request_digest,
                                Delivery::Unknown,
                                None,
                            ),
                        }?
                    }
                };
                Ok(GuardianResponse::Dispatch { operation })
            }
            GuardianRequest::Transition { authorization } => {
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
                        let outcome = permit
                            .perform(|actual| self.effect.transition(actual, current.as_ref()));
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
                                    let epoch = transitions
                                        .last()
                                        .expect("restored transition checked above")
                                        .epoch;
                                    self.effect
                                        .rebind_restored_runtime(&mut self.journal, epoch)?;
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
                                        sandbox_id: command.sandbox_id.clone(),
                                        epoch: transition.epoch,
                                        sequence,
                                        state: transition.state,
                                        applied_revision: command.revision,
                                        operation_id: command.operation_id.clone(),
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
                        let outcome =
                            permit.perform(|actual| self.effect.configure(actual, &current));
                        match outcome {
                            EffectOutcome::Applied(evidence) => {
                                let sequence = current.sequence.next().map_err(|_| {
                                    Error::Protocol("observation sequence overflow")
                                })?;
                                let committed = self.journal.observe(MachineObservation {
                                    sandbox_id: command.sandbox_id.clone(),
                                    epoch: current.epoch,
                                    sequence,
                                    state: current.state,
                                    applied_revision: command.revision,
                                    operation_id: command.operation_id.clone(),
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
            GuardianRequest::Guest {
                sandbox_id,
                request,
            } => {
                if &sandbox_id != self.journal.sandbox_id()
                    || matches!(request, GuestServiceRequest::Dispatch { .. })
                {
                    return Err(Error::Protocol("unauthorized guardian guest request"));
                }
                let mut response = self.effect.query(request)?;
                if let GuestServiceResponse::ResourceUsage { usage } = &mut response {
                    usage.output_retained_bytes = self.journal.retained_output_bytes()?;
                }
                Ok(GuardianResponse::Guest { response })
            }
            GuardianRequest::NativeCheckpoint {
                sandbox_id,
                request,
            } => {
                if &sandbox_id != self.journal.sandbox_id() {
                    return Err(Error::Protocol("guardian sandbox identity mismatch"));
                }
                let response = self.effect.native_checkpoint(request, &mut self.journal)?;
                Ok(GuardianResponse::NativeCheckpoint { response })
            }
            GuardianRequest::Runtime {
                sandbox_id,
                request,
            } => {
                if &sandbox_id != self.journal.sandbox_id() {
                    return Err(Error::Protocol("guardian sandbox identity mismatch"));
                }
                let response = match request {
                    RuntimeRequest::Events { after, maximum } => RuntimeResponse::Events {
                        page: self.journal.events(after, maximum)?,
                    },
                    RuntimeRequest::Process { process_id } => {
                        let snapshot = self.journal.process_snapshot(&process_id)?;
                        let reachable = snapshot.as_ref().is_some_and(|snapshot| {
                            matches!(snapshot.state, ProcessState::Exited(_))
                                || self.effect.live_observation_reachable()
                        });
                        RuntimeResponse::Process {
                            process: Some(match snapshot {
                                Some(value) if reachable => Observation::Current { value },
                                Some(value) => Observation::Unavailable {
                                    last_known: Some(value),
                                },
                                None => Observation::Unavailable { last_known: None },
                            }),
                        }
                    }
                    RuntimeRequest::Processes => {
                        let snapshots = self.journal.process_snapshots()?;
                        let reachable = snapshots
                            .iter()
                            .all(|snapshot| matches!(snapshot.state, ProcessState::Exited(_)))
                            || self.effect.live_observation_reachable();
                        RuntimeResponse::Processes {
                            processes: snapshots
                                .into_iter()
                                .map(|value| {
                                    if matches!(value.state, ProcessState::Exited(_)) || reachable {
                                        Observation::Current { value }
                                    } else {
                                        Observation::Unavailable {
                                            last_known: Some(value),
                                        }
                                    }
                                })
                                .collect(),
                        }
                    }
                    RuntimeRequest::Operation { operation_id } => RuntimeResponse::Operation {
                        operation: self.journal.runtime_operation(&operation_id)?,
                    },
                    RuntimeRequest::Receipt { process_id } => {
                        let value = self.journal.receipt(&process_id)?;
                        RuntimeResponse::Receipt {
                            receipt: value.as_ref().map(|value| value.0.clone()),
                            digest: value.map(|value| value.1),
                        }
                    }
                    RuntimeRequest::ReadOutput {
                        process_id,
                        after,
                        maximum,
                    } => RuntimeResponse::Output {
                        page: evidence_page(self.journal.read_output(
                            &process_id,
                            after,
                            maximum as usize,
                        )?),
                    },
                    RuntimeRequest::AcknowledgeReceipt {
                        operation_id,
                        process_id,
                        receipt_digest,
                    } => {
                        self.journal.acknowledge_receipt(
                            &operation_id,
                            &process_id,
                            &receipt_digest,
                        )?;
                        RuntimeResponse::Complete
                    }
                    RuntimeRequest::Pin {
                        operation_id,
                        process_id,
                        receipt_digest,
                        pin_id,
                    } => {
                        self.journal
                            .pin(&operation_id, &process_id, &receipt_digest, pin_id)?;
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
                        process_id,
                        request,
                    } => RuntimeResponse::Release {
                        status: self.journal.release(&process_id, request)?,
                    },
                    RuntimeRequest::CleanupReleased {
                        process_id,
                        request_digest,
                    } => RuntimeResponse::Release {
                        status: self
                            .journal
                            .cleanup_released(&process_id, &request_digest)?,
                    },
                };
                Ok(GuardianResponse::Runtime { response })
            }
        }
    }

    fn reconcile_lifecycle(&mut self, operation: LifecycleOperation) -> Result<LifecycleOperation> {
        if matches!(operation.delivery, Delivery::Dispatched | Delivery::Unknown)
            && let Some(observed) = self.journal.last_observation()?
            && observed.value().operation_id == operation.command.operation_id
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
            && observed.value().operation_id == operation.command.operation_id
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

fn error_category(error: &Error) -> &'static str {
    match error {
        Error::Io(_) => "transport",
        Error::Json(_) | Error::Protocol(_) => "protocol",
        Error::State(_) => "state",
        Error::Rejected { .. } => "remote",
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
        let inspection = client.inspect(intent.sandbox_id.clone(), Some(operation_id.clone()))?;
        let operation = inspection.lifecycle_operation.ok_or(Error::Protocol(
            "guardian no longer retains a completed lifecycle operation",
        ))?;
        if operation.command.sandbox_id != intent.sandbox_id
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
            operation.command.sandbox_id.clone(),
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

    pub fn dispatch(
        &self,
        mutation: Mutation,
        capability: Capability,
        scope_digest: &Digest,
    ) -> Result<Operation> {
        let authorization = self.catalog.authorize(mutation, capability, scope_digest)?;
        self.guardian.dispatch(authorization)
    }

    pub fn transition(&self, operation_id: &OperationId) -> Result<LifecycleOperation> {
        let authorization = self.catalog.authorize_lifecycle(operation_id)?;
        self.guardian.transition(authorization)
    }

    pub fn inspect(
        &self,
        sandbox_id: SandboxId,
        operation_id: Option<OperationId>,
    ) -> Result<GuardianInspection> {
        self.guardian.inspect(sandbox_id, operation_id)
    }
}

impl GuardianClient {
    pub fn new(endpoint: PathBuf) -> Self {
        Self { endpoint }
    }

    pub fn inspect(
        &self,
        sandbox_id: SandboxId,
        operation_id: Option<OperationId>,
    ) -> Result<GuardianInspection> {
        match self.call(GuardianRequest::Inspect {
            sandbox_id,
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
            GuardianResponse::NativeCheckpoint { .. } => {
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

    pub fn dispatch(&self, authorization: AuthorizedMutation) -> Result<Operation> {
        match self.call(GuardianRequest::Dispatch { authorization })? {
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
            GuardianResponse::NativeCheckpoint { .. } => {
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
            | GuardianResponse::NativeCheckpoint { .. }
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
            | GuardianResponse::NativeCheckpoint { .. }
            | GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
        }
    }

    pub fn guest(
        &self,
        sandbox_id: SandboxId,
        request: GuestServiceRequest,
    ) -> Result<GuestServiceResponse> {
        match self.call(GuardianRequest::Guest {
            sandbox_id,
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
            | GuardianResponse::NativeCheckpoint { .. }
            | GuardianResponse::Runtime { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
        }
    }

    pub fn native_checkpoint(
        &self,
        sandbox_id: SandboxId,
        request: NativeCheckpointRequest,
    ) -> Result<NativeCheckpointResponse> {
        match self.call(GuardianRequest::NativeCheckpoint {
            sandbox_id,
            request,
        })? {
            GuardianResponse::NativeCheckpoint { response } => Ok(response),
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
        sandbox_id: SandboxId,
        request: RuntimeRequest,
    ) -> Result<RuntimeResponse> {
        match self.call(GuardianRequest::Runtime {
            sandbox_id,
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
            | GuardianResponse::NativeCheckpoint { .. } => {
                Err(Error::Protocol("guardian returned the wrong response kind"))
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn call(&self, request: GuardianRequest) -> Result<GuardianResponse> {
        use sandsurf_native::local::LocalConnection;
        let mut connection = LocalConnection::connect(&self.endpoint, REQUEST_TIMEOUT)?;
        let frame = request_frame(&request)?;
        connection.write_frame(&frame, REQUEST_TIMEOUT)?;
        let response = connection
            .read_frame(REQUEST_TIMEOUT)?
            .ok_or(Error::Protocol("guardian closed without a response"))?;
        parse_response_stream(response, || {
            connection.read_frame(REQUEST_TIMEOUT).map_err(Error::Io)
        })
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
    let (sender, receiver) = mpsc::sync_channel::<GuardianIngress>(MAX_GUARDIAN_CONNECTIONS);
    let mut last_request = std::time::Instant::now();
    std::thread::scope(|scope| {
        let stopped_accept = Arc::clone(&stopped);
        let active_accept = Arc::clone(&active);
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
                        let (reply, response) = mpsc::channel();
                        if sender
                            .try_send(GuardianIngress::Request {
                                parsed: Box::new(parse_request(frame)),
                                reply,
                            })
                            .is_err()
                        {
                            return;
                        }
                        if let Ok(response) = response.recv() {
                            let frames = response_frames(sequence, response).or_else(|error| {
                                response_frames(
                                    sequence,
                                    GuardianResponse::Rejected {
                                        category: "protocol".into(),
                                        message: error.to_string(),
                                    },
                                )
                            });
                            if let Ok(frames) = frames {
                                // A lost response never reverses an admitted operation.
                                for frame in frames {
                                    if connection.write_frame(&frame, REQUEST_TIMEOUT).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                if let Err(error) = worker {
                    active_accept.fetch_sub(1, Ordering::AcqRel);
                    eprintln!("sandsurf guardian connection rejected: {error}");
                }
            }
        });
        let result = loop {
            match receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(GuardianIngress::Request { parsed, reply }) => {
                    last_request = std::time::Instant::now();
                    let response = match *parsed {
                        Ok(request) => guardian.handle(request),
                        Err(error) => GuardianResponse::Rejected {
                            category: error_category(&error).to_owned(),
                            message: error.to_string(),
                        },
                    };
                    let _ = reply.send(response);
                }
                Ok(GuardianIngress::Failed(error)) => break Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(error) = guardian.reconcile() {
                        eprintln!("sandsurf guardian reconciliation deferred: {error}");
                    }
                    if last_request.elapsed() >= Duration::from_secs(3) && guardian.can_retire()? {
                        break Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(Error::Protocol("guardian ingress stopped unexpectedly"));
                }
            }
        };
        stopped.store(true, Ordering::Release);
        drop(receiver);
        accept_worker
            .join()
            .map_err(|_| Error::Protocol("guardian accept worker panicked"))?;
        result
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
enum GuardianIngress {
    Request {
        parsed: Box<Result<GuardianRequest>>,
        reply: mpsc::Sender<GuardianResponse>,
    },
    Failed(std::io::Error),
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
fn request_frame(request: &GuardianRequest) -> Result<Frame> {
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
fn response_frames(sequence: Counter, response: GuardianResponse) -> Result<Vec<Frame>> {
    let (response, bytes) = match response {
        GuardianResponse::Runtime {
            response: RuntimeResponse::Output { page },
        } => {
            let (page, bytes) = page
                .into_binary_parts()
                .map_err(|_| Error::Protocol("guardian output page is invalid"))?;
            (
                GuardianResponse::Runtime {
                    response: RuntimeResponse::OutputMetadata { page },
                },
                Some(bytes),
            )
        }
        GuardianResponse::Runtime {
            response: RuntimeResponse::OutputMetadata { .. },
        } => return Err(Error::Protocol("guardian cannot originate output metadata")),
        response => (response, None),
    };
    let mut frames = vec![response_frame(sequence, &response)?];
    if let Some(bytes) = bytes {
        for (index, payload) in bytes.into_iter().enumerate() {
            frames.push(Frame {
                kind: FrameKind::Data,
                stream: OUTPUT_DATA_STREAM,
                sequence: Counter::ONE
                    .checked_add(index as u64)
                    .map_err(|_| Error::Protocol("guardian output sequence overflow"))?,
                authentication: [0; AUTHENTICATION_BYTES],
                payload,
            });
        }
        frames.push(Frame {
            kind: FrameKind::End,
            stream: OUTPUT_DATA_STREAM,
            sequence: Counter::ONE
                .checked_add((frames.len() - 1) as u64)
                .map_err(|_| Error::Protocol("guardian output sequence overflow"))?,
            authentication: [0; AUTHENTICATION_BYTES],
            payload: Vec::new(),
        });
    }
    Ok(frames)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_request(frame: Frame) -> Result<GuardianRequest> {
    require_control_frame(&frame)?;
    let (version, request): (u16, GuardianRequest) = serde_json::from_slice(&frame.payload)?;
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
fn parse_response_stream(
    frame: Frame,
    mut next: impl FnMut() -> Result<Option<Frame>>,
) -> Result<GuardianResponse> {
    let response = parse_response(frame)?;
    let GuardianResponse::Runtime {
        response: RuntimeResponse::OutputMetadata { page },
    } = response
    else {
        return Ok(response);
    };
    page.validate_lengths()
        .map_err(|_| Error::Protocol("guardian output metadata is invalid"))?;
    let mut bytes = Vec::with_capacity(page.chunks.len());
    for (index, chunk) in page.chunks.iter().enumerate() {
        let frame = next()?.ok_or(Error::Protocol("guardian output data is incomplete"))?;
        if frame.kind != FrameKind::Data
            || frame.stream != OUTPUT_DATA_STREAM
            || frame.sequence.get() != index as u64 + 1
            || frame.payload.len() != chunk.length as usize
        {
            return Err(Error::Protocol("guardian output data frame is invalid"));
        }
        bytes.push(frame.payload);
    }
    let end = next()?.ok_or(Error::Protocol("guardian output end is missing"))?;
    if end.kind != FrameKind::End
        || end.stream != OUTPUT_DATA_STREAM
        || end.sequence.get() != bytes.len() as u64 + 1
        || !end.payload.is_empty()
    {
        return Err(Error::Protocol("guardian output end is invalid"));
    }
    let page = page
        .with_binary_parts(bytes)
        .map_err(|_| Error::Protocol("guardian output data differs from metadata"))?;
    Ok(GuardianResponse::Runtime {
        response: RuntimeResponse::Output { page },
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn require_control_frame(frame: &Frame) -> Result<()> {
    if frame.kind != FrameKind::Control || frame.stream != 0 || frame.sequence == Counter::ZERO {
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
    fn guardian_output_uses_verified_binary_frames_at_the_control_bound() {
        let response = dense_response();
        let mut frames = response_frames(Counter::ONE, response.clone()).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].kind, FrameKind::Control);
        assert_eq!(frames[1].kind, FrameKind::Data);
        assert_eq!(frames[1].payload.len(), MAX_STREAM_BYTES);
        let first = frames.remove(0);
        let mut remaining = frames.into_iter();
        assert_eq!(
            parse_response_stream(first, || Ok(remaining.next())).unwrap(),
            response
        );
    }

    #[test]
    fn guardian_output_rejects_corrupt_binary_data() {
        let mut frames = response_frames(Counter::ONE, dense_response()).unwrap();
        frames[1].payload[0] = 0;
        let first = frames.remove(0);
        let mut remaining = frames.into_iter();
        assert!(matches!(
            parse_response_stream(first, || Ok(remaining.next())),
            Err(Error::Protocol(
                "guardian output data differs from metadata"
            ))
        ));
    }
}
