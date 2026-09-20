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
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const SERVICE_VERSION: u16 = 1;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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

pub trait GuardianEffect {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome;
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
            Err(error) => GuardianResponse::Rejected {
                category: error_category(&error).to_owned(),
                message: error.to_string(),
            },
        }
    }

    fn handle_inner(&mut self, request: GuardianRequest) -> Result<GuardianResponse> {
        match request {
            GuardianRequest::Inspect {
                sandbox_id,
                operation_id,
            } => {
                if &sandbox_id != self.journal.sandbox_id() {
                    return Err(Error::Protocol("guardian sandbox identity mismatch"));
                }
                let observation = match self.journal.last_observation()? {
                    Some(value) => Observation::Current {
                        value: value.value().clone(),
                    },
                    None => Observation::Unavailable { last_known: None },
                };
                let operation = operation_id
                    .as_ref()
                    .map(|id| self.journal.operation(id))
                    .transpose()?
                    .flatten();
                Ok(GuardianResponse::Inspection {
                    value: GuardianInspection {
                        sandbox_id,
                        observation,
                        operation,
                    },
                })
            }
            GuardianRequest::Dispatch { authorization } => {
                let operation_id = authorization.statement.mutation.operation_id.clone();
                let request_digest = authorization.statement.mutation.request_digest.clone();
                self.journal.admit(authorization.clone())?;
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
        }
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
            GuardianResponse::Inspection { value } => Ok(value),
            GuardianResponse::Dispatch { .. } => {
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
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn call(&self, request: GuardianRequest) -> Result<GuardianResponse> {
        use sandsurf_native::local::LocalConnection;
        let mut connection = LocalConnection::connect(&self.endpoint, REQUEST_TIMEOUT)?;
        let frame = request_frame(&request)?;
        connection.write_frame(&frame, REQUEST_TIMEOUT)?;
        let response = connection
            .read_frame(REQUEST_TIMEOUT)?
            .ok_or(Error::Protocol("guardian closed without a response"))?;
        parse_response(response)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn call(&self, _: GuardianRequest) -> Result<GuardianResponse> {
        Err(Error::Unsupported(
            "native guardian control transport is not implemented on this host",
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn serve_guardian<E: GuardianEffect>(
    endpoint: &Path,
    guardian: &mut Guardian<E>,
) -> Result<()> {
    use sandsurf_native::local::LocalListener;
    let listener = LocalListener::bind(endpoint)?;
    loop {
        let mut connection = match listener.accept(Duration::from_secs(1)) {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error.into()),
        };
        let frame = match connection.read_frame(REQUEST_TIMEOUT) {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => continue,
        };
        let sequence = frame.sequence;
        let response = match parse_request(frame) {
            Ok(request) => guardian.handle(request),
            Err(error) => GuardianResponse::Rejected {
                category: error_category(&error).to_owned(),
                message: error.to_string(),
            },
        };
        let frame = response_frame(sequence, &response)?;
        // A lost response never rolls back the durable dispatch decision.
        let _ = connection.write_frame(&frame, REQUEST_TIMEOUT);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn serve_guardian<E: GuardianEffect>(_: &Path, _: &mut Guardian<E>) -> Result<()> {
    Err(Error::Unsupported(
        "native guardian control transport is not implemented on this host",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn request_frame(request: &GuardianRequest) -> Result<Frame> {
    let payload = serde_json::to_vec(&(SERVICE_VERSION, request))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(Error::Protocol("guardian request exceeds its bound"));
    }
    Ok(Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ONE,
        payload,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn response_frame(sequence: Counter, response: &GuardianResponse) -> Result<Frame> {
    let payload = serde_json::to_vec(&(SERVICE_VERSION, response))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(Error::Protocol("guardian response exceeds its bound"));
    }
    Ok(Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence,
        payload,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_request(frame: Frame) -> Result<GuardianRequest> {
    require_control_frame(&frame)?;
    let (version, request): (u16, GuardianRequest) = serde_json::from_slice(&frame.payload)?;
    if version != SERVICE_VERSION {
        return Err(Error::Protocol("guardian service version mismatch"));
    }
    Ok(request)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_control_frame(frame: &Frame) -> Result<()> {
    if frame.kind != FrameKind::Control || frame.stream != 0 || frame.sequence == Counter::ZERO {
        return Err(Error::Protocol("invalid guardian control frame"));
    }
    Ok(())
}
