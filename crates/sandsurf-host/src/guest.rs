use sandbox_vm::{GuestChannel, GuestChannelError, GuestConnection};
use sandsurf_control::{
    EffectOutcome, Error as ControlError, Result as ControlResult, WorkloadDriver,
};
use sandsurf_protocol::{
    AUTHENTICATION_BYTES, BootCapability, CONTROL_COMPLETE, Counter, Frame, FrameKind,
    GuestChallenge, GuestServiceRequest, GuestServiceResponse, HostHandshake, Mutation,
    ProcessState,
};
use sandsurf_protocol::{Capability, Digest, SandboxId};
use sandsurf_state::RuntimeJournal;
use std::fmt;
use std::io;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum GuestClientError {
    Channel(GuestChannelError),
    Io(io::Error),
    Protocol(&'static str),
    Contract(sandsurf_protocol::Invalid),
    Json(serde_json::Error),
}

impl fmt::Display for GuestClientError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(error) => error.fmt(output),
            Self::Io(error) => error.fmt(output),
            Self::Protocol(message) => output.write_str(message),
            Self::Contract(error) => error.fmt(output),
            Self::Json(error) => error.fmt(output),
        }
    }
}

impl std::error::Error for GuestClientError {}
impl From<GuestChannelError> for GuestClientError {
    fn from(value: GuestChannelError) -> Self {
        Self::Channel(value)
    }
}
impl From<io::Error> for GuestClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<sandsurf_protocol::Invalid> for GuestClientError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}
impl From<serde_json::Error> for GuestClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub struct GuestClient<C> {
    channel: C,
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
}

impl<C: GuestChannel> GuestClient<C> {
    pub fn new(
        channel: C,
        sandbox_id: SandboxId,
        epoch: Counter,
        boot_identity: Digest,
        capability: [u8; 32],
    ) -> Self {
        Self {
            channel,
            sandbox_id,
            epoch,
            boot_identity,
            capability,
        }
    }

    pub fn call(
        &mut self,
        request: &GuestServiceRequest,
    ) -> Result<GuestServiceResponse, GuestClientError> {
        let mut connection = self.channel.connect()?;
        connection.set_io_timeout(Some(IO_TIMEOUT))?;
        let (handshake, hello) = HostHandshake::start(
            BootCapability::from_bytes(self.capability),
            self.sandbox_id.clone(),
            self.epoch,
            self.boot_identity.clone(),
        )?;
        write_unauthed(&mut *connection, &hello)?;
        let challenge: GuestChallenge = read_unauthed(&mut *connection)?;
        let (finish, mut codec) = handshake.finish(&challenge)?;
        write_unauthed(&mut *connection, &finish)?;

        let payload = serde_json::to_vec(request)?;
        if payload.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
            return Err(GuestClientError::Protocol(
                "guest request exceeds control bound",
            ));
        }
        codec
            .seal(Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: Counter::ONE,
                authentication: [0; AUTHENTICATION_BYTES],
                payload,
            })?
            .write(&mut *connection)?;
        let response = Frame::read(&mut *connection)?.ok_or(GuestClientError::Protocol(
            "guest closed without a response",
        ))?;
        let response = codec.open(response)?;
        if response.kind != FrameKind::Control || response.stream != 0 {
            return Err(GuestClientError::Protocol(
                "guest returned a non-control response",
            ));
        }
        let response = serde_json::from_slice(&response.payload)?;
        let completion = Frame::read(&mut *connection)?.ok_or(GuestClientError::Protocol(
            "guest closed without protocol completion",
        ))?;
        let completion = codec.open(completion)?;
        if completion.kind != FrameKind::Control
            || completion.stream != 0
            || completion.payload != CONTROL_COMPLETE
        {
            return Err(GuestClientError::Protocol(
                "guest returned an invalid protocol completion",
            ));
        }
        Ok(response)
    }
}

pub struct RemoteWorkloadDriver<C> {
    client: GuestClient<C>,
}

impl<C> RemoteWorkloadDriver<C> {
    pub fn new(client: GuestClient<C>) -> Self {
        Self { client }
    }
}

impl<C: GuestChannel> WorkloadDriver for RemoteWorkloadDriver<C> {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        match self.client.call(&GuestServiceRequest::Dispatch {
            mutation: mutation.clone(),
            capability,
        }) {
            Ok(GuestServiceResponse::Effect { outcome }) => effect(outcome),
            Ok(GuestServiceResponse::File { .. }) => EffectOutcome::Applied(
                sandsurf_protocol::digest(
                    sandsurf_protocol::Domain::Operation,
                    &(
                        "guest-filesystem-applied-v1",
                        &mutation.operation_id,
                        &mutation.request_digest,
                    ),
                )
                .unwrap_or_else(|_| sandsurf_protocol::bytes_digest(b"guest-filesystem-applied")),
            ),
            Ok(GuestServiceResponse::Error { .. }) => EffectOutcome::NotApplied(
                sandsurf_protocol::bytes_digest(b"guest-rejected-workload-operation"),
            ),
            Ok(other) => {
                eprintln!("sandsurf guest mutation returned an unexpected response: {other:?}");
                EffectOutcome::Unknown
            }
            Err(error) => {
                eprintln!("sandsurf guest mutation transport failed: {error}");
                EffectOutcome::Unknown
            }
        }
    }

    fn reconcile(&mut self, journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        let processes = match self.client.call(&GuestServiceRequest::Processes) {
            Ok(GuestServiceResponse::Processes { processes }) => processes,
            _ => return Ok(()),
        };
        for snapshot in processes {
            let process_id = &snapshot.request.process_id;
            journal.observe_process(&snapshot)?;
            let mut committed = journal.process_boundary(process_id)?;
            loop {
                let maximum = u32::try_from(sandsurf_protocol::MAX_STREAM_BYTES)
                    .map_err(|_| sandsurf_state::Error::Corrupt("stream bound overflow"))?;
                let page = match self.client.call(&GuestServiceRequest::ReadOutput {
                    process_id: process_id.clone(),
                    after: committed.final_cursor,
                    maximum,
                }) {
                    Ok(GuestServiceResponse::Output { page }) => page,
                    // Transport unavailability is not evidence corruption. The
                    // bytes remain in the guest spool and reconciliation resumes
                    // at the last committed cursor on the next pass.
                    _ => return Ok(()),
                };
                if page.required_bytes.is_some() {
                    return Err(sandsurf_state::Error::Corrupt(
                        "guest output chunk exceeds protocol bound",
                    ));
                }
                if page.chunks.is_empty() {
                    break;
                }
                for chunk in page.chunks {
                    if chunk.cursor != committed.final_cursor {
                        return Err(sandsurf_state::Error::Corrupt(
                            "guest output cursor is not contiguous",
                        ));
                    }
                    committed = journal.append_output(
                        process_id,
                        committed.chunks.next()?,
                        chunk.stream,
                        &chunk.bytes,
                    )?;
                }
                if committed.final_cursor >= page.available {
                    break;
                }
            }
            if let ProcessState::Exited(completion) = snapshot.state {
                if committed != completion.output {
                    return Err(sandsurf_state::Error::Corrupt(
                        "guardian output does not cover guest completion",
                    ));
                }
                if journal.receipt(process_id)?.is_none() {
                    journal.publish_receipt(
                        process_id,
                        completion.outcome,
                        completion.cleanup_digest,
                        completion.accounting_digest,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        let mut last = None;
        // Query requests are either observations or exact identity-bound,
        // idempotent supervisor operations. A Firecracker local-init vsock
        // connection can fail before guest delivery, so reconnect without
        // changing the request identity.
        for attempt in 0..3 {
            match self.client.call(&request) {
                Ok(response) => return Ok(response),
                Err(error) => last = Some(error),
            }
            if attempt != 2 {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let error = last.expect("guest query is attempted at least once");
        eprintln!("sandsurf guest query transport failed: {error}");
        Err(ControlError::Rejected {
            category: "guest".into(),
            message: error.to_string(),
        })
    }
}

fn effect(outcome: sandsurf_protocol::GuestEffectOutcome) -> EffectOutcome {
    match outcome {
        sandsurf_protocol::GuestEffectOutcome::Applied { evidence } => {
            EffectOutcome::Applied(evidence)
        }
        sandsurf_protocol::GuestEffectOutcome::NotApplied { evidence } => {
            EffectOutcome::NotApplied(evidence)
        }
        sandsurf_protocol::GuestEffectOutcome::Unknown => EffectOutcome::Unknown,
    }
}

fn write_unauthed<T: serde::Serialize>(
    connection: &mut dyn GuestConnection,
    value: &T,
) -> Result<(), GuestClientError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
        return Err(GuestClientError::Protocol(
            "guest handshake exceeds control bound",
        ));
    }
    Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ZERO,
        authentication: [0; AUTHENTICATION_BYTES],
        payload,
    }
    .write(connection)?;
    Ok(())
}

fn read_unauthed<T: serde::de::DeserializeOwned>(
    connection: &mut dyn GuestConnection,
) -> Result<T, GuestClientError> {
    let frame = Frame::read(connection)?.ok_or(GuestClientError::Protocol(
        "guest handshake closed unexpectedly",
    ))?;
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence != Counter::ZERO
        || frame.authentication != [0; AUTHENTICATION_BYTES]
    {
        return Err(GuestClientError::Protocol(
            "guest handshake frame is malformed",
        ));
    }
    Ok(serde_json::from_slice(&frame.payload)?)
}
