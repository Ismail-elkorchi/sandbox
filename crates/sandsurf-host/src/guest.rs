use sandsurf_control::{
    EffectOutcome, Error as ControlError, Result as ControlResult, WorkloadDriver,
};
use sandsurf_native::{GuestChannel, GuestChannelError, GuestConnection};
use sandsurf_protocol::{
    AUTHENTICATION_BYTES, BootCapability, CONTROL_COMPLETE, Counter, Frame, FrameKind,
    GuestChallenge, GuestServiceRequest, GuestServiceResponse, HostHandshake, Mutation,
    ProcessState, SessionCodec,
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
    session: Option<GuestSession>,
}

struct GuestSession {
    connection: Box<dyn GuestConnection>,
    codec: SessionCodec,
    outgoing: Counter,
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
            session: None,
        }
    }

    pub fn call(
        &mut self,
        request: &GuestServiceRequest,
    ) -> Result<GuestServiceResponse, GuestClientError> {
        if self.session.is_none() {
            self.session = Some(self.connect()?);
        }
        let result = self.call_session(request);
        if result.is_err()
            || matches!(
                request,
                GuestServiceRequest::RebindEpoch { .. } | GuestServiceRequest::PrepareStop
            )
        {
            self.session = None;
        }
        result
    }

    fn connect(&mut self) -> Result<GuestSession, GuestClientError> {
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
        let (finish, codec) = handshake.finish(&challenge)?;
        write_unauthed(&mut *connection, &finish)?;
        Ok(GuestSession {
            connection,
            codec,
            outgoing: Counter::ZERO,
        })
    }

    fn call_session(
        &mut self,
        request: &GuestServiceRequest,
    ) -> Result<GuestServiceResponse, GuestClientError> {
        let session = self
            .session
            .as_mut()
            .ok_or(GuestClientError::Protocol("guest session is unavailable"))?;
        let payload = serde_json::to_vec(request)?;
        if payload.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
            return Err(GuestClientError::Protocol(
                "guest request exceeds control bound",
            ));
        }
        session.outgoing = session.outgoing.next()?;
        session
            .codec
            .seal(Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: session.outgoing,
                authentication: [0; AUTHENTICATION_BYTES],
                payload,
            })?
            .write(&mut *session.connection)?;
        let response = Frame::read(&mut *session.connection)?.ok_or(GuestClientError::Protocol(
            "guest closed without a response",
        ))?;
        let response = session.codec.open(response)?;
        if response.kind != FrameKind::Control || response.stream != 0 {
            return Err(GuestClientError::Protocol(
                "guest returned a non-control response",
            ));
        }
        let response = serde_json::from_slice(&response.payload)?;
        let completion = Frame::read(&mut *session.connection)?.ok_or(
            GuestClientError::Protocol("guest closed without protocol completion"),
        )?;
        let completion = session.codec.open(completion)?;
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
    reconcile_cursor: usize,
}

impl<C> RemoteWorkloadDriver<C> {
    pub fn new(client: GuestClient<C>) -> Self {
        Self {
            client,
            reconcile_cursor: 0,
        }
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
        // Reconciliation shares the guardian owner with lifecycle and control.
        // Drain a bounded, rotating slice instead of allowing a chatty service
        // to hold that owner until its entire spool has been copied.
        const RECONCILE_PROCESS_BUDGET: usize = 8;
        let process_count = processes.len();
        if process_count == 0 {
            self.reconcile_cursor = 0;
            return Ok(());
        }
        let start = self.reconcile_cursor % process_count;
        let count = process_count.min(RECONCILE_PROCESS_BUDGET);
        self.reconcile_cursor = (start + count) % process_count;
        for offset in 0..count {
            let snapshot = &processes[(start + offset) % process_count];
            let process_id = &snapshot.request.process_id;
            journal.observe_process(snapshot)?;
            if matches!(&snapshot.state, ProcessState::Exited(_))
                && journal.receipt(process_id)?.is_some()
            {
                continue;
            }
            let mut committed = journal.process_boundary(process_id)?;
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
            if let ProcessState::Exited(completion) = &snapshot.state {
                if committed != completion.output {
                    if committed.final_cursor >= page.available {
                        return Err(sandsurf_state::Error::Corrupt(
                            "guardian output does not cover guest completion",
                        ));
                    }
                } else if journal.receipt(process_id)?.is_none() {
                    journal.publish_receipt(
                        process_id,
                        completion.outcome.clone(),
                        completion.cleanup_digest.clone(),
                        completion.accounting_digest.clone(),
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sandsurf_protocol::{GuestFinish, GuestHandshake, GuestHello};
    use std::os::unix::net::UnixStream;

    struct PairChannel(Option<UnixStream>);

    impl GuestChannel for PairChannel {
        fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError> {
            self.0
                .take()
                .map(|stream| Box::new(stream) as Box<dyn GuestConnection>)
                .ok_or_else(|| GuestChannelError::Protocol("unexpected reconnect".into()))
        }
    }

    fn send_unauthed<T: serde::Serialize>(stream: &mut UnixStream, value: &T) {
        Frame {
            kind: FrameKind::Control,
            stream: 0,
            sequence: Counter::ZERO,
            authentication: [0; AUTHENTICATION_BYTES],
            payload: serde_json::to_vec(value).unwrap(),
        }
        .write(stream)
        .unwrap();
    }

    #[test]
    fn authenticated_guest_session_serves_multiple_requests() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let sandbox = SandboxId::try_from("persistent-guest").unwrap();
        let boot = sandsurf_protocol::bytes_digest(b"verified-boot");
        let capability = [7; 32];
        let expected_sandbox = sandbox.clone();
        let expected_boot = boot.clone();
        let server = std::thread::spawn(move || {
            server_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let hello: GuestHello = read_unauthed(&mut server_stream).unwrap();
            let (handshake, challenge) = GuestHandshake::accept(
                BootCapability::from_bytes(capability),
                &expected_sandbox,
                Counter::ONE,
                &expected_boot,
                &hello,
            )
            .unwrap();
            send_unauthed(&mut server_stream, &challenge);
            let finish: GuestFinish = read_unauthed(&mut server_stream).unwrap();
            let mut codec = handshake.finish(&finish).unwrap();
            let mut outgoing = Counter::ZERO;
            for _ in 0..2 {
                let request = codec
                    .open(Frame::read(&mut server_stream).unwrap().unwrap())
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<GuestServiceRequest>(&request.payload).unwrap(),
                    GuestServiceRequest::ProbeIdentity
                );
                for payload in [
                    serde_json::to_vec(&GuestServiceResponse::Identity {
                        sandbox_id: expected_sandbox.clone(),
                        epoch: Counter::ONE,
                        boot_identity: expected_boot.clone(),
                    })
                    .unwrap(),
                    CONTROL_COMPLETE.to_vec(),
                ] {
                    outgoing = outgoing.next().unwrap();
                    codec
                        .seal(Frame {
                            kind: FrameKind::Control,
                            stream: 0,
                            sequence: outgoing,
                            authentication: [0; AUTHENTICATION_BYTES],
                            payload,
                        })
                        .unwrap()
                        .write(&mut server_stream)
                        .unwrap();
                }
            }
        });
        let mut client = GuestClient::new(
            PairChannel(Some(client_stream)),
            sandbox.clone(),
            Counter::ONE,
            boot.clone(),
            capability,
        );
        for _ in 0..2 {
            assert_eq!(
                client.call(&GuestServiceRequest::ProbeIdentity).unwrap(),
                GuestServiceResponse::Identity {
                    sandbox_id: sandbox.clone(),
                    epoch: Counter::ONE,
                    boot_identity: boot.clone(),
                }
            );
        }
        server.join().unwrap();
    }
}
