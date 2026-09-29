use crate::guardian::{EffectOutcome, Error as ControlError, GuestDriver, Result as ControlResult};
use crate::guest_worker::{ExecutionHints, GuestPoll, GuestProgress};
use sandsurf_native::{GuestChannel, GuestChannelError, GuestConnection};
use sandsurf_protocol::{
    AUTHENTICATION_BYTES, BootCapability, CONTROL_COMPLETE, Counter, Frame, FrameKind,
    GuestChallenge, GuestCommand, GuestServiceRequest, GuestServiceResponse, HostHandshake,
    SessionCodec,
};
use sandsurf_protocol::{
    AuthenticatedFrameChannel, FilesystemRequest, FilesystemResponse, RequestEnvelope,
    bytes_digest, receive_binary, send_binary,
};
use sandsurf_protocol::{Digest, MachineId};
use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

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
    machine_id: MachineId,
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    session: Option<GuestSession>,
}

struct GuestSession {
    connection: DeadlineConnection,
    codec: SessionCodec,
    outgoing: Counter,
}

/// A fragmented frame has one absolute I/O deadline, not one per byte/read.
struct DeadlineConnection {
    inner: Box<dyn GuestConnection>,
    deadline: Instant,
}
impl DeadlineConnection {
    fn new(inner: Box<dyn GuestConnection>, timeout: Duration) -> Self {
        Self {
            inner,
            deadline: Instant::now() + timeout,
        }
    }
    fn renew(&mut self, timeout: Duration) {
        self.deadline = Instant::now() + timeout;
    }
    fn bound(&self) -> io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "guest operation deadline exceeded")
            })?;
        self.inner.set_io_timeout(Some(remaining)).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("guest transport timeout setup ({remaining:?}): {error}"),
            )
        })
    }
}
impl Read for DeadlineConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.bound()?;
        self.inner
            .read(bytes)
            .map_err(|error| io::Error::new(error.kind(), format!("guest transport read: {error}")))
    }
}
impl Write for DeadlineConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bound()?;
        self.inner.write(bytes).map_err(|error| {
            io::Error::new(error.kind(), format!("guest transport write: {error}"))
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.bound()?;
        self.inner.flush().map_err(|error| {
            io::Error::new(error.kind(), format!("guest transport flush: {error}"))
        })
    }
}
impl GuestConnection for DeadlineConnection {
    fn set_io_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        self.bound()
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn deliver_bootstrap(
    mut channel: impl GuestChannel,
    bytes: &[u8],
) -> Result<(), GuestClientError> {
    if bytes.len() > 4096 {
        return Err(GuestClientError::Protocol(
            "guest bootstrap exceeds its bound",
        ));
    }
    let mut connection = DeadlineConnection::new(channel.connect()?, IO_TIMEOUT);
    connection.write_all(bytes)?;
    connection.flush()?;
    Ok(())
}

impl<C: GuestChannel> GuestClient<C> {
    pub fn new(
        channel: C,
        machine_id: MachineId,
        generation: Counter,
        boot_identity: Digest,
        capability: [u8; 32],
    ) -> Self {
        Self {
            channel,
            machine_id,
            generation,
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
        if result.is_err() || matches!(request, GuestServiceRequest::RebindGeneration { .. }) {
            self.session = None;
        }
        result
    }

    fn connect(&mut self) -> Result<GuestSession, GuestClientError> {
        let mut connection = DeadlineConnection::new(self.channel.connect()?, IO_TIMEOUT);
        let (handshake, hello) = HostHandshake::start(
            BootCapability::from_bytes(self.capability),
            self.machine_id.clone(),
            self.generation,
            self.boot_identity.clone(),
        )?;
        write_unauthed(&mut connection, &hello)?;
        let challenge: GuestChallenge = read_unauthed(&mut connection)?;
        let (finish, codec) = handshake.finish(&challenge)?;
        write_unauthed(&mut connection, &finish)?;
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
        session.connection.renew(IO_TIMEOUT);
        let (wire, bytes) = RequestEnvelope::split(request.clone())?;
        let payload = serde_json::to_vec(&wire)?;
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
            .write(&mut session.connection)?;
        if let Some(bytes) = bytes {
            send_binary(
                &mut AuthenticatedFrameChannel {
                    io: &mut session.connection,
                    codec: &mut session.codec,
                },
                bytes,
            )?;
        }
        let response = Frame::read(&mut session.connection)?.ok_or(GuestClientError::Protocol(
            "guest closed without a response",
        ))?;
        let response = session.codec.open(response)?;
        if response.kind != FrameKind::Control || response.stream != 0 {
            return Err(GuestClientError::Protocol(
                "guest returned a non-control response",
            ));
        }
        let response: GuestServiceResponse = serde_json::from_slice(&response.payload)?;
        let response = if let Some(metadata) = response.binary_descriptor()? {
            let maximum = match (request, &response) {
                (
                    GuestServiceRequest::ReadOutput { after, maximum, .. },
                    GuestServiceResponse::OutputMetadata { page },
                ) if page.after == *after => *maximum as usize,
                (
                    GuestServiceRequest::FilesystemQuery {
                        request:
                            FilesystemRequest::Read {
                                offset, maximum, ..
                            },
                    },
                    GuestServiceResponse::File {
                        response: FilesystemResponse::ReadMetadata { range },
                    },
                ) if range.offset == *offset => *maximum as usize,
                _ => {
                    return Err(GuestClientError::Protocol(
                        "unexpected binary guest response",
                    ));
                }
            };
            let bytes = receive_binary(
                &mut AuthenticatedFrameChannel {
                    io: &mut session.connection,
                    codec: &mut session.codec,
                },
                &metadata,
                maximum,
            )?;
            response.with_wire_bytes(bytes)?
        } else {
            response
        };
        let completion = Frame::read(&mut session.connection)?.ok_or(
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

pub struct ManagedGuestClient<C> {
    client: GuestClient<C>,
    reconcile_cursor: usize,
    rebind: Option<PendingRebind<C>>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ManagementRebind {
    pub machine_id: MachineId,
    pub generation: Counter,
    pub boot_identity: Digest,
    pub capability: [u8; 32],
    pub request: GuestServiceRequest,
}

pub struct PendingRebind<C> {
    pub source: GuestClient<C>,
    pub request: GuestServiceRequest,
    attempted: bool,
}
impl<C> PendingRebind<C> {
    pub fn new(source: GuestClient<C>, request: GuestServiceRequest) -> Self {
        Self {
            source,
            request,
            attempted: false,
        }
    }
}

impl<C> ManagedGuestClient<C> {
    pub fn new(client: GuestClient<C>, rebind: Option<PendingRebind<C>>) -> Self {
        Self {
            client,
            reconcile_cursor: 0,
            rebind,
        }
    }
}

impl<C: GuestChannel> ManagedGuestClient<C> {
    fn ensure_bound(&mut self) -> ControlResult<()> {
        let Some(pending) = self.rebind.as_mut() else {
            return Ok(());
        };
        let current = |response: &GuestServiceResponse, client: &GuestClient<C>| {
            matches!(response,
            GuestServiceResponse::Identity { machine_id, generation, boot_identity, .. }
            if machine_id == &client.machine_id && generation == &client.generation && boot_identity == &client.boot_identity)
        };
        if self
            .client
            .call(&GuestServiceRequest::ProbeIdentity)
            .is_ok_and(|response| current(&response, &self.client))
        {
            self.rebind = None;
            return Ok(());
        }
        if !pending.attempted {
            // Delivery is ambiguous after transport failure. Never blindly replay
            // the generation change; subsequent jobs probe the target identity.
            pending.attempted = true;
            let _ = pending.source.call(&pending.request);
        }
        if self
            .client
            .call(&GuestServiceRequest::ProbeIdentity)
            .is_ok_and(|response| current(&response, &self.client))
        {
            self.rebind = None;
            Ok(())
        } else {
            Err(ControlError::Unsupported(
                "restored management binding unavailable; native computer remains running",
            ))
        }
    }
}

impl<C: GuestChannel + Send> GuestDriver for ManagedGuestClient<C> {
    fn dispatch(&mut self, command: &GuestCommand) -> EffectOutcome {
        if self.ensure_bound().is_err() {
            return EffectOutcome::NotApplied(bytes_digest(
                b"management-binding-unavailable-before-command-delivery",
            ));
        }
        match self.client.call(&GuestServiceRequest::Dispatch {
            command: command.clone(),
        }) {
            Ok(GuestServiceResponse::Effect { outcome }) => effect(outcome),
            Ok(GuestServiceResponse::File { .. }) => EffectOutcome::Applied(
                sandsurf_protocol::digest(
                    sandsurf_protocol::Domain::Operation,
                    &(
                        "guest-filesystem-applied-v1",
                        &command.operation_id,
                        &command.request_digest,
                    ),
                )
                .unwrap_or_else(|_| sandsurf_protocol::bytes_digest(b"guest-filesystem-applied")),
            ),
            Ok(GuestServiceResponse::Error { .. }) => EffectOutcome::NotApplied(
                sandsurf_protocol::bytes_digest(b"guest-rejected-defaults-operation"),
            ),
            Ok(other) => {
                eprintln!("sandsurf guest command returned an unexpected response: {other:?}");
                EffectOutcome::Unknown
            }
            Err(error) => {
                eprintln!("sandsurf guest command transport failed: {error}");
                EffectOutcome::Unknown
            }
        }
    }

    fn poll(&mut self, hints: &ExecutionHints) -> ControlResult<GuestPoll> {
        self.ensure_bound()?;
        let identity = match self.client.call(&GuestServiceRequest::ProbeIdentity) {
            Ok(GuestServiceResponse::Identity {
                machine_id,
                generation,
                boot_identity,
                management,
            }) if machine_id == self.client.machine_id
                && generation == self.client.generation
                && boot_identity == self.client.boot_identity =>
            {
                management
            }
            Ok(_) => {
                return Err(ControlError::Protocol(
                    "guest management report has a different binding",
                ));
            }
            Err(error) => {
                return Err(ControlError::Rejected {
                    category: "guest-unavailable".into(),
                    message: error.to_string(),
                });
            }
        };
        let processes = match self.client.call(&GuestServiceRequest::Processes) {
            Ok(GuestServiceResponse::Processes { processes }) => processes,
            Ok(_) => {
                return Err(ControlError::Protocol(
                    "guest execution inventory is malformed",
                ));
            }
            Err(error) => {
                return Err(ControlError::Rejected {
                    category: "guest-unavailable".into(),
                    message: error.to_string(),
                });
            }
        };
        const BUDGET: usize = 8;
        let mut progress = Vec::new();
        if processes.is_empty() {
            self.reconcile_cursor = 0;
            return Ok(GuestPoll {
                identity: Some(identity),
                executions: progress,
            });
        }
        let start = self.reconcile_cursor % processes.len();
        let count = processes.len().min(BUDGET);
        self.reconcile_cursor = (start + count) % processes.len();
        for offset in 0..count {
            let snapshot = &processes[(start + offset) % processes.len()];
            let Some(hint) = hints.get(&snapshot.request.execution_id) else {
                continue;
            };
            if hint.generation != snapshot.request.generation {
                continue;
            }
            let output = if hint.settled {
                None
            } else {
                let response = self
                    .client
                    .call(&GuestServiceRequest::ReadOutput {
                        execution_id: snapshot.request.execution_id.clone(),
                        after: hint.boundary.final_cursor,
                        maximum: sandsurf_protocol::MAX_STREAM_BYTES as u32,
                    })
                    .map_err(|error| ControlError::Rejected {
                        category: "guest-unavailable".into(),
                        message: error.to_string(),
                    })?;
                let GuestServiceResponse::Output { page } = response else {
                    return Err(ControlError::Protocol("guest output response is malformed"));
                };
                page.clone()
                    .into_binary_parts()
                    .map_err(|_| ControlError::Protocol("guest output page is malformed"))?;
                Some(page)
            };
            progress.push(GuestProgress {
                snapshot: snapshot.clone(),
                output,
            });
        }
        Ok(GuestPoll {
            identity: Some(identity),
            executions: progress,
        })
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        self.ensure_bound()?;
        self.client
            .call(&request)
            .map_err(|error| ControlError::Rejected {
                category: "guest-unavailable".into(),
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
    connection: &mut impl Read,
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
    use sandsurf_protocol::{
        GuestFinish, GuestHandshake, GuestHello, RPC_DATA_STREAM, RetainedChunkMetadata,
        RetainedPageMetadata, Stream,
    };
    use std::os::unix::net::UnixStream;

    fn test_management_identity() -> sandsurf_protocol::GuestManagementIdentity {
        sandsurf_protocol::GuestManagementIdentity {
            boot_id: "test-linux-boot".try_into().unwrap(),
            instance_id: "test-management-instance".try_into().unwrap(),
        }
    }

    struct PairChannel(Option<UnixStream>);

    #[test]
    fn slowly_fragmented_guest_frame_cannot_extend_its_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let frame = Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: Counter::ONE,
                authentication: [0; AUTHENTICATION_BYTES],
                payload: vec![42; 1024],
            };
            let mut bytes = Vec::new();
            frame.write(&mut bytes).unwrap();
            for byte in bytes {
                if server.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        let connection =
            sandsurf_native::UnixGuestConnection::new(client, Some(IO_TIMEOUT)).unwrap();
        let mut connection =
            DeadlineConnection::new(Box::new(connection), Duration::from_millis(25));
        let started = Instant::now();
        let error = Frame::read(&mut connection).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(connection);
        writer.join().unwrap();
    }

    impl GuestChannel for PairChannel {
        fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError> {
            self.0
                .take()
                .ok_or_else(|| GuestChannelError::Protocol("unexpected reconnect".into()))
                .and_then(|stream| {
                    Ok(Box::new(sandsurf_native::UnixGuestConnection::new(
                        stream,
                        Some(IO_TIMEOUT),
                    )?) as Box<dyn GuestConnection>)
                })
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
        let machine = MachineId::try_from("persistent-guest").unwrap();
        let boot = sandsurf_protocol::bytes_digest(b"verified-boot");
        let capability = [7; 32];
        let expected_machine = machine.clone();
        let expected_boot = boot.clone();
        let server = std::thread::spawn(move || {
            server_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let hello: GuestHello = read_unauthed(&mut server_stream).unwrap();
            let (handshake, challenge) = GuestHandshake::accept(
                BootCapability::from_bytes(capability),
                &expected_machine,
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
                    serde_json::from_slice::<RequestEnvelope<GuestServiceRequest>>(
                        &request.payload
                    )
                    .unwrap()
                    .assemble(None)
                    .unwrap(),
                    GuestServiceRequest::ProbeIdentity
                );
                for payload in [
                    serde_json::to_vec(&GuestServiceResponse::Identity {
                        machine_id: expected_machine.clone(),
                        generation: Counter::ONE,
                        boot_identity: expected_boot.clone(),
                        management: test_management_identity(),
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
            machine.clone(),
            Counter::ONE,
            boot.clone(),
            capability,
        );
        for _ in 0..2 {
            assert_eq!(
                client.call(&GuestServiceRequest::ProbeIdentity).unwrap(),
                GuestServiceResponse::Identity {
                    machine_id: machine.clone(),
                    generation: Counter::ONE,
                    boot_identity: boot.clone(),
                    management: test_management_identity(),
                }
            );
        }
        server.join().unwrap();
    }

    #[test]
    fn authenticated_output_uses_credit_limited_binary_frames() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let machine = MachineId::try_from("binary-guest").unwrap();
        let process = sandsurf_protocol::ExecutionId::try_from("binary-process").unwrap();
        let boot = bytes_digest(b"verified-binary-boot");
        let capability = [9; 32];
        let server_machine = machine.clone();
        let server_boot = boot.clone();
        let server_process = process.clone();
        let server = std::thread::spawn(move || {
            server_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let hello: GuestHello = read_unauthed(&mut server_stream).unwrap();
            let (handshake, challenge) = GuestHandshake::accept(
                BootCapability::from_bytes(capability),
                &server_machine,
                Counter::ONE,
                &server_boot,
                &hello,
            )
            .unwrap();
            send_unauthed(&mut server_stream, &challenge);
            let finish: GuestFinish = read_unauthed(&mut server_stream).unwrap();
            let mut codec = handshake.finish(&finish).unwrap();
            let request = codec
                .open(Frame::read(&mut server_stream).unwrap().unwrap())
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<RequestEnvelope<GuestServiceRequest>>(&request.payload)
                    .unwrap()
                    .assemble(None)
                    .unwrap(),
                GuestServiceRequest::ReadOutput {
                    execution_id: server_process,
                    after: Counter::ZERO,
                    maximum: 64,
                }
            );
            let pieces = [vec![0, 255, 1], vec![3, 4]];
            let metadata = RetainedPageMetadata {
                after: Counter::ZERO,
                available: 5u64.try_into().unwrap(),
                chunks: vec![
                    RetainedChunkMetadata {
                        cursor: Counter::ZERO,
                        stream: Stream::Stdout,
                        length: 3,
                        digest: bytes_digest(&pieces[0]),
                    },
                    RetainedChunkMetadata {
                        cursor: 3u64.try_into().unwrap(),
                        stream: Stream::Stderr,
                        length: 2,
                        digest: bytes_digest(&pieces[1]),
                    },
                ],
                required_bytes: None,
            };
            codec.open_stream(RPC_DATA_STREAM, true).unwrap();
            codec
                .seal(Frame {
                    kind: FrameKind::Control,
                    stream: 0,
                    sequence: Counter::ONE,
                    authentication: [0; AUTHENTICATION_BYTES],
                    payload: serde_json::to_vec(&GuestServiceResponse::OutputMetadata {
                        page: metadata,
                    })
                    .unwrap(),
                })
                .unwrap()
                .write(&mut server_stream)
                .unwrap();
            let credit = codec
                .open(Frame::read(&mut server_stream).unwrap().unwrap())
                .unwrap();
            assert_eq!(credit.kind, FrameKind::Credit);
            assert_eq!(credit.stream, RPC_DATA_STREAM);
            assert_eq!(credit.payload, 5u64.to_be_bytes());
            codec.accept_send_credit(RPC_DATA_STREAM, 5).unwrap();
            for (index, bytes) in pieces.into_iter().enumerate() {
                codec
                    .seal(Frame {
                        kind: FrameKind::Data,
                        stream: RPC_DATA_STREAM,
                        sequence: ((index + 1) as u64).try_into().unwrap(),
                        authentication: [0; AUTHENTICATION_BYTES],
                        payload: bytes,
                    })
                    .unwrap()
                    .write(&mut server_stream)
                    .unwrap();
            }
            codec
                .seal(Frame {
                    kind: FrameKind::End,
                    stream: RPC_DATA_STREAM,
                    sequence: 3u64.try_into().unwrap(),
                    authentication: [0; AUTHENTICATION_BYTES],
                    payload: Vec::new(),
                })
                .unwrap()
                .write(&mut server_stream)
                .unwrap();
            codec.close_stream(RPC_DATA_STREAM).unwrap();
            codec
                .seal(Frame {
                    kind: FrameKind::Control,
                    stream: 0,
                    sequence: 2u64.try_into().unwrap(),
                    authentication: [0; AUTHENTICATION_BYTES],
                    payload: CONTROL_COMPLETE.to_vec(),
                })
                .unwrap()
                .write(&mut server_stream)
                .unwrap();
        });
        let mut client = GuestClient::new(
            PairChannel(Some(client_stream)),
            machine,
            Counter::ONE,
            boot,
            capability,
        );
        let response = client
            .call(&GuestServiceRequest::ReadOutput {
                execution_id: process,
                after: Counter::ZERO,
                maximum: 64,
            })
            .unwrap();
        let GuestServiceResponse::Output { page } = response else {
            panic!("guest did not return output");
        };
        assert_eq!(page.chunks[0].bytes, [0, 255, 1]);
        assert_eq!(page.chunks[1].bytes, [3, 4]);
        server.join().unwrap();
    }
}
