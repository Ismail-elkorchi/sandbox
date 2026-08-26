#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};

pub const MAGIC: [u8; 4] = *b"SBX1";
pub const HEADER_LEN: usize = 12;
pub const MAX_CONTROL_PAYLOAD: usize = 1024 * 1024;
pub const MAX_STREAM_PAYLOAD: usize = 64 * 1024;
pub const INITIAL_STREAM_CREDIT: u64 = 1024 * 1024;
pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Hello = 1,
    Probe = 2,
    PrepareRun = 3,
    StartPreparedRun = 4,
    CancelPreparedRun = 5,
    PrepareSession = 6,
    ActivateSession = 7,
    CancelPreparedSession = 8,
    PrepareProcess = 9,
    StartPreparedProcess = 10,
    CancelPreparedProcess = 11,
    Stdin = 12,
    CloseStdin = 13,
    StreamCredit = 14,
    Terminate = 15,
    CloseSession = 16,
    Shutdown = 17,
    HelloAck = 101,
    ProbeResult = 102,
    RunPrepared = 103,
    SessionPrepared = 104,
    SessionActive = 105,
    ProcessPrepared = 106,
    ProcessStarted = 107,
    Stdout = 108,
    Stderr = 109,
    Event = 110,
    ProcessExit = 111,
    SessionClosed = 112,
    Error = 113,
    RuntimeMetrics = 114,
    Artifact = 115,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        let message = match value {
            1 => Self::Hello,
            2 => Self::Probe,
            3 => Self::PrepareRun,
            4 => Self::StartPreparedRun,
            5 => Self::CancelPreparedRun,
            6 => Self::PrepareSession,
            7 => Self::ActivateSession,
            8 => Self::CancelPreparedSession,
            9 => Self::PrepareProcess,
            10 => Self::StartPreparedProcess,
            11 => Self::CancelPreparedProcess,
            12 => Self::Stdin,
            13 => Self::CloseStdin,
            14 => Self::StreamCredit,
            15 => Self::Terminate,
            16 => Self::CloseSession,
            17 => Self::Shutdown,
            101 => Self::HelloAck,
            102 => Self::ProbeResult,
            103 => Self::RunPrepared,
            104 => Self::SessionPrepared,
            105 => Self::SessionActive,
            106 => Self::ProcessPrepared,
            107 => Self::ProcessStarted,
            108 => Self::Stdout,
            109 => Self::Stderr,
            110 => Self::Event,
            111 => Self::ProcessExit,
            112 => Self::SessionClosed,
            113 => Self::Error,
            114 => Self::RuntimeMetrics,
            115 => Self::Artifact,
            _ => return Err(ProtocolError::UnknownMessageType(value)),
        };
        Ok(message)
    }
}

impl MessageType {
    #[must_use]
    pub const fn is_binary(self) -> bool {
        matches!(
            self,
            Self::Stdin | Self::Stdout | Self::Stderr | Self::Artifact
        )
    }

    #[must_use]
    pub const fn payload_limit(self) -> usize {
        if self.is_binary() {
            MAX_STREAM_PAYLOAD
        } else {
            MAX_CONTROL_PAYLOAD
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Frame {
    pub message_type: MessageType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn control<T: Serialize>(
        message_type: MessageType,
        value: &T,
    ) -> Result<Self, ProtocolError> {
        if message_type.is_binary() {
            return Err(ProtocolError::WrongPayloadClass);
        }
        let payload = serde_json::to_vec(value).map_err(ProtocolError::Json)?;
        if payload.len() > MAX_CONTROL_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge {
                declared: payload.len(),
                maximum: MAX_CONTROL_PAYLOAD,
            });
        }
        Ok(Self {
            message_type,
            flags: 0,
            payload,
        })
    }

    pub fn binary(message_type: MessageType, payload: Vec<u8>) -> Result<Self, ProtocolError> {
        if !message_type.is_binary() {
            return Err(ProtocolError::WrongPayloadClass);
        }
        if payload.len() > MAX_STREAM_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge {
                declared: payload.len(),
                maximum: MAX_STREAM_PAYLOAD,
            });
        }
        Ok(Self {
            message_type,
            flags: 0,
            payload,
        })
    }

    pub fn parse_control<T: for<'de> Deserialize<'de>>(&self) -> Result<T, ProtocolError> {
        if self.message_type.is_binary() {
            return Err(ProtocolError::WrongPayloadClass);
        }
        std::str::from_utf8(&self.payload).map_err(|_| ProtocolError::InvalidUtf8)?;
        serde_json::from_slice(&self.payload).map_err(ProtocolError::Json)
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    InvalidMagic,
    UnknownMessageType(u8),
    ReservedBits,
    PayloadTooLarge { declared: usize, maximum: usize },
    InvalidUtf8,
    Json(serde_json::Error),
    WrongPayloadClass,
    CreditExceeded,
    CreditOverflow,
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "protocol I/O error: {error}"),
            Self::InvalidMagic => formatter.write_str("invalid protocol magic"),
            Self::UnknownMessageType(value) => write!(formatter, "unknown message type {value}"),
            Self::ReservedBits => formatter.write_str("non-zero reserved header bits"),
            Self::PayloadTooLarge { declared, maximum } => {
                write!(
                    formatter,
                    "payload length {declared} exceeds limit {maximum}"
                )
            }
            Self::InvalidUtf8 => formatter.write_str("control payload is not valid UTF-8"),
            Self::Json(error) => write!(formatter, "invalid control JSON: {error}"),
            Self::WrongPayloadClass => formatter.write_str("wrong payload class for message type"),
            Self::CreditExceeded => formatter.write_str("stream sender exceeded available credit"),
            Self::CreditOverflow => formatter.write_str("stream credit overflow"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<io::Error> for ProtocolError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn read_frame(reader: &mut impl Read) -> Result<Option<Frame>, ProtocolError> {
    let mut header = [0_u8; HEADER_LEN];
    let mut received = 0;
    while received < HEADER_LEN {
        match reader.read(&mut header[received..]) {
            Ok(0) if received == 0 => return Ok(None),
            Ok(0) => {
                return Err(ProtocolError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame header",
                )));
            }
            Ok(count) => received += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ProtocolError::Io(error)),
        }
    }
    if header[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let message_type = MessageType::try_from(header[4])?;
    if header[5] != 0 || header[6] != 0 || header[7] != 0 {
        return Err(ProtocolError::ReservedBits);
    }
    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let maximum = message_type.payload_limit();
    if length > maximum {
        return Err(ProtocolError::PayloadTooLarge {
            declared: length,
            maximum,
        });
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    if !message_type.is_binary() {
        std::str::from_utf8(&payload).map_err(|_| ProtocolError::InvalidUtf8)?;
    }
    Ok(Some(Frame {
        message_type,
        flags: header[5],
        payload,
    }))
}

pub fn write_frame(writer: &mut impl Write, frame: &Frame) -> Result<(), ProtocolError> {
    if frame.flags != 0 {
        return Err(ProtocolError::ReservedBits);
    }
    let maximum = frame.message_type.payload_limit();
    if frame.payload.len() > maximum {
        return Err(ProtocolError::PayloadTooLarge {
            declared: frame.payload.len(),
            maximum,
        });
    }
    let length =
        u32::try_from(frame.payload.len()).map_err(|_| ProtocolError::PayloadTooLarge {
            declared: frame.payload.len(),
            maximum,
        })?;
    let mut header = [0_u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = frame.message_type as u8;
    header[5] = frame.flags;
    header[8..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(&frame.payload)?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct StreamCredit {
    available: u64,
}

impl StreamCredit {
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            available: INITIAL_STREAM_CREDIT,
        }
    }

    #[must_use]
    pub const fn available(&self) -> u64 {
        self.available
    }

    pub fn consume(&mut self, amount: usize) -> Result<(), ProtocolError> {
        let amount = u64::try_from(amount).map_err(|_| ProtocolError::CreditExceeded)?;
        if amount > self.available {
            return Err(ProtocolError::CreditExceeded);
        }
        self.available -= amount;
        Ok(())
    }

    pub fn grant(&mut self, amount: u64) -> Result<(), ProtocolError> {
        self.available = self
            .available
            .checked_add(amount)
            .ok_or(ProtocolError::CreditOverflow)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hello {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub package_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestId {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamCreditMessage {
    pub stream: String,
    pub bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trips_partial_reads() {
        let frame = Frame::control(
            MessageType::Hello,
            &RequestId {
                request_id: "r1".into(),
            },
        )
        .expect("frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("write");
        let decoded = read_frame(&mut Cursor::new(bytes))
            .expect("read")
            .expect("frame");
        assert_eq!(decoded.message_type, MessageType::Hello);
        assert_eq!(
            decoded
                .parse_control::<RequestId>()
                .expect("json")
                .request_id,
            "r1"
        );
    }

    #[test]
    fn rejects_reserved_and_oversized_frames_before_allocation() {
        let mut reserved = [0_u8; HEADER_LEN];
        reserved[..4].copy_from_slice(&MAGIC);
        reserved[4] = MessageType::Hello as u8;
        reserved[6] = 1;
        assert!(matches!(
            read_frame(&mut Cursor::new(reserved)),
            Err(ProtocolError::ReservedBits)
        ));

        let mut flags = [0_u8; HEADER_LEN];
        flags[..4].copy_from_slice(&MAGIC);
        flags[4] = MessageType::Hello as u8;
        flags[5] = 1;
        assert!(matches!(
            read_frame(&mut Cursor::new(flags)),
            Err(ProtocolError::ReservedBits)
        ));

        let mut oversized = [0_u8; HEADER_LEN];
        oversized[..4].copy_from_slice(&MAGIC);
        oversized[4] = MessageType::Stdout as u8;
        oversized[8..].copy_from_slice(&(MAX_STREAM_PAYLOAD as u32 + 1).to_be_bytes());
        assert!(matches!(
            read_frame(&mut Cursor::new(oversized)),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn credit_is_checked() {
        let mut credit = StreamCredit::initial();
        credit
            .consume(INITIAL_STREAM_CREDIT as usize)
            .expect("consume");
        assert!(matches!(
            credit.consume(1),
            Err(ProtocolError::CreditExceeded)
        ));
    }

    #[test]
    fn rejects_invalid_utf8_unknown_type_and_truncated_payload() {
        let mut invalid_utf8 = [0_u8; HEADER_LEN + 1];
        invalid_utf8[..4].copy_from_slice(&MAGIC);
        invalid_utf8[4] = MessageType::Hello as u8;
        invalid_utf8[8..12].copy_from_slice(&1_u32.to_be_bytes());
        invalid_utf8[12] = 0xff;
        assert!(matches!(
            read_frame(&mut Cursor::new(invalid_utf8)),
            Err(ProtocolError::InvalidUtf8)
        ));

        let mut unknown = [0_u8; HEADER_LEN];
        unknown[..4].copy_from_slice(&MAGIC);
        unknown[4] = 99;
        assert!(matches!(
            read_frame(&mut Cursor::new(unknown)),
            Err(ProtocolError::UnknownMessageType(99))
        ));

        let mut truncated = [0_u8; HEADER_LEN];
        truncated[..4].copy_from_slice(&MAGIC);
        truncated[4] = MessageType::Hello as u8;
        truncated[8..12].copy_from_slice(&2_u32.to_be_bytes());
        assert!(matches!(
            read_frame(&mut Cursor::new(truncated)),
            Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }
}
