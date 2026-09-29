//! One bounded, credited byte-transfer mechanism for private RPC channels.
//! Domain metadata remains separate from the bytes it describes.

use crate::{
    AUTHENTICATION_BYTES, Counter, Digest, Frame, FrameKind, Invalid, MAX_STREAM_BYTES,
    SessionCodec, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const RPC_DATA_STREAM: u32 = 1;
pub const MAX_RPC_DATA_BYTES: usize = 1024 * 1024;
pub const MAX_RPC_DATA_CHUNKS: usize = 256;
pub type BinaryData = Vec<Vec<u8>>;
pub type WireParts<T> = (T, Option<BinaryData>);

/// A request has at most one byte payload. Control metadata carries an empty
/// placeholder; bounded data is reconstructed before admission or dispatch.
pub trait RpcRequest {
    fn binary_field(&mut self) -> Option<(&mut Vec<u8>, usize)>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestEnvelope<T> {
    pub request: T,
    pub binary: Option<Vec<BinaryChunk>>,
}

impl<T: RpcRequest> RequestEnvelope<T> {
    pub fn split(mut request: T) -> Result<WireParts<Self>, Invalid> {
        let (binary, data) = match request.binary_field() {
            Some((field, maximum)) => {
                if field.len() > maximum {
                    return Err(Invalid("request bytes exceed their bound"));
                }
                let bytes = std::mem::take(field);
                let data = bytes
                    .chunks(MAX_STREAM_BYTES)
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>();
                let metadata = describe_binary(&data)?;
                validate_binary(&metadata, maximum)?;
                (Some(metadata), Some(data))
            }
            None => (None, None),
        };
        Ok((Self { request, binary }, data))
    }

    pub fn descriptor(&mut self) -> Result<Option<&[BinaryChunk]>, Invalid> {
        match (self.request.binary_field(), &self.binary) {
            (Some((field, maximum)), Some(binary)) if field.is_empty() => {
                validate_binary(binary, maximum)?;
                Ok(Some(binary))
            }
            (None, None) => Ok(None),
            _ => Err(Invalid(
                "request byte field differs from its wire descriptor",
            )),
        }
    }

    pub fn assemble(mut self, data: Option<Vec<Vec<u8>>>) -> Result<T, Invalid> {
        self.descriptor()?;
        match (self.request.binary_field(), self.binary, data) {
            (Some((field, maximum)), Some(metadata), Some(data)) => {
                validate_binary(&metadata, maximum)?;
                if describe_binary(&data)? != metadata {
                    return Err(Invalid("request bytes differ from descriptor"));
                }
                *field = data.into_iter().flatten().collect();
            }
            (None, None, None) => {}
            _ => return Err(Invalid("request data is absent or unexpected")),
        }
        Ok(self.request)
    }
}

impl RpcRequest for crate::FilesystemRequest {
    fn binary_field(&mut self) -> Option<(&mut Vec<u8>, usize)> {
        match self {
            Self::Write { bytes, .. } | Self::WriteChunk { bytes, .. } => {
                Some((bytes, MAX_STREAM_BYTES))
            }
            _ => None,
        }
    }
}
impl RpcRequest for crate::GuestRequest {
    fn binary_field(&mut self) -> Option<(&mut Vec<u8>, usize)> {
        match self {
            Self::WriteInput { bytes, .. } => Some((bytes, MAX_STREAM_BYTES)),
            Self::Filesystem { request } => request.binary_field(),
            _ => None,
        }
    }
}
impl RpcRequest for crate::GuestCommand {
    fn binary_field(&mut self) -> Option<(&mut Vec<u8>, usize)> {
        self.request.binary_field()
    }
}
impl RpcRequest for crate::GuestServiceRequest {
    fn binary_field(&mut self) -> Option<(&mut Vec<u8>, usize)> {
        match self {
            Self::InstallSecret { bytes, .. } => Some((bytes, MAX_RPC_DATA_BYTES)),
            Self::Dispatch { command } => command.binary_field(),
            Self::FilesystemQuery { request } => request.binary_field(),
            _ => None,
        }
    }
}
impl RpcRequest for crate::GuardianRequest {
    fn binary_field(&mut self) -> Option<(&mut Vec<u8>, usize)> {
        match self {
            Self::Dispatch { command } => command.binary_field(),
            Self::Guest { request, .. } | Self::QueryGuest { request, .. } => {
                request.binary_field()
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryChunk {
    pub length: u32,
    pub digest: Digest,
}

pub fn describe_binary(chunks: &[Vec<u8>]) -> Result<Vec<BinaryChunk>, Invalid> {
    let metadata: Vec<_> = chunks
        .iter()
        .map(|bytes| BinaryChunk {
            length: bytes.len().try_into().unwrap_or(u32::MAX),
            digest: bytes_digest(bytes),
        })
        .collect();
    validate_binary(&metadata, MAX_RPC_DATA_BYTES)?;
    Ok(metadata)
}

pub fn validate_binary(metadata: &[BinaryChunk], maximum: usize) -> Result<usize, Invalid> {
    if maximum > MAX_RPC_DATA_BYTES || metadata.len() > MAX_RPC_DATA_CHUNKS {
        return Err(Invalid("RPC data envelope exceeds its bound"));
    }
    let mut total = 0usize;
    for chunk in metadata {
        if chunk.length == 0 || chunk.length as usize > MAX_STREAM_BYTES {
            return Err(Invalid("RPC data chunk length is invalid"));
        }
        total = total
            .checked_add(chunk.length as usize)
            .filter(|total| *total <= maximum)
            .ok_or(Invalid("RPC data exceeds its receive credit"))?;
    }
    Ok(total)
}

pub trait FrameChannel {
    fn send(&mut self, frame: Frame) -> io::Result<()>;
    fn receive(&mut self) -> io::Result<Option<Frame>>;
    fn open(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn grant_receive(&mut self, _bytes: usize) -> io::Result<()> {
        Ok(())
    }
    fn accept_send(&mut self, _bytes: usize) -> io::Result<()> {
        Ok(())
    }
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct AuthenticatedFrameChannel<'a, T: Read + Write> {
    pub io: &'a mut T,
    pub codec: &'a mut SessionCodec,
}
impl<T: Read + Write> FrameChannel for AuthenticatedFrameChannel<'_, T> {
    fn send(&mut self, frame: Frame) -> io::Result<()> {
        self.codec
            .seal(frame)
            .map_err(io::Error::other)?
            .write(self.io)
    }
    fn receive(&mut self) -> io::Result<Option<Frame>> {
        Frame::read(self.io)?
            .map(|frame| {
                let mut verified = self.codec.open(frame).map_err(io::Error::other)?;
                verified.authentication = [0; AUTHENTICATION_BYTES];
                Ok(verified)
            })
            .transpose()
    }
    fn open(&mut self) -> io::Result<()> {
        self.codec
            .open_stream(RPC_DATA_STREAM, true)
            .map_err(io::Error::other)
    }
    fn grant_receive(&mut self, bytes: usize) -> io::Result<()> {
        self.codec
            .grant_receive_credit(RPC_DATA_STREAM, bytes as u64)
            .map_err(io::Error::other)
    }
    fn accept_send(&mut self, bytes: usize) -> io::Result<()> {
        self.codec
            .accept_send_credit(RPC_DATA_STREAM, bytes as u64)
            .map_err(io::Error::other)
    }
    fn close(&mut self) -> io::Result<()> {
        self.codec
            .close_stream(RPC_DATA_STREAM)
            .map_err(io::Error::other)
    }
}

fn frame(kind: FrameKind, sequence: usize, payload: Vec<u8>) -> io::Result<Frame> {
    Ok(Frame {
        kind,
        stream: RPC_DATA_STREAM,
        sequence: Counter::try_from(sequence as u64).map_err(io::Error::other)?,
        authentication: [0; AUTHENTICATION_BYTES],
        payload,
    })
}

pub fn send_binary(channel: &mut impl FrameChannel, chunks: Vec<Vec<u8>>) -> io::Result<()> {
    let descriptor = describe_binary(&chunks).map_err(io::Error::other)?;
    let total = validate_binary(&descriptor, MAX_RPC_DATA_BYTES).map_err(io::Error::other)?;
    channel.open()?;
    let credit = channel.receive()?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "RPC receive credit missing")
    })?;
    if credit.kind != FrameKind::Credit
        || credit.stream != RPC_DATA_STREAM
        || credit.sequence != Counter::ONE
        || credit.authentication != [0; AUTHENTICATION_BYTES]
        || credit.payload != (total as u64).to_be_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RPC receive credit differs from metadata",
        ));
    }
    channel.accept_send(total)?;
    let count = chunks.len();
    for (index, bytes) in chunks.into_iter().enumerate() {
        channel.send(frame(FrameKind::Data, index + 1, bytes)?)?;
    }
    channel.send(frame(FrameKind::End, count + 1, Vec::new())?)?;
    channel.close()
}

pub fn receive_binary(
    channel: &mut impl FrameChannel,
    metadata: &[BinaryChunk],
    maximum: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let total = validate_binary(metadata, maximum).map_err(io::Error::other)?;
    channel.open()?;
    channel.grant_receive(total)?;
    channel.send(frame(
        FrameKind::Credit,
        1,
        (total as u64).to_be_bytes().to_vec(),
    )?)?;
    let mut chunks = Vec::with_capacity(metadata.len());
    for (index, chunk) in metadata.iter().enumerate() {
        let data = channel
            .receive()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "RPC data incomplete"))?;
        if data.kind != FrameKind::Data
            || data.stream != RPC_DATA_STREAM
            || data.sequence.get() != index as u64 + 1
            || data.authentication != [0; AUTHENTICATION_BYTES]
            || data.payload.len() != chunk.length as usize
            || bytes_digest(&data.payload) != chunk.digest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RPC data differs from metadata",
            ));
        }
        chunks.push(data.payload);
    }
    let end = channel
        .receive()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "RPC data end missing"))?;
    if end.kind != FrameKind::End
        || end.stream != RPC_DATA_STREAM
        || end.sequence.get() != chunks.len() as u64 + 1
        || end.authentication != [0; AUTHENTICATION_BYTES]
        || !end.payload.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RPC data end is invalid",
        ));
    }
    channel.close()?;
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn request_envelope_binds_bytes_and_rejects_parallel_json_payloads() {
        let request = crate::FilesystemRequest::Write {
            path: "/etc/agent.conf".try_into().unwrap(),
            bytes: vec![255; MAX_STREAM_BYTES],
            mode: 0o600,
            expected: crate::FileExpectation::Any,
        };
        let (mut wire, data) = RequestEnvelope::split(request.clone()).unwrap();
        assert!(serde_json::to_vec(&wire).unwrap().len() < 1024);
        assert_eq!(wire.descriptor().unwrap().unwrap().len(), 1);
        assert_eq!(wire.clone().assemble(data.clone()).unwrap(), request);
        let mut corrupt = data.unwrap();
        corrupt[0][0] ^= 1;
        assert!(wire.clone().assemble(Some(corrupt)).is_err());
        assert!(wire.clone().assemble(None).is_err());
        wire.request = request;
        assert!(wire.descriptor().is_err());
    }

    #[test]
    fn request_envelope_enforces_domain_limit_before_copying_or_receive_credit() {
        let request = crate::FilesystemRequest::Write {
            path: "/etc/agent.conf".try_into().unwrap(),
            bytes: vec![0; MAX_STREAM_BYTES + 1],
            mode: 0o600,
            expected: crate::FileExpectation::Any,
        };
        assert!(RequestEnvelope::split(request).is_err());
        let mut wire = RequestEnvelope {
            request: crate::FilesystemRequest::Write {
                path: "/etc/agent.conf".try_into().unwrap(),
                bytes: Vec::new(),
                mode: 0o600,
                expected: crate::FileExpectation::Any,
            },
            binary: Some(vec![
                BinaryChunk {
                    length: MAX_STREAM_BYTES as u32,
                    digest: bytes_digest(&[])
                };
                2
            ]),
        };
        assert!(wire.descriptor().is_err());
    }
    struct Channel {
        incoming: VecDeque<Frame>,
        sent: Vec<Frame>,
    }
    impl FrameChannel for Channel {
        fn send(&mut self, frame: Frame) -> io::Result<()> {
            self.sent.push(frame);
            Ok(())
        }
        fn receive(&mut self) -> io::Result<Option<Frame>> {
            Ok(self.incoming.pop_front())
        }
    }
    #[test]
    fn transfer_is_credited_digest_bound_and_sequence_checked() {
        let chunks = vec![vec![255; MAX_STREAM_BYTES], b"second".to_vec()];
        let metadata = describe_binary(&chunks).unwrap();
        let total = validate_binary(&metadata, MAX_RPC_DATA_BYTES).unwrap();
        let mut writer = Channel {
            incoming: VecDeque::from([frame(
                FrameKind::Credit,
                1,
                (total as u64).to_be_bytes().to_vec(),
            )
            .unwrap()]),
            sent: Vec::new(),
        };
        send_binary(&mut writer, chunks.clone()).unwrap();
        let frames = writer.sent;
        let mut reader = Channel {
            incoming: frames.clone().into(),
            sent: Vec::new(),
        };
        assert_eq!(
            receive_binary(&mut reader, &metadata, total).unwrap(),
            chunks
        );
        assert_eq!(reader.sent[0].payload, (total as u64).to_be_bytes());
        for corrupt in [0, 1, 2] {
            let mut input = frames.clone();
            if corrupt == 0 {
                input[0].payload[0] ^= 1;
            }
            if corrupt == 1 {
                input[0].sequence = Counter::ZERO;
            }
            if corrupt == 2 {
                input[2].payload.push(1);
            }
            let mut reader = Channel {
                incoming: input.into(),
                sent: Vec::new(),
            };
            assert!(receive_binary(&mut reader, &metadata, total).is_err());
        }
        assert!(validate_binary(&metadata, total - 1).is_err());
    }
    #[test]
    fn empty_data_still_has_an_exact_credit_and_end() {
        let mut writer = Channel {
            incoming: VecDeque::from([
                frame(FrameKind::Credit, 1, 0_u64.to_be_bytes().to_vec()).unwrap()
            ]),
            sent: Vec::new(),
        };
        send_binary(&mut writer, Vec::new()).unwrap();
        let mut reader = Channel {
            incoming: writer.sent.into(),
            sent: Vec::new(),
        };
        assert!(receive_binary(&mut reader, &[], 0).unwrap().is_empty());
    }
}
