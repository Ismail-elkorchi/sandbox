use crate::{Counter, Invalid};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 4] = b"SSF1";
pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 24;
pub const MAX_CONTROL_BYTES: usize = 256 * 1024;
pub const MAX_STREAM_BYTES: usize = 64 * 1024;
pub const MAX_STREAMS: usize = 256;
pub const MAX_CREDIT: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Control = 1,
    Data = 2,
    Credit = 3,
    End = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub stream: u32,
    pub sequence: Counter,
    pub payload: Vec<u8>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Frame {
    pub fn read(reader: &mut impl Read) -> io::Result<Option<Self>> {
        let mut header = [0; HEADER_BYTES];
        loop {
            match reader.read(&mut header[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        reader.read_exact(&mut header[1..])?;
        if &header[..4] != MAGIC
            || u16::from_be_bytes([header[4], header[5]]) != VERSION
            || header[7] != 0
        {
            return Err(invalid("invalid Sandsurf frame header"));
        }
        let kind = match header[6] {
            1 => FrameKind::Control,
            2 => FrameKind::Data,
            3 => FrameKind::Credit,
            4 => FrameKind::End,
            _ => return Err(invalid("unknown frame kind")),
        };
        let stream = u32::from_be_bytes(header[8..12].try_into().expect("fixed header"));
        let sequence = Counter::try_from(u64::from_be_bytes(
            header[12..20].try_into().expect("fixed header"),
        ))
        .map_err(|_| invalid("sequence overflow"))?;
        let length = u32::from_be_bytes(header[20..24].try_into().expect("fixed header")) as usize;
        validate(kind, stream, length)?;
        // Every allocation is preceded by kind-specific length validation.
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload)?;
        Ok(Some(Self {
            kind,
            stream,
            sequence,
            payload,
        }))
    }

    pub fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        validate(self.kind, self.stream, self.payload.len())?;
        let mut header = [0; HEADER_BYTES];
        header[..4].copy_from_slice(MAGIC);
        header[4..6].copy_from_slice(&VERSION.to_be_bytes());
        header[6] = self.kind as u8;
        header[8..12].copy_from_slice(&self.stream.to_be_bytes());
        header[12..20].copy_from_slice(&self.sequence.get().to_be_bytes());
        header[20..24].copy_from_slice(&(self.payload.len() as u32).to_be_bytes());
        writer.write_all(&header)?;
        writer.write_all(&self.payload)
    }
}

fn validate(kind: FrameKind, stream: u32, length: usize) -> io::Result<()> {
    let valid = match kind {
        FrameKind::Control => stream == 0 && length <= MAX_CONTROL_BYTES,
        FrameKind::Data => stream != 0 && (1..=MAX_STREAM_BYTES).contains(&length),
        FrameKind::Credit => stream != 0 && length == 8,
        FrameKind::End => stream != 0 && length == 0,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid("invalid stream or payload bound"))
    }
}

/// Per-channel credit accounting. Control traffic never consumes data credits.
#[derive(Default)]
pub struct Credits(BTreeMap<u32, u64>);
impl Credits {
    pub fn open(&mut self, stream: u32) -> Result<(), Invalid> {
        if stream == 0 || self.0.len() >= MAX_STREAMS || self.0.contains_key(&stream) {
            return Err(Invalid("stream admission refused"));
        }
        self.0.insert(stream, 0);
        Ok(())
    }
    pub fn grant(&mut self, stream: u32, amount: u64) -> Result<(), Invalid> {
        let credit = self.0.get_mut(&stream).ok_or(Invalid("unknown stream"))?;
        let total = credit
            .checked_add(amount)
            .filter(|v| *v <= MAX_CREDIT)
            .ok_or(Invalid("credit overflow"))?;
        *credit = total;
        Ok(())
    }
    pub fn consume(&mut self, stream: u32, amount: usize) -> Result<(), Invalid> {
        if amount > MAX_STREAM_BYTES {
            return Err(Invalid("stream frame too large"));
        }
        let credit = self.0.get_mut(&stream).ok_or(Invalid("unknown stream"))?;
        *credit = credit
            .checked_sub(amount as u64)
            .ok_or(Invalid("stream credit exhausted"))?;
        Ok(())
    }
    pub fn close(&mut self, stream: u32) -> Result<(), Invalid> {
        self.0
            .remove(&stream)
            .map(|_| ())
            .ok_or(Invalid("unknown stream"))
    }
}
