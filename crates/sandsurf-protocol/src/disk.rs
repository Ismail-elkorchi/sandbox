//! Closed offline filesystem protocol. Host filenames, credentials, networking
//! and native handles never enter this channel. Bulk data is streamed in fixed
//! chunks; metadata and request counts have independent bounds.
use crate::{Counter, Frame, FrameKind, MAX_CONTROL_BYTES, MAX_STREAM_BYTES};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};

pub const DISK_EXECUTOR_PORT: u32 = 10790;
pub const MAX_DISK_OPERATIONS: u64 = 64;
pub const MAX_DISK_TRANSFER: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskCompression {
    None,
    Gzip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiskOperation {
    Mount {
        writable: bool,
    },
    MakeExt4,
    ImportTar {
        bytes: u64,
        compression: DiskCompression,
    },
    Sync,
    Unmount,
    CheckExt4,
    Remove {
        path: String,
    },
    Write {
        path: String,
        bytes: String,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    Realpath {
        path: String,
    },
    FileSize {
        path: String,
    },
    Download {
        path: String,
        offset: u64,
        bytes: u64,
    },
}

impl DiskOperation {
    pub fn mutation(&self) -> bool {
        matches!(
            self,
            Self::Mount { writable: true }
                | Self::MakeExt4
                | Self::ImportTar { .. }
                | Self::Remove { .. }
                | Self::Write { .. }
                | Self::Chmod { .. }
        )
    }

    pub fn validate(&self, writable: bool) -> io::Result<()> {
        if self.mutation() && !writable {
            return Err(invalid("read-only disk mutation"));
        }
        let path = match self {
            Self::Remove { path }
            | Self::Write { path, .. }
            | Self::Chmod { path, .. }
            | Self::Realpath { path }
            | Self::FileSize { path }
            | Self::Download { path, .. } => Some(path),
            _ => None,
        };
        if path.is_some_and(|path| {
            !path.starts_with('/')
                || path.len() > 4096
                || path.chars().any(char::is_control)
                || path.split('/').any(|part| part == "..")
        }) {
            return Err(invalid("invalid offline guest path"));
        }
        match self {
            Self::ImportTar { bytes, .. } | Self::Download { bytes, .. }
                if *bytes == 0 || *bytes > MAX_DISK_TRANSFER =>
            {
                Err(invalid("disk transfer exceeds bound"))
            }
            Self::Download { offset, bytes, .. } if offset.checked_add(*bytes).is_none() => {
                Err(invalid("disk range overflow"))
            }
            Self::Write { bytes, .. } if bytes.len() > 16384 => {
                Err(invalid("disk metadata write exceeds bound"))
            }
            Self::Chmod { mode, .. } if *mode > 0o7777 => Err(invalid("invalid disk mode")),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DiskReply {
    Complete,
    Text { value: String },
    Size { bytes: u64 },
    Failed { message: String },
}

impl DiskReply {
    pub fn validate_for(&self, operation: &DiskOperation) -> io::Result<()> {
        let valid = match (operation, self) {
            (_, Self::Failed { message }) => message.len() <= 4096,
            (DiskOperation::Realpath { .. }, Self::Text { value }) => {
                value.len() <= 4096 && !value.contains('\0')
            }
            (DiskOperation::FileSize { .. }, Self::Size { bytes }) => *bytes <= MAX_DISK_TRANSFER,
            (
                DiskOperation::Download {
                    bytes: expected, ..
                },
                Self::Size { bytes },
            ) => expected == bytes,
            (
                DiskOperation::Mount { .. }
                | DiskOperation::MakeExt4
                | DiskOperation::ImportTar { .. }
                | DiskOperation::Sync
                | DiskOperation::Unmount
                | DiskOperation::CheckExt4
                | DiskOperation::Remove { .. }
                | DiskOperation::Write { .. }
                | DiskOperation::Chmod { .. },
                Self::Complete,
            ) => true,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(invalid("disk reply differs from the requested observation"))
        }
    }

    pub fn text(self) -> io::Result<String> {
        match self {
            Self::Text { value } => Ok(value),
            _ => Err(invalid("disk reply is not text")),
        }
    }

    pub fn size(self) -> io::Result<u64> {
        match self {
            Self::Size { bytes } => Ok(bytes),
            _ => Err(invalid("disk reply is not a size")),
        }
    }
}

/// One ordered private device connection. A malformed or oversized frame never
/// causes a second attempt or a reconnected replay of a filesystem mutation.
pub struct DiskChannel<T> {
    io: T,
    sent: Counter,
    received: Counter,
    failed: bool,
}
impl<T: Read + Write> DiskChannel<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            sent: Counter::ZERO,
            received: Counter::ZERO,
            failed: false,
        }
    }

    pub fn send_metadata<V: Serialize>(&mut self, value: &V) -> io::Result<()> {
        self.ready()?;
        // Count first so a programmer cannot serialize an unbounded record.
        let mut page = crate::ControlPage::default();
        page.push(value).map_err(io::Error::other)?;
        let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
        self.send(FrameKind::Control, bytes)
    }
    pub fn metadata<V: DeserializeOwned>(&mut self) -> io::Result<V> {
        let frame = self.receive(FrameKind::Control)?;
        let result = serde_json::from_slice(&frame.payload).map_err(io::Error::other);
        self.checked(result)
    }
    pub fn send_data(&mut self, input: &mut impl Read, bytes: u64) -> io::Result<()> {
        self.ready()?;
        if bytes == 0 || bytes > MAX_DISK_TRANSFER {
            return Err(invalid("invalid disk transfer credit"));
        }
        let mut remaining = bytes;
        let mut buffer = [0; MAX_STREAM_BYTES];
        while remaining != 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            let result = input.read_exact(&mut buffer[..count]);
            self.checked(result)?;
            self.send(FrameKind::Data, buffer[..count].to_vec())?;
            remaining -= count as u64;
        }
        Ok(())
    }
    pub fn data(&mut self, output: &mut impl Write, bytes: u64) -> io::Result<()> {
        self.ready()?;
        if bytes == 0 || bytes > MAX_DISK_TRANSFER {
            return Err(invalid("invalid disk receive credit"));
        }
        let mut remaining = bytes;
        while remaining != 0 {
            let frame = self.receive(FrameKind::Data)?;
            if frame.payload.is_empty() || frame.payload.len() as u64 > remaining {
                return self.checked(Err(invalid("disk bytes exceed exact receive credit")));
            }
            let result = output.write_all(&frame.payload);
            self.checked(result)?;
            remaining -= frame.payload.len() as u64;
        }
        Ok(())
    }
    pub fn data_reader(&mut self, bytes: u64) -> io::Result<DiskDataReader<'_, T>> {
        self.ready()?;
        if bytes == 0 || bytes > MAX_DISK_TRANSFER {
            return Err(invalid("invalid disk receive credit"));
        }
        Ok(DiskDataReader {
            channel: self,
            remaining: bytes,
            chunk: Vec::new(),
            offset: 0,
        })
    }
    fn send(&mut self, kind: FrameKind, payload: Vec<u8>) -> io::Result<()> {
        self.ready()?;
        self.sent = self.sent.next().map_err(io::Error::other)?;
        let result = Frame {
            kind,
            stream: u32::from(kind == FrameKind::Data),
            sequence: self.sent,
            authentication: [0; crate::AUTHENTICATION_BYTES],
            payload,
        }
        .write(&mut self.io);
        self.checked(result)
    }
    fn receive(&mut self, kind: FrameKind) -> io::Result<Frame> {
        self.ready()?;
        let result = Frame::read(&mut self.io)
            .and_then(|frame| frame.ok_or_else(|| io::ErrorKind::UnexpectedEof.into()));
        let frame = self.checked(result)?;
        let next = self.received.next().map_err(io::Error::other)?;
        if frame.kind != kind
            || frame.stream != u32::from(kind == FrameKind::Data)
            || frame.sequence != next
            || frame.authentication != [0; crate::AUTHENTICATION_BYTES]
            || frame.payload.len()
                > if kind == FrameKind::Control {
                    MAX_CONTROL_BYTES
                } else {
                    MAX_STREAM_BYTES
                }
        {
            return self.checked(Err(invalid("invalid disk device frame")));
        }
        self.received = next;
        Ok(frame)
    }

    fn ready(&self) -> io::Result<()> {
        if self.failed {
            Err(invalid("disk connection is permanently failed"))
        } else {
            Ok(())
        }
    }

    fn checked<V>(&mut self, result: io::Result<V>) -> io::Result<V> {
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

pub struct DiskDataReader<'a, T> {
    channel: &'a mut DiskChannel<T>,
    remaining: u64,
    chunk: Vec<u8>,
    offset: usize,
}
impl<T: Read + Write> Read for DiskDataReader<'_, T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        if self.offset == self.chunk.len() {
            self.chunk = self.channel.receive(FrameKind::Data)?.payload;
            self.offset = 0;
            if self.chunk.is_empty() || self.chunk.len() as u64 > self.remaining {
                return self
                    .channel
                    .checked(Err(invalid("disk bytes exceed exact receive credit")));
            }
        }
        let count = bytes.len().min(self.chunk.len() - self.offset);
        bytes[..count].copy_from_slice(&self.chunk[self.offset..self.offset + count]);
        self.offset += count;
        self.remaining -= count as u64;
        Ok(count)
    }
}

impl<T> Drop for DiskDataReader<'_, T> {
    fn drop(&mut self) {
        // Abandoning credited bytes loses framing. Never reinterpret them as
        // another operation, and never resume a partially applied mutation.
        if self.remaining != 0 {
            self.channel.failed = true;
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn wire(kind: FrameKind, sequence: u64, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        Frame {
            kind,
            stream: u32::from(kind == FrameKind::Data),
            sequence: sequence.try_into().unwrap(),
            authentication: [0; crate::AUTHENTICATION_BYTES],
            payload: bytes.into(),
        }
        .write(&mut output)
        .unwrap();
        output
    }

    #[test]
    fn bounded_stream_can_be_read_with_smaller_consumer_buffers() {
        let first = vec![b'a'; MAX_STREAM_BYTES];
        let mut bytes = wire(FrameKind::Data, 1, &first);
        bytes.extend(wire(FrameKind::Data, 2, b"last"));
        bytes.extend(wire(FrameKind::Control, 3, b"{\"kind\":\"complete\"}"));
        let mut channel = DiskChannel::new(Cursor::new(bytes));
        let mut reader = channel.data_reader((first.len() + 4) as u64).unwrap();
        let mut buffer = [0; 7];
        let mut total = 0;
        loop {
            let count = reader.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            total += count;
        }
        assert_eq!(total, first.len() + 4);
        drop(reader);
        assert_eq!(
            channel.metadata::<DiskReply>().unwrap(),
            DiskReply::Complete
        );
    }

    #[test]
    fn lost_credit_malformed_metadata_and_wrong_order_permanently_fail() {
        for bytes in [
            wire(FrameKind::Data, 2, b"x"),
            wire(FrameKind::Control, 1, b"not-json"),
        ] {
            let mut channel = DiskChannel::new(Cursor::new(bytes));
            assert!(channel.metadata::<DiskReply>().is_err());
            assert!(channel.send_metadata(&DiskOperation::Sync).is_err());
        }
        let mut channel = DiskChannel::new(Cursor::new(wire(FrameKind::Data, 1, b"abc")));
        {
            let mut reader = channel.data_reader(3).unwrap();
            reader.read_exact(&mut [0]).unwrap();
        }
        assert!(channel.send_metadata(&DiskOperation::Sync).is_err());
        let mut channel = DiskChannel::new(Cursor::new(wire(FrameKind::Data, 1, b"abc")));
        assert!(channel.data(&mut io::sink(), 2).is_err());
        assert!(channel.metadata::<DiskReply>().is_err());
        let mut channel = DiskChannel::new(Cursor::new(Vec::<u8>::new()));
        assert!(channel.send_data(&mut &b"short"[..], 6).is_err());
        assert!(channel.send_metadata(&DiskOperation::Sync).is_err());
    }

    #[test]
    fn truncated_frames_and_unexpected_reply_shapes_are_rejected() {
        let bytes = wire(FrameKind::Control, 1, b"{\"kind\":\"complete\"}");
        for length in 0..bytes.len() {
            let mut channel = DiskChannel::new(Cursor::new(bytes[..length].to_vec()));
            assert!(channel.metadata::<DiskReply>().is_err());
            assert!(channel.send_metadata(&DiskOperation::Sync).is_err());
        }
        assert!(
            DiskReply::Complete
                .validate_for(&DiskOperation::FileSize {
                    path: "/boot/kernel".into()
                })
                .is_err()
        );
        assert!(
            DiskReply::Size { bytes: 9 }
                .validate_for(&DiskOperation::Download {
                    path: "/boot/kernel".into(),
                    offset: 0,
                    bytes: 8
                })
                .is_err()
        );
        assert!(
            DiskReply::Text {
                value: "x".repeat(4097)
            }
            .validate_for(&DiskOperation::Realpath {
                path: "/text".into()
            })
            .is_err()
        );
    }

    #[test]
    fn failed_channel_does_not_consume_new_input() {
        let mut channel = DiskChannel::new(Cursor::new(Vec::<u8>::new()));
        assert!(channel.metadata::<DiskReply>().is_err());
        let mut input = Cursor::new(b"untouched");
        assert!(channel.send_data(&mut input, 9).is_err());
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn closed_protocol_rejects_unused_operations_and_replies() {
        for kind in [
            "execute",
            "mkdir",
            "zero-free-space",
            "cat",
            "stat",
            "readlink",
            "exists",
        ] {
            let value = format!("{{\"kind\":\"{kind}\"}}");
            assert!(serde_json::from_str::<DiskOperation>(&value).is_err());
        }
        for kind in ["stat", "exists"] {
            let value = format!("{{\"kind\":\"{kind}\"}}");
            assert!(serde_json::from_str::<DiskReply>(&value).is_err());
        }
    }

    #[test]
    fn requests_never_admit_host_paths_or_read_only_mutations() {
        for path in ["relative", "/../escape", "/etc/\0host", "/etc/\nline"] {
            assert!(
                DiskOperation::Realpath { path: path.into() }
                    .validate(false)
                    .is_err()
            );
        }
        assert!(DiskOperation::MakeExt4.validate(false).is_err());
        assert!(
            DiskOperation::Mount { writable: true }
                .validate(false)
                .is_err()
        );
        assert!(
            DiskOperation::Download {
                path: "/file".into(),
                offset: u64::MAX,
                bytes: 1
            }
            .validate(false)
            .is_err()
        );
        assert!(
            DiskOperation::ImportTar {
                bytes: MAX_DISK_TRANSFER + 1,
                compression: DiskCompression::None
            }
            .validate(true)
            .is_err()
        );
    }
}
