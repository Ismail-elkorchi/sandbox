use sandsurf_protocol::{
    Counter, OutputBoundary, ProcessId, RetainedChunk, RetainedPage, SandboxId, Stream,
    bytes_digest, extend_output_boundary, initial_output_boundary,
};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

const MAGIC: &[u8; 4] = b"SSO1";
const HEADER_BYTES: usize = 4 + 8 + 1 + 4 + 32;
const MAX_READ_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum SpoolError {
    Io(io::Error),
    Invalid(&'static str),
    Capacity,
    Failed,
}

impl fmt::Display for SpoolError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "output spool I/O: {error}"),
            Self::Invalid(message) => write!(output, "invalid output spool: {message}"),
            Self::Capacity => output.write_str("output retention reservation exhausted"),
            Self::Failed => output.write_str("output spool is failed"),
        }
    }
}

impl std::error::Error for SpoolError {}
impl From<io::Error> for SpoolError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct OutputSpool {
    file: File,
    state: Mutex<SpoolState>,
    maximum: u64,
}

struct SpoolState {
    boundary: OutputBoundary,
    file_bytes: u64,
    failed: bool,
    finalized: Option<OutputBoundary>,
}

impl OutputSpool {
    pub fn create(
        path: &Path,
        maximum: Counter,
        sandbox: &SandboxId,
        process: &ProcessId,
        epoch: Counter,
    ) -> Result<Self, SpoolError> {
        if maximum == Counter::ZERO {
            return Err(SpoolError::Invalid("reservation must be positive"));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        file.sync_all()?;
        Ok(Self {
            file,
            state: Mutex::new(SpoolState {
                boundary: initial_output_boundary(sandbox, process, epoch)
                    .map_err(|_| SpoolError::Invalid("output identity is invalid"))?,
                file_bytes: 0,
                failed: false,
                finalized: None,
            }),
            maximum: maximum.get(),
        })
    }

    /// Durably append before publishing the new cursor. Any storage/capacity
    /// failure poisons completion: callers must retain an unknown operation and
    /// may not mint a receipt that claims complete output.
    pub fn append(&self, stream: Stream, bytes: &[u8]) -> Result<Counter, SpoolError> {
        if bytes.is_empty() || bytes.len() > sandsurf_protocol::MAX_STREAM_BYTES {
            return Err(SpoolError::Invalid("chunk size is outside frame bounds"));
        }
        let mut state = self.state.lock().map_err(|_| SpoolError::Failed)?;
        if state.failed || state.finalized.is_some() {
            return Err(SpoolError::Failed);
        }
        let sequence = state
            .boundary
            .chunks
            .next()
            .map_err(|_| SpoolError::Capacity)?;
        let next_boundary = extend_output_boundary(&state.boundary, sequence, stream, bytes)
            .map_err(|_| SpoolError::Capacity)?;
        if next_boundary.final_cursor.get() > self.maximum {
            state.failed = true;
            return Err(SpoolError::Capacity);
        }
        let digest = bytes_digest(bytes);
        let mut record = Vec::with_capacity(HEADER_BYTES + bytes.len());
        record.extend_from_slice(MAGIC);
        record.extend_from_slice(&state.boundary.final_cursor.get().to_be_bytes());
        record.push(stream_tag(stream));
        record.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        let digest_bytes = decode_digest(&digest)?;
        record.extend_from_slice(&digest_bytes);
        record.extend_from_slice(bytes);
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(state.file_bytes))?;
        if let Err(error) = file.write_all(&record).and_then(|()| file.sync_data()) {
            state.failed = true;
            return Err(error.into());
        }
        state.file_bytes = state
            .file_bytes
            .checked_add(record.len() as u64)
            .ok_or(SpoolError::Capacity)?;
        state.boundary = next_boundary;
        Ok(state.boundary.final_cursor)
    }

    pub fn read(&self, after: Counter, maximum: usize) -> Result<RetainedPage, SpoolError> {
        if maximum == 0 || maximum > MAX_READ_BYTES {
            return Err(SpoolError::Invalid("read bound must be 1..1 MiB"));
        }
        let state = self.state.lock().map_err(|_| SpoolError::Failed)?;
        if after > state.boundary.final_cursor {
            return Err(SpoolError::Invalid("cursor is beyond retained output"));
        }
        let expected_file_bytes = state.file_bytes;
        let available = state.boundary.final_cursor;
        drop(state);

        let mut file = self.file.try_clone()?;
        if file.metadata()?.len() != expected_file_bytes {
            return Err(SpoolError::Invalid("spool length changed unexpectedly"));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut file_cursor = 0u64;
        let mut content_cursor = 0u64;
        let mut found = after == Counter::ZERO;
        let mut retained = 0usize;
        let mut chunks = Vec::new();
        let mut required_bytes = None;
        while file_cursor < expected_file_bytes {
            let mut header = [0u8; HEADER_BYTES];
            file.read_exact(&mut header)?;
            file_cursor += HEADER_BYTES as u64;
            if &header[..4] != MAGIC {
                return Err(SpoolError::Invalid("record magic mismatch"));
            }
            let cursor = u64::from_be_bytes(header[4..12].try_into().unwrap());
            let stream = parse_stream(header[12])?;
            let length = u32::from_be_bytes(header[13..17].try_into().unwrap()) as usize;
            if cursor != content_cursor
                || length == 0
                || length > sandsurf_protocol::MAX_STREAM_BYTES
                || file_cursor + length as u64 > expected_file_bytes
            {
                return Err(SpoolError::Invalid("record bounds or cursor mismatch"));
            }
            let mut bytes = vec![0u8; length];
            file.read_exact(&mut bytes)?;
            file_cursor += length as u64;
            if decode_digest(&bytes_digest(&bytes))?.as_slice() != &header[17..49] {
                return Err(SpoolError::Invalid("record digest mismatch"));
            }
            if cursor == after.get() {
                found = true;
            }
            if found && retained + length <= maximum {
                chunks.push(RetainedChunk {
                    cursor: Counter::try_from(cursor).map_err(|_| SpoolError::Capacity)?,
                    stream,
                    digest: bytes_digest(&bytes),
                    bytes,
                });
                retained += length;
            } else if found {
                if chunks.is_empty() {
                    required_bytes =
                        Some(Counter::try_from(length as u64).map_err(|_| SpoolError::Capacity)?);
                }
                break;
            }
            content_cursor = content_cursor
                .checked_add(length as u64)
                .ok_or(SpoolError::Capacity)?;
        }
        if after == available {
            found = true;
        }
        if !found {
            return Err(SpoolError::Invalid("cursor is not a chunk boundary"));
        }
        Ok(RetainedPage {
            after,
            available,
            chunks,
            required_bytes,
        })
    }

    pub fn finalize(&self) -> Result<OutputBoundary, SpoolError> {
        let mut state = self.state.lock().map_err(|_| SpoolError::Failed)?;
        if state.failed {
            return Err(SpoolError::Failed);
        }
        if let Some(value) = &state.finalized {
            return Ok(value.clone());
        }
        self.file.sync_all()?;
        let boundary = state.boundary.clone();
        state.finalized = Some(boundary.clone());
        Ok(boundary)
    }

    pub fn has_failed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.failed)
    }
}

fn decode_digest(value: &sandsurf_protocol::Digest) -> Result<[u8; 32], SpoolError> {
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value.as_str()[offset..offset + 2], 16)
            .map_err(|_| SpoolError::Invalid("digest encoding is invalid"))?;
    }
    Ok(bytes)
}

fn stream_tag(stream: Stream) -> u8 {
    match stream {
        Stream::Stdout => 1,
        Stream::Stderr => 2,
        Stream::Terminal => 3,
    }
}

fn parse_stream(value: u8) -> Result<Stream, SpoolError> {
    match value {
        1 => Ok(Stream::Stdout),
        2 => Ok(Stream::Stderr),
        3 => Ok(Stream::Terminal),
        _ => Err(SpoolError::Invalid("unknown stream tag")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sandsurf-spool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn spool(path: &Path, maximum: u64) -> OutputSpool {
        OutputSpool::create(
            path,
            maximum.try_into().unwrap(),
            &SandboxId::try_from("box").unwrap(),
            &ProcessId::try_from("process").unwrap(),
            Counter::ONE,
        )
        .unwrap()
    }

    #[test]
    fn binary_output_is_durable_cursor_addressed_and_finalized() {
        let path = path();
        let spool = spool(&path, 1024);
        assert_eq!(spool.append(Stream::Stdout, &[0, 255, 1]).unwrap().get(), 3);
        assert_eq!(spool.append(Stream::Stderr, b"err").unwrap().get(), 6);
        let page = spool.read(Counter::ZERO, 1024).unwrap();
        assert_eq!(page.available.get(), 6);
        assert_eq!(page.chunks[0].bytes, [0, 255, 1]);
        assert_eq!(
            spool
                .read(3u64.try_into().unwrap(), 1024)
                .unwrap()
                .chunks
                .len(),
            1
        );
        assert!(spool.read(2u64.try_into().unwrap(), 1024).is_err());
        let boundary = spool.finalize().unwrap();
        assert_eq!(boundary.final_cursor.get(), 6);
        assert_eq!(boundary.omitted_bytes, Counter::ZERO);
        assert!(spool.append(Stream::Stdout, b"late").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn capacity_failure_prevents_a_false_completion_boundary() {
        let path = path();
        let spool = spool(&path, 3);
        spool.append(Stream::Stdout, b"abc").unwrap();
        assert!(matches!(
            spool.append(Stream::Stdout, b"d"),
            Err(SpoolError::Capacity)
        ));
        assert!(spool.has_failed());
        assert!(spool.finalize().is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn undersized_page_reports_the_next_atomic_chunk() {
        let path = path();
        let spool = spool(&path, 1024);
        spool.append(Stream::Stdout, b"0123456789").unwrap();
        let page = spool.read(Counter::ZERO, 4).unwrap();
        assert!(page.chunks.is_empty());
        assert_eq!(page.required_bytes.unwrap().get(), 10);
        assert_eq!(page.available.get(), 10);
        fs::remove_file(path).unwrap();
    }
}
