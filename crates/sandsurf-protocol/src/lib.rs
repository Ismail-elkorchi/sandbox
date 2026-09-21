#![deny(unsafe_code)]

mod checkpoint;
mod environment;
mod frame;
mod guest;
mod session;
mod types;

pub use checkpoint::*;
pub use environment::*;
pub use frame::*;
pub use guest::*;
pub use sandbox_digest::SandsurfDomain as Domain;
pub use session::*;
pub use types::*;

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Invalid {}

pub fn digest<T: Serialize>(domain: Domain, value: &T) -> Result<Digest, Invalid> {
    sandbox_digest::sandsurf_digest(domain, value)
        .map_err(|_| Invalid("non-canonical digest input"))?
        .try_into()
}

pub fn bytes_digest(bytes: &[u8]) -> Digest {
    let hash = Sha256::digest(bytes);
    Digest::try_from(format!("{hash:x}")).expect("SHA-256 encoding")
}

/// Establish the content-chain identity for one process before any bytes are
/// retained. Guest and guardian both use this exact boundary contract.
pub fn initial_output_boundary(
    sandbox: &SandboxId,
    process: &ProcessId,
    epoch: Counter,
) -> Result<OutputBoundary, Invalid> {
    Ok(OutputBoundary {
        final_cursor: Counter::ZERO,
        chunks: Counter::ZERO,
        stdout_bytes: Counter::ZERO,
        stderr_bytes: Counter::ZERO,
        terminal_bytes: Counter::ZERO,
        omitted_bytes: Counter::ZERO,
        final_hash: digest(Domain::Output, &(sandbox, process, epoch))?,
    })
}

/// Advance a complete-output boundary by one non-empty, ordered binary chunk.
/// This computes evidence only; each authority must durably store the bytes
/// before publishing the returned boundary.
pub fn extend_output_boundary(
    boundary: &OutputBoundary,
    sequence: Counter,
    stream: Stream,
    bytes: &[u8],
) -> Result<OutputBoundary, Invalid> {
    if bytes.is_empty() || bytes.len() > MAX_STREAM_BYTES || sequence != boundary.chunks.next()? {
        return Err(Invalid("output chunk is empty, oversized, or out of order"));
    }
    let content = bytes_digest(bytes);
    let final_hash = digest(
        Domain::Output,
        &(
            &boundary.final_hash,
            sequence,
            boundary.final_cursor,
            stream,
            &content,
            bytes.len(),
        ),
    )?;
    let mut next = boundary.clone();
    next.final_cursor = next.final_cursor.checked_add(bytes.len() as u64)?;
    next.chunks = sequence;
    match stream {
        Stream::Stdout => next.stdout_bytes = next.stdout_bytes.checked_add(bytes.len() as u64)?,
        Stream::Stderr => next.stderr_bytes = next.stderr_bytes.checked_add(bytes.len() as u64)?,
        Stream::Terminal => {
            next.terminal_bytes = next.terminal_bytes.checked_add(bytes.len() as u64)?
        }
    }
    next.final_hash = final_hash;
    Ok(next)
}
