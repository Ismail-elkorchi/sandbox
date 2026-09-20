#![deny(unsafe_code)]

mod frame;
mod session;
mod types;

pub use frame::*;
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
