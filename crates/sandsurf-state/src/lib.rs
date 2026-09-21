#![deny(unsafe_op_in_unsafe_fn)]

//! Internal persistence mechanisms, not an executable host service or VM backend.
//!
//! `HostCatalog` owns approved authority and lifecycle intent; `RuntimeJournal`
//! records facts supplied by its trusted guardian. Opening a journal establishes
//! storage-writer exclusion, not live VM ownership, confinement, or guest identity.
//! The VM owner must establish those boundaries before publishing observations.
//! Host-signed exact-operation envelopes cross the private host/guardian boundary;
//! they are not a guardian-owned grant database or application capability.
//! External capture commitments are trusted consumer
//! assertions; pins retain bytes in this store. Native state admission validates
//! owner-only POSIX modes/ACLs or protected Windows DACLs and held handles.

mod authority;
mod catalog;
mod database;
mod disks;
mod runtime;
#[cfg(target_os = "windows")]
mod windows;

pub use catalog::*;
pub use disks::*;
pub use runtime::*;

/// Return the stable filesystem identity of a non-reparse Windows directory.
/// The handle excludes delete sharing while the identity is observed.
#[cfg(target_os = "windows")]
pub fn native_directory_identity(path: &std::path::Path) -> std::io::Result<(u64, u64)> {
    windows::directory_identity(path)
}

use sandsurf_protocol::Invalid;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Json(serde_json::Error),
    Invalid(Invalid),
    Conflict(&'static str),
    Capacity(&'static str),
    Missing(&'static str),
    Corrupt(&'static str),
    Unsupported(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "storage I/O: {e}"),
            Self::Sql(e) => write!(f, "storage transaction: {e}"),
            Self::Json(e) => write!(f, "stored contract: {e}"),
            Self::Invalid(e) => e.fmt(f),
            Self::Conflict(e)
            | Self::Capacity(e)
            | Self::Missing(e)
            | Self::Corrupt(e)
            | Self::Unsupported(e) => f.write_str(e),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sql(value)
    }
}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<Invalid> for Error {
    fn from(value: Invalid) -> Self {
        Self::Invalid(value)
    }
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_string(value)?;
    if json.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
        return Err(Error::Capacity("metadata record exceeds control bound"));
    }
    Ok(json)
}
fn decode<T: DeserializeOwned>(json: &str) -> Result<T> {
    if json.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
        return Err(Error::Corrupt("metadata record exceeds control bound"));
    }
    Ok(serde_json::from_str(json)?)
}
