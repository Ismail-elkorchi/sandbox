#![deny(unsafe_op_in_unsafe_fn)]

//! Concurrent process/PTY service for the persistent Linux workload guest.
//!
//! Client connection lifetime is deliberately absent from this API. Process
//! groups and retained output are owned by the guest supervisor until explicit
//! lifecycle or evidence handoff occurs at the guardian.

mod filesystem;
#[cfg(target_os = "linux")]
mod process;
mod spool;

pub use filesystem::*;
#[cfg(target_os = "linux")]
pub use process::*;
pub use spool::*;
