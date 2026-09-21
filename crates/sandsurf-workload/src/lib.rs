#![deny(unsafe_op_in_unsafe_fn)]

//! Concurrent process/PTY service for the persistent Linux workload guest.
//!
//! Client connection lifetime is deliberately absent from this API. Process
//! groups and retained output are owned by the guest supervisor until explicit
//! lifecycle or evidence handoff occurs at the guardian.

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(all(target_os = "linux", feature = "guardian"))]
mod driver;
#[cfg(target_os = "linux")]
mod filesystem;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod service;
mod spool;

#[cfg(target_os = "linux")]
pub use cgroup::*;
#[cfg(all(target_os = "linux", feature = "guardian"))]
pub use driver::*;
#[cfg(target_os = "linux")]
pub use filesystem::*;
#[cfg(target_os = "linux")]
pub use process::*;
pub use sandsurf_protocol::{
    DirectoryEntry, DirectoryPage, FileKind, FileRange, FileRevision, FileStat, ProcessCompletion,
    ProcessSnapshot, ProcessState, RetainedChunk, RetainedPage, WatchEvent, WatchEventKind,
};
#[cfg(target_os = "linux")]
pub use service::*;
pub use spool::*;
