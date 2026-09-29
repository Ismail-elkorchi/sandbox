#![deny(unsafe_op_in_unsafe_fn)]

//! Ordinary Linux management and independent execution/PTY keepers.
//!
//! Client and management-service lifetimes do not own processes or terminals.
//! Every guest component remains controllable by guest root; only the native
//! host boundary and host-retained bytes can support host-verifiable claims.

#[cfg(target_os = "linux")]
mod executions;
#[cfg(target_os = "linux")]
mod filesystem;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod service;
mod spool;

#[cfg(target_os = "linux")]
pub use executions::{ExecutionRegistry, execution_keeper_main};
#[cfg(target_os = "linux")]
pub use filesystem::*;
#[cfg(target_os = "linux")]
pub use process::ProcessError;
pub use sandsurf_protocol::{
    DirectoryEntry, DirectoryPage, ExecutionCompletion, ExecutionSnapshot, ExecutionState,
    FileKind, FileRange, FileRevision, FileStat, RetainedChunk, RetainedPage, WatchEvent,
    WatchEventKind,
};
#[cfg(target_os = "linux")]
pub use service::*;
pub use spool::*;
