#![deny(unsafe_op_in_unsafe_fn)]

//! Native ownership mechanisms shared by the host/guardian and guest bootstrap.
//! They do not admit authority, launch arbitrary programs, or qualify a VM.

pub mod capacity;
pub mod guest_channel;
#[cfg(target_os = "linux")]
pub mod network_sockets;
#[cfg(windows)]
pub mod owned_windows;
pub mod process_budget;
pub mod resource_broker;
pub mod resources;
pub mod serial_channel;
pub mod service_pool;
pub mod socket_io;
pub mod storage;
pub mod storage_usage;
pub mod volume;
/// Original file descriptions retained by one native worker, never reacquired
/// from paths. Bounds apply before descriptor/handle transfer on every host.
pub const MAX_WORKER_CUSTODY: usize = 8;
#[cfg(any(windows, test))]
mod windows_arguments;

/// Access requested for an account-private file. Validation never repairs or
/// adopts a foreign ACL, mode, owner, link, or reparse identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateFileAccess {
    ReadOnly,
    ReadWrite,
}
#[cfg(unix)]
pub mod unix_io;

#[cfg(unix)]
pub use guest_channel::DirectUnixChannel;
#[cfg(unix)]
pub use guest_channel::UnixGuestConnection;
#[cfg(unix)]
pub use guest_channel::UnixVsockChannel;
pub use guest_channel::{GuestChannel, GuestChannelError, GuestConnection};

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod local;

#[cfg(target_os = "windows")]
#[path = "local_windows.rs"]
pub mod local;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod filesystem;

#[cfg(target_os = "macos")]
pub mod macos;
