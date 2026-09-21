#![deny(unsafe_op_in_unsafe_fn)]

//! Native ownership mechanisms shared by the host/guardian and guest bootstrap.
//! They do not admit authority, launch arbitrary programs, or qualify a VM.

pub mod guest_channel;

#[cfg(unix)]
pub use guest_channel::DirectUnixChannel;
#[cfg(target_os = "windows")]
pub use guest_channel::HyperVChannel;
#[cfg(unix)]
pub use guest_channel::UnixVsockChannel;
pub use guest_channel::{GuestChannel, GuestChannelError, GuestConnection};

#[cfg(target_os = "windows")]
pub mod virtual_disk;

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
