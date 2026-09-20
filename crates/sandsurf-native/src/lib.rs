#![deny(unsafe_op_in_unsafe_fn)]

//! Native ownership mechanisms shared by the host/guardian and guest bootstrap.
//! They do not admit authority, launch arbitrary programs, or qualify a VM.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod local;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod filesystem;

#[cfg(target_os = "macos")]
pub mod macos;
