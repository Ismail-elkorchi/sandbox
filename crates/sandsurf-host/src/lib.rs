#![deny(unsafe_code)]

pub mod api;
pub mod artifacts;
mod boot_preparation;
mod capture;
mod console;
pub mod guardian;
pub mod guest;
mod guest_transport;
mod guest_worker;
mod image_records;
pub mod image_worker;
pub mod images;
mod ipc_frames;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(any(target_os = "macos", windows))]
pub mod qemu;
pub mod qualification;
pub mod resources;
mod restore;
mod restore_preparation;
pub mod secrets;
pub mod service;
mod snapshots;
mod storage;
pub mod supervision;
