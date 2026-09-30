#![deny(unsafe_code)]

pub mod api;
#[cfg(any(target_os = "macos", feature = "apple-source-check"))]
pub mod apple;
pub mod artifacts;
mod capture;
pub mod guardian;
pub mod guest;
mod guest_worker;
pub mod images;
mod ipc_frames;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod secrets;
pub mod service;
mod snapshots;
mod storage;
#[cfg(target_os = "windows")]
pub mod windows;
