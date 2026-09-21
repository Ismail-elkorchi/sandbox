#![deny(unsafe_code)]

pub mod api;
#[cfg(any(target_os = "macos", feature = "apple-source-check"))]
pub mod apple;
mod checkpoints;
pub mod guest;
#[cfg(target_os = "linux")]
pub mod images;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
mod registry;
pub mod secrets;
pub mod service;
#[cfg(target_os = "windows")]
pub mod windows;
pub mod workspace;
