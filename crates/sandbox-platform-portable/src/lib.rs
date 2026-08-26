#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::result_large_err)]

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod runtime;

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use runtime::runtime_main;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn runtime_main() {
    panic!("portable runtime is only available on Windows and macOS");
}
