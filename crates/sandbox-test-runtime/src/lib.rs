#![deny(unsafe_code)]

/// The fake backend is deliberately unavailable unless this crate is compiled
/// with its test-only feature. Production code never depends on it.
#[must_use]
pub const fn test_backend_enabled() -> bool {
    cfg!(feature = "test-backend")
}
