#![deny(unsafe_code)]

pub const GUEST_PROTOCOL_MAJOR: u16 = 1;
pub const GUEST_PROTOCOL_MINOR: u16 = 0;
pub const GUEST_CONTROL_PORT: u32 = 10_789;
pub const GUEST_BOOTSTRAP_PORT: u32 = 10_788;
pub const AUTHENTICATION_MAGIC: &[u8; 8] = b"SCFAUTH1";
