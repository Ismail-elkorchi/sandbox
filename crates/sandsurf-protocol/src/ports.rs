#![deny(unsafe_code)]

pub const GUEST_PROTOCOL_MAJOR: u16 = 1;
pub const GUEST_PROTOCOL_MINOR: u16 = 0;
pub const GUEST_CONTROL_PORT: u32 = 10_789;
/// Fixed virtio-serial connection slots. Device transport, not guest authority.
pub const GUEST_SERIAL_CONNECTIONS: usize = 8;
pub const GUEST_SERIAL_PREFIX: &str = "sandsurf.control.";
pub const AUTHENTICATION_MAGIC: &[u8; 8] = b"SCFAUTH1";
