#![deny(unsafe_code)]

pub const GUEST_PROTOCOL_MAJOR: u16 = 2;
pub const GUEST_PROTOCOL_MINOR: u16 = 0;
pub const GUEST_CONTROL_PORT: u32 = 10_789;
pub const GUEST_EXPOSURE_PORT: u32 = 10_790;
pub const NETWORK_HTTP_PORT: u32 = 12_080;
pub const NETWORK_SOCKS_PORT: u32 = 12_081;
pub const NETWORK_DNS_TCP_PORT: u32 = 12_082;
pub const NETWORK_DNS_UDP_PORT: u32 = 12_083;
pub const NETWORK_AUTH_MAGIC: &[u8; 7] = b"SBXNET1";
pub const AUTHENTICATION_MAGIC: &[u8; 8] = b"SSFAUTH2";
