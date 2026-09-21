#![deny(unsafe_op_in_unsafe_fn)]

mod exposure;
#[cfg(target_os = "linux")]
mod firecracker;
mod network;

pub use exposure::VmPortGateway;
#[cfg(target_os = "linux")]
pub use firecracker::{
    FirecrackerConfig, FirecrackerError, FirecrackerProcess, FirecrackerRestore,
    FirecrackerSnapshot,
};
pub use network::VmNetworkBridge;
pub use sandbox_image::{ImageTrust, VerifiedImage, verify_image};
pub use sandbox_network_broker::{BrokerSnapshot, NetworkViolation};
pub use sandsurf_native::{GuestChannel, GuestChannelError, GuestConnection, UnixVsockChannel};
