#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
mod artifact;
#[cfg(target_os = "linux")]
mod changeset;
mod exposure;
#[cfg(target_os = "linux")]
mod firecracker;
mod network;

#[cfg(target_os = "linux")]
pub use artifact::{
    ArtifactBundle, ArtifactEntry, ArtifactError, ArtifactKind, ImportOmission, collect_artifacts,
    validate_artifact_bundle,
};
#[cfg(target_os = "linux")]
pub use changeset::{
    ApplyError, ApplyReport, BaseEntry, ChangeOperation, ChangeSet, apply_change_set,
    create_change_set, recover_interrupted_apply, validate_change_set,
};
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
