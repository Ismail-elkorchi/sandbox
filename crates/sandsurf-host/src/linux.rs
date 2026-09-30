//! Linux guardian integration for one retained Firecracker machine.

use crate::guardian::{
    EffectOutcome, Error as ControlError, GuardianEffect, GuestDriver, Result as ControlResult,
};
use crate::guest::{GuestClient, ManagedGuestClient, ManagementRebind, PendingRebind};
use sandsurf_image::{Architecture, ImageTrust, RootfsFormat, VerifiedImage, verify_image};
use sandsurf_machine::firecracker::{FirecrackerConfig, FirecrackerProcess, FirecrackerRestore};
use sandsurf_machine::linux::{
    FirecrackerDriver, FirecrackerGenerationFactory, FirecrackerQualification,
    FirecrackerRestoreSource,
};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_native::UnixVsockChannel;
use sandsurf_network::{VmNetworkBridge, VmPortGateway};
use sandsurf_protocol::{AUTHENTICATION_MAGIC, GUEST_CONTROL_PORT};
use sandsurf_protocol::{
    Counter, Digest, Domain, ExecutionDefaults, GuestCommand, GuestServiceRequest,
    GuestServiceResponse, LifecycleCommand, MachineId, MachineObservation, MachineState,
    NativeFullCapture, NativeSnapshotRequest, NativeSnapshotResponse, NetworkDestination,
    NetworkPolicy, Resources, RuntimeConfiguration, SnapshotArtifact, SnapshotProcessWatermark,
    VmEngine, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONFIG_VERSION: u16 = 1;
const BUNDLED_IMAGE_MANIFEST_DIGEST: Option<&str> =
    option_env!("SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST");

#[derive(Debug)]
pub enum LinuxError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandsurf_image::ImageError),
    Invalid(String),
}

impl fmt::Display for LinuxError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "Linux guardian I/O: {error}"),
            Self::Json(error) => write!(output, "Linux guardian configuration: {error}"),
            Self::Image(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for LinuxError {}
impl From<io::Error> for LinuxError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for LinuxError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_image::ImageError> for LinuxError {
    fn from(value: sandsurf_image::ImageError) -> Self {
        Self::Image(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxGuardianConfig {
    format_version: u16,
    machine_id: MachineId,
    image_digest: Digest,
    resources: Resources,
    launcher: PathBuf,
    firecracker: PathBuf,
    firecracker_sha256: String,
    image_manifest: PathBuf,
    system_seed: PathBuf,
    system_seed_sha256: String,
    guest_cid: u32,
}

/// Resolve and copy an exact source-built boot/defaults bundle into the host's
/// immutable image store before catalog admission. Local unsigned images are
/// accepted only through the explicit qualification environment variable;
/// packaged images require their release signature and index digest.
pub fn prepare_config(
    host_root: &Path,
    executable: &Path,
    machine_id: &MachineId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<LinuxGuardianConfig, LinuxError> {
    let existing_path = host_root
        .join("machines")
        .join(machine_id.as_str())
        .join("guardian/config.json");
    if existing_path.exists() {
        let existing = read_config(&existing_path, machine_id)?;
        if existing.image_digest != *image_digest || existing.launcher != executable {
            return Err(LinuxError::Invalid(
                "existing Machine configuration conflicts with create request".into(),
            ));
        }
        return Ok(existing);
    }
    let installed_root = host_root.join("images").join(image_digest.as_str());
    let (verified, source_template) = if installed_root.exists() {
        let verified = verify_image(
            &installed_root.join("manifest.json"),
            ImageTrust::ExplicitLocal,
        )?;
        let template = verified.system_path.clone();
        (verified, template)
    } else {
        resolve_source_bundle(executable)?
    };
    if verified.manifest_digest != image_digest.as_str()
        || verified.manifest.architecture
            != if cfg!(target_arch = "aarch64") {
                Architecture::Arm64
            } else {
                Architecture::X64
            }
        || verified.manifest.system.rootfs.format != RootfsFormat::Ext4
    {
        return Err(LinuxError::Invalid(
            "image identity, architecture or system disk format do not match".into(),
        ));
    }
    require_regular(&source_template, 128 * 1024 * 1024 * 1024)?;
    let installed = sandsurf_image::install_image(&host_root.join("images"), &verified)?;

    let firecracker = std::env::var_os("SANDSURF_FIRECRACKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            executable
                .parent()
                .unwrap_or(Path::new("/"))
                .join(if cfg!(target_arch = "aarch64") {
                    "firecracker-v1.17.0-aarch64"
                } else {
                    "firecracker-v1.17.0-x86_64"
                })
        });
    require_regular(&firecracker, 256 * 1024 * 1024)?;
    if resources.vcpus.get() > 32
        || resources.memory_mib.get() < 128
        || resources.memory_mib.get() > 65_536
    {
        return Err(LinuxError::Invalid(
            "requested VM shape is outside the Firecracker envelope".into(),
        ));
    }
    Ok(LinuxGuardianConfig {
        format_version: CONFIG_VERSION,
        machine_id: machine_id.clone(),
        image_digest: image_digest.clone(),
        resources: resources.clone(),
        launcher: executable.to_path_buf(),
        firecracker_sha256: sha256_file(&firecracker, 256 * 1024 * 1024)?,
        firecracker,
        image_manifest: installed.join("manifest.json"),
        system_seed_sha256: sha256_file(
            &installed.join(&verified.manifest.system.rootfs.path),
            128 * 1024 * 1024 * 1024,
        )?,
        system_seed: installed.join(&verified.manifest.system.rootfs.path),
        guest_cid: allocate_guest_cid(host_root)?,
    })
}

pub(crate) fn resolve_source_bundle(
    executable: &Path,
) -> Result<(VerifiedImage, PathBuf), LinuxError> {
    let local_manifest = std::env::var_os("SANDSURF_LOCAL_IMAGE_MANIFEST").map(PathBuf::from);
    if let Some(path) = local_manifest {
        if !path.is_absolute() {
            return Err(LinuxError::Invalid(
                "SANDSURF_LOCAL_IMAGE_MANIFEST must be absolute".into(),
            ));
        }
        let verified = verify_image(&path, ImageTrust::ExplicitLocal)?;
        let template = verified.system_path.clone();
        Ok((verified, template))
    } else {
        let package = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| LinuxError::Invalid("native package layout is invalid".into()))?;
        let architecture = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        };
        let relative_manifest = format!("development-{architecture}/manifest.json");
        let manifest = package.join("images").join(&relative_manifest);
        let index: ImageIndex = read_json(&package.join("images/manifest.json"), 1024 * 1024)?;
        let expected = index
            .files
            .get(&relative_manifest)
            .ok_or_else(|| LinuxError::Invalid("packaged boot manifest is absent".into()))?
            .clone();
        let pinned = BUNDLED_IMAGE_MANIFEST_DIGEST.ok_or_else(|| {
            LinuxError::Invalid(
                "native host was built without a bundled image trust identity".into(),
            )
        })?;
        if expected != pinned {
            return Err(LinuxError::Invalid(
                "packaged image index differs from the native trust identity".into(),
            ));
        }
        let verified = verify_image(
            &manifest,
            ImageTrust::Pinned {
                manifest_digest: pinned,
            },
        )?;
        let template = verified.system_path.clone();
        Ok((verified, template))
    }
}

pub fn write_config(path: &Path, config: &LinuxGuardianConfig) -> Result<(), LinuxError> {
    if path.exists() {
        let existing = read_json::<LinuxGuardianConfig>(path, 1024 * 1024)?;
        return if existing == *config {
            Ok(())
        } else {
            Err(LinuxError::Invalid(
                "guardian configuration is already bound to different inputs".into(),
            ))
        };
    }
    let bytes = serde_json::to_vec(config)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub fn read_config(path: &Path, machine_id: &MachineId) -> Result<LinuxGuardianConfig, LinuxError> {
    let value: LinuxGuardianConfig = read_json(path, 1024 * 1024)?;
    if value.format_version != CONFIG_VERSION || value.machine_id != *machine_id {
        return Err(LinuxError::Invalid(
            "guardian configuration identity is invalid".into(),
        ));
    }
    let image = verify_image(&value.image_manifest, ImageTrust::ExplicitLocal)?;
    if image.manifest_digest != value.image_digest.as_str()
        || sha256_file(&value.firecracker, 256 * 1024 * 1024)? != value.firecracker_sha256
        || sha256_file(&value.system_seed, 128 * 1024 * 1024 * 1024)? != value.system_seed_sha256
    {
        return Err(LinuxError::Invalid(
            "guardian configuration artifact identity changed".into(),
        ));
    }
    Ok(value)
}

pub fn execution_defaults(
    host_root: &Path,
    image_digest: &Digest,
) -> Result<ExecutionDefaults, LinuxError> {
    let image = verify_image(
        &host_root
            .join("images")
            .join(image_digest.as_str())
            .join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if image.manifest_digest != image_digest.as_str() {
        return Err(LinuxError::Invalid(
            "installed image identity changed".into(),
        ));
    }
    let defaults = image.manifest.system.defaults;
    Ok(ExecutionDefaults {
        environment: defaults.environment,
        user: defaults.user,
        working_directory: defaults.working_directory,
    })
}

pub struct LinuxGuardianEffect {
    machine_root: PathBuf,
    config: LinuxGuardianConfig,
    machine: FirecrackerDriver<LinuxGenerationFactory>,
    guest_binding: Arc<Mutex<Option<ActiveGuest>>>,
    network: Arc<Mutex<Option<VmNetworkBridge>>>,
    network_usage: NetworkUsage,
    exposures: Arc<Mutex<Option<VmPortGateway>>>,
    installed_runtime: Option<InstalledRuntime>,
    restore_lineage: Option<RestoreLineage>,
    suspend_capture_operation: Option<sandsurf_protocol::OperationId>,
}

struct RestoreLineage {
    snapshot_id: sandsurf_protocol::SnapshotId,
    source_machine_id: MachineId,
    source_generation: Counter,
}

/// Evidence that a specific host-owned configuration is live in one guest
/// generation. This is an observation cache only: lifecycle/configuration commands
/// remain the sole authority, and a new generation always invalidates it.
struct InstalledRuntime {
    generation: Counter,
    configuration: RuntimeConfiguration,
    evidence: Digest,
}

#[derive(Default)]
struct NetworkUsageValue {
    rx_bytes: u64,
    tx_bytes: u64,
    connections: u64,
}

type NetworkUsage = Arc<Mutex<NetworkUsageValue>>;

fn accumulate_network_usage(usage: &NetworkUsage, report: &sandsurf_network::BrokerReport) {
    if let Ok(mut usage) = usage.lock() {
        usage.rx_bytes = usage.rx_bytes.saturating_add(report.rx_bytes);
        usage.tx_bytes = usage.tx_bytes.saturating_add(report.tx_bytes);
        usage.connections = usage.connections.saturating_add(report.connections);
    }
}

impl LinuxGuardianEffect {
    fn management_binding(&self) -> Option<ActiveGuest> {
        self.guest_binding.lock().ok()?.clone()
    }
    pub fn open(machine_root: &Path, config: LinuxGuardianConfig) -> Result<Self, LinuxError> {
        fs::metadata("/dev/kvm").map_err(|_| LinuxError::Invalid("KVM is unavailable".into()))?;
        let image = verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        let disks = machine_root.join("disks");
        fs::create_dir_all(&disks)?;
        let system_disk = disks.join("system.ext4");

        let active = Arc::new(Mutex::new(None));
        let network = Arc::new(Mutex::new(None));
        let network_usage = Arc::new(Mutex::new(NetworkUsageValue::default()));
        let exposures = Arc::new(Mutex::new(None));
        let factory = LinuxGenerationFactory {
            config: config.clone(),
            machine_root: machine_root.to_path_buf(),
            kernel: image.kernel_path,
            system_disk,
            active: Arc::clone(&active),
            pending: None,
            pending_restore: None,
        };
        let machine = FirecrackerDriver::new(
            config.machine_id.clone(),
            crate::service::native_guest_architecture(),
            FirecrackerQualification {
                lifecycle: None,
                full_state: None,
            },
            factory,
        );
        Ok(Self {
            machine_root: machine_root.to_path_buf(),
            config,
            machine,
            guest_binding: active,
            network,
            network_usage,
            exposures,
            installed_runtime: None,
            restore_lineage: None,
            suspend_capture_operation: None,
        })
    }

    fn install_runtime_configuration(
        &mut self,
        configuration: &RuntimeConfiguration,
    ) -> RuntimeInstallation {
        let Some(active) = self.management_binding() else {
            return RuntimeInstallation::Unknown;
        };
        if let Some(installed) = self.installed_runtime.as_ref()
            && installed.generation == active.generation
            && installed.configuration == *configuration
        {
            return RuntimeInstallation::Applied(installed.evidence.clone());
        }
        self.installed_runtime = None;
        let rules = match network_rules(&configuration.network) {
            Ok(value) => value,
            Err(_) => {
                return RuntimeInstallation::NotApplied(bytes_digest(
                    b"network-policy-normalization-failed",
                ));
            }
        };
        let Ok(mut network) = self.network.lock() else {
            return RuntimeInstallation::Unknown;
        };
        if let Some(old) = network.take() {
            let report = old.stop();
            accumulate_network_usage(&self.network_usage, &report);
            if !report.cleanup_failures.is_empty() {
                return RuntimeInstallation::Unknown;
            }
        }
        let bridge = match VmNetworkBridge::start_partitioned(
            &active.socket,
            active.network_capability,
            rules,
        ) {
            Ok(value) => value,
            Err(_) => return RuntimeInstallation::Unknown,
        };
        *network = Some(bridge);
        drop(network);

        let Ok(mut exposures) = self.exposures.lock() else {
            return RuntimeInstallation::Unknown;
        };
        if let Some(old) = exposures.take()
            && old.stop().is_err()
        {
            return RuntimeInstallation::Unknown;
        }
        let gateway = match VmPortGateway::start(
            &active.socket,
            active.network_capability,
            &configuration.exposures,
        ) {
            Ok(value) => value,
            Err(_) => {
                drop(exposures);
                self.stop_runtime_data_planes();
                return RuntimeInstallation::Unknown;
            }
        };
        *exposures = Some(gateway);
        drop(exposures);

        let resource_evidence = digest(
            Domain::Operation,
            &("native-machine-geometry-v1", &configuration.resources),
        )
        .unwrap_or_else(|_| bytes_digest(b"native-geometry-unavailable"));
        match digest(
            Domain::Authority,
            &(
                "sandsurf-linux-runtime-configuration-v2",
                resource_evidence,
                configuration,
            ),
        ) {
            Ok(evidence) => {
                self.installed_runtime = Some(InstalledRuntime {
                    generation: active.generation,
                    configuration: configuration.clone(),
                    evidence: evidence.clone(),
                });
                RuntimeInstallation::Applied(evidence)
            }
            Err(_) => RuntimeInstallation::Unknown,
        }
    }

    fn stop_runtime_data_planes(&mut self) {
        self.installed_runtime = None;
        if let Ok(mut network) = self.network.lock()
            && let Some(bridge) = network.take()
        {
            let report = bridge.stop();
            accumulate_network_usage(&self.network_usage, &report);
        }
        if let Ok(mut exposures) = self.exposures.lock()
            && let Some(gateway) = exposures.take()
        {
            let _ = gateway.stop();
        }
    }

    fn contain_unpublished_machine(&mut self) {
        self.machine.contain_unobserved();
        if let Ok(mut active) = self.guest_binding.lock() {
            *active = None;
        }
        self.stop_runtime_data_planes();
    }
}

enum RuntimeInstallation {
    Applied(Digest),
    NotApplied(Digest),
    Unknown,
}

impl GuardianEffect for LinuxGuardianEffect {
    fn capture_owner(&self) -> ControlResult<Option<sandsurf_protocol::OperationId>> {
        Ok(crate::capture::CaptureBoundary::read(&self.machine_root)?
            .map(|capture| capture.operation_id))
    }
    fn guest_driver(&mut self) -> Box<dyn GuestDriver> {
        Box::new(LinuxGuest {
            active: Arc::clone(&self.guest_binding),
            remote: Arc::new(Mutex::new(None)),
        })
    }

    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        let cold_boot = command.desired == sandsurf_protocol::DesiredState::Running
            && current.is_none_or(|value| {
                matches!(value.state, MachineState::Stopped | MachineState::Failed)
            });
        let mut outcome = apply_lifecycle(&mut self.machine, command, current);
        let running = matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Running)
        );
        if running {
            if cold_boot {
                self.config.resources = command.configuration.resources.clone();
            }
            let runtime_evidence = match self.install_runtime_configuration(&command.configuration)
            {
                RuntimeInstallation::Applied(evidence) => evidence,
                RuntimeInstallation::NotApplied(evidence) => {
                    self.contain_unpublished_machine();
                    return MachineOutcome::NotApplied(evidence);
                }
                RuntimeInstallation::Unknown => {
                    self.contain_unpublished_machine();
                    return MachineOutcome::Unknown;
                }
            };
            if let MachineOutcome::Observed(values) = &mut outcome
                && let Some(last) = values.last_mut()
            {
                last.evidence_digest = match digest(
                    Domain::Authority,
                    &(
                        "sandsurf-running-with-host-configuration-v1",
                        &last.evidence_digest,
                        runtime_evidence,
                        command.revision,
                    ),
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        self.contain_unpublished_machine();
                        return MachineOutcome::Unknown;
                    }
                };
            }
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| matches!(value.state, MachineState::Stopped | MachineState::Suspended | MachineState::Destroyed))
        ) {
            if let Ok(mut active) = self.guest_binding.lock() {
                *active = None;
            }
            self.stop_runtime_data_planes();
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Suspended)
        ) && let Some(operation_id) = self.suspend_capture_operation.take()
            && let Err(error) = remove_full_capture(&self.machine_root, &operation_id)
        {
            // The durable snapshot is already committed. Retaining this
            // private duplicate is safe and lets later recovery retry cleanup.
            eprintln!("sandsurf retained suspend staging after cleanup failure: {error}");
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| matches!(value.state, MachineState::Suspended | MachineState::Stopped | MachineState::Destroyed))
        ) && let Err(error) = crate::capture::CaptureBoundary::clear(&self.machine_root)
        {
            eprintln!("sandsurf capture cleanup deferred: {error}");
        }
        outcome
    }

    fn validate_resources(
        &self,
        resources: &Resources,
        current: &MachineObservation,
    ) -> ControlResult<()> {
        resources
            .validate()
            .map_err(|_| ControlError::Protocol("invalid native resource envelope"))?;
        if resources.disk_bytes != self.config.resources.disk_bytes {
            return Err(ControlError::Unsupported(
                "disk capacity changes require the storage replacement capability",
            ));
        }
        if (resources.vcpus != self.config.resources.vcpus
            || resources.memory_mib != self.config.resources.memory_mib)
            && current.state != MachineState::Stopped
        {
            return Err(ControlError::Unsupported(
                "RAM and vCPU changes require a powered-off computer",
            ));
        }
        Ok(())
    }

    fn configure(
        &mut self,
        command: &sandsurf_protocol::ConfigurationCommand,
        current: &MachineObservation,
    ) -> EffectOutcome {
        if self
            .validate_resources(&command.configuration.resources, current)
            .is_err()
        {
            return EffectOutcome::NotApplied(bytes_digest(b"native-resource-change-unsupported"));
        }
        if current.state == MachineState::Stopped {
            return match self.machine.configure(command, current) {
                sandsurf_machine::ConfigurationOutcome::Applied(evidence) => {
                    EffectOutcome::Applied(evidence)
                }
                sandsurf_machine::ConfigurationOutcome::NotApplied(evidence) => {
                    EffectOutcome::NotApplied(evidence)
                }
                sandsurf_machine::ConfigurationOutcome::Unknown => EffectOutcome::Unknown,
            };
        }
        match self.machine.configure(command, current) {
            sandsurf_machine::ConfigurationOutcome::Applied(machine_evidence) => {
                match self.install_runtime_configuration(&command.configuration) {
                    RuntimeInstallation::Applied(runtime_evidence) => match digest(
                        Domain::Authority,
                        &(
                            "sandsurf-linux-runtime-configuration-v2",
                            machine_evidence,
                            runtime_evidence,
                            &command.configuration,
                        ),
                    ) {
                        Ok(evidence) => EffectOutcome::Applied(evidence),
                        Err(_) => EffectOutcome::Unknown,
                    },
                    RuntimeInstallation::NotApplied(evidence) => {
                        EffectOutcome::NotApplied(evidence)
                    }
                    RuntimeInstallation::Unknown => EffectOutcome::Unknown,
                }
            }
            sandsurf_machine::ConfigurationOutcome::NotApplied(evidence) => {
                EffectOutcome::NotApplied(evidence)
            }
            sandsurf_machine::ConfigurationOutcome::Unknown => EffectOutcome::Unknown,
        }
    }

    fn resource_usage(&mut self) -> ControlResult<sandsurf_protocol::ResourceUsage> {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ControlError::Protocol("host clock unavailable"))?
            .as_millis();
        let observed = Counter::try_from(
            u64::try_from(millis).map_err(|_| ControlError::Protocol("host time overflow"))?,
        )
        .map_err(|_| ControlError::Protocol("host time overflow"))?;
        let mut usage =
            sandsurf_protocol::ResourceUsage::host_observation("host-native-linux", observed);
        let accumulated = self
            .network_usage
            .lock()
            .map_err(|_| crate::guardian::Error::Protocol("network usage lock poisoned"))?;
        let current = self
            .network
            .lock()
            .map_err(|_| crate::guardian::Error::Protocol("network bridge lock poisoned"))?
            .as_ref()
            .map_or_else(Default::default, VmNetworkBridge::snapshot);
        usage.network_rx_bytes = Counter::try_from(
            accumulated.rx_bytes.saturating_add(current.rx_bytes),
        )
        .map_err(|_| crate::guardian::Error::Protocol("network receive accounting overflow"))?;
        usage.network_tx_bytes = Counter::try_from(
            accumulated.tx_bytes.saturating_add(current.tx_bytes),
        )
        .map_err(|_| crate::guardian::Error::Protocol("network transmit accounting overflow"))?;
        usage.network_connections =
            Counter::try_from(accumulated.connections.saturating_add(current.connections))
                .map_err(|_| {
                    crate::guardian::Error::Protocol("network connection accounting overflow")
                })?;
        Ok(usage)
    }

    fn native_snapshot(
        &mut self,
        request: NativeSnapshotRequest,
        journal: &mut RuntimeJournal,
    ) -> ControlResult<NativeSnapshotResponse> {
        match request {
            NativeSnapshotRequest::PrepareDisk { operation_id } => {
                self.prepare_capture_boundary(operation_id, journal)?;
                Ok(NativeSnapshotResponse::Complete {
                    evidence: bytes_digest(b"native-computer-paused-for-disk-capture-v1"),
                })
            }
            NativeSnapshotRequest::FinishDisk { operation_id } => {
                crate::capture::CaptureBoundary::require(&self.machine_root, &operation_id)?;
                self.finish_native_capture()?;
                Ok(NativeSnapshotResponse::Complete {
                    evidence: bytes_digest(b"native-disk-capture-released-v1"),
                })
            }
            NativeSnapshotRequest::PrepareFull {
                snapshot_id,
                operation_id,
            } => self.prepare_full_capture(snapshot_id, operation_id, journal),
            NativeSnapshotRequest::FinishFull { operation_id } => {
                crate::capture::CaptureBoundary::require(&self.machine_root, &operation_id)?;
                self.finish_native_capture().map_err(|_| {
                    ControlError::Unsupported("native VM could not resume after full capture")
                })?;
                remove_full_capture(&self.machine_root, &operation_id)?;
                Ok(NativeSnapshotResponse::Complete {
                    evidence: bytes_digest(b"firecracker-full-capture-finished-v1"),
                })
            }
            NativeSnapshotRequest::CommitSuspend {
                operation_id,
                manifest_digest,
            } => {
                self.machine
                    .commit_suspend(&operation_id, manifest_digest.clone())
                    .map_err(|_| {
                        ControlError::Unsupported(
                            "native suspend capture does not match the paused VM",
                        )
                    })?;
                self.suspend_capture_operation = Some(operation_id.clone());
                Ok(NativeSnapshotResponse::Complete {
                    evidence: digest(
                        Domain::Snapshot,
                        &(
                            "sandsurf-firecracker-suspend-commit-v1",
                            operation_id,
                            manifest_digest,
                        ),
                    )
                    .map_err(|_| ControlError::Protocol("suspend evidence digest failed"))?,
                })
            }
            NativeSnapshotRequest::StageRestore {
                snapshot_id,
                manifest_digest,
                system_disk,
                expected,
            } => self.stage_full_restore(snapshot_id, manifest_digest, system_disk, *expected),
        }
    }

    fn rebind_restored_runtime(
        &mut self,
        journal: &mut RuntimeJournal,
        generation: Counter,
    ) -> sandsurf_state::Result<()> {
        let lineage = self
            .restore_lineage
            .take()
            .ok_or(sandsurf_state::Error::Conflict(
                "restored native VM has no staged process lineage",
            ))?;
        journal.rebind_processes(
            &lineage.snapshot_id,
            &lineage.source_machine_id,
            lineage.source_generation,
            generation,
        )
    }

    fn observe_power(&mut self) -> ControlResult<Option<sandsurf_machine::NativePowerObservation>> {
        self.machine
            .observe_power()
            .map_err(|_| ControlError::Protocol("native power observation unavailable"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReconnectState {
    format_version: u16,
    snapshot_id: sandsurf_protocol::SnapshotId,
    capture_operation_id: sandsurf_protocol::OperationId,
    machine_id: MachineId,
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

impl LinuxGuardianEffect {
    fn stage_full_restore(
        &mut self,
        snapshot_id: sandsurf_protocol::SnapshotId,
        manifest_digest: Digest,
        system_disk: SnapshotArtifact,
        expected: sandsurf_protocol::FullSnapshotMetadata,
    ) -> ControlResult<NativeSnapshotResponse> {
        let architecture = match crate::service::native_guest_architecture() {
            sandsurf_machine::GuestArchitecture::Amd64 => "amd64",
            sandsurf_machine::GuestArchitecture::Arm64 => "arm64",
        };
        let configuration_digest = firecracker_configuration_digest(&self.config)
            .map_err(|_| ControlError::Protocol("restore configuration digest failed"))?;
        if expected.engine != VmEngine::Firecracker
            || expected.engine_version != "1.17.0"
            || expected.architecture != architecture
            || expected.configuration_digest != configuration_digest
        {
            return Err(ControlError::Unsupported(
                "full snapshot is incompatible with this Firecracker configuration",
            ));
        }
        let memory = expected.memory.as_ref().ok_or(ControlError::Unsupported(
            "Firecracker full snapshots require a separate memory artifact",
        ))?;
        let host_root = self
            .machine_root
            .parent()
            .and_then(Path::parent)
            .ok_or(ControlError::Protocol("machine root has no host root"))?;
        let directory = host_root.join("snapshots").join(snapshot_id.as_str());
        let artifacts = [
            ("system.ext4", &system_disk),
            ("snapshot.vmstate", &expected.snapshot_state),
            ("memory", memory),
            ("reconnect.json", &expected.reconnect_state),
        ];
        for (name, artifact) in artifacts {
            let actual = crate::snapshots::file_digest(&directory.join(name), artifact.bytes.get())
                .map_err(|_| ControlError::Protocol("full snapshot artifact is corrupt"))?;
            if actual != artifact.digest {
                return Err(ControlError::Protocol(
                    "full snapshot artifact digest mismatch",
                ));
            }
        }
        for (path, artifact) in [(self.machine_root.join("disks/system.ext4"), &system_disk)] {
            if crate::snapshots::file_digest(&path, artifact.bytes.get())
                .map_err(|_| ControlError::Protocol("restore disk is unavailable"))?
                != artifact.digest
            {
                return Err(ControlError::Unsupported(
                    "mutable disks no longer match the suspended full snapshot",
                ));
            }
        }
        let reconnect: ReconnectState =
            read_json(&directory.join("reconnect.json"), 1024 * 1024)
                .map_err(|_| ControlError::Protocol("restore reconnect state is invalid"))?;
        if reconnect.snapshot_id != snapshot_id {
            return Err(ControlError::Protocol(
                "restore reconnect identity does not match snapshot",
            ));
        }
        let source_machine_id = reconnect.machine_id.clone();
        let source_generation = reconnect.generation;
        self.machine
            .stage_restore(FirecrackerRestoreSource {
                snapshot_id: snapshot_id.clone(),
                capture_operation_id: reconnect.capture_operation_id,
                source_machine_id: reconnect.machine_id,
                source_generation: reconnect.generation,
                manifest_digest: manifest_digest.clone(),
                snapshot_state: directory.join("snapshot.vmstate"),
                snapshot_memory: directory.join("memory"),
                reconnect_state: directory.join("reconnect.json"),
            })
            .map_err(|_| ControlError::Unsupported("native restore stage conflicts"))?;
        self.restore_lineage = Some(RestoreLineage {
            snapshot_id: snapshot_id.clone(),
            source_machine_id,
            source_generation,
        });
        Ok(NativeSnapshotResponse::Complete {
            evidence: digest(
                Domain::Snapshot,
                &(
                    "sandsurf-firecracker-restore-staged-v1",
                    snapshot_id,
                    manifest_digest,
                    expected.generation,
                ),
            )
            .map_err(|_| ControlError::Protocol("restore stage evidence digest failed"))?,
        })
    }

    fn prepare_capture_boundary(
        &mut self,
        operation_id: sandsurf_protocol::OperationId,
        journal: &RuntimeJournal,
    ) -> ControlResult<()> {
        let observation = journal.last_observation()?.ok_or(ControlError::Protocol(
            "capture has no native machine observation",
        ))?;
        let boundary = crate::capture::CaptureBoundary::begin(
            &self.machine_root,
            operation_id,
            observation.value().generation,
            observation.value().state,
        )?;
        let result = if boundary.preserve_pause {
            self.machine.adopt_pause_for_capture()
        } else {
            self.machine.pause_for_capture()
        };
        result.map_err(|_| ControlError::Unsupported("native capture pause failed"))
    }

    fn finish_native_capture(&mut self) -> ControlResult<()> {
        let Some(boundary) = crate::capture::CaptureBoundary::read(&self.machine_root)? else {
            return Ok(());
        };
        // Re-adopt the held native pause after an interrupted request before
        // releasing it; a missing management connection is irrelevant.
        self.machine
            .adopt_pause_for_capture()
            .map_err(|_| ControlError::Unsupported("native capture owner unavailable"))?;
        let result = if boundary.preserve_pause {
            self.machine.finish_capture_preserving_pause()
        } else {
            self.machine.resume_after_capture()
        };
        result.map_err(|_| ControlError::Unsupported("native capture completion failed"))?;
        crate::capture::CaptureBoundary::clear(&self.machine_root)
    }

    fn prepare_full_capture(
        &mut self,
        snapshot_id: sandsurf_protocol::SnapshotId,
        operation_id: sandsurf_protocol::OperationId,
        journal: &mut RuntimeJournal,
    ) -> ControlResult<NativeSnapshotResponse> {
        self.prepare_capture_boundary(operation_id.clone(), journal)?;
        let directory = full_capture_directory(&self.machine_root, &operation_id);
        if directory.join("capture.json").exists() {
            let capture: NativeFullCapture =
                read_json(&directory.join("capture.json"), 1024 * 1024)
                    .map_err(|_| ControlError::Protocol("retained full capture is invalid"))?;
            return Ok(NativeSnapshotResponse::Prepared {
                capture,
                processes: process_watermarks(journal)?,
            });
        }
        let snapshot = match self.machine.create_full_snapshot(&operation_id) {
            Ok(value) => value,
            Err(_) => {
                let _ = self.finish_native_capture();
                return Err(ControlError::Unsupported(
                    "Firecracker could not create a full snapshot",
                ));
            }
        };
        let result = (|| -> Result<NativeFullCapture, LinuxError> {
            crate::snapshots::private_directory(
                directory
                    .parent()
                    .ok_or_else(|| LinuxError::Invalid("capture root has no parent".into()))?,
            )
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            crate::snapshots::private_directory(&directory)
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let snapshot_state = directory.join("snapshot.vmstate");
            let memory = directory.join("memory");
            let state_digest = crate::snapshots::copy_and_verify(
                &snapshot.snapshot_state,
                &snapshot_state,
                snapshot.state_bytes,
                None,
            )
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let memory_digest = crate::snapshots::copy_and_verify(
                &snapshot.snapshot_memory,
                &memory,
                snapshot.memory_bytes,
                None,
            )
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let active = self.management_binding().ok_or_else(|| {
                LinuxError::Invalid("guest reconnect state is unavailable".into())
            })?;
            let reconnect = ReconnectState {
                format_version: 1,
                snapshot_id: snapshot_id.clone(),
                capture_operation_id: operation_id.clone(),
                machine_id: active.machine_id,
                generation: active.generation,
                boot_identity: active.boot_identity,
                capability: active.capability,
                network_capability: active.network_capability,
            };
            let reconnect_path = directory.join("reconnect.json");
            write_private_json(&reconnect_path, &reconnect)?;
            let reconnect_bytes = reconnect_path.metadata()?.len();
            let reconnect_digest = crate::snapshots::file_digest(&reconnect_path, reconnect_bytes)
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let configuration_digest = firecracker_configuration_digest(&self.config)
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let generation = digest(
                Domain::Snapshot,
                &(
                    "sandsurf-full-capture-generation-v1",
                    snapshot_id,
                    &operation_id,
                    &state_digest,
                    &memory_digest,
                    &reconnect_digest,
                ),
            )
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let capture = NativeFullCapture {
                engine: VmEngine::Firecracker,
                engine_version: "1.17.0".into(),
                architecture: match crate::service::native_guest_architecture() {
                    sandsurf_machine::GuestArchitecture::Amd64 => "amd64",
                    sandsurf_machine::GuestArchitecture::Arm64 => "arm64",
                }
                .into(),
                configuration_digest,
                snapshot_state: SnapshotArtifact {
                    digest: state_digest,
                    bytes: Counter::try_from(snapshot.state_bytes)
                        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                },
                memory: Some(SnapshotArtifact {
                    digest: memory_digest,
                    bytes: Counter::try_from(snapshot.memory_bytes)
                        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                }),
                reconnect_state: SnapshotArtifact {
                    digest: reconnect_digest,
                    bytes: Counter::try_from(reconnect_bytes)
                        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                },
                generation,
            };
            write_private_json(&directory.join("capture.json"), &capture)?;
            crate::snapshots::sync_directory(&directory)
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            Ok(capture)
        })();
        match result {
            Ok(capture) => Ok(NativeSnapshotResponse::Prepared {
                capture,
                processes: process_watermarks(journal)?,
            }),
            Err(error) => {
                let _ = self.finish_native_capture();
                Err(ControlError::Rejected {
                    category: "snapshot".into(),
                    message: error.to_string(),
                })
            }
        }
    }
}

fn firecracker_configuration_digest(
    config: &LinuxGuardianConfig,
) -> Result<Digest, sandsurf_protocol::Invalid> {
    digest(
        Domain::Snapshot,
        &(
            "sandsurf-firecracker-configuration-v1",
            &config.image_digest,
            &config.firecracker_sha256,
            &config.resources,
            config.guest_cid,
            sandsurf_protocol::GUEST_PROTOCOL_MAJOR,
            sandsurf_protocol::GUEST_PROTOCOL_MINOR,
        ),
    )
}

fn process_watermarks(journal: &RuntimeJournal) -> ControlResult<Vec<SnapshotProcessWatermark>> {
    journal
        .process_snapshots()
        .map_err(ControlError::State)?
        .into_iter()
        .map(|snapshot| {
            let output = journal
                .process_boundary(&snapshot.request.execution_id)
                .map_err(ControlError::State)?;
            Ok(SnapshotProcessWatermark { snapshot, output })
        })
        .collect()
}

fn full_capture_directory(
    machine_root: &Path,
    operation_id: &sandsurf_protocol::OperationId,
) -> PathBuf {
    machine_root
        .join("guardian/full-captures")
        .join(operation_id.as_str())
}

fn remove_full_capture(
    machine_root: &Path,
    operation_id: &sandsurf_protocol::OperationId,
) -> ControlResult<()> {
    let directory = full_capture_directory(machine_root, operation_id);
    for name in [
        "capture.json",
        "reconnect.json",
        "snapshot.vmstate",
        "memory",
    ] {
        match fs::remove_file(directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(ControlError::Io(error)),
        }
    }
    match fs::remove_dir(&directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ControlError::Io(error)),
    }
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), LinuxError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn network_rules(policy: &NetworkPolicy) -> Result<sandsurf_network::BrokerPolicy, LinuxError> {
    policy
        .validate()
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let mut rules = sandsurf_network::BrokerPolicy::default();
    for rule in &policy.rules {
        let destination = match &rule.destination {
            NetworkDestination::Dns {
                name,
                include_subdomains,
                allow_private_addresses,
            } => sandsurf_network::policy::ManagedNetworkDestination::Dns {
                name: sandsurf_network::policy::normalize_dns_name(name)
                    .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                include_subdomains: *include_subdomains,
                allow_private_addresses: *allow_private_addresses,
            },
            NetworkDestination::Ip { cidr } => {
                sandsurf_network::policy::ManagedNetworkDestination::Ip { cidr: cidr.clone() }
            }
        };
        let ports = rule
            .ports
            .iter()
            .map(|range| {
                if range.from == range.to {
                    sandsurf_network::policy::ManagedNetworkPort::Single(range.from)
                } else {
                    sandsurf_network::policy::ManagedNetworkPort::Range {
                        from: range.from,
                        to: range.to,
                    }
                }
            })
            .collect();
        let managed = sandsurf_network::policy::ManagedNetworkRule {
            transport: "tcp".into(),
            destination,
            ports,
        };
        match rule.plane {
            sandsurf_protocol::NetworkPlane::NamedProxy => rules.named_proxy.push(managed),
            sandsurf_protocol::NetworkPlane::DirectTcp => rules.direct_tcp.push(managed),
            sandsurf_protocol::NetworkPlane::Dns => rules.dns.push(managed),
        }
    }
    Ok(rules)
}

#[derive(Clone, PartialEq, Eq)]
struct ActiveGuest {
    rebind: Option<ManagementRebind>,
    socket: PathBuf,
    machine_id: MachineId,
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

struct PendingGuest {
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

struct PendingRestore {
    source: ReconnectState,
    next: PendingGuest,
    snapshot_id: sandsurf_protocol::SnapshotId,
    generation_seed: [u8; 32],
}

struct LinuxGenerationFactory {
    config: LinuxGuardianConfig,
    machine_root: PathBuf,
    kernel: PathBuf,
    system_disk: PathBuf,
    active: Arc<Mutex<Option<ActiveGuest>>>,
    pending: Option<PendingGuest>,
    pending_restore: Option<PendingRestore>,
}

impl FirecrackerGenerationFactory for LinuxGenerationFactory {
    fn configuration(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        resources: &Resources,
    ) -> Result<FirecrackerConfig, Digest> {
        if *machine_id != self.config.machine_id
            || self.pending.is_some()
            || self.pending_restore.is_some()
        {
            return Err(bytes_digest(b"linux-generation-factory-identity-conflict"));
        }
        self.config.resources = resources.clone();
        ensure_mutable_disk(
            &self.config.system_seed,
            &self.system_disk,
            resources.disk_bytes.get(),
        )
        .map_err(|error| {
            eprintln!("sandsurf disk preparation failed: {error}");
            bytes_digest(b"linux-system-disk-preparation-failed")
        })?;
        let capability = random_bytes().map_err(|_| bytes_digest(b"linux-boot-entropy"))?;
        let network_capability =
            random_bytes().map_err(|_| bytes_digest(b"linux-network-entropy"))?;
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-linux-boot-v1",
                &self.config.image_digest,
                &self.config.firecracker_sha256,
                sandsurf_protocol::GUEST_PROTOCOL_MAJOR,
                sandsurf_protocol::GUEST_PROTOCOL_MINOR,
            ),
        )
        .map_err(|_| bytes_digest(b"linux-boot-identity"))?;
        let nonce = hex(&random_bytes().map_err(|_| bytes_digest(b"linux-boot-entropy"))?);
        let guardian = self.machine_root.join("guardian");
        let authentication_image = guardian.join(format!("auth-{}-{nonce}.img", generation.get()));
        write_authentication(
            &authentication_image,
            machine_id,
            generation,
            &boot_identity,
            &capability,
            &network_capability,
        )
        .map_err(|_| bytes_digest(b"linux-authentication-disk"))?;
        let state_directory = guardian.join(format!("vm-{}-{nonce}", generation.get()));
        let owner_token = hex(&random_bytes().map_err(|_| bytes_digest(b"linux-owner-entropy"))?);
        self.pending = Some(PendingGuest {
            generation,
            boot_identity,
            capability,
            network_capability,
        });
        Ok(FirecrackerConfig {
            launcher_executable: self.config.launcher.clone(),
            firecracker_executable: self.config.firecracker.clone(),
            firecracker_sha256: self.config.firecracker_sha256.clone(),
            state_directory,
            kernel_image: self.kernel.clone(),
            system_disk: self.system_disk.clone(),
            authentication_image,
            owner_token,
            guest_cid: self.config.guest_cid,
            guest_port: GUEST_CONTROL_PORT,
            vcpu_count: u8::try_from(resources.vcpus.get())
                .map_err(|_| bytes_digest(b"linux-vcpu-overflow"))?,
            memory_mib: u32::try_from(resources.memory_mib.get())
                .map_err(|_| bytes_digest(b"linux-memory-overflow"))?,
        })
    }

    fn bind_management(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"linux-boot-capability-missing"))?;
        if pending.generation != generation || *machine_id != self.config.machine_id {
            return Err(bytes_digest(b"linux-boot-capability-mismatch"));
        }
        let active = ActiveGuest {
            socket: process.vsock_path.clone(),
            machine_id: machine_id.clone(),
            generation,
            boot_identity: pending.boot_identity,
            capability: pending.capability,
            network_capability: pending.network_capability,
            rebind: None,
        };
        let evidence = digest(
            Domain::Operation,
            &("host-management-channel-bound-v1", machine_id, generation),
        )
        .map_err(|_| bytes_digest(b"management-binding-evidence"))?;
        *self
            .active
            .lock()
            .map_err(|_| bytes_digest(b"guest-endpoint-lock"))? = Some(active);
        Ok(evidence)
    }

    fn restore_configuration(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        source: &FirecrackerRestoreSource,
    ) -> Result<(FirecrackerConfig, FirecrackerRestore), Digest> {
        if self.pending_restore.is_some() {
            return Err(bytes_digest(b"linux-restore-already-pending"));
        }
        let reconnect: ReconnectState = read_json(&source.reconnect_state, 1024 * 1024)
            .map_err(|_| bytes_digest(b"linux-restore-reconnect-state-invalid"))?;
        if reconnect.format_version != 1
            || reconnect.snapshot_id != source.snapshot_id
            || reconnect.capture_operation_id != source.capture_operation_id
            || reconnect.machine_id != source.source_machine_id
            || reconnect.generation != source.source_generation
        {
            return Err(bytes_digest(b"linux-restore-reconnect-identity-mismatch"));
        }
        let resources = self.config.resources.clone();
        let configuration = self.configuration(machine_id, generation, &resources)?;
        let next = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"linux-restore-next-capability-missing"))?;
        let generation_seed = random_bytes().map_err(|_| bytes_digest(b"linux-restore-entropy"))?;
        self.pending_restore = Some(PendingRestore {
            source: reconnect,
            next,
            snapshot_id: source.snapshot_id.clone(),
            generation_seed,
        });
        Ok((
            configuration,
            FirecrackerRestore {
                snapshot_state: source.snapshot_state.clone(),
                snapshot_memory: source.snapshot_memory.clone(),
            },
        ))
    }

    fn bind_restored_management(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest> {
        let pending = self
            .pending_restore
            .take()
            .ok_or_else(|| bytes_digest(b"linux-restore-capability-missing"))?;
        if pending.next.generation != generation || *machine_id != self.config.machine_id {
            return Err(bytes_digest(b"linux-restore-target-identity-mismatch"));
        }
        let rebind = ManagementRebind {
            machine_id: pending.source.machine_id.clone(),
            generation: pending.source.generation,
            boot_identity: pending.source.boot_identity.clone(),
            capability: pending.source.capability,
            request: GuestServiceRequest::RebindGeneration {
                snapshot_id: pending.snapshot_id.clone(),
                capture_operation_id: pending.source.capture_operation_id.clone(),
                machine_id: machine_id.clone(),
                previous_generation: pending.source.generation,
                generation,
                boot_identity: pending.next.boot_identity.clone(),
                capability: pending.next.capability,
                network_capability: pending.next.network_capability,
                generation_seed: pending.generation_seed,
            },
        };
        let active = ActiveGuest {
            socket: process.vsock_path.clone(),
            machine_id: machine_id.clone(),
            generation,
            boot_identity: pending.next.boot_identity,
            capability: pending.next.capability,
            network_capability: pending.next.network_capability,
            rebind: Some(rebind),
        };
        *self
            .active
            .lock()
            .map_err(|_| bytes_digest(b"guest-endpoint-lock"))? = Some(active);
        digest(
            Domain::Operation,
            &(
                "native-restored-management-binding-v1",
                machine_id,
                generation,
            ),
        )
        .map_err(|_| bytes_digest(b"management-binding-evidence"))
    }
}

struct LinuxGuest {
    active: Arc<Mutex<Option<ActiveGuest>>>,
    remote: LinuxRemoteCache,
}

type LinuxRemoteCache = Arc<Mutex<Option<(ActiveGuest, ManagedGuestClient<UnixVsockChannel>)>>>;

fn with_cached_guest<T>(
    active: &ActiveGuest,
    cache: &LinuxRemoteCache,
    operation: impl FnOnce(&mut ManagedGuestClient<UnixVsockChannel>) -> T,
) -> Option<T> {
    let mut cache = cache.lock().ok()?;
    if cache.as_ref().is_none_or(|(cached, _)| cached != active) {
        *cache = Some((active.clone(), managed_guest(active)));
    }
    Some(operation(&mut cache.as_mut()?.1))
}

impl LinuxGuest {
    fn endpoint(&self) -> Option<ActiveGuest> {
        self.active.lock().ok()?.clone()
    }

    fn with_driver<T>(
        &self,
        operation: impl FnOnce(&mut ManagedGuestClient<UnixVsockChannel>) -> T,
    ) -> Option<T> {
        let active = self.endpoint();
        let Some(active) = active else {
            if let Ok(mut remote) = self.remote.lock() {
                *remote = None;
            }
            return None;
        };
        with_cached_guest(&active, &self.remote, operation)
    }
}

impl GuestDriver for LinuxGuest {
    fn dispatch(&mut self, command: &GuestCommand) -> EffectOutcome {
        self.with_driver(|driver| driver.dispatch(command))
            .unwrap_or_else(|| {
                EffectOutcome::NotApplied(bytes_digest(b"guest-machine-not-running"))
            })
    }

    fn poll(
        &mut self,
        hints: &crate::guest_worker::ExecutionHints,
    ) -> ControlResult<crate::guest_worker::GuestPoll> {
        self.with_driver(|driver| driver.poll(hints))
            .ok_or(ControlError::Unsupported("guest management unavailable"))?
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        self.with_driver(|driver| driver.query(request))
            .ok_or(ControlError::Unsupported(
                "guest is unavailable because the machine has no live owner",
            ))?
    }
}

fn managed_guest(active: &ActiveGuest) -> ManagedGuestClient<UnixVsockChannel> {
    let pending = active.rebind.as_ref().map(|binding| {
        let source = ActiveGuest {
            machine_id: binding.machine_id.clone(),
            generation: binding.generation,
            boot_identity: binding.boot_identity.clone(),
            capability: binding.capability,
            rebind: None,
            ..active.clone()
        };
        PendingRebind::new(guest_client(&source), binding.request.clone())
    });
    ManagedGuestClient::new(guest_client(active), pending)
}

fn guest_client(active: &ActiveGuest) -> GuestClient<UnixVsockChannel> {
    GuestClient::new(
        UnixVsockChannel {
            socket_path: active.socket.clone(),
            guest_port: GUEST_CONTROL_PORT,
            timeout: Duration::from_secs(10),
        },
        active.machine_id.clone(),
        active.generation,
        active.boot_identity.clone(),
        active.capability,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageIndex {
    #[serde(rename = "formatVersion")]
    _format_version: u16,
    #[serde(rename = "buildId")]
    _build_id: String,
    files: std::collections::BTreeMap<String, String>,
}

fn ensure_mutable_disk(
    source: &Path,
    destination: &Path,
    requested_bytes: u64,
) -> Result<(), LinuxError> {
    crate::storage::materialize(
        source,
        destination,
        requested_bytes,
        crate::storage::DiskFormat::Raw,
        |staged| reserve_disk_capacity(staged, requested_bytes).map_err(io::Error::other),
    )?;
    reserve_disk_capacity(destination, requested_bytes)
}

fn reserve_disk_capacity(destination: &Path, requested_bytes: u64) -> Result<(), LinuxError> {
    let fallocate =
        sandsurf_native::filesystem::protected_tool(&["/usr/bin/fallocate", "/bin/fallocate"])?;
    let status = std::process::Command::new(fallocate)
        .args(["--keep-size", "--length", &requested_bytes.to_string()])
        .arg(destination)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(LinuxError::Invalid(
            "host storage cannot reserve the persistent disk capacity".into(),
        ));
    }
    File::open(destination)?.sync_all()?;
    require_allocated(destination, requested_bytes)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn require_allocated(path: &Path, requested_bytes: u64) -> Result<(), LinuxError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path)?;
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| LinuxError::Invalid("allocated disk size overflow".into()))?;
    if allocated < requested_bytes {
        return Err(LinuxError::Invalid(
            "persistent disk capacity is not physically reserved".into(),
        ));
    }
    Ok(())
}

fn write_authentication(
    path: &Path,
    machine_id: &MachineId,
    generation: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
    network_capability: &[u8; 32],
) -> Result<(), LinuxError> {
    let identity = machine_id.as_str().as_bytes();
    let size = u16::try_from(identity.len())
        .map_err(|_| LinuxError::Invalid("machine identity is too long".into()))?;
    let digest = decode_hex(boot_identity.as_str())?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(AUTHENTICATION_MAGIC);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(identity);
    bytes.extend_from_slice(&generation.get().to_be_bytes());
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(capability);
    bytes.extend_from_slice(network_capability);
    bytes.resize(512, 0);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn decode_hex(value: &str) -> Result<[u8; 32], LinuxError> {
    if value.len() != 64 {
        return Err(LinuxError::Invalid("digest is malformed".into()));
    }
    let mut bytes = [0; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| LinuxError::Invalid("digest is malformed".into()))?;
    }
    Ok(bytes)
}

fn random_bytes() -> Result<[u8; 32], LinuxError> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| LinuxError::Invalid("host entropy unavailable".into()))?;
    Ok(bytes)
}

fn allocate_guest_cid(host_root: &Path) -> Result<u32, LinuxError> {
    let mut used = std::collections::BTreeSet::new();
    let machines = host_root.join("machines");
    if machines.exists() {
        for entry in fs::read_dir(&machines)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path().join("guardian/config.json");
            if path.exists() {
                let value: LinuxGuardianConfig = read_json(&path, 1024 * 1024)?;
                used.insert(value.guest_cid);
            }
        }
    }
    for _ in 0..64 {
        let bytes = random_bytes()?;
        let random = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"));
        let candidate = 3 + random % (u32::MAX - 3);
        if used.insert(candidate) {
            return Ok(candidate);
        }
    }
    Err(LinuxError::Invalid(
        "could not allocate a unique guest CID".into(),
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn require_regular(path: &Path, maximum: u64) -> Result<(), LinuxError> {
    if !path.is_absolute() {
        return Err(LinuxError::Invalid("artifact path must be absolute".into()));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(LinuxError::Invalid(
            "artifact must be a bounded regular file".into(),
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path, maximum: u64) -> Result<String, LinuxError> {
    require_regular(path, maximum)?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = [0; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| LinuxError::Invalid("artifact length overflow".into()))?;
        if total > maximum {
            return Err(LinuxError::Invalid("artifact exceeds bound".into()));
        }
        hasher.update(&bytes[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, LinuxError> {
    require_regular(path, maximum)?;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(LinuxError::Invalid("JSON artifact exceeds bound".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn guest_filesystem_bytes_are_opaque_during_creation_and_reopen() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-opaque-disk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let source = root.join("root-controlled-seed");
        let destination = root.join("system.ext4");
        let contents = b"deliberately invalid filesystem metadata";
        fs::write(&source, contents).unwrap();
        ensure_mutable_disk(&source, &destination, 8192).unwrap();
        assert_eq!(fs::metadata(&destination).unwrap().len(), 8192);
        assert_eq!(&fs::read(&destination).unwrap()[..contents.len()], contents);
        fs::remove_file(source).unwrap();
        ensure_mutable_disk(&root.join("missing-seed"), &destination, 8192).unwrap();
        assert_eq!(&fs::read(&destination).unwrap()[..contents.len()], contents);
        crate::storage::retire(&destination).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
