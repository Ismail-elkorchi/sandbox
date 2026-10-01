//! Linux guardian integration for one retained Firecracker machine.

use crate::capture::{
    full_directory as full_capture_directory, remove_full as remove_full_capture,
};
use crate::guardian::{
    EffectOutcome, Error as ControlError, GuardianEffect, GuestDriver, Result as ControlResult,
};
use crate::guest::{GuestClient, ManagedGuestClient, ManagementRebind, PendingRebind};
use sandsurf_image::{Architecture, ImageTrust, RootfsFormat, verify_image};
use sandsurf_machine::firecracker::{FirecrackerConfig, FirecrackerProcess, FirecrackerRestore};
use sandsurf_machine::linux::{
    FirecrackerDriver, FirecrackerGenerationFactory, FirecrackerQualification,
    FirecrackerRestoreSource,
};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_native::UnixVsockChannel;
use sandsurf_native::storage::object_name;
use sandsurf_network::NativeNetworkGateway;
use sandsurf_protocol::{AUTHENTICATION_MAGIC, GUEST_CONTROL_PORT};
use sandsurf_protocol::{
    Counter, Digest, Domain, ExecutionDefaults, GuestCommand, GuestServiceRequest,
    GuestServiceResponse, LifecycleCommand, MachineId, MachineObservation, MachineState,
    NativeFullCapture, NativeSnapshotRequest, NativeSnapshotResponse, NetworkPolicy, Resources,
    RuntimeConfiguration, SnapshotArtifact, VmEngine, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONFIG_VERSION: u16 = 1;

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

impl LinuxGuardianConfig {
    pub(crate) fn resources(&self) -> &Resources {
        &self.resources
    }
}

/// Exact native mechanism under qualification. Network owners must bind their
/// actual attachment/device configuration here when changing the NIC model.
pub fn qualification_configuration(
    config: &LinuxGuardianConfig,
    machine_root: &Path,
) -> Result<crate::qualification::NativeConfiguration, LinuxError> {
    let observation: NativeBootObservation =
        read_json(&machine_root.join("guardian/current-boot.json"), 8192)?;
    if observation.machine_id != config.machine_id {
        return Err(LinuxError::Invalid(
            "native boot observation belongs to another machine".into(),
        ));
    }
    qualification_for_boot(config, &observation.boot, machine_root)
}

fn qualification_for_boot(
    config: &LinuxGuardianConfig,
    boot: &sandsurf_image::boot::FrozenBoot,
    machine_root: &Path,
) -> Result<crate::qualification::NativeConfiguration, LinuxError> {
    let machine_volume = sandsurf_native::volume::require(
        machine_root,
        config.resources.physical_storage_bytes.get(),
    )?;
    let host_root = machine_root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| LinuxError::Invalid("machine root has no host volume".into()))?;
    let shared_volume = sandsurf_native::volume::inspect(host_root)?;
    Ok(crate::qualification::NativeConfiguration {
        build_digest: crate::qualification::build_digest()?,
        platform: "linux".into(),
        architecture: std::env::consts::ARCH.into(),
        hardware_digest: crate::qualification::hardware_digest()?,
        engine: VmEngine::Firecracker,
        engine_digest: config
            .firecracker_sha256
            .clone()
            .try_into()
            .map_err(|_| LinuxError::Invalid("invalid engine identity".into()))?,
        image_digest: config.image_digest.clone(),
        kernel_digest: boot
            .kernel
            .sha256
            .clone()
            .try_into()
            .map_err(|_| LinuxError::Invalid("invalid verified kernel identity".into()))?,
        initramfs_digest: boot
            .initramfs
            .as_ref()
            .map(|v| v.sha256.clone().try_into())
            .transpose()
            .map_err(|_| LinuxError::Invalid("invalid verified initramfs identity".into()))?,
        nic_configuration_digest: digest(
            Domain::Resource,
            &(
                "firecracker-isolated-tap-af-packet-vnet-hdr-ingress-drop-auxdata-vlan-deny",
                "machine-derived-locally-administered-mac",
                sandsurf_network::MTU,
                sandsurf_network::GUEST_IPV4.to_string(),
                sandsurf_network::GUEST_IPV6.to_string(),
            ),
        )
        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
        storage_configuration_digest: digest(
            Domain::Resource,
            &(
                "raw-ext4-complete-system-disk",
                config.resources.disk_bytes,
                &config.system_seed_sha256,
                "operator-bounded-ext4-volumes",
                (machine_volume.device, machine_volume.bytes),
                (shared_volume.device, shared_volume.bytes),
            ),
        )
        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
        resources: config.resources.clone(),
    })
}

/// Resolve the host-owned image previously admitted through the image catalog.
/// Machine creation never publishes image bytes or bypasses image accounting.
pub fn prepare_config(
    host_root: &Path,
    executable: &Path,
    machine_id: &MachineId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<LinuxGuardianConfig, LinuxError> {
    sandsurf_native::capacity::require_persistent_storage(host_root)?;
    resources
        .validate()
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    crate::resources::require_network_capacity(resources)?;
    crate::resources::require_machine_storage(host_root, machine_id, resources)?;
    let existing_path = host_root
        .join("machines")
        .join(object_name(machine_id.as_str()))
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
    let verified = crate::images::resolve_native_image(host_root, image_digest)
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let source_template = &verified.system_path;
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
    require_regular(source_template, 128 * 1024 * 1024 * 1024)?;
    let installed = host_root.join("images").join(image_digest.as_str());

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
    value
        .resources
        .validate()
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    crate::resources::require_network_capacity(&value.resources)?;
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
    process_envelope: sandsurf_native::resources::ProcessEnvelope,
    machine_root: PathBuf,
    config: LinuxGuardianConfig,
    machine: FirecrackerDriver<LinuxGenerationFactory>,
    guest_binding: Arc<Mutex<Option<ActiveGuest>>>,
    guest_transport: Arc<LinuxGuestTransport>,
    network: Arc<Mutex<Option<Arc<NativeNetworkGateway>>>>,
    network_usage: NetworkUsage,
    installed_runtime: Option<InstalledRuntime>,
    suspend_capture_operation: Option<sandsurf_protocol::OperationId>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreLineage {
    snapshot_id: sandsurf_protocol::SnapshotId,
    source_machine_id: MachineId,
    source_generation: Counter,
    executions: Vec<sandsurf_protocol::CapturedExecution>,
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

fn accumulate_network_usage(usage: &NetworkUsage, report: &sandsurf_network::NetworkReport) {
    if let Ok(mut usage) = usage.lock() {
        usage.rx_bytes = usage.rx_bytes.saturating_add(report.rx_bytes);
        usage.tx_bytes = usage.tx_bytes.saturating_add(report.tx_bytes);
        usage.connections = usage.connections.saturating_add(report.connections);
    }
}

impl LinuxGuardianEffect {
    fn refresh_qualification(&mut self, resources: &Resources) -> Result<(), LinuxError> {
        let mut configuration = self.config.clone();
        configuration.resources = resources.clone();
        let Some(active) = self.management_binding() else {
            self.machine.set_qualification(FirecrackerQualification {
                lifecycle: None,
                full_state: None,
            });
            return Ok(());
        };
        let boot = crate::storage::read_boot(&active.boot_directory)?;
        let exact = qualification_for_boot(&configuration, &boot, &self.machine_root)?;
        let root = self
            .machine_root
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| LinuxError::Invalid("machine root has no host root".into()))?;
        let evidence = |scope| match crate::qualification::lookup(root, &exact, scope) {
            sandsurf_protocol::Qualification::Qualified { evidence } => Some(evidence),
            _ => None,
        };
        self.machine.set_qualification(FirecrackerQualification {
            lifecycle: evidence(crate::qualification::QualificationScope::Lifecycle),
            full_state: evidence(crate::qualification::QualificationScope::FullState),
        });
        Ok(())
    }
    fn management_binding(&self) -> Option<ActiveGuest> {
        self.guest_binding.lock().ok()?.clone()
    }
    pub fn open(machine_root: &Path, config: LinuxGuardianConfig) -> Result<Self, LinuxError> {
        sandsurf_native::volume::require(
            machine_root,
            config.resources.physical_storage_bytes.get(),
        )?;
        let process_envelope =
            sandsurf_native::resources::ProcessEnvelope::current(machine_root, &config.resources)?;
        fs::metadata("/dev/kvm").map_err(|_| LinuxError::Invalid("KVM is unavailable".into()))?;
        verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        let disks = machine_root.join("disks");
        sandsurf_native::local::ensure_private_directory(&disks)?;
        sandsurf_native::storage::sync_directory(machine_root)?;
        let system_disk = disks.join("system.ext4");

        let active = Arc::new(Mutex::new(None));
        let network = Arc::new(Mutex::new(None));
        let network_usage = Arc::new(Mutex::new(NetworkUsageValue::default()));
        let factory = LinuxGenerationFactory {
            network: Arc::clone(&network),
            network_usage: Arc::clone(&network_usage),
            config: config.clone(),
            machine_root: machine_root.to_path_buf(),
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
            process_envelope,
            machine_root: machine_root.to_path_buf(),
            config,
            machine,
            guest_binding: active,
            guest_transport: Arc::new(LinuxGuestTransport::new(
                crate::capture::CaptureBoundary::read(machine_root)
                    .map_err(|error| LinuxError::Invalid(error.to_string()))?
                    .is_some(),
            )),
            network,
            network_usage,
            installed_runtime: None,
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
            && self
                .network
                .lock()
                .is_ok_and(|owner| owner.as_ref().is_some_and(|gateway| gateway.is_alive()))
        {
            return RuntimeInstallation::Applied(installed.evidence.clone());
        }
        self.installed_runtime = None;
        let Ok(network) = self.network.lock() else {
            return RuntimeInstallation::Unknown;
        };
        let Some(gateway) = network.as_ref() else {
            return RuntimeInstallation::Unknown;
        };
        if gateway
            .configure(&configuration.network, &configuration.exposures)
            .is_err()
        {
            return RuntimeInstallation::Unknown;
        }
        drop(network);

        let resource_evidence = digest(
            Domain::Operation,
            &("native-machine-geometry-v1", &configuration.resources),
        )
        .unwrap_or_else(|_| bytes_digest(b"native-geometry-unavailable"));
        match digest(
            Domain::Authority,
            &(
                "sandsurf-linux-runtime-configuration-v1",
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
            let _ = bridge.configure(&NetworkPolicy::default(), &[]);
            let snapshot = bridge.snapshot();
            let report = sandsurf_network::NetworkReport {
                connections: snapshot.connections,
                violations: snapshot.violations,
                rx_bytes: snapshot.rx_bytes,
                tx_bytes: snapshot.tx_bytes,
                cleanup_failures: Vec::new(),
            };
            accumulate_network_usage(&self.network_usage, &report);
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
    Unknown,
}

impl GuardianEffect for LinuxGuardianEffect {
    fn resource_envelope(&self) -> Option<Resources> {
        Some(self.config.resources.clone())
    }
    fn assess_resources(
        &self,
        resources: &Resources,
        current: &MachineObservation,
    ) -> sandsurf_protocol::ResourceChangeAssessment {
        let mut assessment = crate::resources::assess(resources, &self.config.resources, current);
        if let Err(error) = sandsurf_native::volume::require(
            &self.machine_root,
            resources.physical_storage_bytes.get(),
        ) {
            assessment.mode = sandsurf_protocol::ResourceChangeMode::Unsupported;
            assessment.reasons.push(error.to_string());
        }
        assessment
    }
    fn guest_io_admissible(&self) -> bool {
        !self.guest_transport.capture_blocked.load(Ordering::Acquire)
    }
    fn capture_owner(&self) -> ControlResult<Option<sandsurf_protocol::OperationId>> {
        Ok(crate::capture::CaptureBoundary::read(&self.machine_root)?
            .map(|capture| capture.operation_id))
    }
    fn guest_driver(&mut self) -> Box<dyn GuestDriver> {
        Box::new(LinuxGuest {
            active: Arc::clone(&self.guest_binding),
            remote: Arc::clone(&self.guest_transport),
        })
    }

    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        // Current signed authority is installed outside the guest before any
        // start/resume transition can execute guest code.
        if (command.desired == sandsurf_protocol::DesiredState::Running
            && self
                .process_envelope
                .apply(&command.configuration.resources)
                .is_err())
            || (matches!(
                command.desired,
                sandsurf_protocol::DesiredState::Running
                    | sandsurf_protocol::DesiredState::Suspended
            ) && self
                .refresh_qualification(&command.configuration.resources)
                .is_err())
        {
            self.contain_unpublished_machine();
            return MachineOutcome::Unknown;
        }
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
            if self
                .refresh_qualification(&command.configuration.resources)
                .is_err()
            {
                self.contain_unpublished_machine();
                return MachineOutcome::Unknown;
            }
            let runtime_evidence = match self.install_runtime_configuration(&command.configuration)
            {
                RuntimeInstallation::Applied(evidence) => evidence,
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
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| matches!(value.state, MachineState::Running | MachineState::Suspended | MachineState::Stopped | MachineState::Destroyed))
        ) && matches!(
            crate::capture::CaptureBoundary::read(&self.machine_root),
            Ok(None)
        ) {
            let _ = self.guest_transport.release_capture();
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
        if self.assess_resources(resources, current).mode
            == sandsurf_protocol::ResourceChangeMode::Unsupported
        {
            return Err(ControlError::Unsupported(
                "native resource change exceeds supported envelope",
            ));
        }
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
        if self
            .process_envelope
            .apply(&command.configuration.resources)
            .is_err()
            || self
                .refresh_qualification(&command.configuration.resources)
                .is_err()
        {
            self.contain_unpublished_machine();
            return EffectOutcome::Unknown;
        }
        self.config.resources = command.configuration.resources.clone();
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
                            "sandsurf-linux-runtime-configuration-v1",
                            machine_evidence,
                            runtime_evidence,
                            &command.configuration,
                        ),
                    ) {
                        Ok(evidence) => EffectOutcome::Applied(evidence),
                        Err(_) => EffectOutcome::Unknown,
                    },
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
        let native = self.process_envelope.usage()?;
        usage.cpu_micros = Some(native.cpu_micros);
        usage.memory_current = Some(native.memory_current);
        usage.memory_peak = native.memory_peak;
        usage.io_read_bytes = native.io_read_bytes;
        usage.io_write_bytes = native.io_write_bytes;
        usage.provenance.cpu = sandsurf_protocol::MeasurementSource::HostCgroup;
        usage.provenance.memory = sandsurf_protocol::MeasurementSource::HostCgroup;
        usage.provenance.io = if native.io_read_bytes.is_some() {
            sandsurf_protocol::MeasurementSource::HostCgroup
        } else {
            sandsurf_protocol::MeasurementSource::Unavailable
        };
        usage.host_counter_epoch = Some(bytes_digest(
            std::env::var("INVOCATION_ID")
                .map_err(|_| {
                    ControlError::Protocol("host resource unit invocation identity unavailable")
                })?
                .as_bytes(),
        ));
        usage.provenance.network = sandsurf_protocol::MeasurementSource::HostNetwork;
        let accumulated = self
            .network_usage
            .lock()
            .map_err(|_| crate::guardian::Error::Protocol("network usage lock poisoned"))?;
        let current = self
            .network
            .lock()
            .map_err(|_| crate::guardian::Error::Protocol("network bridge lock poisoned"))?
            .as_ref()
            .map_or_else(Default::default, |gateway| gateway.snapshot());
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
    ) -> ControlResult<()> {
        let Some(lineage) = crate::restore::load::<RestoreLineage>(&self.machine_root)? else {
            return Ok(());
        };
        if generation == lineage.source_generation {
            return Ok(()); // Admitted, but native resume has not occurred.
        }
        if generation <= lineage.source_generation {
            return Err(ControlError::Protocol(
                "restore integration generation mismatch",
            ));
        }
        journal.restore_executions(
            &lineage.snapshot_id,
            &lineage.source_machine_id,
            lineage.source_generation,
            generation,
            &lineage.executions,
        )?;
        crate::restore::complete(&self.machine_root)
    }

    fn retire_restore_intent(&mut self) -> ControlResult<()> {
        crate::restore::complete(&self.machine_root)
    }

    fn observe_power(&mut self) -> ControlResult<Option<sandsurf_machine::NativePowerObservation>> {
        self.machine
            .observe_power()
            .map_err(|_| ControlError::Protocol("native power observation unavailable"))
    }
    fn take_console(&mut self) -> Option<sandsurf_machine::NativeConsole> {
        self.machine.take_console()
    }
    fn take_guest_reset(&mut self) -> Option<Digest> {
        self.machine.take_guest_reset()
    }
    fn recover_guest_reset(&mut self, current: &MachineObservation) -> ControlResult<Digest> {
        let configuration = self
            .installed_runtime
            .as_ref()
            .ok_or(ControlError::Protocol(
                "guest reset has no applied native envelope",
            ))?
            .configuration
            .clone();
        self.stop_runtime_data_planes();
        if let Ok(mut active) = self.guest_binding.lock() {
            *active = None;
        }
        let command = LifecycleCommand {
            machine_id: current.machine_id.clone(),
            operation_id: sandsurf_protocol::OperationId::try_from(format!(
                "native-reset-{}",
                current.generation.get()
            ))
            .map_err(|_| ControlError::Protocol("reset identity overflow"))?,
            desired: sandsurf_protocol::DesiredState::Running,
            revision: current.applied_revision,
            request_digest: current.evidence_digest.clone(),
            configuration,
        };
        // Driver start advances from the contained prior generation. The
        // guardian has already committed the target Starting fence.
        let previous = MachineObservation {
            generation: Counter::try_from(current.generation.get() - 1)
                .map_err(|_| ControlError::Protocol("reset generation invalid"))?,
            state: MachineState::Stopped,
            ..current.clone()
        };
        match self.transition(&command, Some(&previous)) {
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| {
                    value.generation == current.generation && value.state == MachineState::Running
                }) =>
            {
                Ok(values.last().unwrap().evidence_digest.clone())
            }
            _ => Err(ControlError::Protocol("native guest reset recovery failed")),
        }
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
    boot: sandsurf_image::boot::FrozenBoot,
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
        let directory = self
            .machine_root
            .join("snapshots")
            .join(object_name(snapshot_id.as_str()));
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
        if crate::snapshots::file_digest(
            &self.machine_root.join("disks/system.ext4"),
            system_disk.bytes.get(),
        )
        .map_err(|_| ControlError::Protocol("restore disk is unavailable"))?
            != system_disk.digest
        {
            return Err(ControlError::Unsupported(
                "mutable disks no longer match the suspended full snapshot",
            ));
        }
        let reconnect: ReconnectState =
            read_json(&directory.join("reconnect.json"), 1024 * 1024)
                .map_err(|_| ControlError::Protocol("restore reconnect state is invalid"))?;
        if reconnect.snapshot_id != snapshot_id {
            return Err(ControlError::Protocol(
                "restore reconnect identity does not match snapshot",
            ));
        }
        if reconnect.machine_id != self.config.machine_id {
            return Err(ControlError::Unsupported(
                "full memory forks are unsupported",
            ));
        }
        let source_machine_id = reconnect.machine_id.clone();
        let source_generation = reconnect.generation;
        crate::restore::stage(&self.machine_root, manifest_digest.clone(), || {
            Ok(RestoreLineage {
                executions: expected.executions.clone(),
                snapshot_id: snapshot_id.clone(),
                source_machine_id: source_machine_id.clone(),
                source_generation,
            })
        })?;
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
        // A capture can reset the vsock device, including connections in the
        // source VM. Close the reusable session only after its active bounded
        // RPC finishes, and exclude queued RPCs throughout the native pause.
        self.guest_transport.quiesce()?;
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
        self.guest_transport.quiesce()?;
        // Preparation may have stopped before pause delivery, or resume may
        // have applied before its response was lost. Inspect native power, not
        // management, before choosing whether another resume is necessary.
        let power = self
            .machine
            .observe_power()
            .map_err(|_| ControlError::Unsupported("native capture owner unavailable"))?
            .ok_or(ControlError::Unsupported(
                "native capture owner unavailable",
            ))?;
        let result = if boundary.needs_resume(power.state)? {
            self.machine
                .adopt_pause_for_capture()
                .map_err(|_| ControlError::Unsupported("native capture owner unavailable"))?;
            self.machine.resume_after_capture()
        } else {
            self.machine.finish_capture_without_resume()
        };
        result.map_err(|_| ControlError::Unsupported("native capture completion failed"))?;
        crate::capture::CaptureBoundary::clear(&self.machine_root)?;
        self.guest_transport.release_capture()
    }

    fn prepare_full_capture(
        &mut self,
        snapshot_id: sandsurf_protocol::SnapshotId,
        operation_id: sandsurf_protocol::OperationId,
        journal: &mut RuntimeJournal,
    ) -> ControlResult<NativeSnapshotResponse> {
        let result = self.prepare_full_capture_inner(snapshot_id, operation_id.clone(), journal);
        if result.is_err()
            && crate::capture::CaptureBoundary::require(&self.machine_root, &operation_id)?
                .is_some()
        {
            // Do not erase an indeterminate pause owner. Only confirmed native
            // completion permits retiring this operation's unpublished copy.
            self.finish_native_capture()?;
            crate::capture::remove_full(&self.machine_root, &operation_id)?;
        }
        result
    }

    fn prepare_full_capture_inner(
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
            return Ok(NativeSnapshotResponse::Prepared { capture });
        }
        crate::capture::reset_unpublished_full(&self.machine_root, &operation_id)?;
        let boundary = crate::capture::CaptureBoundary::require(&self.machine_root, &operation_id)?
            .ok_or(ControlError::Protocol(
                "full capture has no native boundary",
            ))?;
        let executions = journal.capture_executions(boundary.generation)?;
        let snapshot = self
            .machine
            .create_full_snapshot(&operation_id)
            .map_err(|_| {
                ControlError::Unsupported("Firecracker could not create a full snapshot")
            })?;
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
                boot: crate::storage::copy_boot(&active.boot_directory, &directory.join("boot"))?,
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
                executions,
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
            Ok(capture) => Ok(NativeSnapshotResponse::Prepared { capture }),
            Err(error) => Err(ControlError::Rejected {
                category: "snapshot".into(),
                message: error.to_string(),
            }),
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

#[derive(Clone, PartialEq, Eq)]
struct ActiveGuest {
    rebind: Option<ManagementRebind>,
    socket: PathBuf,
    machine_id: MachineId,
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    boot_directory: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeBootObservation {
    machine_id: MachineId,
    generation: Counter,
    boot: sandsurf_image::boot::FrozenBoot,
}

impl LinuxGenerationFactory {
    fn record_boot(&self, active: &ActiveGuest) -> Result<(), Digest> {
        let boot = crate::storage::read_boot(&active.boot_directory)
            .map_err(|_| bytes_digest(b"linux-native-boot-artifacts-invalid"))?;
        let observation = NativeBootObservation {
            machine_id: active.machine_id.clone(),
            generation: active.generation,
            boot,
        };
        let guardian = self.machine_root.join("guardian");
        let stage = guardian.join(format!(
            ".current-boot-{}.json",
            hex(&random_bytes()
                .map_err(|_| bytes_digest(b"linux-native-boot-observation-entropy"))?)
        ));
        write_private_json(&stage, &observation)
            .map_err(|_| bytes_digest(b"linux-native-boot-observation-write-failed"))?;
        let result = sandsurf_native::storage::replace_journal_file(
            &stage,
            &guardian.join("current-boot.json"),
        );
        if result.is_err() {
            let _ = fs::remove_file(&stage);
        }
        result.map_err(|_| bytes_digest(b"linux-native-boot-observation-write-failed"))
    }
}

struct PendingGuest {
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    boot_directory: PathBuf,
}

struct PendingRestore {
    source: ReconnectState,
    next: PendingGuest,
    snapshot_id: sandsurf_protocol::SnapshotId,
    generation_seed: [u8; 32],
    executions: Vec<sandsurf_protocol::CapturedExecution>,
}

struct LinuxGenerationFactory {
    network: Arc<Mutex<Option<Arc<NativeNetworkGateway>>>>,
    network_usage: NetworkUsage,
    config: LinuxGuardianConfig,
    machine_root: PathBuf,
    system_disk: PathBuf,
    active: Arc<Mutex<Option<ActiveGuest>>>,
    pending: Option<PendingGuest>,
    pending_restore: Option<PendingRestore>,
}

fn bind_network_owner(
    owner: &Arc<Mutex<Option<Arc<NativeNetworkGateway>>>>,
    usage: &NetworkUsage,
    next: &Arc<NativeNetworkGateway>,
) -> Result<(), Digest> {
    let mut owner = owner
        .lock()
        .map_err(|_| bytes_digest(b"native-network-owner-lock"))?;
    if let Some(previous) = owner.as_ref()
        && !Arc::ptr_eq(previous, next)
    {
        let _ = previous.configure(&NetworkPolicy::default(), &[]);
        let snapshot = previous.snapshot();
        accumulate_network_usage(
            usage,
            &sandsurf_network::NetworkReport {
                connections: snapshot.connections,
                violations: snapshot.violations,
                rx_bytes: snapshot.rx_bytes,
                tx_bytes: snapshot.tx_bytes,
                cleanup_failures: Vec::new(),
            },
        );
    }
    *owner = Some(Arc::clone(next));
    Ok(())
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
        let image = verify_image(&self.config.image_manifest, ImageTrust::ExplicitLocal)
            .map_err(|_| bytes_digest(b"linux-boot-image-invalid"))?;
        ensure_mutable_disk(
            &self.config.system_seed,
            &self.system_disk,
            resources.disk_bytes.get(),
            &image.manifest.system.clone_profile,
        )
        .map_err(|error| {
            eprintln!("sandsurf disk preparation failed: {error}");
            bytes_digest(b"linux-system-disk-preparation-failed")
        })?;
        let storage_lease = crate::storage::attach(&self.system_disk).map_err(|error| {
            eprintln!("sandsurf disk attachment refused: {error}");
            bytes_digest(b"linux-system-disk-attachment-failed")
        })?;
        let boot_directory = self.machine_root.join("guardian").join(format!(
            "boot-{}-{}",
            generation.get(),
            hex(&random_bytes().map_err(|_| bytes_digest(b"linux-boot-entropy"))?)
        ));
        let boot = crate::storage::freeze_boot(&image, &self.system_disk, &boot_directory)
            .map_err(|error| {
                eprintln!("sandsurf boot selection failed: {error}");
                bytes_digest(b"linux-boot-artifacts-invalid")
            })?;
        self.configuration_from_boot(
            machine_id,
            generation,
            resources,
            storage_lease,
            boot_directory,
            boot,
        )
    }

    fn bind_management(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest> {
        bind_network_owner(&self.network, &self.network_usage, &process.network)?;
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
            boot_directory: pending.boot_directory,
            rebind: None,
        };
        let evidence = digest(
            Domain::Operation,
            &("host-management-channel-bound-v1", machine_id, generation),
        )
        .map_err(|_| bytes_digest(b"management-binding-evidence"))?;
        self.record_boot(&active)?;
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
        if *machine_id != self.config.machine_id
            || self.pending.is_some()
            || self.pending_restore.is_some()
        {
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
        let boot_directory = source
            .reconnect_state
            .parent()
            .ok_or_else(|| bytes_digest(b"linux-restore-boot-owner-missing"))?
            .join("boot");
        if crate::storage::read_boot(&boot_directory)
            .map_err(|_| bytes_digest(b"linux-restore-boot-artifacts-invalid"))?
            != reconnect.boot
        {
            return Err(bytes_digest(b"linux-restore-boot-identity-mismatch"));
        }
        // StageRestore already verified the restored disk against the capture.
        // Resume does not install an OS, customize identities, or read /boot.
        let storage_lease = crate::storage::attach(&self.system_disk)
            .map_err(|_| bytes_digest(b"linux-restore-storage-custody"))?;
        let resources = self.config.resources.clone();
        let configuration = self.configuration_from_boot(
            machine_id,
            generation,
            &resources,
            storage_lease,
            boot_directory,
            reconnect.boot.clone(),
        )?;
        let next = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"linux-restore-next-capability-missing"))?;
        let generation_seed = random_bytes().map_err(|_| bytes_digest(b"linux-restore-entropy"))?;
        self.pending_restore = Some(PendingRestore {
            executions: crate::restore::load::<RestoreLineage>(&self.machine_root)
                .map_err(|_| bytes_digest(b"linux-restore-membership-unavailable"))?
                .ok_or_else(|| bytes_digest(b"linux-restore-membership-missing"))?
                .executions,
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
        bind_network_owner(&self.network, &self.network_usage, &process.network)?;
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
            staging: GuestServiceRequest::StageExecutionRestore {
                snapshot_id: pending.snapshot_id.clone(),
                capture_operation_id: pending.source.capture_operation_id.clone(),
                machine_id: machine_id.clone(),
                previous_generation: pending.source.generation,
                generation,
                executions: pending.executions.clone(),
            },
            request: GuestServiceRequest::RebindGeneration {
                snapshot_id: pending.snapshot_id.clone(),
                capture_operation_id: pending.source.capture_operation_id.clone(),
                machine_id: machine_id.clone(),
                previous_generation: pending.source.generation,
                generation,
                boot_identity: pending.next.boot_identity.clone(),
                capability: pending.next.capability,
                generation_seed: pending.generation_seed,
            },
        };
        let active = ActiveGuest {
            socket: process.vsock_path.clone(),
            machine_id: machine_id.clone(),
            generation,
            boot_identity: pending.next.boot_identity,
            capability: pending.next.capability,
            boot_directory: pending.next.boot_directory,
            rebind: Some(rebind),
        };
        self.record_boot(&active)?;
        *self
            .active
            .lock()
            .map_err(|_| bytes_digest(b"guest-endpoint-lock"))? = Some(active);
        digest(
            Domain::Operation,
            &(
                "host-restored-management-channel-bound-v1",
                machine_id,
                generation,
            ),
        )
        .map_err(|_| bytes_digest(b"management-binding-evidence"))
    }
}

impl LinuxGenerationFactory {
    fn configuration_from_boot(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        resources: &Resources,
        storage_lease: Arc<File>,
        boot_directory: PathBuf,
        boot: sandsurf_image::boot::FrozenBoot,
    ) -> Result<FirecrackerConfig, Digest> {
        let (kernel, initial_ramdisk) = sandsurf_image::boot::paths(&boot_directory, &boot);
        let capability = random_bytes().map_err(|_| bytes_digest(b"linux-boot-entropy"))?;
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-linux-boot-v1",
                &self.config.image_digest,
                &self.config.firecracker_sha256,
                &boot,
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
        )
        .map_err(|_| bytes_digest(b"linux-authentication-disk"))?;
        let state_directory = guardian.join(format!("vm-{}-{nonce}", generation.get()));
        let owner_token = hex(&random_bytes().map_err(|_| bytes_digest(b"linux-owner-entropy"))?);
        self.pending = Some(PendingGuest {
            generation,
            boot_identity,
            capability,
            boot_directory,
        });
        Ok(FirecrackerConfig {
            network_identity: sandsurf_network::LinkIdentity::for_machine(machine_id),
            launcher_executable: self.config.launcher.clone(),
            firecracker_executable: self.config.firecracker.clone(),
            firecracker_sha256: self.config.firecracker_sha256.clone(),
            state_directory,
            kernel_image: kernel,
            initial_ramdisk,
            system_disk: self.system_disk.clone(),
            storage_lease,
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
}

struct LinuxGuest {
    active: Arc<Mutex<Option<ActiveGuest>>>,
    remote: Arc<LinuxGuestTransport>,
}

/// Only I/O coordination, not a second capture or lifecycle authority. The
/// persisted CaptureBoundary owns admission and recovery. Keep this gate closed
/// until that boundary has been retired after native resume or confirmed stop.
struct LinuxGuestTransport {
    capture_blocked: AtomicBool,
    session: Mutex<Option<(ActiveGuest, ManagedGuestClient<UnixVsockChannel>)>>,
}

impl LinuxGuestTransport {
    fn new(capture_blocked: bool) -> Self {
        Self {
            capture_blocked: AtomicBool::new(capture_blocked),
            session: Mutex::new(None),
        }
    }

    fn quiesce(&self) -> ControlResult<()> {
        self.quiesce_with_timeout(Duration::from_secs(10))
    }

    fn quiesce_with_timeout(&self, timeout: Duration) -> ControlResult<()> {
        self.capture_blocked.store(true, Ordering::Release);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match self.session.try_lock() {
                Ok(mut session) => {
                    *session = None;
                    return Ok(());
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(ControlError::Protocol("guest transport lock poisoned"));
                }
                Err(std::sync::TryLockError::WouldBlock)
                    if std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    return Err(ControlError::Unsupported(
                        "guest I/O has not quiesced; capture remains pending",
                    ));
                }
            }
        }
    }

    fn release_capture(&self) -> ControlResult<()> {
        self.quiesce()?;
        self.capture_blocked.store(false, Ordering::Release);
        Ok(())
    }
}

fn with_cached_guest<T>(
    active: &ActiveGuest,
    transport: &LinuxGuestTransport,
    operation: impl FnOnce(&mut ManagedGuestClient<UnixVsockChannel>) -> T,
) -> Option<T> {
    let mut cache = transport.session.lock().ok()?;
    if transport.capture_blocked.load(Ordering::Acquire) {
        return None;
    }
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
            if let Ok(mut remote) = self.remote.session.lock() {
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
                EffectOutcome::NotApplied(bytes_digest(b"guest-management-not-dispatched"))
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
                "guest management transport is unavailable",
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
        PendingRebind::new(
            guest_client(&source),
            binding.request.clone(),
            binding.staging.clone(),
        )
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

fn ensure_mutable_disk(
    source: &Path,
    destination: &Path,
    requested_bytes: u64,
    clone_profile: &sandsurf_image::identity::CloneProfile,
) -> Result<(), LinuxError> {
    crate::storage::materialize(
        source,
        destination,
        requested_bytes,
        crate::storage::DiskFormat::Raw,
        |staged| sandsurf_image::identity::customize(staged, clone_profile),
    )?;
    Ok(())
}

fn write_authentication(
    path: &Path,
    machine_id: &MachineId,
    generation: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
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
    fn memory_restore_uses_saved_running_boot_without_opening_seed_or_guest_selection() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-restore-boot-{}",
            hex(&random_bytes().unwrap())
        ));
        sandsurf_native::local::create_private_directory(&root).unwrap();
        for name in ["guardian", "disks", "snapshot"] {
            sandsurf_native::local::create_private_directory(&root.join(name)).unwrap();
        }
        let disk = root.join("disks/system.ext4");
        crate::storage::publish_disk(&disk, 4096, crate::storage::DiskFormat::Raw, |stage| {
            // Not a filesystem at all: any disk interpretation is a bug here.
            sandsurf_native::local::create_private_file(stage)?.write_all(&[7; 4096])
        })
        .unwrap();
        let kernel = root.join("running-kernel");
        let mut bytes = vec![0; 4096];
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        bytes[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        bytes[0x236] = 1;
        sandsurf_native::local::create_private_file(&kernel)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let boot = crate::storage::pin_boot(
            &kernel,
            None,
            Architecture::X64,
            &root.join("snapshot/boot"),
        )
        .unwrap();
        let machine_id: MachineId = "saved-machine".try_into().unwrap();
        let snapshot_id: sandsurf_protocol::SnapshotId = "saved-state".try_into().unwrap();
        let operation: sandsurf_protocol::OperationId = "capture-operation".try_into().unwrap();
        write_private_json(
            &root.join("snapshot/reconnect.json"),
            &ReconnectState {
                format_version: 1,
                snapshot_id: snapshot_id.clone(),
                capture_operation_id: operation.clone(),
                machine_id: machine_id.clone(),
                generation: Counter::ONE,
                boot_identity: bytes_digest(b"running"),
                capability: [1; 32],
                boot,
            },
        )
        .unwrap();
        crate::restore::stage(&root, bytes_digest(b"manifest"), || {
            Ok(RestoreLineage {
                snapshot_id: snapshot_id.clone(),
                source_machine_id: machine_id.clone(),
                source_generation: Counter::ONE,
                executions: Vec::new(),
            })
        })
        .unwrap();
        let resources = Resources::from_geometry(
            Counter::ONE,
            Counter::try_from(128).unwrap(),
            Counter::try_from(4096).unwrap(),
            Counter::try_from(4096).unwrap(),
            Counter::ONE,
        )
        .unwrap();
        let config = LinuxGuardianConfig {
            format_version: 1,
            machine_id: machine_id.clone(),
            image_digest: bytes_digest(b"seed"),
            resources,
            launcher: root.join("unused-launcher"),
            firecracker: root.join("unused-vmm"),
            firecracker_sha256: "a".repeat(64),
            image_manifest: root.join("missing-image-manifest"),
            system_seed: root.join("missing-seed"),
            system_seed_sha256: "b".repeat(64),
            guest_cid: 17,
        };
        let mut factory = LinuxGenerationFactory {
            network: Arc::new(Mutex::new(None)),
            network_usage: Arc::new(Mutex::new(NetworkUsageValue::default())),
            config,
            machine_root: root.clone(),
            system_disk: disk.clone(),
            active: Arc::new(Mutex::new(None)),
            pending: None,
            pending_restore: None,
        };
        let source = FirecrackerRestoreSource {
            snapshot_id,
            capture_operation_id: operation,
            source_machine_id: machine_id.clone(),
            source_generation: Counter::ONE,
            manifest_digest: bytes_digest(b"manifest"),
            snapshot_state: root.join("snapshot/vmstate"),
            snapshot_memory: root.join("snapshot/memory"),
            reconnect_state: root.join("snapshot/reconnect.json"),
        };
        let (configuration, _) = factory
            .restore_configuration(&machine_id, Counter::try_from(2).unwrap(), &source)
            .unwrap();
        assert_eq!(
            configuration.kernel_image,
            root.join("snapshot/boot/kernel")
        );
        assert!(configuration.initial_ramdisk.is_none());
        assert_eq!(fs::read(&disk).unwrap(), [7; 4096]);
        drop(configuration);
        drop(factory);
        fs::remove_dir_all(root).unwrap();
    }

    fn endpoint() -> ActiveGuest {
        ActiveGuest {
            rebind: None,
            socket: PathBuf::from("/not-connected"),
            machine_id: "capture-transport".try_into().unwrap(),
            generation: Counter::ONE,
            boot_identity: bytes_digest(b"boot"),
            capability: [1; 32],
            boot_directory: PathBuf::from("/not-connected/boot"),
        }
    }

    #[test]
    fn capture_drains_active_rpc_and_excludes_queued_sends() {
        use std::sync::mpsc;
        let transport = Arc::new(LinuxGuestTransport::new(false));
        let (entered, entry) = mpsc::channel();
        let (finish, finished) = mpsc::channel();
        let worker_transport = Arc::clone(&transport);
        let worker = std::thread::spawn(move || {
            with_cached_guest(&endpoint(), &worker_transport, |_| {
                entered.send(()).unwrap();
                finished.recv_timeout(Duration::from_secs(5)).unwrap();
            })
        });
        entry.recv_timeout(Duration::from_secs(5)).unwrap();
        let capture_transport = Arc::clone(&transport);
        let (quiesced, quiescence) = mpsc::channel();
        let capture = std::thread::spawn(move || {
            capture_transport.quiesce().unwrap();
            quiesced.send(()).unwrap();
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !transport.capture_blocked.load(Ordering::Acquire) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(
            quiescence.try_recv().is_err(),
            "capture must await the active RPC"
        );
        finish.send(()).unwrap();
        assert!(worker.join().unwrap().is_some());
        quiescence.recv_timeout(Duration::from_secs(5)).unwrap();
        capture.join().unwrap();
        assert!(transport.session.lock().unwrap().is_none());
        assert!(
            with_cached_guest(&endpoint(), &transport, |_| panic!("sent while paused")).is_none()
        );
        transport.release_capture().unwrap();
        assert_eq!(with_cached_guest(&endpoint(), &transport, |_| 42), Some(42));
        assert!(transport.session.lock().unwrap().is_some());
        transport.quiesce().unwrap();
        assert!(transport.session.lock().unwrap().is_none());
    }

    #[test]
    fn interrupted_capture_transport_starts_closed_until_recovery() {
        let transport = LinuxGuestTransport::new(true);
        assert!(
            with_cached_guest(&endpoint(), &transport, |_| panic!("sent before recovery"))
                .is_none()
        );
        transport.release_capture().unwrap();
        assert_eq!(with_cached_guest(&endpoint(), &transport, |_| 7), Some(7));
    }

    #[test]
    fn slow_guest_cannot_indefinitely_block_native_capture_control() {
        let transport = LinuxGuestTransport::new(false);
        let session = transport.session.lock().unwrap();
        assert!(
            transport
                .quiesce_with_timeout(Duration::from_millis(2))
                .is_err()
        );
        assert!(transport.capture_blocked.load(Ordering::Acquire));
        drop(session);
        transport.release_capture().unwrap();
        assert!(!transport.capture_blocked.load(Ordering::Acquire));
    }

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
        sandsurf_native::local::create_private_file(&source)
            .unwrap()
            .write_all(contents)
            .unwrap();
        ensure_mutable_disk(
            &source,
            &destination,
            8192,
            &sandsurf_image::identity::CloneProfile::Preserve,
        )
        .unwrap();
        assert_eq!(fs::metadata(&destination).unwrap().len(), 8192);
        assert_eq!(&fs::read(&destination).unwrap()[..contents.len()], contents);
        fs::remove_file(source).unwrap();
        ensure_mutable_disk(
            &root.join("missing-seed"),
            &destination,
            8192,
            &sandsurf_image::identity::CloneProfile::Preserve,
        )
        .unwrap();
        assert_eq!(&fs::read(&destination).unwrap()[..contents.len()], contents);
        crate::storage::retire(&destination, 8192, crate::storage::DiskFormat::Raw).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
