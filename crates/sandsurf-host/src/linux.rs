//! Linux guardian integration for one retained Firecracker machine.

use crate::guest::{GuestClient, RemoteWorkloadDriver};
use sandbox_guest::{AUTHENTICATION_MAGIC, GUEST_CONTROL_PORT};
use sandbox_image::{ImageTrust, RootfsFormat, VerifiedImage, verify_image};
use sandbox_vm::{
    FirecrackerConfig, FirecrackerProcess, FirecrackerRestore, UnixVsockChannel, VmNetworkBridge,
    VmPortGateway,
};
use sandsurf_control::{
    EffectOutcome, Error as ControlError, GuardianEffect, Result as ControlResult, WorkloadDriver,
};
use sandsurf_machine::linux::{
    FirecrackerDriver, FirecrackerEpochFactory, FirecrackerQualification, FirecrackerRestoreSource,
};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_protocol::{
    Capability, CheckpointArtifact, CheckpointProcessWatermark, Counter, Digest, Domain,
    GuestServiceRequest, GuestServiceResponse, LifecycleCommand, LiveResourceLimits,
    MachineObservation, MachineState, Mutation, NativeCheckpointRequest, NativeCheckpointResponse,
    NativeFullCapture, NetworkDestination, NetworkPolicy, Resources, RuntimeConfiguration,
    SandboxId, VmEngine, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONFIG_VERSION: u16 = 1;
const RELEASE_PUBLIC_KEY: [u8; 32] = [
    0x49, 0x5b, 0x4a, 0x26, 0xa6, 0x5d, 0xf6, 0x6f, 0x70, 0x90, 0x06, 0x5e, 0xd2, 0x3a, 0x30, 0xa2,
    0x9a, 0xd3, 0xb5, 0x3e, 0x0e, 0xd9, 0x0d, 0x65, 0x06, 0xa2, 0xd6, 0xc8, 0xc0, 0xab, 0xa6, 0x84,
];

#[derive(Debug)]
pub enum LinuxError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandbox_image::ImageError),
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
impl From<sandbox_image::ImageError> for LinuxError {
    fn from(value: sandbox_image::ImageError) -> Self {
        Self::Image(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxGuardianConfig {
    format_version: u16,
    sandbox_id: SandboxId,
    image_digest: Digest,
    resources: Resources,
    launcher: PathBuf,
    firecracker: PathBuf,
    firecracker_sha256: String,
    image_manifest: PathBuf,
    disk_template: PathBuf,
    disk_template_sha256: String,
    guest_cid: u32,
}

/// Resolve and copy an exact source-built boot/workload bundle into the host's
/// immutable image store before catalog admission. Local unsigned images are
/// accepted only through the explicit qualification environment variable;
/// packaged images require their release signature and index digest.
pub fn prepare_config(
    host_root: &Path,
    executable: &Path,
    sandbox_id: &SandboxId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<LinuxGuardianConfig, LinuxError> {
    let existing_path = host_root
        .join("sandboxes")
        .join(sandbox_id.as_str())
        .join("guardian/config.json");
    if existing_path.exists() {
        let existing = read_config(&existing_path, sandbox_id)?;
        if existing.image_digest != *image_digest
            || existing.resources != *resources
            || existing.launcher != executable
        {
            return Err(LinuxError::Invalid(
                "existing Sandbox configuration conflicts with create request".into(),
            ));
        }
        return Ok(existing);
    }
    let installed_root = host_root.join("images").join(image_digest.as_str());
    let (verified, source_template) = if installed_root.exists() {
        (
            verify_image(
                &installed_root.join("manifest.json"),
                ImageTrust::ExplicitLocal,
            )?,
            installed_root.join("empty-workspace.ext4"),
        )
    } else {
        resolve_source_bundle(executable)?
    };
    if verified.manifest_digest != image_digest.as_str()
        || verified.manifest.boot_bundle.bootstrap.format != RootfsFormat::Ext4
        || verified.manifest.workload.rootfs.format != RootfsFormat::Ext4
        || !verified.manifest.boot_bundle.capabilities.overlayfs
        || !verified.manifest.boot_bundle.capabilities.cgroup_v2
        || !verified.manifest.boot_bundle.capabilities.devpts
    {
        return Err(LinuxError::Invalid(
            "image identity or required guest features do not match".into(),
        ));
    }
    require_regular(&source_template, 128 * 1024 * 1024 * 1024)?;
    let installed = install_image(host_root, &verified, &source_template)?;

    let firecracker = std::env::var_os("SANDSURF_FIRECRACKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            executable
                .parent()
                .unwrap_or(Path::new("/"))
                .join("firecracker-v1.17.0-x86_64")
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
        sandbox_id: sandbox_id.clone(),
        image_digest: image_digest.clone(),
        resources: resources.clone(),
        launcher: executable.to_path_buf(),
        firecracker_sha256: sha256_file(&firecracker, 256 * 1024 * 1024)?,
        firecracker,
        image_manifest: installed.join("manifest.json"),
        disk_template_sha256: sha256_file(
            &installed.join("empty-workspace.ext4"),
            128 * 1024 * 1024 * 1024,
        )?,
        disk_template: installed.join("empty-workspace.ext4"),
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
        let template = std::env::var_os("SANDSURF_EMPTY_DISK_IMAGE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                path.parent()
                    .unwrap_or(Path::new("/"))
                    .join("empty-workspace.ext4")
            });
        Ok((verify_image(&path, ImageTrust::ExplicitLocal)?, template))
    } else {
        let package = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| LinuxError::Invalid("native package layout is invalid".into()))?;
        let manifest = package.join("images/minimal-x64/manifest.json");
        let index: ImageIndex = read_json(&package.join("images/manifest.json"), 1024 * 1024)?;
        let expected = index
            .files
            .get("minimal-x64/manifest.json")
            .ok_or_else(|| LinuxError::Invalid("packaged boot manifest is absent".into()))?
            .clone();
        Ok((
            verify_image(
                &manifest,
                ImageTrust::Bundled {
                    manifest_digest: &expected,
                    release_public_key: &RELEASE_PUBLIC_KEY,
                },
            )?,
            executable
                .parent()
                .ok_or_else(|| LinuxError::Invalid("native package layout is invalid".into()))?
                .join("empty-workspace.ext4"),
        ))
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

pub fn read_config(path: &Path, sandbox_id: &SandboxId) -> Result<LinuxGuardianConfig, LinuxError> {
    let value: LinuxGuardianConfig = read_json(path, 1024 * 1024)?;
    if value.format_version != CONFIG_VERSION || value.sandbox_id != *sandbox_id {
        return Err(LinuxError::Invalid(
            "guardian configuration identity is invalid".into(),
        ));
    }
    let image = verify_image(&value.image_manifest, ImageTrust::ExplicitLocal)?;
    if image.manifest_digest != value.image_digest.as_str()
        || sha256_file(&value.firecracker, 256 * 1024 * 1024)? != value.firecracker_sha256
        || sha256_file(&value.disk_template, 128 * 1024 * 1024 * 1024)?
            != value.disk_template_sha256
    {
        return Err(LinuxError::Invalid(
            "guardian configuration artifact identity changed".into(),
        ));
    }
    Ok(value)
}

pub fn workload_defaults(
    host_root: &Path,
    image_digest: &Digest,
) -> Result<crate::api::WorkloadDefaultsView, LinuxError> {
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
    let defaults = image.manifest.workload.defaults;
    Ok(crate::api::WorkloadDefaultsView {
        environment: defaults.environment,
        user: defaults.user,
        working_directory: defaults.working_directory,
        entrypoint: defaults.entrypoint,
        command: defaults.command,
    })
}

pub struct LinuxGuardianEffect {
    sandbox_root: PathBuf,
    config: LinuxGuardianConfig,
    machine: FirecrackerDriver<LinuxEpochFactory>,
    workload: LinuxWorkload,
    network: Arc<Mutex<Option<VmNetworkBridge>>>,
    network_usage: NetworkUsage,
    exposures: Arc<Mutex<Option<VmPortGateway>>>,
    installed_runtime: Option<InstalledRuntime>,
    restore_lineage: Option<RestoreLineage>,
    suspend_capture_operation: Option<sandsurf_protocol::OperationId>,
    capture_origin_was_paused: bool,
}

struct RestoreLineage {
    checkpoint_id: sandsurf_protocol::CheckpointId,
    source_sandbox_id: SandboxId,
    source_epoch: Counter,
    capture_operation_id: sandsurf_protocol::OperationId,
}

/// Evidence that a specific host-owned configuration is live in one guest
/// epoch. This is an observation cache only: lifecycle/configuration commands
/// remain the sole authority, and a new epoch always invalidates it.
struct InstalledRuntime {
    epoch: Counter,
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

fn accumulate_network_usage(usage: &NetworkUsage, report: &sandbox_network_broker::BrokerReport) {
    if let Ok(mut usage) = usage.lock() {
        usage.rx_bytes = usage.rx_bytes.saturating_add(report.rx_bytes);
        usage.tx_bytes = usage.tx_bytes.saturating_add(report.tx_bytes);
        usage.connections = usage.connections.saturating_add(report.connections);
    }
}

impl LinuxGuardianEffect {
    pub fn open(sandbox_root: &Path, config: LinuxGuardianConfig) -> Result<Self, LinuxError> {
        fs::metadata("/dev/kvm").map_err(|_| LinuxError::Invalid("KVM is unavailable".into()))?;
        let image = verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        let disks = sandbox_root.join("disks");
        fs::create_dir_all(&disks)?;
        let workload_state = disks.join("workload-state.ext4");
        let control_state = disks.join("control-state.ext4");
        ensure_mutable_disk(
            &config.disk_template,
            &workload_state,
            config.resources.disk_bytes.get(),
        )?;
        let control_bytes = config
            .resources
            .output_bytes
            .get()
            .checked_add(64 * 1024 * 1024)
            .ok_or_else(|| LinuxError::Invalid("control disk size overflow".into()))?
            .max(128 * 1024 * 1024);
        if control_bytes > 8 * 1024 * 1024 * 1024 {
            return Err(LinuxError::Invalid(
                "control/output reservation exceeds the initial disk envelope".into(),
            ));
        }
        ensure_mutable_disk(&config.disk_template, &control_state, control_bytes)?;

        let active = Arc::new(Mutex::new(None));
        let network = Arc::new(Mutex::new(None));
        let network_usage = Arc::new(Mutex::new(NetworkUsageValue::default()));
        let exposures = Arc::new(Mutex::new(None));
        let factory = LinuxEpochFactory {
            config: config.clone(),
            sandbox_root: sandbox_root.to_path_buf(),
            kernel: image.kernel_path,
            bootstrap: image.bootstrap_path,
            workload: image.workload_path,
            workload_state,
            control_state,
            active: Arc::clone(&active),
            pending: None,
            pending_restore: None,
        };
        let machine = FirecrackerDriver::new(
            config.sandbox_id.clone(),
            crate::service::native_guest_architecture(),
            FirecrackerQualification {
                lifecycle: None,
                full_state: None,
            },
            factory,
        );
        Ok(Self {
            sandbox_root: sandbox_root.to_path_buf(),
            config,
            machine,
            workload: LinuxWorkload { active },
            network,
            network_usage,
            exposures,
            installed_runtime: None,
            restore_lineage: None,
            suspend_capture_operation: None,
            capture_origin_was_paused: false,
        })
    }

    fn finish_filesystem_capture(
        &mut self,
        operation_id: sandsurf_protocol::OperationId,
    ) -> ControlResult<GuestServiceResponse> {
        let request = GuestServiceRequest::FinishFilesystemCapture { operation_id };
        let mut last = None;
        // A Firecracker vsock connection opened concurrently with vCPU resume
        // can time out without ever reaching the guest. The finish operation is
        // identity-bound and idempotent, so reconnect it without replaying any
        // workload mutation.
        for attempt in 0..3 {
            match self.workload.query(request.clone()) {
                Ok(response) => return Ok(response),
                Err(error) => last = Some(error),
            }
            if attempt != 2 {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Err(last.expect("capture finish is attempted at least once"))
    }

    fn install_runtime_configuration(
        &mut self,
        configuration: &RuntimeConfiguration,
    ) -> RuntimeInstallation {
        let Some(active) = self.workload.endpoint() else {
            return RuntimeInstallation::Unknown;
        };
        if let Some(installed) = self.installed_runtime.as_ref()
            && installed.epoch == active.epoch
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

        let resource_evidence =
            match guest_client(&active).call(&GuestServiceRequest::ApplyResources {
                resources: configuration.resources.clone(),
            }) {
                Ok(GuestServiceResponse::ResourcesApplied { evidence }) => evidence,
                _ => {
                    self.stop_runtime_data_planes();
                    return RuntimeInstallation::Unknown;
                }
            };
        match digest(
            Domain::Grant,
            &(
                "sandsurf-linux-runtime-configuration-v2",
                resource_evidence,
                configuration,
            ),
        ) {
            Ok(evidence) => {
                self.installed_runtime = Some(InstalledRuntime {
                    epoch: active.epoch,
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
        if let Ok(mut active) = self.workload.active.lock() {
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
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        self.workload.dispatch(mutation, capability)
    }

    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        let mut outcome = apply_lifecycle(&mut self.machine, command, current);
        let running = matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Running)
        );
        if running {
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
            if let Some(lineage) = self.restore_lineage.as_ref() {
                let operation_id = lineage.capture_operation_id.clone();
                match self.finish_filesystem_capture(operation_id) {
                    Ok(GuestServiceResponse::FilesystemCaptureFinished { .. }) => {}
                    Ok(_) | Err(_) => {
                        self.contain_unpublished_machine();
                        return MachineOutcome::Unknown;
                    }
                }
            }
            if let MachineOutcome::Observed(values) = &mut outcome
                && let Some(last) = values.last_mut()
            {
                last.evidence_digest = match digest(
                    Domain::Grant,
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
            if let Ok(mut active) = self.workload.active.lock() {
                *active = None;
            }
            self.stop_runtime_data_planes();
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Suspended)
        ) && let Some(operation_id) = self.suspend_capture_operation.take()
            && let Err(error) = remove_full_capture(&self.sandbox_root, &operation_id)
        {
            // The durable checkpoint is already committed. Retaining this
            // private duplicate is safe and lets later recovery retry cleanup.
            eprintln!("sandsurf retained suspend staging after cleanup failure: {error}");
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| matches!(value.state, MachineState::Suspended | MachineState::Stopped | MachineState::Destroyed))
        ) {
            self.capture_origin_was_paused = false;
        }
        outcome
    }

    fn configure(
        &mut self,
        command: &sandsurf_protocol::ConfigurationCommand,
        current: &MachineObservation,
    ) -> EffectOutcome {
        match self.machine.configure(command, current) {
            sandsurf_machine::ConfigurationOutcome::Applied(machine_evidence) => {
                match self.install_runtime_configuration(&command.configuration) {
                    RuntimeInstallation::Applied(runtime_evidence) => match digest(
                        Domain::Grant,
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

    fn reconcile(&mut self, journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        let running = journal
            .last_observation()?
            .is_some_and(|value| value.value().state == MachineState::Running);
        // Opening a new Firecracker vsock connection while vCPUs are paused
        // leaves a local-init connection that cannot be completed by the guest
        // and can poison the transport after resume. Runtime evidence remains
        // retained in the guest spool until the machine is running again.
        if !running || self.machine.capture_is_paused() {
            return Ok(());
        }
        self.workload.reconcile(journal)
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        if let GuestServiceRequest::PrepareFilesystemCapture { operation_id } = &request {
            let operation_id = operation_id.clone();
            let response = self.workload.query(request)?;
            if !matches!(
                response,
                GuestServiceResponse::FilesystemCapturePrepared { .. }
            ) {
                return Ok(response);
            }
            if self.machine.pause_for_capture().is_err() {
                let _ = self.machine.resume_after_capture();
                let _ = self.finish_filesystem_capture(operation_id);
                return Err(sandsurf_control::Error::Unsupported(
                    "native VM could not establish the filesystem capture pause",
                ));
            }
            return Ok(response);
        }
        if matches!(request, GuestServiceRequest::FinishFilesystemCapture { .. }) {
            let GuestServiceRequest::FinishFilesystemCapture { operation_id } = request else {
                unreachable!("matched capture finish request")
            };
            self.machine.resume_after_capture().map_err(|_| {
                sandsurf_control::Error::Unsupported(
                    "native VM could not leave the filesystem capture pause",
                )
            })?;
            return self.finish_filesystem_capture(operation_id);
        }
        let usage_requested = matches!(request, GuestServiceRequest::ResourceUsage);
        let mut response = self.workload.query(request)?;
        if usage_requested && let GuestServiceResponse::ResourceUsage { usage } = &mut response {
            let accumulated = self
                .network_usage
                .lock()
                .map_err(|_| sandsurf_control::Error::Protocol("network usage lock poisoned"))?;
            let current = self
                .network
                .lock()
                .map_err(|_| sandsurf_control::Error::Protocol("network bridge lock poisoned"))?
                .as_ref()
                .map_or_else(Default::default, VmNetworkBridge::snapshot);
            usage.network_rx_bytes =
                Counter::try_from(accumulated.rx_bytes.saturating_add(current.rx_bytes)).map_err(
                    |_| sandsurf_control::Error::Protocol("network receive accounting overflow"),
                )?;
            usage.network_tx_bytes =
                Counter::try_from(accumulated.tx_bytes.saturating_add(current.tx_bytes)).map_err(
                    |_| sandsurf_control::Error::Protocol("network transmit accounting overflow"),
                )?;
            usage.network_connections =
                Counter::try_from(accumulated.connections.saturating_add(current.connections))
                    .map_err(|_| {
                        sandsurf_control::Error::Protocol("network connection accounting overflow")
                    })?;
        }
        Ok(response)
    }

    fn native_checkpoint(
        &mut self,
        request: NativeCheckpointRequest,
        journal: &mut RuntimeJournal,
    ) -> ControlResult<NativeCheckpointResponse> {
        match request {
            NativeCheckpointRequest::PrepareFull {
                checkpoint_id,
                operation_id,
            } => self.prepare_full_capture(checkpoint_id, operation_id, journal),
            NativeCheckpointRequest::FinishFull { operation_id } => {
                self.machine.resume_after_capture().map_err(|_| {
                    ControlError::Unsupported("native VM could not resume after full capture")
                })?;
                let response = self.finish_filesystem_capture(operation_id.clone())?;
                if !matches!(
                    response,
                    GuestServiceResponse::FilesystemCaptureFinished { .. }
                ) {
                    return Err(ControlError::Protocol(
                        "guest did not release the full capture barrier",
                    ));
                }
                if self.capture_origin_was_paused {
                    self.machine
                        .restore_public_pause_after_capture()
                        .map_err(|_| {
                            ControlError::Unsupported(
                                "native VM could not restore the published pause",
                            )
                        })?;
                    self.capture_origin_was_paused = false;
                }
                remove_full_capture(&self.sandbox_root, &operation_id)?;
                Ok(NativeCheckpointResponse::Complete {
                    evidence: bytes_digest(b"firecracker-full-capture-finished-v1"),
                })
            }
            NativeCheckpointRequest::CommitSuspend {
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
                Ok(NativeCheckpointResponse::Complete {
                    evidence: digest(
                        Domain::Checkpoint,
                        &(
                            "sandsurf-firecracker-suspend-commit-v1",
                            operation_id,
                            manifest_digest,
                        ),
                    )
                    .map_err(|_| ControlError::Protocol("suspend evidence digest failed"))?,
                })
            }
            NativeCheckpointRequest::StageRestore {
                checkpoint_id,
                manifest_digest,
                workload_disk,
                expected,
            } => self.stage_full_restore(checkpoint_id, manifest_digest, workload_disk, *expected),
        }
    }

    fn rebind_restored_runtime(
        &mut self,
        journal: &mut RuntimeJournal,
        epoch: Counter,
    ) -> sandsurf_state::Result<()> {
        let lineage = self
            .restore_lineage
            .take()
            .ok_or(sandsurf_state::Error::Conflict(
                "restored native VM has no staged process lineage",
            ))?;
        journal.rebind_processes(
            &lineage.checkpoint_id,
            &lineage.source_sandbox_id,
            lineage.source_epoch,
            epoch,
        )
    }

    fn live_observation_reachable(&mut self) -> bool {
        self.machine.has_live_owner()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReconnectState {
    format_version: u16,
    checkpoint_id: sandsurf_protocol::CheckpointId,
    capture_operation_id: sandsurf_protocol::OperationId,
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

impl LinuxGuardianEffect {
    fn stage_full_restore(
        &mut self,
        checkpoint_id: sandsurf_protocol::CheckpointId,
        manifest_digest: Digest,
        workload_disk: CheckpointArtifact,
        expected: sandsurf_protocol::FullCheckpointMetadata,
    ) -> ControlResult<NativeCheckpointResponse> {
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
                "full checkpoint is incompatible with this Firecracker configuration",
            ));
        }
        let host_root = self
            .sandbox_root
            .parent()
            .and_then(Path::parent)
            .ok_or(ControlError::Protocol("sandbox root has no host root"))?;
        let directory = host_root.join("checkpoints").join(checkpoint_id.as_str());
        let artifacts = [
            ("workload-state.ext4", &workload_disk),
            ("control-state.ext4", &expected.control_disk),
            ("snapshot.vmstate", &expected.snapshot_state),
            ("memory", &expected.memory),
            ("reconnect.json", &expected.reconnect_state),
        ];
        for (name, artifact) in artifacts {
            let actual =
                crate::checkpoints::file_digest(&directory.join(name), artifact.bytes.get())
                    .map_err(|_| ControlError::Protocol("full checkpoint artifact is corrupt"))?;
            if actual != artifact.digest {
                return Err(ControlError::Protocol(
                    "full checkpoint artifact digest mismatch",
                ));
            }
        }
        for (path, artifact) in [
            (
                self.sandbox_root.join("disks/workload-state.ext4"),
                &workload_disk,
            ),
            (
                self.sandbox_root.join("disks/control-state.ext4"),
                &expected.control_disk,
            ),
        ] {
            if crate::checkpoints::file_digest(&path, artifact.bytes.get())
                .map_err(|_| ControlError::Protocol("restore disk is unavailable"))?
                != artifact.digest
            {
                return Err(ControlError::Unsupported(
                    "mutable disks no longer match the suspended full checkpoint",
                ));
            }
        }
        let reconnect: ReconnectState =
            read_json(&directory.join("reconnect.json"), 1024 * 1024)
                .map_err(|_| ControlError::Protocol("restore reconnect state is invalid"))?;
        if reconnect.checkpoint_id != checkpoint_id {
            return Err(ControlError::Protocol(
                "restore reconnect identity does not match checkpoint",
            ));
        }
        let source_sandbox_id = reconnect.sandbox_id.clone();
        let source_epoch = reconnect.epoch;
        let capture_operation_id = reconnect.capture_operation_id.clone();
        self.machine
            .stage_restore(FirecrackerRestoreSource {
                checkpoint_id: checkpoint_id.clone(),
                capture_operation_id: reconnect.capture_operation_id,
                source_sandbox_id: reconnect.sandbox_id,
                source_epoch: reconnect.epoch,
                manifest_digest: manifest_digest.clone(),
                snapshot_state: directory.join("snapshot.vmstate"),
                snapshot_memory: directory.join("memory"),
                reconnect_state: directory.join("reconnect.json"),
            })
            .map_err(|_| ControlError::Unsupported("native restore stage conflicts"))?;
        self.restore_lineage = Some(RestoreLineage {
            checkpoint_id: checkpoint_id.clone(),
            source_sandbox_id,
            source_epoch,
            capture_operation_id,
        });
        Ok(NativeCheckpointResponse::Complete {
            evidence: digest(
                Domain::Checkpoint,
                &(
                    "sandsurf-firecracker-restore-staged-v1",
                    checkpoint_id,
                    manifest_digest,
                    expected.generation,
                ),
            )
            .map_err(|_| ControlError::Protocol("restore stage evidence digest failed"))?,
        })
    }

    fn prepare_full_capture(
        &mut self,
        checkpoint_id: sandsurf_protocol::CheckpointId,
        operation_id: sandsurf_protocol::OperationId,
        journal: &mut RuntimeJournal,
    ) -> ControlResult<NativeCheckpointResponse> {
        let state = journal
            .last_observation()
            .map_err(ControlError::State)?
            .ok_or(ControlError::Protocol(
                "full capture has no machine observation",
            ))?
            .value()
            .state;
        if !matches!(state, MachineState::Running | MachineState::Paused) {
            return Err(ControlError::Unsupported(
                "full capture requires a running or paused machine",
            ));
        }
        let public_paused = state == MachineState::Paused;
        let directory = full_capture_directory(&self.sandbox_root, &operation_id);
        if directory.join("capture.json").exists() {
            self.capture_origin_was_paused = public_paused;
            let capture: NativeFullCapture =
                read_json(&directory.join("capture.json"), 1024 * 1024)
                    .map_err(|_| ControlError::Protocol("retained full capture is invalid"))?;
            return Ok(NativeCheckpointResponse::Prepared {
                capture,
                processes: process_watermarks(journal)?,
            });
        }
        if public_paused {
            self.machine
                .resume_public_pause_for_capture()
                .map_err(|_| {
                    ControlError::Unsupported(
                        "native VM could not coordinate capture from a published pause",
                    )
                })?;
            self.capture_origin_was_paused = true;
        }
        let response = match self
            .workload
            .query(GuestServiceRequest::PrepareFilesystemCapture {
                operation_id: operation_id.clone(),
            }) {
            Ok(value) => value,
            Err(error) => {
                if public_paused {
                    let _ = self.machine.restore_public_pause_after_capture();
                    self.capture_origin_was_paused = false;
                }
                return Err(error);
            }
        };
        if !matches!(
            response,
            GuestServiceResponse::FilesystemCapturePrepared { .. }
        ) {
            if public_paused {
                let _ = self.machine.restore_public_pause_after_capture();
                self.capture_origin_was_paused = false;
            }
            return Err(ControlError::Protocol(
                "guest did not establish a full capture barrier",
            ));
        }
        // Close the stream race after workload freeze and before VM pause.
        if let Err(error) = self.workload.reconcile(journal) {
            let _ = self.finish_filesystem_capture(operation_id.clone());
            if public_paused {
                let _ = self.machine.restore_public_pause_after_capture();
                self.capture_origin_was_paused = false;
            }
            return Err(ControlError::State(error));
        }
        let snapshot = match self.machine.create_full_snapshot(&operation_id) {
            Ok(value) => value,
            Err(_) => {
                let _ = self.machine.resume_after_capture();
                let _ = self.finish_filesystem_capture(operation_id);
                if public_paused {
                    let _ = self.machine.restore_public_pause_after_capture();
                    self.capture_origin_was_paused = false;
                }
                return Err(ControlError::Unsupported(
                    "Firecracker could not create a full snapshot",
                ));
            }
        };
        let result = (|| -> Result<NativeFullCapture, LinuxError> {
            crate::checkpoints::private_directory(
                directory
                    .parent()
                    .ok_or_else(|| LinuxError::Invalid("capture root has no parent".into()))?,
            )
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            crate::checkpoints::private_directory(&directory)
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let snapshot_state = directory.join("snapshot.vmstate");
            let memory = directory.join("memory");
            let state_digest = crate::checkpoints::copy_and_verify(
                &snapshot.snapshot_state,
                &snapshot_state,
                snapshot.state_bytes,
                None,
            )
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let memory_digest = crate::checkpoints::copy_and_verify(
                &snapshot.snapshot_memory,
                &memory,
                snapshot.memory_bytes,
                None,
            )
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let active = self.workload.endpoint().ok_or_else(|| {
                LinuxError::Invalid("guest reconnect state is unavailable".into())
            })?;
            let reconnect = ReconnectState {
                format_version: 1,
                checkpoint_id: checkpoint_id.clone(),
                capture_operation_id: operation_id.clone(),
                sandbox_id: active.sandbox_id,
                epoch: active.epoch,
                boot_identity: active.boot_identity,
                capability: active.capability,
                network_capability: active.network_capability,
            };
            let reconnect_path = directory.join("reconnect.json");
            write_private_json(&reconnect_path, &reconnect)?;
            let reconnect_bytes = reconnect_path.metadata()?.len();
            let reconnect_digest =
                crate::checkpoints::file_digest(&reconnect_path, reconnect_bytes)
                    .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let configuration_digest = firecracker_configuration_digest(&self.config)
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            let generation = digest(
                Domain::Checkpoint,
                &(
                    "sandsurf-full-capture-generation-v1",
                    checkpoint_id,
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
                snapshot_state: CheckpointArtifact {
                    digest: state_digest,
                    bytes: Counter::try_from(snapshot.state_bytes)
                        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                },
                memory: CheckpointArtifact {
                    digest: memory_digest,
                    bytes: Counter::try_from(snapshot.memory_bytes)
                        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                },
                reconnect_state: CheckpointArtifact {
                    digest: reconnect_digest,
                    bytes: Counter::try_from(reconnect_bytes)
                        .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                },
                generation,
            };
            write_private_json(&directory.join("capture.json"), &capture)?;
            crate::checkpoints::sync_directory(&directory)
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            Ok(capture)
        })();
        match result {
            Ok(capture) => Ok(NativeCheckpointResponse::Prepared {
                capture,
                processes: process_watermarks(journal)?,
            }),
            Err(error) => {
                let _ = self.machine.resume_after_capture();
                let _ = self.finish_filesystem_capture(operation_id);
                if public_paused {
                    let _ = self.machine.restore_public_pause_after_capture();
                    self.capture_origin_was_paused = false;
                }
                Err(ControlError::Rejected {
                    category: "checkpoint".into(),
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
        Domain::Checkpoint,
        &(
            "sandsurf-firecracker-configuration-v1",
            &config.image_digest,
            &config.firecracker_sha256,
            &config.resources,
            config.guest_cid,
            sandbox_guest::GUEST_PROTOCOL_MAJOR,
            sandbox_guest::GUEST_PROTOCOL_MINOR,
        ),
    )
}

fn process_watermarks(journal: &RuntimeJournal) -> ControlResult<Vec<CheckpointProcessWatermark>> {
    journal
        .process_snapshots()
        .map_err(ControlError::State)?
        .into_iter()
        .map(|snapshot| {
            let output = journal
                .process_boundary(&snapshot.request.process_id)
                .map_err(ControlError::State)?;
            Ok(CheckpointProcessWatermark { snapshot, output })
        })
        .collect()
}

fn full_capture_directory(
    sandbox_root: &Path,
    operation_id: &sandsurf_protocol::OperationId,
) -> PathBuf {
    sandbox_root
        .join("guardian/full-captures")
        .join(operation_id.as_str())
}

fn remove_full_capture(
    sandbox_root: &Path,
    operation_id: &sandsurf_protocol::OperationId,
) -> ControlResult<()> {
    let directory = full_capture_directory(sandbox_root, operation_id);
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

fn network_rules(
    policy: &NetworkPolicy,
) -> Result<sandbox_network_broker::BrokerPolicy, LinuxError> {
    policy
        .validate()
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let mut rules = sandbox_network_broker::BrokerPolicy::default();
    for rule in &policy.rules {
        let destination = match &rule.destination {
            NetworkDestination::Dns {
                name,
                include_subdomains,
                allow_private_addresses,
            } => sandbox_policy::ManagedNetworkDestination::Dns {
                name: sandbox_policy::normalize_dns_name(name)
                    .map_err(|error| LinuxError::Invalid(error.to_string()))?,
                include_subdomains: *include_subdomains,
                allow_private_addresses: *allow_private_addresses,
            },
            NetworkDestination::Ip { cidr } => {
                sandbox_policy::ManagedNetworkDestination::Ip { cidr: cidr.clone() }
            }
        };
        let ports = rule
            .ports
            .iter()
            .map(|range| {
                if range.from == range.to {
                    sandbox_policy::ManagedNetworkPort::Single(range.from)
                } else {
                    sandbox_policy::ManagedNetworkPort::Range {
                        from: range.from,
                        to: range.to,
                    }
                }
            })
            .collect();
        let managed = sandbox_policy::ManagedNetworkRule {
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

#[derive(Clone)]
struct ActiveGuest {
    socket: PathBuf,
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

struct PendingGuest {
    epoch: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

struct PendingRestore {
    source: ReconnectState,
    next: PendingGuest,
    checkpoint_id: sandsurf_protocol::CheckpointId,
    capture_operation_id: sandsurf_protocol::OperationId,
    generation_seed: [u8; 32],
}

struct LinuxEpochFactory {
    config: LinuxGuardianConfig,
    sandbox_root: PathBuf,
    kernel: PathBuf,
    bootstrap: PathBuf,
    workload: PathBuf,
    workload_state: PathBuf,
    control_state: PathBuf,
    active: Arc<Mutex<Option<ActiveGuest>>>,
    pending: Option<PendingGuest>,
    pending_restore: Option<PendingRestore>,
}

impl FirecrackerEpochFactory for LinuxEpochFactory {
    fn configuration(
        &mut self,
        sandbox_id: &SandboxId,
        epoch: Counter,
    ) -> Result<FirecrackerConfig, Digest> {
        if *sandbox_id != self.config.sandbox_id
            || self.pending.is_some()
            || self.pending_restore.is_some()
        {
            return Err(bytes_digest(b"linux-epoch-factory-identity-conflict"));
        }
        let capability = random_bytes().map_err(|_| bytes_digest(b"linux-boot-entropy"))?;
        let network_capability =
            random_bytes().map_err(|_| bytes_digest(b"linux-network-entropy"))?;
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-linux-boot-v1",
                &self.config.image_digest,
                &self.config.firecracker_sha256,
                sandbox_guest::GUEST_PROTOCOL_MAJOR,
                sandbox_guest::GUEST_PROTOCOL_MINOR,
            ),
        )
        .map_err(|_| bytes_digest(b"linux-boot-identity"))?;
        let nonce = hex(&random_bytes().map_err(|_| bytes_digest(b"linux-boot-entropy"))?);
        let guardian = self.sandbox_root.join("guardian");
        let authentication_image = guardian.join(format!("auth-{}-{nonce}.img", epoch.get()));
        write_authentication(
            &authentication_image,
            sandbox_id,
            epoch,
            &boot_identity,
            &capability,
            &network_capability,
        )
        .map_err(|_| bytes_digest(b"linux-authentication-disk"))?;
        let state_directory = guardian.join(format!("vm-{}-{nonce}", epoch.get()));
        let owner_token = hex(&random_bytes().map_err(|_| bytes_digest(b"linux-owner-entropy"))?);
        self.pending = Some(PendingGuest {
            epoch,
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
            rootfs_image: self.bootstrap.clone(),
            workload_image: self.workload.clone(),
            workspace_image: self.workload_state.clone(),
            control_image: self.control_state.clone(),
            authentication_image,
            owner_token,
            guest_cid: self.config.guest_cid,
            guest_port: GUEST_CONTROL_PORT,
            vcpu_count: u8::try_from(self.config.resources.vcpus.get())
                .map_err(|_| bytes_digest(b"linux-vcpu-overflow"))?,
            memory_mib: u32::try_from(self.config.resources.memory_mib.get())
                .map_err(|_| bytes_digest(b"linux-memory-overflow"))?,
        })
    }

    fn authenticate(
        &mut self,
        sandbox_id: &SandboxId,
        epoch: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"linux-boot-capability-missing"))?;
        if pending.epoch != epoch || *sandbox_id != self.config.sandbox_id {
            return Err(bytes_digest(b"linux-boot-capability-mismatch"));
        }
        let active = ActiveGuest {
            socket: process.vsock_path.clone(),
            sandbox_id: sandbox_id.clone(),
            epoch,
            boot_identity: pending.boot_identity,
            capability: pending.capability,
            network_capability: pending.network_capability,
        };
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if process.has_exited().unwrap_or(true) {
                return Err(bytes_digest(
                    b"firecracker-exited-before-guest-authentication",
                ));
            }
            let mut client = guest_client(&active);
            let failure = match client.call(&GuestServiceRequest::ProbeIdentity) {
                Ok(GuestServiceResponse::Identity {
                    sandbox_id: observed_sandbox,
                    epoch: observed_epoch,
                    boot_identity,
                }) if observed_sandbox == *sandbox_id
                    && observed_epoch == epoch
                    && boot_identity == active.boot_identity =>
                {
                    let memory = self
                        .config
                        .resources
                        .memory_mib
                        .get()
                        .checked_mul(1024 * 1024)
                        .ok_or_else(|| bytes_digest(b"guest-memory-envelope-overflow"))?;
                    if !matches!(
                        guest_client(&active).call(&GuestServiceRequest::ApplyResources {
                            resources: LiveResourceLimits {
                                workload_memory_bytes: Counter::try_from(memory).map_err(|_| {
                                    bytes_digest(b"guest-memory-envelope-overflow")
                                })?,
                                workload_processes: self.config.resources.processes,
                                cpu_max: None,
                            },
                        }),
                        Ok(GuestServiceResponse::ResourcesApplied { .. })
                    ) {
                        return Err(bytes_digest(b"guest-resource-envelope-apply"));
                    }
                    let evidence = digest(
                        Domain::Operation,
                        &(
                            "sandsurf-guest-authenticated-v1",
                            sandbox_id,
                            epoch,
                            &active.boot_identity,
                        ),
                    )
                    .map_err(|_| bytes_digest(b"guest-authentication-evidence"))?;
                    *self
                        .active
                        .lock()
                        .map_err(|_| bytes_digest(b"guest-endpoint-lock"))? = Some(active);
                    return Ok(evidence);
                }
                Ok(_) => "guest returned an unexpected authentication probe".into(),
                Err(error) => error.to_string(),
            };
            if Instant::now() >= deadline {
                eprintln!(
                    "sandsurf guest authentication deadline elapsed: {}",
                    failure
                );
                return Err(bytes_digest(b"guest-authentication-timeout"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn prepare_stop(&mut self, sandbox_id: &SandboxId, epoch: Counter) -> Result<Digest, Digest> {
        let active = self
            .active
            .lock()
            .map_err(|_| bytes_digest(b"guest-endpoint-lock"))?
            .clone()
            .ok_or_else(|| bytes_digest(b"guest-stop-endpoint-missing"))?;
        if active.sandbox_id != *sandbox_id || active.epoch != epoch {
            return Err(bytes_digest(b"guest-stop-epoch-mismatch"));
        }
        match guest_client(&active).call(&GuestServiceRequest::PrepareStop) {
            Ok(GuestServiceResponse::ReadyToStop { evidence }) => Ok(evidence),
            _ => Err(bytes_digest(b"guest-stop-barrier-unconfirmed")),
        }
    }

    fn restore_configuration(
        &mut self,
        sandbox_id: &SandboxId,
        epoch: Counter,
        source: &FirecrackerRestoreSource,
    ) -> Result<(FirecrackerConfig, FirecrackerRestore), Digest> {
        if self.pending_restore.is_some() {
            return Err(bytes_digest(b"linux-restore-already-pending"));
        }
        let reconnect: ReconnectState = read_json(&source.reconnect_state, 1024 * 1024)
            .map_err(|_| bytes_digest(b"linux-restore-reconnect-state-invalid"))?;
        if reconnect.format_version != 1
            || reconnect.checkpoint_id != source.checkpoint_id
            || reconnect.capture_operation_id != source.capture_operation_id
            || reconnect.sandbox_id != source.source_sandbox_id
            || reconnect.epoch != source.source_epoch
        {
            return Err(bytes_digest(b"linux-restore-reconnect-identity-mismatch"));
        }
        let configuration = self.configuration(sandbox_id, epoch)?;
        let next = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"linux-restore-next-capability-missing"))?;
        let generation_seed = random_bytes().map_err(|_| bytes_digest(b"linux-restore-entropy"))?;
        self.pending_restore = Some(PendingRestore {
            source: reconnect,
            next,
            checkpoint_id: source.checkpoint_id.clone(),
            capture_operation_id: source.capture_operation_id.clone(),
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

    fn authenticate_restore(
        &mut self,
        sandbox_id: &SandboxId,
        epoch: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest> {
        let pending = self
            .pending_restore
            .take()
            .ok_or_else(|| bytes_digest(b"linux-restore-capability-missing"))?;
        if pending.next.epoch != epoch || *sandbox_id != self.config.sandbox_id {
            return Err(bytes_digest(b"linux-restore-target-identity-mismatch"));
        }
        let source = ActiveGuest {
            socket: process.vsock_path.clone(),
            sandbox_id: pending.source.sandbox_id.clone(),
            epoch: pending.source.epoch,
            boot_identity: pending.source.boot_identity.clone(),
            capability: pending.source.capability,
            network_capability: pending.source.network_capability,
        };
        let active = ActiveGuest {
            socket: process.vsock_path.clone(),
            sandbox_id: sandbox_id.clone(),
            epoch,
            boot_identity: pending.next.boot_identity.clone(),
            capability: pending.next.capability,
            network_capability: pending.next.network_capability,
        };
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if process.has_exited().unwrap_or(true) {
                return Err(bytes_digest(b"firecracker-exited-before-guest-rebind"));
            }
            let response = guest_client(&source).call(&GuestServiceRequest::RebindEpoch {
                checkpoint_id: pending.checkpoint_id.clone(),
                capture_operation_id: pending.capture_operation_id.clone(),
                sandbox_id: sandbox_id.clone(),
                previous_epoch: pending.source.epoch,
                epoch,
                boot_identity: pending.next.boot_identity.clone(),
                capability: pending.next.capability,
                network_capability: pending.next.network_capability,
                generation_seed: pending.generation_seed,
            });
            match response {
                Ok(GuestServiceResponse::EpochRebound { .. }) => break,
                Ok(other) => {
                    // The epoch rotation is an exact, durable guest mutation.
                    // If its response was lost, the old capability is already
                    // invalid; authenticate with the fresh identity instead of
                    // replaying or declaring failure.
                    if restored_identity_matches(&active) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        eprintln!("sandsurf guest rebind deadline: unexpected response {other:?}");
                        return Err(bytes_digest(b"guest-restore-rebind-timeout"));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => {
                    if restored_identity_matches(&active) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        eprintln!("sandsurf guest rebind deadline: {error}");
                        return Err(bytes_digest(b"guest-restore-rebind-timeout"));
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
        let authentication_deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let authentication_failure =
                match guest_client(&active).call(&GuestServiceRequest::ProbeIdentity) {
                    Ok(GuestServiceResponse::Identity {
                        sandbox_id: observed_sandbox,
                        epoch: observed_epoch,
                        boot_identity,
                    }) if observed_sandbox == active.sandbox_id
                        && observed_epoch == active.epoch
                        && boot_identity == active.boot_identity =>
                    {
                        break;
                    }
                    Ok(other) => format!("unexpected response: {other:?}"),
                    Err(error) => error.to_string(),
                };
            if process.has_exited().unwrap_or(true) {
                return Err(bytes_digest(b"firecracker-exited-after-guest-rebind"));
            }
            if Instant::now() >= authentication_deadline {
                eprintln!(
                    "sandsurf fresh restored guest authentication deadline: {authentication_failure}"
                );
                return Err(bytes_digest(b"guest-restore-new-capability-rejected"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let memory = self
            .config
            .resources
            .memory_mib
            .get()
            .checked_mul(1024 * 1024)
            .ok_or_else(|| bytes_digest(b"guest-memory-envelope-overflow"))?;
        let resources = LiveResourceLimits {
            workload_memory_bytes: Counter::try_from(memory)
                .map_err(|_| bytes_digest(b"guest-memory-envelope-overflow"))?,
            workload_processes: self.config.resources.processes,
            cpu_max: None,
        };
        let resource_deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if matches!(
                guest_client(&active).call(&GuestServiceRequest::ApplyResources {
                    resources: resources.clone(),
                }),
                Ok(GuestServiceResponse::ResourcesApplied { .. })
            ) {
                break;
            }
            if process.has_exited().unwrap_or(true) || Instant::now() >= resource_deadline {
                return Err(bytes_digest(b"guest-restore-resource-envelope-apply"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let evidence = digest(
            Domain::Operation,
            &(
                "sandsurf-guest-restored-and-rebound-v1",
                sandbox_id,
                epoch,
                &pending.checkpoint_id,
                &active.boot_identity,
                bytes_digest(&pending.generation_seed),
            ),
        )
        .map_err(|_| bytes_digest(b"guest-restore-evidence"))?;
        *self
            .active
            .lock()
            .map_err(|_| bytes_digest(b"guest-endpoint-lock"))? = Some(active);
        Ok(evidence)
    }
}

struct LinuxWorkload {
    active: Arc<Mutex<Option<ActiveGuest>>>,
}

impl LinuxWorkload {
    fn endpoint(&self) -> Option<ActiveGuest> {
        self.active.lock().ok()?.clone()
    }
}

impl WorkloadDriver for LinuxWorkload {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        let Some(active) = self.endpoint() else {
            return EffectOutcome::NotApplied(bytes_digest(b"guest-machine-not-running"));
        };
        RemoteWorkloadDriver::new(guest_client(&active)).dispatch(mutation, capability)
    }

    fn reconcile(&mut self, journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        if let Some(active) = self.endpoint() {
            RemoteWorkloadDriver::new(guest_client(&active)).reconcile(journal)?;
        }
        Ok(())
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        let active = self.endpoint().ok_or(ControlError::Unsupported(
            "guest is unavailable because the machine has no live owner",
        ))?;
        RemoteWorkloadDriver::new(guest_client(&active)).query(request)
    }
}

fn guest_client(active: &ActiveGuest) -> GuestClient<UnixVsockChannel> {
    GuestClient::new(
        UnixVsockChannel {
            socket_path: active.socket.clone(),
            guest_port: GUEST_CONTROL_PORT,
            timeout: Duration::from_secs(10),
        },
        active.sandbox_id.clone(),
        active.epoch,
        active.boot_identity.clone(),
        active.capability,
    )
}

fn restored_identity_matches(active: &ActiveGuest) -> bool {
    matches!(
        guest_client(active).call(&GuestServiceRequest::ProbeIdentity),
        Ok(GuestServiceResponse::Identity {
            sandbox_id,
            epoch,
            boot_identity,
        }) if sandbox_id == active.sandbox_id
            && epoch == active.epoch
            && boot_identity == active.boot_identity
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

fn install_image(
    host_root: &Path,
    image: &sandbox_image::VerifiedImage,
    template: &Path,
) -> Result<PathBuf, LinuxError> {
    let root = host_root.join("images").join(&image.manifest_digest);
    if root.exists() {
        let installed = verify_image(&root.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if installed.manifest_digest != image.manifest_digest
            || sha256_file(&root.join("empty-workspace.ext4"), 128 * 1024 * 1024 * 1024)?
                != sha256_file(template, 128 * 1024 * 1024 * 1024)?
        {
            return Err(LinuxError::Invalid(
                "installed image identity conflicts with source".into(),
            ));
        }
        return Ok(root);
    }
    let staging = host_root
        .join("images")
        .join(format!("stage-{}", hex(&random_bytes()?)));
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let result: Result<(), LinuxError> = (|| {
        copy_artifact(&image.manifest_path, &staging.join("manifest.json"))?;
        copy_artifact(
            &image.kernel_path,
            &staging.join(&image.manifest.boot_bundle.kernel.path),
        )?;
        copy_artifact(
            &image.bootstrap_path,
            &staging.join(&image.manifest.boot_bundle.bootstrap.path),
        )?;
        copy_artifact(
            &image.workload_path,
            &staging.join(&image.manifest.workload.rootfs.path),
        )?;
        copy_artifact(template, &staging.join("empty-workspace.ext4"))?;
        let copied = verify_image(&staging.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if copied.manifest_digest != image.manifest_digest {
            return Err(LinuxError::Invalid("copied image identity changed".into()));
        }
        File::open(&staging)?.sync_all()?;
        fs::rename(&staging, &root)?;
        File::open(host_root.join("images"))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok(root)
}

fn copy_artifact(source: &Path, destination: &Path) -> Result<(), LinuxError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn ensure_mutable_disk(
    source: &Path,
    destination: &Path,
    requested_bytes: u64,
) -> Result<(), LinuxError> {
    let source_metadata = fs::metadata(source)?;
    if requested_bytes < source_metadata.len()
        || !requested_bytes.is_multiple_of(4096)
        || requested_bytes > 128 * 1024 * 1024 * 1024
    {
        return Err(LinuxError::Invalid(
            "persistent disk geometry is outside the supported ext4 envelope".into(),
        ));
    }
    if destination.exists() {
        let current = fs::symlink_metadata(destination)?;
        if !current.is_file()
            || current.file_type().is_symlink()
            || current.len() != requested_bytes
        {
            return Err(LinuxError::Invalid(
                "persistent disk geometry or type changed".into(),
            ));
        }
    } else {
        copy_artifact(source, destination)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(destination)?;
        file.set_len(requested_bytes)?;
        file.sync_all()?;
    }
    if requested_bytes != source_metadata.len() {
        let resize = protected_tool(&["/usr/sbin/resize2fs", "/sbin/resize2fs"])?;
        let status = std::process::Command::new(resize)
            .arg("-f")
            .arg(destination)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !status.success() {
            return Err(LinuxError::Invalid(
                "persistent ext4 disk resize failed".into(),
            ));
        }
    }
    let fallocate = protected_tool(&["/usr/bin/fallocate", "/bin/fallocate"])?;
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

fn protected_tool(candidates: &[&str]) -> Result<PathBuf, LinuxError> {
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o022 == 0
        {
            return Ok(path);
        }
    }
    Err(LinuxError::Invalid(
        "required protected host storage tool is unavailable".into(),
    ))
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
    sandbox_id: &SandboxId,
    epoch: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
    network_capability: &[u8; 32],
) -> Result<(), LinuxError> {
    let identity = sandbox_id.as_str().as_bytes();
    let size = u16::try_from(identity.len())
        .map_err(|_| LinuxError::Invalid("sandbox identity is too long".into()))?;
    let digest = decode_hex(boot_identity.as_str())?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(AUTHENTICATION_MAGIC);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(identity);
    bytes.extend_from_slice(&epoch.get().to_be_bytes());
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
    let sandboxes = host_root.join("sandboxes");
    if sandboxes.exists() {
        for entry in fs::read_dir(&sandboxes)? {
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
