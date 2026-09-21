//! Windows guardian integration for one retained Hyper-V/HCS Linux VM.

use crate::guest::{GuestClient, RemoteWorkloadDriver};
use crate::windows_network::{WindowsNetworkBridge, WindowsPortGateway};
use sandbox_guest::{
    AUTHENTICATION_MAGIC, GUEST_BOOTSTRAP_PORT, GUEST_CONTROL_PORT, GUEST_EXPOSURE_PORT,
    NETWORK_DNS_TCP_PORT, NETWORK_DNS_UDP_PORT, NETWORK_HTTP_PORT, NETWORK_SOCKS_PORT,
};
use sandbox_image::{Architecture, ImageTrust, VerifiedImage, verify_image};
use sandsurf_control::{
    EffectOutcome, Error as ControlError, GuardianEffect, Result as ControlResult, WorkloadDriver,
};
use sandsurf_machine::windows::{
    HyperVConfig, HyperVDisk, HyperVDriver, HyperVQualification, HyperVRestoreSource,
};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_native::{GuestChannel, HyperVChannel, virtual_disk};
use sandsurf_protocol::{
    Capability, CheckpointArtifact, CheckpointProcessWatermark, Counter, Digest, Domain,
    GuestServiceRequest, GuestServiceResponse, LifecycleCommand, MachineObservation, MachineState,
    Mutation, NativeCheckpointRequest, NativeCheckpointResponse, NetworkDestination, NetworkPolicy,
    Resources, RuntimeConfiguration, SandboxId, VmEngine, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONFIG_VERSION: u16 = 1;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const BUNDLED_IMAGE_MANIFEST_DIGEST: Option<&str> =
    option_env!("SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST");

#[derive(Debug)]
pub enum WindowsError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandbox_image::ImageError),
    Invalid(String),
}

impl fmt::Display for WindowsError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "Windows guardian I/O: {error}"),
            Self::Json(error) => write!(output, "Windows guardian configuration: {error}"),
            Self::Image(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for WindowsError {}
impl From<io::Error> for WindowsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for WindowsError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandbox_image::ImageError> for WindowsError {
    fn from(value: sandbox_image::ImageError) -> Self {
        Self::Image(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsGuardianConfig {
    format_version: u16,
    sandbox_id: SandboxId,
    image_digest: Digest,
    resources: Resources,
    image_manifest: PathBuf,
    vm_id: String,
    hvsock_security_descriptor: String,
}

pub fn prepare_config(
    host_root: &Path,
    executable: &Path,
    sandbox_id: &SandboxId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<WindowsGuardianConfig, WindowsError> {
    let path = host_root
        .join("sandboxes")
        .join(sandbox_id.as_str())
        .join("guardian/config.json");
    if path.exists() {
        let existing = read_config(&path, sandbox_id)?;
        if existing.image_digest != *image_digest || existing.resources != *resources {
            return Err(WindowsError::Invalid(
                "existing Sandbox configuration conflicts with create request".into(),
            ));
        }
        return Ok(existing);
    }
    let image = resolve_source_bundle(host_root, executable, image_digest)?;
    if image.manifest.architecture != Architecture::X64 || image.windows_x64.is_none() {
        return Err(WindowsError::Invalid(
            "image has no qualified Windows x64 boot artifacts".into(),
        ));
    }
    if resources.vcpus.get() > 64
        || resources.memory_mib.get() < 256
        || resources.memory_mib.get() > 1_048_576
        || resources.disk_bytes.get() > MAX_ARTIFACT_BYTES
    {
        return Err(WindowsError::Invalid(
            "requested VM shape is outside the Hyper-V envelope".into(),
        ));
    }
    Ok(WindowsGuardianConfig {
        format_version: CONFIG_VERSION,
        sandbox_id: sandbox_id.clone(),
        image_digest: image_digest.clone(),
        resources: resources.clone(),
        image_manifest: image.manifest_path,
        vm_id: deterministic_vm_id(host_root, sandbox_id),
        hvsock_security_descriptor: sandsurf_native::local::current_user_sddl()?,
    })
}

pub fn write_config(path: &Path, config: &WindowsGuardianConfig) -> Result<(), WindowsError> {
    if path.exists() {
        return if read_json::<WindowsGuardianConfig>(path, 1024 * 1024)? == *config {
            Ok(())
        } else {
            Err(WindowsError::Invalid(
                "guardian configuration is already bound to different inputs".into(),
            ))
        };
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer(&mut file, config)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn read_config(
    path: &Path,
    sandbox_id: &SandboxId,
) -> Result<WindowsGuardianConfig, WindowsError> {
    let value: WindowsGuardianConfig = read_json(path, 1024 * 1024)?;
    if value.format_version != CONFIG_VERSION || value.sandbox_id != *sandbox_id {
        return Err(WindowsError::Invalid(
            "guardian configuration identity is invalid".into(),
        ));
    }
    let image = verify_image(&value.image_manifest, ImageTrust::ExplicitLocal)?;
    if image.manifest_digest != value.image_digest.as_str() || image.windows_x64.is_none() {
        return Err(WindowsError::Invalid(
            "guardian image artifact identity changed".into(),
        ));
    }
    Ok(value)
}

pub fn workload_defaults(
    host_root: &Path,
    image_digest: &Digest,
) -> Result<crate::api::WorkloadDefaultsView, WindowsError> {
    let image = verify_image(
        &host_root
            .join("images")
            .join(image_digest.as_str())
            .join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if image.manifest_digest != image_digest.as_str() {
        return Err(WindowsError::Invalid(
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

pub struct WindowsGuardianEffect {
    sandbox_root: PathBuf,
    config: WindowsGuardianConfig,
    machine: HyperVDriver,
    workload: WindowsWorkload,
    pending: Option<PendingGuest>,
    network: Arc<Mutex<Option<WindowsNetworkBridge>>>,
    network_usage: NetworkUsage,
    exposures: Arc<Mutex<Option<WindowsPortGateway>>>,
    installed_runtime: Option<InstalledRuntime>,
    restore_lineage: Option<RestoreLineage>,
    suspend_capture_operation: Option<sandsurf_protocol::OperationId>,
    capture_origin_was_paused: bool,
}

#[derive(Clone)]
struct ActiveGuest {
    vm_id: String,
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

struct PendingGuest {
    active: ActiveGuest,
    authentication: Vec<u8>,
}

struct WindowsWorkload {
    active: Arc<Mutex<Option<ActiveGuest>>>,
}

struct InstalledRuntime {
    epoch: Counter,
    configuration: RuntimeConfiguration,
    evidence: Digest,
}

struct RestoreLineage {
    checkpoint_id: sandsurf_protocol::CheckpointId,
    source: ReconnectState,
    staged_state: PathBuf,
    generation_seed: [u8; 32],
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

impl WindowsGuardianEffect {
    pub fn open(sandbox_root: &Path, config: WindowsGuardianConfig) -> Result<Self, WindowsError> {
        let image = verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        let windows = image
            .windows_x64
            .ok_or_else(|| WindowsError::Invalid("image has no Windows boot artifacts".into()))?;
        let disks = sandbox_root.join("disks");
        fs::create_dir_all(&disks)?;
        let workload_state = disks.join("workload-state.vhdx");
        let control_state = disks.join("control-state.vhdx");
        ensure_mutable_vhdx(
            &windows.state_template_path,
            &workload_state,
            config.resources.disk_bytes.get(),
        )?;
        let control_bytes = config
            .resources
            .output_bytes
            .get()
            .checked_add(64 * 1024 * 1024)
            .ok_or_else(|| WindowsError::Invalid("control disk size overflow".into()))?
            .max(128 * 1024 * 1024);
        ensure_mutable_vhdx(&windows.state_template_path, &control_state, control_bytes)?;
        let ports = vec![
            GUEST_BOOTSTRAP_PORT,
            GUEST_CONTROL_PORT,
            GUEST_EXPOSURE_PORT,
            NETWORK_HTTP_PORT,
            NETWORK_SOCKS_PORT,
            NETWORK_DNS_TCP_PORT,
            NETWORK_DNS_UDP_PORT,
        ];
        let machine = HyperVDriver::new(HyperVConfig {
            sandbox_id: config.sandbox_id.clone(),
            vm_id: config.vm_id.clone(),
            guest_architecture: crate::service::native_guest_architecture(),
            memory_mib: config.resources.memory_mib.get(),
            vcpus: u32::try_from(config.resources.vcpus.get())
                .map_err(|_| WindowsError::Invalid("vCPU count overflow".into()))?,
            kernel: windows.kernel_path,
            command_line:
                "console=ttyS0 reboot=k panic=1 root=/dev/sda ro init=/sbin/sandbox-guest".into(),
            disks: vec![
                HyperVDisk {
                    path: windows.bootstrap_path,
                    read_only: true,
                },
                HyperVDisk {
                    path: windows.workload_path,
                    read_only: true,
                },
                HyperVDisk {
                    path: workload_state,
                    read_only: false,
                },
                HyperVDisk {
                    path: control_state,
                    read_only: false,
                },
            ],
            hvsock_security_descriptor: config.hvsock_security_descriptor.clone(),
            hvsock_ports: ports,
            operation_timeout: HyperVDriver::default_timeout(),
            qualification: HyperVQualification {
                lifecycle: None,
                full_state: None,
            },
        })
        .map_err(|error| WindowsError::Invalid(format!("invalid Hyper-V VM: {error:?}")))?;
        let active = Arc::new(Mutex::new(None));
        Ok(Self {
            sandbox_root: sandbox_root.to_path_buf(),
            config,
            machine,
            workload: WindowsWorkload { active },
            pending: None,
            network: Arc::new(Mutex::new(None)),
            network_usage: Arc::new(Mutex::new(NetworkUsageValue::default())),
            exposures: Arc::new(Mutex::new(None)),
            installed_runtime: None,
            restore_lineage: None,
            suspend_capture_operation: None,
            capture_origin_was_paused: false,
        })
    }

    fn prepare_boot(&mut self, command: &LifecycleCommand, epoch: Counter) -> Result<(), Digest> {
        let capability = random_bytes().map_err(|_| bytes_digest(b"hyper-v-boot-entropy"))?;
        let network_capability =
            random_bytes().map_err(|_| bytes_digest(b"hyper-v-network-entropy"))?;
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-hyper-v-boot-v1",
                &command.sandbox_id,
                sandbox_guest::GUEST_PROTOCOL_MAJOR,
                sandbox_guest::GUEST_PROTOCOL_MINOR,
            ),
        )
        .map_err(|_| bytes_digest(b"hyper-v-boot-identity"))?;
        let authentication = authentication_record(
            &command.sandbox_id,
            epoch,
            &boot_identity,
            &capability,
            &network_capability,
        )
        .map_err(|_| bytes_digest(b"hyper-v-authentication-record"))?;
        self.pending = Some(PendingGuest {
            active: ActiveGuest {
                vm_id: self.machine.vm_id().to_owned(),
                sandbox_id: command.sandbox_id.clone(),
                epoch,
                boot_identity,
                capability,
                network_capability,
            },
            authentication,
        });
        Ok(())
    }

    fn authenticate_pending(&mut self) -> Result<ActiveGuest, Digest> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"hyper-v-pending-guest-missing"))?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let provisioned = HyperVChannel {
                vm_id: pending.active.vm_id.clone(),
                guest_port: GUEST_BOOTSTRAP_PORT,
                timeout: Duration::from_secs(10),
            }
            .connect()
            .and_then(|mut stream| {
                stream.write_all(&pending.authentication)?;
                stream.flush()?;
                Ok(())
            });
            if provisioned.is_ok() {
                break;
            }
            if !self.machine.has_live_owner() || Instant::now() >= deadline {
                return Err(bytes_digest(b"hyper-v-bootstrap-timeout"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        loop {
            match guest_client(&pending.active).call(&GuestServiceRequest::ProbeIdentity) {
                Ok(GuestServiceResponse::Identity {
                    sandbox_id,
                    epoch,
                    boot_identity,
                }) if sandbox_id == pending.active.sandbox_id
                    && epoch == pending.active.epoch
                    && boot_identity == pending.active.boot_identity =>
                {
                    return Ok(pending.active);
                }
                _ if !self.machine.has_live_owner() || Instant::now() >= deadline => {
                    return Err(bytes_digest(b"hyper-v-guest-authentication-timeout"));
                }
                _ => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    fn authenticate_restored(&mut self, epoch: Counter) -> Result<ActiveGuest, Digest> {
        let lineage = self
            .restore_lineage
            .as_ref()
            .ok_or_else(|| bytes_digest(b"hyper-v-restore-lineage-missing"))?;
        let pending = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"hyper-v-restore-target-capability-missing"))?;
        let active = pending.active;
        if active.epoch != epoch {
            return Err(bytes_digest(b"hyper-v-restore-target-epoch-mismatch"));
        }
        let source = ActiveGuest {
            vm_id: self.machine.vm_id().to_owned(),
            sandbox_id: lineage.source.sandbox_id.clone(),
            epoch: lineage.source.epoch,
            boot_identity: lineage.source.boot_identity.clone(),
            capability: lineage.source.capability,
            network_capability: lineage.source.network_capability,
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let response = guest_client(&source).call(&GuestServiceRequest::RebindEpoch {
                checkpoint_id: lineage.checkpoint_id.clone(),
                capture_operation_id: lineage.source.capture_operation_id.clone(),
                sandbox_id: active.sandbox_id.clone(),
                previous_epoch: lineage.source.epoch,
                epoch,
                boot_identity: active.boot_identity.clone(),
                capability: active.capability,
                network_capability: active.network_capability,
                generation_seed: lineage.generation_seed,
            });
            if matches!(response, Ok(GuestServiceResponse::EpochRebound { .. }))
                || restored_identity_matches(&active)
            {
                break;
            }
            if !self.machine.has_live_owner() || Instant::now() >= deadline {
                return Err(bytes_digest(b"hyper-v-guest-restore-rebind-timeout"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if restored_identity_matches(&active) {
                return Ok(active);
            }
            if !self.machine.has_live_owner() || Instant::now() >= deadline {
                return Err(bytes_digest(b"hyper-v-restored-guest-capability-rejected"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn finish_filesystem_capture(
        &mut self,
        operation_id: sandsurf_protocol::OperationId,
    ) -> ControlResult<GuestServiceResponse> {
        let request = GuestServiceRequest::FinishFilesystemCapture { operation_id };
        let mut last = None;
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
        let directory = hyperv_full_capture_directory(&self.sandbox_root, &operation_id);
        if directory.join("capture.json").exists() {
            self.capture_origin_was_paused = public_paused;
            let capture = read_json(&directory.join("capture.json"), 1024 * 1024)
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
                        "Hyper-V VM could not coordinate capture from a published pause",
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
        if let Err(error) = self.workload.reconcile(journal) {
            let _ = self.finish_filesystem_capture(operation_id.clone());
            if public_paused {
                let _ = self.machine.restore_public_pause_after_capture();
                self.capture_origin_was_paused = false;
            }
            return Err(ControlError::State(error));
        }
        crate::checkpoints::private_directory(
            directory
                .parent()
                .ok_or(ControlError::Protocol("capture root has no parent"))?,
        )
        .map_err(|_| ControlError::Protocol("full capture root is not private"))?;
        crate::checkpoints::private_directory(&directory)
            .map_err(|_| ControlError::Protocol("full capture directory is not private"))?;
        let saved_state = directory.join("snapshot.vmstate");
        for path in [&saved_state, &directory.join("reconnect.json")] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(ControlError::Io(error)),
            }
        }
        if self
            .machine
            .save_full_state(&operation_id, &saved_state)
            .is_err()
        {
            let _ = self.machine.resume_after_capture();
            let _ = self.finish_filesystem_capture(operation_id);
            if public_paused {
                let _ = self.machine.restore_public_pause_after_capture();
                self.capture_origin_was_paused = false;
            }
            return Err(ControlError::Unsupported(
                "HCS could not save full machine state",
            ));
        }
        let result = (|| -> Result<sandsurf_protocol::NativeFullCapture, WindowsError> {
            let active = self.workload.endpoint().ok_or_else(|| {
                WindowsError::Invalid("guest reconnect state is unavailable".into())
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
            let state_bytes = fs::metadata(&saved_state)?.len();
            let state_bound = self
                .config
                .resources
                .memory_mib
                .get()
                .checked_mul(1024 * 1024)
                .and_then(|value| value.checked_add(1024 * 1024 * 1024))
                .ok_or_else(|| WindowsError::Invalid("saved-state bound overflow".into()))?;
            if state_bytes == 0 || state_bytes > state_bound {
                return Err(WindowsError::Invalid(
                    "saved-state artifact exceeds its bound".into(),
                ));
            }
            let state_digest = crate::checkpoints::file_digest(&saved_state, state_bytes)
                .map_err(|error| WindowsError::Invalid(error.to_string()))?;
            let reconnect_bytes = fs::metadata(&reconnect_path)?.len();
            let reconnect_digest =
                crate::checkpoints::file_digest(&reconnect_path, reconnect_bytes)
                    .map_err(|error| WindowsError::Invalid(error.to_string()))?;
            let configuration_digest = hyperv_configuration_digest(&self.config)
                .map_err(|error| WindowsError::Invalid(error.to_string()))?;
            let generation = digest(
                Domain::Checkpoint,
                &(
                    "sandsurf-hyper-v-full-capture-generation-v1",
                    &checkpoint_id,
                    &operation_id,
                    &state_digest,
                    &reconnect_digest,
                ),
            )
            .map_err(|error| WindowsError::Invalid(error.to_string()))?;
            let capture = sandsurf_protocol::NativeFullCapture {
                engine: VmEngine::HyperV,
                engine_version: "hcs-schema-2.2-save-v1".into(),
                architecture: "amd64".into(),
                configuration_digest,
                snapshot_state: CheckpointArtifact {
                    digest: state_digest,
                    bytes: Counter::try_from(state_bytes)
                        .map_err(|error| WindowsError::Invalid(error.to_string()))?,
                },
                memory: None,
                reconnect_state: CheckpointArtifact {
                    digest: reconnect_digest,
                    bytes: Counter::try_from(reconnect_bytes)
                        .map_err(|error| WindowsError::Invalid(error.to_string()))?,
                },
                generation,
            };
            write_private_json(&directory.join("capture.json"), &capture)?;
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

    fn stage_full_restore(
        &mut self,
        checkpoint_id: sandsurf_protocol::CheckpointId,
        manifest_digest: Digest,
        workload_disk: CheckpointArtifact,
        expected: sandsurf_protocol::FullCheckpointMetadata,
    ) -> ControlResult<NativeCheckpointResponse> {
        let configuration_digest = hyperv_configuration_digest(&self.config)
            .map_err(|_| ControlError::Protocol("restore configuration digest failed"))?;
        if expected.engine != VmEngine::HyperV
            || expected.engine_version != "hcs-schema-2.2-save-v1"
            || expected.architecture != "amd64"
            || expected.configuration_digest != configuration_digest
            || expected.memory.is_some()
        {
            return Err(ControlError::Unsupported(
                "full checkpoint is incompatible with this Hyper-V configuration",
            ));
        }
        let host_root = self
            .sandbox_root
            .parent()
            .and_then(Path::parent)
            .ok_or(ControlError::Protocol("sandbox root has no host root"))?;
        let directory = host_root.join("checkpoints").join(checkpoint_id.as_str());
        for (name, artifact) in [
            ("workload-state.ext4", &workload_disk),
            ("control-state.ext4", &expected.control_disk),
            ("snapshot.vmstate", &expected.snapshot_state),
            ("reconnect.json", &expected.reconnect_state),
        ] {
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
                self.sandbox_root.join("disks/workload-state.vhdx"),
                &workload_disk,
            ),
            (
                self.sandbox_root.join("disks/control-state.vhdx"),
                &expected.control_disk,
            ),
        ] {
            if crate::checkpoints::current_disk_digest(&path, artifact.bytes.get())
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
        if reconnect.format_version != 1 || reconnect.checkpoint_id != checkpoint_id {
            return Err(ControlError::Protocol(
                "restore reconnect identity does not match checkpoint",
            ));
        }
        let restore_root = self.sandbox_root.join("guardian/restores");
        crate::checkpoints::private_directory(&restore_root)
            .map_err(|_| ControlError::Protocol("restore staging root is not private"))?;
        let staged_state = restore_root.join(format!("{}.vmrs", manifest_digest.as_str()));
        crate::checkpoints::copy_and_verify(
            &directory.join("snapshot.vmstate"),
            &staged_state,
            expected.snapshot_state.bytes.get(),
            Some(&expected.snapshot_state.digest),
        )
        .map_err(|_| ControlError::Protocol("saved machine state could not be staged"))?;
        self.machine
            .stage_restore(HyperVRestoreSource {
                saved_state: staged_state.clone(),
                manifest_digest: manifest_digest.clone(),
            })
            .map_err(|_| ControlError::Unsupported("native restore stage conflicts"))?;
        self.restore_lineage = Some(RestoreLineage {
            checkpoint_id: checkpoint_id.clone(),
            source: reconnect,
            staged_state,
            generation_seed: random_bytes()
                .map_err(|_| ControlError::Protocol("restore entropy unavailable"))?,
        });
        Ok(NativeCheckpointResponse::Complete {
            evidence: digest(
                Domain::Checkpoint,
                &(
                    "sandsurf-hyper-v-restore-staged-v1",
                    checkpoint_id,
                    manifest_digest,
                    expected.generation,
                ),
            )
            .map_err(|_| ControlError::Protocol("restore stage evidence digest failed"))?,
        })
    }

    fn install_runtime(&mut self, configuration: &RuntimeConfiguration) -> RuntimeInstallation {
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
                    b"hyper-v-network-policy-normalization-failed",
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
        let bridge =
            match WindowsNetworkBridge::start(&active.vm_id, active.network_capability, rules) {
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
        let gateway = match WindowsPortGateway::start(
            &active.vm_id,
            active.network_capability,
            &configuration.exposures,
        ) {
            Ok(value) => value,
            Err(_) => {
                drop(exposures);
                self.stop_data_planes();
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
                    self.stop_data_planes();
                    return RuntimeInstallation::Unknown;
                }
            };
        match digest(
            Domain::Grant,
            &(
                "sandsurf-hyper-v-runtime-configuration-v1",
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

    fn stop_data_planes(&mut self) {
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

    fn contain_unpublished(&mut self) {
        self.machine.contain_unobserved();
        self.pending = None;
        if let Ok(mut active) = self.workload.active.lock() {
            *active = None;
        }
        self.stop_data_planes();
    }
}

enum RuntimeInstallation {
    Applied(Digest),
    NotApplied(Digest),
    Unknown,
}

impl WindowsWorkload {
    fn endpoint(&self) -> Option<ActiveGuest> {
        self.active.lock().ok()?.clone()
    }
}

impl WorkloadDriver for WindowsWorkload {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        let Some(active) = self.endpoint() else {
            return EffectOutcome::NotApplied(bytes_digest(b"hyper-v-guest-not-running"));
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
            "guest is unavailable because the Hyper-V VM has no live owner",
        ))?;
        RemoteWorkloadDriver::new(guest_client(&active)).query(request)
    }
}

impl GuardianEffect for WindowsGuardianEffect {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        self.workload.dispatch(mutation, capability)
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
        let restoring = command.desired == sandsurf_protocol::DesiredState::Running
            && current.is_some_and(|value| value.state == MachineState::Suspended);
        if cold_boot || restoring {
            let epoch = match current {
                Some(value) => match value.epoch.next() {
                    Ok(value) => value,
                    Err(_) => return MachineOutcome::Unknown,
                },
                None => Counter::ONE,
            };
            if let Err(evidence) = self.prepare_boot(command, epoch) {
                return MachineOutcome::NotApplied(evidence);
            }
        }
        let mut outcome = apply_lifecycle(&mut self.machine, command, current);
        let running = matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Running)
        );
        if running {
            if cold_boot || restoring {
                let epoch = match &outcome {
                    MachineOutcome::Observed(values) => values
                        .last()
                        .map(|value| value.epoch)
                        .unwrap_or(Counter::ONE),
                    _ => Counter::ONE,
                };
                let authenticated = if restoring {
                    self.authenticate_restored(epoch)
                } else {
                    self.authenticate_pending()
                };
                match authenticated {
                    Ok(active) => {
                        if let Ok(mut endpoint) = self.workload.active.lock() {
                            *endpoint = Some(active);
                        } else {
                            self.contain_unpublished();
                            return MachineOutcome::Unknown;
                        }
                    }
                    Err(evidence) => {
                        self.contain_unpublished();
                        return MachineOutcome::NotApplied(evidence);
                    }
                }
            }
            let runtime = match self.install_runtime(&command.configuration) {
                RuntimeInstallation::Applied(value) => value,
                RuntimeInstallation::NotApplied(value) => {
                    self.contain_unpublished();
                    return MachineOutcome::NotApplied(value);
                }
                RuntimeInstallation::Unknown => {
                    self.contain_unpublished();
                    return MachineOutcome::Unknown;
                }
            };
            if let MachineOutcome::Observed(values) = &mut outcome
                && let Some(last) = values.last_mut()
            {
                match digest(
                    Domain::Grant,
                    &(
                        "sandsurf-hyper-v-running-with-configuration-v1",
                        &last.evidence_digest,
                        runtime,
                        command.revision,
                    ),
                ) {
                    Ok(evidence) => last.evidence_digest = evidence,
                    Err(_) => {
                        self.contain_unpublished();
                        return MachineOutcome::Unknown;
                    }
                }
            }
            if restoring {
                let Some(operation_id) = self
                    .restore_lineage
                    .as_ref()
                    .map(|lineage| lineage.source.capture_operation_id.clone())
                else {
                    self.contain_unpublished();
                    return MachineOutcome::Unknown;
                };
                match self.finish_filesystem_capture(operation_id) {
                    Ok(GuestServiceResponse::FilesystemCaptureFinished { .. }) => {}
                    Ok(_) | Err(_) => {
                        self.contain_unpublished();
                        return MachineOutcome::Unknown;
                    }
                }
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
            self.stop_data_planes();
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Suspended)
        ) && let Some(operation_id) = self.suspend_capture_operation.take()
            && let Err(error) = remove_hyperv_full_capture(&self.sandbox_root, &operation_id)
        {
            eprintln!("sandsurf retained Hyper-V suspend staging after cleanup failure: {error}");
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
            sandsurf_machine::ConfigurationOutcome::Applied(machine) => {
                match self.install_runtime(&command.configuration) {
                    RuntimeInstallation::Applied(runtime) => digest(
                        Domain::Grant,
                        &(
                            "sandsurf-hyper-v-configuration-applied-v1",
                            machine,
                            runtime,
                            &command.configuration,
                        ),
                    )
                    .map_or(EffectOutcome::Unknown, EffectOutcome::Applied),
                    RuntimeInstallation::NotApplied(value) => EffectOutcome::NotApplied(value),
                    RuntimeInstallation::Unknown => EffectOutcome::Unknown,
                }
            }
            sandsurf_machine::ConfigurationOutcome::NotApplied(value) => {
                EffectOutcome::NotApplied(value)
            }
            sandsurf_machine::ConfigurationOutcome::Unknown => EffectOutcome::Unknown,
        }
    }

    fn reconcile(&mut self, journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        if journal
            .last_observation()?
            .is_some_and(|value| value.value().state == MachineState::Running)
            && !self.machine.capture_is_paused()
        {
            self.workload.reconcile(journal)?;
        }
        Ok(())
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
                let _ = self
                    .workload
                    .query(GuestServiceRequest::FinishFilesystemCapture { operation_id });
                return Err(ControlError::Unsupported(
                    "Hyper-V VM could not establish the filesystem capture pause",
                ));
            }
            return Ok(response);
        }
        if let GuestServiceRequest::FinishFilesystemCapture { operation_id } = request {
            self.machine.resume_after_capture().map_err(|_| {
                ControlError::Unsupported("Hyper-V VM could not leave the filesystem capture pause")
            })?;
            return self.finish_filesystem_capture(operation_id);
        }
        let usage_requested = matches!(request, GuestServiceRequest::ResourceUsage);
        let mut response = self.workload.query(request)?;
        if usage_requested && let GuestServiceResponse::ResourceUsage { usage } = &mut response {
            let accumulated = self
                .network_usage
                .lock()
                .map_err(|_| ControlError::Protocol("network usage lock poisoned"))?;
            let current = self
                .network
                .lock()
                .map_err(|_| ControlError::Protocol("network bridge lock poisoned"))?
                .as_ref()
                .map_or_else(Default::default, WindowsNetworkBridge::snapshot);
            usage.network_rx_bytes =
                Counter::try_from(accumulated.rx_bytes.saturating_add(current.rx_bytes))
                    .map_err(|_| ControlError::Protocol("network receive accounting overflow"))?;
            usage.network_tx_bytes =
                Counter::try_from(accumulated.tx_bytes.saturating_add(current.tx_bytes))
                    .map_err(|_| ControlError::Protocol("network transmit accounting overflow"))?;
            usage.network_connections =
                Counter::try_from(accumulated.connections.saturating_add(current.connections))
                    .map_err(|_| {
                        ControlError::Protocol("network connection accounting overflow")
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
                    ControlError::Unsupported("Hyper-V VM could not resume after full capture")
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
                                "Hyper-V VM could not restore the published pause",
                            )
                        })?;
                    self.capture_origin_was_paused = false;
                }
                remove_hyperv_full_capture(&self.sandbox_root, &operation_id)?;
                Ok(NativeCheckpointResponse::Complete {
                    evidence: bytes_digest(b"hyper-v-full-capture-finished-v1"),
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
                            "native suspend capture does not match the paused Hyper-V VM",
                        )
                    })?;
                self.suspend_capture_operation = Some(operation_id.clone());
                Ok(NativeCheckpointResponse::Complete {
                    evidence: digest(
                        Domain::Checkpoint,
                        &(
                            "sandsurf-hyper-v-suspend-commit-v1",
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
                "restored Hyper-V VM has no staged process lineage",
            ))?;
        journal.rebind_processes(
            &lineage.checkpoint_id,
            &lineage.source.sandbox_id,
            lineage.source.epoch,
            epoch,
        )?;
        match fs::remove_file(&lineage.staged_state) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                eprintln!("sandsurf retained consumed Hyper-V restore state: {error}");
            }
        }
        Ok(())
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

fn hyperv_configuration_digest(
    config: &WindowsGuardianConfig,
) -> Result<Digest, sandsurf_protocol::Invalid> {
    digest(
        Domain::Checkpoint,
        &(
            "sandsurf-hyper-v-configuration-v1",
            &config.image_digest,
            &config.resources,
            &config.vm_id,
            sandbox_guest::GUEST_PROTOCOL_MAJOR,
            sandbox_guest::GUEST_PROTOCOL_MINOR,
        ),
    )
}

fn hyperv_full_capture_directory(
    sandbox_root: &Path,
    operation_id: &sandsurf_protocol::OperationId,
) -> PathBuf {
    sandbox_root
        .join("guardian/full-captures")
        .join(operation_id.as_str())
}

fn remove_hyperv_full_capture(
    sandbox_root: &Path,
    operation_id: &sandsurf_protocol::OperationId,
) -> ControlResult<()> {
    let directory = hyperv_full_capture_directory(sandbox_root, operation_id);
    for name in ["capture.json", "reconnect.json", "snapshot.vmstate"] {
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

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), WindowsError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn guest_client(active: &ActiveGuest) -> GuestClient<HyperVChannel> {
    GuestClient::new(
        HyperVChannel {
            vm_id: active.vm_id.clone(),
            guest_port: GUEST_CONTROL_PORT,
            timeout: Duration::from_secs(10),
        },
        active.sandbox_id.clone(),
        active.epoch,
        active.boot_identity.clone(),
        active.capability,
    )
}

fn authentication_record(
    sandbox_id: &SandboxId,
    epoch: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
    network_capability: &[u8; 32],
) -> Result<Vec<u8>, WindowsError> {
    let identity = sandbox_id.as_str().as_bytes();
    let size = u16::try_from(identity.len())
        .map_err(|_| WindowsError::Invalid("sandbox identity is too long".into()))?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(AUTHENTICATION_MAGIC);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(identity);
    bytes.extend_from_slice(&epoch.get().to_be_bytes());
    bytes.extend_from_slice(&decode_hex(boot_identity.as_str())?);
    bytes.extend_from_slice(capability);
    bytes.extend_from_slice(network_capability);
    bytes.resize(512, 0);
    Ok(bytes)
}

fn network_rules(
    policy: &NetworkPolicy,
) -> Result<sandbox_network_broker::BrokerPolicy, WindowsError> {
    policy
        .validate()
        .map_err(|error| WindowsError::Invalid(error.to_string()))?;
    let mut rules = sandbox_network_broker::BrokerPolicy::default();
    for rule in &policy.rules {
        let destination = match &rule.destination {
            NetworkDestination::Dns {
                name,
                include_subdomains,
                allow_private_addresses,
            } => sandbox_policy::ManagedNetworkDestination::Dns {
                name: sandbox_policy::normalize_dns_name(name)
                    .map_err(|error| WindowsError::Invalid(error.to_string()))?,
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

fn ensure_mutable_vhdx(source: &Path, destination: &Path, bytes: u64) -> Result<(), WindowsError> {
    if !bytes.is_multiple_of(1024 * 1024)
        || !(64 * 1024 * 1024..=MAX_ARTIFACT_BYTES).contains(&bytes)
    {
        return Err(WindowsError::Invalid(
            "persistent VHDX geometry is outside the envelope".into(),
        ));
    }
    if !destination.exists() {
        copy_artifact(source, destination)?;
        virtual_disk::grow_virtual_disk(destination, bytes)?;
    }
    let actual = virtual_disk::virtual_disk_size(destination)?;
    if actual != bytes {
        return Err(WindowsError::Invalid(format!(
            "persistent VHDX virtual size changed: expected {bytes}, observed {actual}"
        )));
    }
    Ok(())
}

fn resolve_source_bundle(
    host_root: &Path,
    executable: &Path,
    expected: &Digest,
) -> Result<VerifiedImage, WindowsError> {
    let installed = host_root.join("images").join(expected.as_str());
    if installed.exists() {
        return Ok(verify_image(
            &installed.join("manifest.json"),
            ImageTrust::ExplicitLocal,
        )?);
    }
    let package = executable
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| WindowsError::Invalid("native package layout is invalid".into()))?;
    let relative = "minimal-x64/manifest.json";
    let index: ImageIndex = read_json(&package.join("images/manifest.json"), 1024 * 1024)?;
    let indexed = index
        .files
        .get(relative)
        .ok_or_else(|| WindowsError::Invalid("packaged image manifest is absent".into()))?;
    let pinned = BUNDLED_IMAGE_MANIFEST_DIGEST.ok_or_else(|| {
        WindowsError::Invalid("native host has no bundled image trust identity".into())
    })?;
    if indexed != pinned || expected.as_str() != pinned {
        return Err(WindowsError::Invalid(
            "packaged image index differs from the native trust identity".into(),
        ));
    }
    let image = verify_image(
        &package.join("images").join(relative),
        ImageTrust::Pinned {
            manifest_digest: pinned,
        },
    )?;
    let installed = install_image(host_root, &image)?;
    Ok(verify_image(
        &installed.join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageIndex {
    #[serde(rename = "formatVersion")]
    _format_version: u16,
    #[serde(rename = "buildId")]
    _build_id: String,
    files: BTreeMap<String, String>,
}

fn install_image(host_root: &Path, image: &VerifiedImage) -> Result<PathBuf, WindowsError> {
    let root = host_root.join("images").join(&image.manifest_digest);
    if root.exists() {
        return Ok(root);
    }
    let staging = host_root
        .join("images")
        .join(format!("stage-{}", hex(&random_bytes()?)));
    fs::create_dir(&staging)?;
    let result = (|| -> Result<(), WindowsError> {
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
        if let Some(template) = &image.manifest.workload.state_template {
            let source = image
                .manifest_path
                .parent()
                .ok_or_else(|| WindowsError::Invalid("image manifest has no parent".into()))?
                .join(&template.path);
            copy_artifact(&source, &staging.join(&template.path))?;
        }
        let windows = image
            .windows_x64
            .as_ref()
            .ok_or_else(|| WindowsError::Invalid("Windows artifacts are absent".into()))?;
        let manifest = image
            .manifest
            .platform_artifacts
            .windows_x64
            .as_ref()
            .ok_or_else(|| WindowsError::Invalid("Windows artifact metadata is absent".into()))?;
        for (source, relative) in [
            (&windows.kernel_path, &manifest.kernel.path),
            (&windows.bootstrap_path, &manifest.bootstrap.path),
            (&windows.workload_path, &manifest.workload.path),
            (&windows.state_template_path, &manifest.state_template.path),
        ] {
            copy_artifact(source, &staging.join(relative))?;
        }
        let copied = verify_image(&staging.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if copied.manifest_digest != image.manifest_digest {
            return Err(WindowsError::Invalid(
                "copied image identity changed".into(),
            ));
        }
        fs::rename(&staging, &root)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok(root)
}

fn copy_artifact(source: &Path, destination: &Path) -> Result<(), WindowsError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn deterministic_vm_id(host_root: &Path, sandbox_id: &SandboxId) -> String {
    let hash = Sha256::digest(format!("{}\0{}", host_root.display(), sandbox_id.as_str()));
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hash[..16]);
    raw[6] = (raw[6] & 0x0f) | 0x50;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[0],
        raw[1],
        raw[2],
        raw[3],
        raw[4],
        raw[5],
        raw[6],
        raw[7],
        raw[8],
        raw[9],
        raw[10],
        raw[11],
        raw[12],
        raw[13],
        raw[14],
        raw[15]
    )
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, WindowsError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(WindowsError::Invalid(
            "JSON artifact is not a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(WindowsError::Invalid("JSON artifact exceeds bound".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn random_bytes() -> Result<[u8; 32], WindowsError> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| WindowsError::Invalid("host entropy unavailable".into()))?;
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<[u8; 32], WindowsError> {
    if value.len() != 64 {
        return Err(WindowsError::Invalid("digest is malformed".into()));
    }
    let mut bytes = [0; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| WindowsError::Invalid("digest is malformed".into()))?;
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("hex formatting cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_identity_is_stable_and_canonical() {
        let sandbox: SandboxId = "box".try_into().unwrap();
        let first = deterministic_vm_id(Path::new(r"C:\Sandsurf"), &sandbox);
        let second = deterministic_vm_id(Path::new(r"C:\Sandsurf"), &sandbox);
        assert_eq!(first, second);
        assert_eq!(first.len(), 36);
        assert_eq!(&first[14..15], "5");
    }
}
