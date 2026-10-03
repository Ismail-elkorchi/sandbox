//! Guardian integration for owned QEMU HVF/WHPX computers.

use crate::capture::{
    full_directory as qemu_full_capture_directory, remove_full as remove_qemu_full_capture,
};
use crate::guardian::{
    EffectOutcome, Error as ControlError, GuardianEffect, GuestDriver, Result as ControlResult,
};
use crate::guest::{GuestClient, ManagedGuestClient, ManagementRebind, PendingRebind};
use crate::guest_transport::GuestTransport;
use sandsurf_image::{Architecture, ImageTrust, RootfsFormat, verify_image};
use sandsurf_machine::qemu::{Accelerator, LaunchConfig};
use sandsurf_machine::qemu_driver::{
    QemuBudgets, QemuConfig, QemuDriver, QemuRestoreSource, native_engine,
};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_native::serial_channel::SerialChannel;
use sandsurf_native::storage::object_name;
use sandsurf_network::NativeNetworkGateway;
use sandsurf_protocol::{BootCapability, BootIdentity};
use sandsurf_protocol::{
    Counter, Digest, Domain, GuestServiceRequest, LifecycleCommand, MachineId, MachineObservation,
    MachineState, NativeSnapshotRequest, NativeSnapshotResponse, NetworkPolicy, Resources,
    RuntimeConfiguration, SnapshotArtifact, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const CONFIG_VERSION: u16 = 1;

#[derive(Debug)]
pub enum QemuError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandsurf_image::ImageError),
    Invalid(String),
}

impl fmt::Display for QemuError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "Qemu guardian I/O: {error}"),
            Self::Json(error) => write!(output, "Qemu guardian configuration: {error}"),
            Self::Image(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for QemuError {}
impl From<io::Error> for QemuError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for QemuError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_image::ImageError> for QemuError {
    fn from(value: sandsurf_image::ImageError) -> Self {
        Self::Image(value)
    }
}

pub fn accelerator() -> Accelerator {
    if cfg!(target_os = "macos") {
        Accelerator::Hvf
    } else {
        Accelerator::Whpx
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QemuGuardianConfig {
    format_version: u16,
    machine_id: MachineId,
    image_digest: Digest,
    resources: Resources,
    runtime_manifest: PathBuf,
    runtime_digest: Digest,
    image_manifest: PathBuf,
    system_seed: PathBuf,
    system_seed_sha256: String,
}

impl QemuGuardianConfig {
    pub(crate) fn resources(&self) -> &Resources {
        &self.resources
    }
}

pub fn prepare_config(
    host_root: &Path,
    executable: &Path,
    machine_id: &MachineId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<QemuGuardianConfig, QemuError> {
    QemuBudgets::derive(resources, accelerator())?;
    crate::resources::require_network_capacity(resources)?;
    crate::resources::require_machine_storage(host_root, machine_id, resources)?;
    let existing_path = host_root
        .join("machines")
        .join(object_name(machine_id.as_str()))
        .join("guardian/config.json");
    if existing_path.exists() {
        let existing = read_config(&existing_path, machine_id)?;
        if existing.image_digest != *image_digest {
            return Err(QemuError::Invalid(
                "existing Machine configuration conflicts with create request".into(),
            ));
        }
        return Ok(existing);
    }
    let verified = crate::images::resolve_native_image(host_root, image_digest)
        .map_err(|error| QemuError::Invalid(error.to_string()))?;
    let template = verified.system_path.clone();
    if verified.manifest.architecture
        != if cfg!(target_arch = "aarch64") {
            Architecture::Arm64
        } else {
            Architecture::X64
        }
        || verified.manifest.system.rootfs.format != RootfsFormat::Ext4
    {
        return Err(QemuError::Invalid(
            "image does not satisfy the Qemu Linux guest contract".into(),
        ));
    }
    sandsurf_image::boot::validate_kernel(&verified.kernel_path, verified.manifest.architecture)?
        .require_qemu()?;
    let runtime_manifest = executable
        .parent()
        .ok_or_else(|| QemuError::Invalid("native executable has no directory".into()))?
        .join("qemu-runtime.json");
    let runtime_digest = file_digest(&runtime_manifest, 65536)?;
    sandsurf_machine::qemu_runtime::verify(
        &runtime_manifest,
        &runtime_digest,
        crate::service::native_guest_architecture(),
    )?;
    sandsurf_machine::validate_hardware(
        &native_engine(),
        resources.vcpus.get(),
        resources.memory_mib.get(),
    )?;
    Ok(QemuGuardianConfig {
        format_version: CONFIG_VERSION,
        machine_id: machine_id.clone(),
        image_digest: image_digest.clone(),
        resources: resources.clone(),
        runtime_manifest,
        runtime_digest,
        image_manifest: verified.manifest_path,
        system_seed_sha256: sha256_file(&template, 128 * 1024 * 1024 * 1024)?,
        system_seed: template,
    })
}

pub fn write_config(path: &Path, config: &QemuGuardianConfig) -> Result<(), QemuError> {
    match crate::image_records::publish(path, config) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if crate::image_records::read::<QemuGuardianConfig>(path)? == *config {
                Ok(())
            } else {
                Err(QemuError::Invalid(
                    "guardian configuration is already bound to different inputs".into(),
                ))
            }
        }
        Err(error) => Err(error.into()),
    }
}

pub fn read_config(path: &Path, machine_id: &MachineId) -> Result<QemuGuardianConfig, QemuError> {
    let value: QemuGuardianConfig = read_json(path, 1024 * 1024)?;
    if value.format_version != CONFIG_VERSION || value.machine_id != *machine_id {
        return Err(QemuError::Invalid(
            "guardian configuration identity is invalid".into(),
        ));
    }
    sandsurf_machine::qemu_runtime::verify(
        &value.runtime_manifest,
        &value.runtime_digest,
        crate::service::native_guest_architecture(),
    )?;
    let image = verify_image(&value.image_manifest, ImageTrust::ExplicitLocal)?;
    if image.manifest_digest != value.image_digest.as_str()
        || sha256_file(&value.system_seed, 128 * 1024 * 1024 * 1024)? != value.system_seed_sha256
    {
        return Err(QemuError::Invalid(
            "guardian configuration artifact identity changed".into(),
        ));
    }
    Ok(value)
}

pub struct QemuGuardianEffect {
    machine_root: PathBuf,
    config: QemuGuardianConfig,
    machine: QemuDriver,
    guest_binding: Arc<Mutex<Option<ActiveGuest>>>,
    guest_transport: Arc<GuestTransport<ActiveGuest, SerialChannel>>,
    pending: Option<ActiveGuest>,
    network: Arc<Mutex<Option<Arc<NativeNetworkGateway>>>>,
    network_usage: NetworkUsage,
    installed_runtime: Option<InstalledRuntime>,
    suspend_capture_operation: Option<sandsurf_protocol::OperationId>,
    prepared_boot: Option<crate::boot_preparation::PreparedBoot>,
}

#[derive(Clone, PartialEq, Eq)]
struct ActiveGuest {
    rebind: Option<ManagementRebind>,
    channel: Option<SerialChannel>,
    machine_id: MachineId,
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    boot_directory: PathBuf,
}

struct InstalledRuntime {
    generation: Counter,
    configuration: RuntimeConfiguration,
    evidence: Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreLineage {
    snapshot_id: sandsurf_protocol::SnapshotId,
    source: ReconnectState,
    staged_state: PathBuf,
    generation_seed: [u8; 32],
    executions: Vec<sandsurf_protocol::CapturedExecution>,
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

impl QemuGuardianEffect {
    fn management_binding(&self) -> Option<ActiveGuest> {
        self.guest_binding.lock().ok()?.clone()
    }
    pub fn open(machine_root: &Path, config: QemuGuardianConfig) -> Result<Self, QemuError> {
        let budget = QemuBudgets::derive(&config.resources, accelerator())?.guardian;
        #[cfg(target_os = "macos")]
        if sandsurf_native::resource_broker::macos::current_worker_budget()
            != Some(sandsurf_native::resource_broker::worker_budget(budget)?)
        {
            return Err(QemuError::Invalid(
                "guardian has no matching root-installed resource envelope".into(),
            ));
        }
        #[cfg(windows)]
        sandsurf_native::process_budget::windows::JobEnvelope::verify_current_factory(budget)?;
        let image = verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        let disks = machine_root.join("disks");
        ensure_private_directory(&disks)?;
        sandsurf_native::storage::sync_directory(machine_root)?;
        let system_disk = disks.join("system.ext4");
        let authentication_disk = machine_root.join("guardian/auth.img");
        let capture_directory = machine_root.join("guardian/full-captures");
        ensure_private_directory(&capture_directory)?;
        let runtime = sandsurf_machine::qemu_runtime::verify(
            &config.runtime_manifest,
            &config.runtime_digest,
            crate::service::native_guest_architecture(),
        )?;
        let qemu = QemuConfig {
            runtime_manifest: config.runtime_manifest.clone(),
            runtime_digest: config.runtime_digest.clone(),
            capture_directory,
            launch: LaunchConfig {
                accelerator: accelerator(),
                machine_id: config.machine_id.clone(),
                architecture: crate::service::native_guest_architecture(),
                kernel: image.kernel_path,
                initramfs: image.initramfs_path,
                system_disk,
                authentication_disk,
                firmware_directory: runtime.firmware_directory,
                memory_mib: u32::try_from(config.resources.memory_mib.get())
                    .map_err(io::Error::other)?,
                vcpus: u32::try_from(config.resources.vcpus.get()).map_err(io::Error::other)?,
            },
        };
        let active = Arc::new(Mutex::new(None));
        let network_usage = Arc::new(Mutex::new(NetworkUsageValue::default()));
        Ok(Self {
            machine_root: machine_root.to_path_buf(),
            config: config.clone(),
            machine: QemuDriver::new(qemu)
                .map_err(|error| QemuError::Invalid(format!("invalid Qemu VM: {error:?}")))?,
            guest_binding: active,
            guest_transport: Arc::new(GuestTransport::new(
                crate::capture::CaptureBoundary::read(machine_root)
                    .map_err(|error| QemuError::Invalid(error.to_string()))?
                    .is_some(),
            )),
            pending: None,
            network: Arc::new(Mutex::new(None)),
            network_usage,
            installed_runtime: None,
            suspend_capture_operation: None,
            prepared_boot: None,
        })
    }

    fn prepare_boot(
        &mut self,
        command: &LifecycleCommand,
        generation: Counter,
        prepared: Option<crate::boot_preparation::PreparedBoot>,
    ) -> Result<(), Digest> {
        let restoring = crate::restore::load::<RestoreLineage>(&self.machine_root)
            .map_err(|_| bytes_digest(b"qemu-restore-lineage-invalid"))?;
        let (boot_directory, boot) = if let Some(lineage) = &restoring {
            let boot_directory = self.machine_root.join("guardian").join(format!(
                "boot-{}-{}",
                generation.get(),
                random_bytes()
                    .map_err(|_| bytes_digest(b"qemu-boot-entropy"))?
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            let source = self
                .machine_root
                .join("snapshots")
                .join(object_name(lineage.snapshot_id.as_str()))
                .join("boot");
            let boot = crate::storage::copy_boot(&source, &boot_directory)
                .map_err(|_| bytes_digest(b"qemu-restore-boot-artifacts-invalid"))?;
            if boot != lineage.source.boot {
                return Err(bytes_digest(b"qemu-restore-boot-identity-mismatch"));
            }
            (boot_directory, boot)
        } else {
            prepared
                .ok_or_else(|| bytes_digest(b"qemu-prepared-boot-missing"))?
                .consume(
                    &self.machine_root,
                    &command.machine_id,
                    generation,
                    &self.config.image_digest,
                    command.configuration.resources.disk_bytes.get(),
                )?
        };
        let custody = if restoring.is_some() {
            self.machine
                .restore_custody()
                .ok_or_else(|| bytes_digest(b"qemu-restore-custody-missing"))?
        } else {
            vec![
                crate::storage::attach(&self.machine_root.join("disks/system.ext4"))
                    .map_err(|_| bytes_digest(b"qemu-system-disk-attachment-failed"))?,
            ]
        };
        let (kernel, initramfs) = sandsurf_image::boot::paths(&boot_directory, &boot);
        sandsurf_image::boot::validate_kernel(&kernel, boot.architecture)
            .and_then(|format| format.require_qemu())
            .map_err(|_| bytes_digest(b"qemu-kernel-loader-contract-invalid"))?;
        let authentication_disk = boot_directory.join("auth.img");
        self.machine
            .stage_boot_artifacts(kernel, initramfs, authentication_disk.clone())
            .map_err(|_| bytes_digest(b"qemu-boot-staging-failed"))?;
        let capability = random_bytes().map_err(|_| bytes_digest(b"qemu-boot-entropy"))?;
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-qemu-boot-v1",
                &command.machine_id,
                &boot,
                sandsurf_protocol::GUEST_PROTOCOL_MAJOR,
                sandsurf_protocol::GUEST_PROTOCOL_MINOR,
            ),
        )
        .map_err(|_| bytes_digest(b"qemu-boot-identity"))?;
        write_authentication(
            &authentication_disk,
            &command.machine_id,
            generation,
            &boot_identity,
            &capability,
        )
        .map_err(|_| bytes_digest(b"qemu-authentication-disk"))?;
        self.pending = Some(ActiveGuest {
            channel: None,
            machine_id: command.machine_id.clone(),
            generation,
            boot_identity,
            capability,
            boot_directory,
            rebind: None,
        });
        self.machine
            .stage_storage_custody(custody)
            .map_err(|_| bytes_digest(b"qemu-system-disk-custody-conflict"))?;
        Ok(())
    }

    fn bind_pending(&mut self) -> Result<ActiveGuest, Digest> {
        let mut active = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"qemu-pending-binding-missing"))?;
        active.channel = self.machine.management_channel();
        Ok(active)
    }

    fn bind_restored(&mut self, generation: Counter) -> Result<ActiveGuest, Digest> {
        let lineage = crate::restore::load::<RestoreLineage>(&self.machine_root)
            .map_err(|_| bytes_digest(b"qemu-restore-lineage-unavailable"))?
            .ok_or_else(|| bytes_digest(b"qemu-restore-lineage-missing"))?;
        let mut active = self.bind_pending()?;
        if active.generation != generation {
            return Err(bytes_digest(b"qemu-restore-binding-generation-mismatch"));
        }
        active.rebind = Some(ManagementRebind {
            machine_id: lineage.source.machine_id.clone(),
            generation: lineage.source.generation,
            boot_identity: lineage.source.boot_identity.clone(),
            capability: lineage.source.capability,
            staging: GuestServiceRequest::StageExecutionRestore {
                snapshot_id: lineage.snapshot_id.clone(),
                capture_operation_id: lineage.source.capture_operation_id.clone(),
                machine_id: active.machine_id.clone(),
                previous_generation: lineage.source.generation,
                generation,
                executions: lineage.executions.clone(),
            },
            request: GuestServiceRequest::RebindGeneration {
                snapshot_id: lineage.snapshot_id.clone(),
                capture_operation_id: lineage.source.capture_operation_id.clone(),
                machine_id: active.machine_id.clone(),
                previous_generation: lineage.source.generation,
                generation,
                boot_identity: active.boot_identity.clone(),
                capability: active.capability,
                generation_seed: lineage.generation_seed,
            },
        });
        Ok(active)
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
            observation.value(),
            journal.accepted_revision()?,
        )?;
        self.guest_transport.quiesce()?;
        let result = if boundary.preserve_pause {
            self.machine.adopt_pause_for_capture()
        } else {
            self.machine.pause_for_capture()
        };
        result.map_err(|_| ControlError::Unsupported("native capture pause failed"))
    }

    fn finish_native_capture(&mut self, journal: &RuntimeJournal) -> ControlResult<()> {
        let Some(boundary) = crate::capture::CaptureBoundary::read(&self.machine_root)? else {
            return Ok(());
        };
        self.guest_transport.quiesce()?;
        let power = self
            .machine
            .observe_power()
            .map_err(|_| ControlError::Unsupported("native capture owner unavailable"))?
            .ok_or(ControlError::Unsupported(
                "native capture owner unavailable",
            ))?;
        let observation = journal.last_observation()?.ok_or(ControlError::Protocol(
            "capture release has no native machine observation",
        ))?;
        let result = if boundary.needs_resume(
            power.state,
            observation.value(),
            journal.accepted_revision()?,
        )? {
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
            self.finish_native_capture(journal)?;
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
        let _snapshot_custody =
            crate::snapshots::retain_input(&self.machine_root.join("snapshots"), &snapshot_id)
                .map_err(|_| {
                    ControlError::Unsupported("full snapshot storage is retired or unavailable")
                })?;
        self.prepare_capture_boundary(operation_id.clone(), journal)?;
        let directory = qemu_full_capture_directory(&self.machine_root, &operation_id);
        if directory.join("capture.json").exists() {
            let capture = read_json(&directory.join("capture.json"), 1024 * 1024)
                .map_err(|_| ControlError::Protocol("retained full capture is invalid"))?;
            return Ok(NativeSnapshotResponse::Prepared { capture });
        }
        crate::capture::reset_unpublished_full(&self.machine_root, &operation_id)?;
        let boundary = crate::capture::CaptureBoundary::require(&self.machine_root, &operation_id)?
            .ok_or(ControlError::Protocol(
                "full capture has no native boundary",
            ))?;
        let executions = journal.capture_executions(boundary.generation)?;
        crate::snapshots::private_directory(
            directory
                .parent()
                .ok_or(ControlError::Protocol("capture root has no parent"))?,
        )
        .map_err(|_| ControlError::Protocol("full capture root is not private"))?;
        crate::snapshots::private_directory(&directory)
            .map_err(|_| ControlError::Protocol("full capture directory is not private"))?;
        let saved_state = directory.join("snapshot.vmstate");
        if self
            .machine
            .save_full_state(&operation_id, &saved_state)
            .is_err()
        {
            return Err(ControlError::Unsupported(
                "Qemu Virtualization could not save full machine state",
            ));
        }
        let result = (|| -> Result<sandsurf_protocol::NativeFullCapture, QemuError> {
            let active = self
                .management_binding()
                .ok_or_else(|| QemuError::Invalid("guest reconnect state is unavailable".into()))?;
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
            let state_bytes = fs::metadata(&saved_state)?.len();
            let state_bound = self
                .config
                .resources
                .memory_mib
                .get()
                .checked_mul(1024 * 1024)
                .and_then(|value| value.checked_add(1024 * 1024 * 1024))
                .ok_or_else(|| QemuError::Invalid("saved-state bound overflow".into()))?;
            let state_digest = file_digest(&saved_state, state_bound)?;
            let reconnect_bytes = fs::metadata(&reconnect_path)?.len();
            let reconnect_digest = file_digest(&reconnect_path, 1024 * 1024)?;
            let configuration_digest = qemu_configuration_digest(&self.config)
                .map_err(|error| QemuError::Invalid(error.to_string()))?;
            let generation = digest(
                Domain::Snapshot,
                &(
                    "sandsurf-qemu-full-capture-generation-v1",
                    &snapshot_id,
                    &operation_id,
                    &state_digest,
                    &reconnect_digest,
                ),
            )
            .map_err(|error| QemuError::Invalid(error.to_string()))?;
            let capture = sandsurf_protocol::NativeFullCapture {
                engine: native_engine(),
                engine_version: "qemu-11.1.2-state-v1".into(),
                architecture: native_architecture_name().into(),
                configuration_digest,
                executions,
                snapshot_state: SnapshotArtifact {
                    digest: state_digest,
                    bytes: Counter::try_from(state_bytes)
                        .map_err(|error| QemuError::Invalid(error.to_string()))?,
                },
                memory: None,
                reconnect_state: SnapshotArtifact {
                    digest: reconnect_digest,
                    bytes: Counter::try_from(reconnect_bytes)
                        .map_err(|error| QemuError::Invalid(error.to_string()))?,
                },
                generation,
            };
            write_private_json(&directory.join("capture.json"), &capture)?;
            crate::snapshots::sync_directory(&directory)
                .map_err(|error| QemuError::Invalid(error.to_string()))?;
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

    fn prepare_full_restore(
        &self,
        mut input: crate::restore_preparation::RestorePreparation,
    ) -> ControlResult<crate::restore_preparation::RestorePreparation> {
        let expected = &input.expected;
        let configuration_digest = qemu_configuration_digest(&self.config)
            .map_err(|_| ControlError::Protocol("restore configuration digest failed"))?;
        if expected.engine != native_engine()
            || expected.engine_version != "qemu-11.1.2-state-v1"
            || expected.architecture != native_architecture_name()
            || expected.configuration_digest != configuration_digest
            || expected.memory.is_some()
        {
            return Err(ControlError::Unsupported(
                "full snapshot is incompatible with this Qemu VM configuration",
            ));
        }
        input.machine_root = self.machine_root.clone();
        Ok(input)
    }

    fn install_full_restore(
        &mut self,
        prepared: crate::restore_preparation::PreparedRestore,
    ) -> ControlResult<NativeSnapshotResponse> {
        if self.prepare_full_restore(prepared.input.clone())? != prepared.input {
            return Err(ControlError::Protocol(
                "prepared restore native binding changed",
            ));
        }
        let preparation_digest = prepared.input.binding()?;
        let response = prepared.input.evidence()?;
        let staged_state = prepared
            .input
            .staged_state_path()
            .ok_or(ControlError::Protocol(
                "prepared restore has no native state copy",
            ))?;
        let crate::restore_preparation::RestorePreparation {
            snapshot_id,
            manifest_digest,
            expected,
            ..
        } = prepared.input;
        let reconnect: ReconnectState = serde_json::from_slice(&prepared.reconnect)
            .map_err(|_| ControlError::Protocol("restore reconnect state is invalid"))?;
        if reconnect.format_version != 1 || reconnect.snapshot_id != snapshot_id {
            return Err(ControlError::Protocol(
                "restore reconnect identity does not match snapshot",
            ));
        }
        if reconnect.machine_id != self.config.machine_id {
            return Err(ControlError::Unsupported(
                "full memory forks are unsupported",
            ));
        }
        crate::restore::stage(&self.machine_root, manifest_digest.clone(), || {
            Ok(RestoreLineage {
                executions: expected.executions.clone(),
                snapshot_id: snapshot_id.clone(),
                source: reconnect,
                staged_state: staged_state.clone(),
                generation_seed: random_bytes()
                    .map_err(|_| ControlError::Protocol("restore entropy unavailable"))?,
            })
        })?;
        self.machine
            .stage_restore(QemuRestoreSource {
                preparation_digest,
                saved_state: staged_state,
                manifest_digest,
                disk_custody: prepared.disk_custody,
                snapshot_custody: prepared.snapshot_custody,
            })
            .map_err(|_| ControlError::Unsupported("native restore stage conflicts"))?;
        Ok(response)
    }

    fn record_installed_runtime(
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
        let Some(gateway) = self.machine.network() else {
            return RuntimeInstallation::Unknown;
        };
        // Boot/resume or the configuration effect has installed this exact
        // envelope through the original native owner. Recording it must not
        // reconfigure the same gateway a second time.
        if !gateway.is_alive() {
            return RuntimeInstallation::Unknown;
        }
        if let Ok(mut network) = self.network.lock() {
            if let Some(previous) = network.as_ref()
                && !Arc::ptr_eq(previous, &gateway)
            {
                let _ = previous.configure(&NetworkPolicy::default(), &[]);
                let s = previous.snapshot();
                accumulate_network_usage(
                    &self.network_usage,
                    &sandsurf_network::NetworkReport {
                        connections: s.connections,
                        violations: s.violations,
                        rx_bytes: s.rx_bytes,
                        tx_bytes: s.tx_bytes,
                        cleanup_failures: Vec::new(),
                    },
                );
            }
            *network = Some(gateway);
        } else {
            return RuntimeInstallation::Unknown;
        }
        let resource_evidence = digest(Domain::Resource, &configuration.resources)
            .map_err(|_| ())
            .ok();
        match digest(
            Domain::Authority,
            &(
                "sandsurf-qemu-runtime-configuration-v1",
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

    fn stop_data_planes(&mut self) {
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

    fn contain_unpublished(&mut self) {
        self.machine.contain_unobserved();
        self.pending = None;
        if let Ok(mut active) = self.guest_binding.lock() {
            *active = None;
        }
        self.stop_data_planes();
    }
}

enum RuntimeInstallation {
    Applied(Digest),
    Unknown,
}

impl GuardianEffect for QemuGuardianEffect {
    fn staged_restore_binding(&self) -> Option<&Digest> {
        self.machine.staged_restore_binding()
    }
    fn restore_preparation(
        &self,
        snapshot_id: sandsurf_protocol::SnapshotId,
        manifest_digest: Digest,
        system_disk: sandsurf_protocol::SnapshotArtifact,
        expected: sandsurf_protocol::FullSnapshotMetadata,
    ) -> ControlResult<crate::restore_preparation::RestorePreparation> {
        self.prepare_full_restore(crate::restore_preparation::RestorePreparation {
            machine_root: self.machine_root.clone(),
            snapshot_id,
            manifest_digest,
            system_disk,
            expected,
        })
    }
    fn install_prepared_restore(
        &mut self,
        prepared: crate::restore_preparation::PreparedRestore,
    ) -> ControlResult<NativeSnapshotResponse> {
        self.install_full_restore(prepared)
    }
    fn boot_preparation(
        &self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> ControlResult<Option<crate::boot_preparation::BootPreparation>> {
        crate::boot_preparation::BootPreparation::cold(
            &self.machine_root,
            &self.config.image_digest,
            command,
            current,
        )
    }
    fn install_prepared_boot(
        &mut self,
        prepared: crate::boot_preparation::PreparedBoot,
    ) -> ControlResult<()> {
        if self.prepared_boot.is_some() {
            return Err(ControlError::Protocol("prepared boot is already staged"));
        }
        self.prepared_boot = Some(prepared);
        Ok(())
    }
    fn guest_io_admissible(&self) -> bool {
        self.guest_transport.admissible()
    }
    fn resource_envelope(&self) -> Option<Resources> {
        Some(self.config.resources.clone())
    }

    fn assess_resources(
        &self,
        resources: &Resources,
        _current: &MachineObservation,
    ) -> sandsurf_protocol::ResourceChangeAssessment {
        use sandsurf_protocol::ResourceChangeMode;
        let mut assessment =
            crate::resources::assess(resources, &self.config.resources, &native_engine());
        if let Err(error) = QemuBudgets::derive(resources, accelerator()).and_then(|_| {
            sandsurf_native::volume::require(
                &self.machine_root,
                resources.physical_storage_bytes.get(),
            )
            .map(|_| ())
        }) {
            assessment.mode = ResourceChangeMode::Unsupported;
            assessment.reasons.push(error.to_string());
        } else if assessment.mode != ResourceChangeMode::Unsupported
            && *resources != self.config.resources
        {
            assessment.mode = ResourceChangeMode::RequiresReboot;
            assessment.reasons =
                vec!["native QEMU resource envelopes change only after confirmed power-off".into()];
        }
        assessment
    }
    fn capture_owner(&self) -> ControlResult<Option<sandsurf_protocol::OperationId>> {
        Ok(crate::capture::CaptureBoundary::read(&self.machine_root)?
            .map(|capture| capture.operation_id))
    }
    fn guest_driver(&mut self) -> Box<dyn GuestDriver> {
        self.guest_transport
            .driver(Arc::clone(&self.guest_binding), managed_guest)
    }

    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        let prepared = self.prepared_boot.take();
        let cold_boot = command.desired == sandsurf_protocol::DesiredState::Running
            && current.is_none_or(|value| {
                matches!(value.state, MachineState::Stopped | MachineState::Failed)
            });
        if cold_boot && crate::restore::complete(&self.machine_root).is_err() {
            return MachineOutcome::NotApplied(bytes_digest(
                b"cold-boot-could-not-retire-restore-integration",
            ));
        }
        let restoring = command.desired == sandsurf_protocol::DesiredState::Running
            && current.is_some_and(|value| value.state == MachineState::Suspended);
        if cold_boot {
            self.config.resources = command.configuration.resources.clone();
        }
        if cold_boot || restoring {
            let generation = match current {
                Some(value) => match value.generation.next() {
                    Ok(value) => value,
                    Err(_) => return MachineOutcome::Unknown,
                },
                None => Counter::ONE,
            };
            if let Err(evidence) = self.prepare_boot(command, generation, prepared) {
                return MachineOutcome::NotApplied(evidence);
            }
        }
        let mut outcome = apply_lifecycle(&mut self.machine, command, current);
        self.prepared_boot = None;
        self.machine.discard_pending_storage_custody();
        let running = matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Running)
        );
        if running {
            if cold_boot || restoring {
                let generation = match &outcome {
                    MachineOutcome::Observed(values) => values
                        .last()
                        .map(|value| value.generation)
                        .unwrap_or(Counter::ONE),
                    _ => Counter::ONE,
                };
                let authenticated = if restoring {
                    self.bind_restored(generation)
                } else {
                    self.bind_pending()
                };
                match authenticated {
                    Ok(active) => {
                        if let Ok(mut endpoint) = self.guest_binding.lock() {
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
            let runtime = match self.record_installed_runtime(&command.configuration) {
                RuntimeInstallation::Applied(value) => value,
                RuntimeInstallation::Unknown => {
                    self.contain_unpublished();
                    return MachineOutcome::Unknown;
                }
            };
            if let MachineOutcome::Observed(values) = &mut outcome
                && let Some(last) = values.last_mut()
            {
                match digest(
                    Domain::Authority,
                    &(
                        "sandsurf-qemu-running-with-configuration-v1",
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
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| matches!(value.state, MachineState::Stopped | MachineState::Suspended | MachineState::Destroyed))
        ) {
            if let Ok(mut active) = self.guest_binding.lock() {
                *active = None;
            }
            self.stop_data_planes();
        }
        if matches!(&outcome, MachineOutcome::Observed(values) if values.last().is_some_and(|value| matches!(value.state, MachineState::Stopped | MachineState::Destroyed)))
            && crate::restore::complete(&self.machine_root).is_err()
        {
            return MachineOutcome::Unknown;
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Suspended)
        ) && let Some(operation_id) = self.suspend_capture_operation.take()
            && let Err(error) = remove_qemu_full_capture(&self.machine_root, &operation_id)
        {
            eprintln!("sandsurf retained Qemu suspend staging after cleanup failure: {error}");
        }
        if let Err(error) = self
            .guest_transport
            .reconcile_capture(&self.machine_root, &outcome)
        {
            eprintln!("sandsurf capture transport recovery deferred: {error}");
        }
        outcome
    }

    fn validate_resources(
        &self,
        resources: &Resources,
        current: &MachineObservation,
    ) -> ControlResult<()> {
        QemuBudgets::derive(resources, accelerator())?;
        resources
            .validate()
            .map_err(|_| ControlError::Protocol("invalid native resource envelope"))?;
        if resources.disk_bytes != self.config.resources.disk_bytes {
            return Err(ControlError::Unsupported(
                "disk capacity changes require the storage replacement capability",
            ));
        }
        crate::resources::require_network_capacity(resources)?;
        sandsurf_native::volume::require(
            &self.machine_root,
            resources.physical_storage_bytes.get(),
        )?;
        if *resources != self.config.resources
            && !matches!(current.state, MachineState::Stopped | MachineState::Failed)
        {
            return Err(ControlError::Unsupported(
                "native process envelopes change only after confirmed power-off",
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
        if let Err(evidence) = self.machine.validate_attachment(
            &command.machine_id,
            command.revision,
            &command.configuration.resources,
            current,
        ) {
            return EffectOutcome::NotApplied(evidence);
        }
        let runtime = if matches!(current.state, MachineState::Stopped | MachineState::Failed) {
            None
        } else {
            if self
                .machine
                .install_network(&command.configuration)
                .is_err()
            {
                self.contain_unpublished();
                return EffectOutcome::Unknown;
            }
            match self.record_installed_runtime(&command.configuration) {
                RuntimeInstallation::Applied(evidence) => Some(evidence),
                RuntimeInstallation::Unknown => {
                    self.contain_unpublished();
                    return EffectOutcome::Unknown;
                }
            }
        };
        match digest(
            Domain::Authority,
            &(
                "sandsurf-qemu-configuration-applied-v1",
                &command.machine_id,
                command.revision,
                &command.request_digest,
                runtime,
                &command.configuration,
            ),
        ) {
            Ok(evidence) => {
                self.config.resources = command.configuration.resources.clone();
                EffectOutcome::Applied(evidence)
            }
            Err(_) => {
                self.contain_unpublished();
                EffectOutcome::Unknown
            }
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
            sandsurf_protocol::ResourceUsage::host_observation("host-native-qemu", observed);
        #[cfg(target_os = "macos")]
        if let Ok(guardian) = sandsurf_native::resource_broker::macos::current_worker_usage()
            && let Ok(vm) = self.machine.resource_usage()
        {
            let combine = |a: u64, b: u64| -> ControlResult<Counter> {
                Counter::try_from(
                    a.checked_add(b)
                        .ok_or(ControlError::Protocol("native measurement overflow"))?,
                )
                .map_err(|_| ControlError::Protocol("native measurement overflow"))
            };
            usage.cpu_micros = Some(combine(
                guardian.cpu_micros,
                vm.as_ref().map_or(0, |vm| vm.cpu_micros),
            )?);
            usage.memory_current = Some(combine(
                guardian.memory_current,
                vm.as_ref().map_or(0, |vm| vm.memory_current),
            )?);
            usage.io_read_bytes = Some(combine(
                guardian.io_read_bytes,
                vm.as_ref().map_or(0, |vm| vm.io_read_bytes),
            )?);
            usage.io_write_bytes = Some(combine(
                guardian.io_write_bytes,
                vm.as_ref().map_or(0, |vm| vm.io_write_bytes),
            )?);
            usage.provenance.cpu = sandsurf_protocol::MeasurementSource::HostDarwinTask;
            usage.provenance.memory = sandsurf_protocol::MeasurementSource::HostDarwinTask;
            usage.provenance.io = sandsurf_protocol::MeasurementSource::HostDarwinTask;
            // Native counters restart on a new original worker. No sum of
            // individual peaks is represented as an aggregate high-water mark.
            usage.host_counter_epoch = Some(
                digest(
                    Domain::Operation,
                    &(
                        "sandsurf-darwin-counter-epoch-v1",
                        std::process::id(),
                        guardian.owner_start_ticks,
                        guardian.worker_start_ticks,
                        vm.as_ref()
                            .map(|vm| (vm.owner_start_ticks, vm.worker_start_ticks)),
                    ),
                )
                .map_err(|_| ControlError::Protocol("native counter identity unavailable"))?,
            );
        }
        #[cfg(windows)]
        if let Ok(budgets) = QemuBudgets::derive(&self.config.resources, accelerator())
            && let Ok(guardian) =
                sandsurf_native::process_budget::windows::JobEnvelope::current_factory_usage(
                    budgets.guardian,
                )
            && let Ok(vm) = self.machine.resource_usage()
            && let (Some(guardian_memory), Some(guardian_creation), Some(vm_memory)) = (
                guardian.current_private_commit,
                guardian.process_creation_time,
                vm.as_ref().map_or(Some(0), |vm| vm.current_private_commit),
            )
        {
            let combine = |a: u64, b: u64| -> ControlResult<Counter> {
                Counter::try_from(
                    a.checked_add(b)
                        .ok_or(ControlError::Protocol("native measurement overflow"))?,
                )
                .map_err(|_| ControlError::Protocol("native measurement overflow"))
            };
            usage.cpu_ledgers = Some(sandsurf_protocol::CpuLedgers {
                native_micros: Some(combine(
                    guardian.cpu_micros,
                    vm.as_ref().map_or(0, |vm| vm.cpu_micros),
                )?),
                native_source: sandsurf_protocol::MeasurementSource::HostJob,
                ..Default::default()
            });
            usage.memory_current = Some(combine(guardian_memory, vm_memory)?);
            usage.io_read_bytes = Some(combine(
                guardian.io_read_bytes,
                vm.as_ref().map_or(0, |vm| vm.io_read_bytes),
            )?);
            usage.io_write_bytes = Some(combine(
                guardian.io_write_bytes,
                vm.as_ref().map_or(0, |vm| vm.io_write_bytes),
            )?);
            usage.provenance.memory = sandsurf_protocol::MeasurementSource::HostJob;
            usage.provenance.io = sandsurf_protocol::MeasurementSource::HostJob;
            // Job CPU excludes hypervisor scheduling. Do not expose it as
            // total computer CPU, nor sum individual peaks into a false peak.
            usage.host_counter_epoch = Some(
                digest(
                    Domain::Operation,
                    &(
                        "sandsurf-windows-counter-epoch-v1",
                        std::process::id(),
                        guardian_creation,
                        vm.as_ref().and_then(|vm| vm.process_creation_time),
                    ),
                )
                .map_err(|_| ControlError::Protocol("native counter identity unavailable"))?,
            );
        }
        #[cfg(windows)]
        if usage.host_counter_epoch.is_some()
            && let Ok(Some(partition)) = self.machine.partition_usage()
        {
            let ledgers = usage.cpu_ledgers.get_or_insert_with(Default::default);
            ledgers.partition_micros = Some(partition.total_runtime_micros);
            ledgers.partition_hypervisor_micros = Some(partition.hypervisor_runtime_micros);
            ledgers.partition_source = sandsurf_protocol::MeasurementSource::HostPartition;
        }
        usage.provenance.network = sandsurf_protocol::MeasurementSource::HostNetwork;
        let accumulated = self
            .network_usage
            .lock()
            .map_err(|_| ControlError::Protocol("network usage lock poisoned"))?;
        let current = self
            .network
            .lock()
            .map_err(|_| ControlError::Protocol("network bridge lock poisoned"))?
            .as_ref()
            .map_or_else(Default::default, |gateway| gateway.snapshot());
        usage.network_rx_bytes =
            Counter::try_from(accumulated.rx_bytes.saturating_add(current.rx_bytes))
                .map_err(|_| ControlError::Protocol("network receive accounting overflow"))?;
        usage.network_tx_bytes =
            Counter::try_from(accumulated.tx_bytes.saturating_add(current.tx_bytes))
                .map_err(|_| ControlError::Protocol("network transmit accounting overflow"))?;
        usage.network_connections =
            Counter::try_from(accumulated.connections.saturating_add(current.connections))
                .map_err(|_| ControlError::Protocol("network connection accounting overflow"))?;
        Ok(usage)
    }

    fn native_snapshot(
        &mut self,
        request: NativeSnapshotRequest,
        journal: &mut RuntimeJournal,
    ) -> ControlResult<NativeSnapshotResponse> {
        match request {
            NativeSnapshotRequest::PrepareDisk { operation_id, .. } => {
                self.prepare_capture_boundary(operation_id, journal)?;
                Ok(NativeSnapshotResponse::Complete {
                    evidence: bytes_digest(b"native-computer-paused-for-disk-capture-v1"),
                })
            }
            NativeSnapshotRequest::FinishDisk { operation_id } => {
                crate::capture::CaptureBoundary::require(&self.machine_root, &operation_id)?;
                self.finish_native_capture(journal)?;
                Ok(NativeSnapshotResponse::Complete {
                    evidence: bytes_digest(b"native-disk-capture-released-v1"),
                })
            }
            NativeSnapshotRequest::PrepareFull {
                snapshot_id,
                operation_id,
                ..
            } => {
                if matches!(
                    sandsurf_machine::qemu_driver::full_state_capability(),
                    sandsurf_protocol::Capability::Unsupported { .. }
                ) {
                    return Err(ControlError::Unsupported(
                        "native WHPX full-state transfer is unavailable",
                    ));
                }
                self.prepare_full_capture(snapshot_id, operation_id, journal)
            }
            NativeSnapshotRequest::FinishFull { operation_id } => {
                crate::capture::CaptureBoundary::require(&self.machine_root, &operation_id)?;
                self.finish_native_capture(journal).map_err(|_| {
                    ControlError::Unsupported("Qemu VM could not resume after full capture")
                })?;
                remove_qemu_full_capture(&self.machine_root, &operation_id)?;
                Ok(NativeSnapshotResponse::Complete {
                    evidence: bytes_digest(b"qemu-full-capture-finished-v1"),
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
                            "native suspend capture does not match the paused Qemu VM",
                        )
                    })?;
                self.suspend_capture_operation = Some(operation_id.clone());
                Ok(NativeSnapshotResponse::Complete {
                    evidence: digest(
                        Domain::Snapshot,
                        &(
                            "sandsurf-qemu-suspend-commit-v1",
                            operation_id,
                            manifest_digest,
                        ),
                    )
                    .map_err(|_| ControlError::Protocol("suspend evidence digest failed"))?,
                })
            }
            NativeSnapshotRequest::StageRestore { .. } => Err(ControlError::Protocol(
                "full restore requires detached preparation",
            )),
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
        if generation == lineage.source.generation {
            return Ok(());
        }
        if generation <= lineage.source.generation {
            return Err(ControlError::Protocol(
                "restore integration generation mismatch",
            ));
        }
        journal.restore_executions(
            &lineage.snapshot_id,
            &lineage.source.machine_id,
            lineage.source.generation,
            generation,
            &lineage.executions,
        )?;
        self.retire_restore_intent()
    }

    fn retire_restore_intent(&mut self) -> ControlResult<()> {
        if let Some(lineage) = crate::restore::load::<RestoreLineage>(&self.machine_root)? {
            crate::restore::retire_stage(&self.machine_root, &lineage.staged_state)?;
        }
        crate::restore::complete(&self.machine_root)
    }

    fn observe_power(&mut self) -> ControlResult<Option<sandsurf_machine::NativePowerObservation>> {
        self.machine
            .observe_power()
            .map_err(|_| ControlError::Protocol("native power observation unavailable"))
    }
    fn observe_detachment(&self) -> ControlResult<Option<Digest>> {
        Ok(crate::storage::observe_detached(
            &self.machine_root.join("disks/system.ext4"),
        )?)
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
        self.stop_data_planes();
        if let Ok(mut active) = self.guest_binding.lock() {
            *active = None;
        }
        crate::guardian::restart_after_native_reset(self, current, configuration)
    }
    fn guest_reset_configuration(&self) -> ControlResult<RuntimeConfiguration> {
        self.installed_runtime
            .as_ref()
            .map(|runtime| runtime.configuration.clone())
            .ok_or(ControlError::Protocol(
                "guest reset has no applied native envelope",
            ))
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

fn native_architecture_name() -> &'static str {
    match crate::service::native_guest_architecture() {
        sandsurf_machine::GuestArchitecture::Amd64 => "amd64",
        sandsurf_machine::GuestArchitecture::Arm64 => "arm64",
    }
}

fn qemu_configuration_digest(
    config: &QemuGuardianConfig,
) -> Result<Digest, sandsurf_protocol::Invalid> {
    digest(
        Domain::Snapshot,
        &(
            "sandsurf-qemu-configuration-v1",
            &config.image_digest,
            &config.runtime_digest,
            &config.resources,
            native_architecture_name(),
            sandsurf_protocol::GUEST_PROTOCOL_MAJOR,
            sandsurf_protocol::GUEST_PROTOCOL_MINOR,
        ),
    )
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), QemuError> {
    let mut file = sandsurf_native::local::create_private_file(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn managed_guest(active: &ActiveGuest) -> ManagedGuestClient<SerialChannel> {
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

fn guest_client(active: &ActiveGuest) -> GuestClient<SerialChannel> {
    GuestClient::new(
        active
            .channel
            .clone()
            .expect("only a published native binding creates a guest client"),
        active.machine_id.clone(),
        active.generation,
        active.boot_identity.clone(),
        active.capability,
    )
}

fn write_authentication(
    path: &Path,
    machine_id: &MachineId,
    generation: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
) -> Result<(), QemuError> {
    let bytes = BootIdentity {
        machine_id: machine_id.clone(),
        generation,
        boot_digest: boot_identity.clone(),
        capability: BootCapability::from_bytes(*capability),
    }
    .encode()
    .map_err(|error| QemuError::Invalid(error.to_string()))?;
    let mut file = sandsurf_native::local::create_private_file(path)?;
    file.write_all(&bytes[..])?;
    file.sync_all()?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), QemuError> {
    sandsurf_native::local::ensure_private_directory(path)?;
    Ok(())
}

fn require_regular(path: &Path, maximum: u64) -> Result<(), QemuError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(QemuError::Invalid(
            "artifact must be a bounded absolute regular file".into(),
        ));
    }
    Ok(())
}

fn file_digest(path: &Path, maximum: u64) -> Result<Digest, QemuError> {
    sha256_file(path, maximum)?
        .try_into()
        .map_err(|error| QemuError::Invalid(format!("artifact digest is invalid: {error}")))
}

fn sha256_file(path: &Path, maximum: u64) -> Result<String, QemuError> {
    require_regular(path, maximum)?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| QemuError::Invalid("artifact length overflow".into()))?;
        if total > maximum {
            return Err(QemuError::Invalid("artifact exceeds bound".into()));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, QemuError> {
    require_regular(path, maximum)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(QemuError::Invalid("JSON artifact exceeds bound".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn random_bytes() -> Result<[u8; 32], QemuError> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| QemuError::Invalid("host entropy unavailable".into()))?;
    Ok(bytes)
}
