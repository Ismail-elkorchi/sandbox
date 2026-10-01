//! Windows guardian integration for one retained Hyper-V/HCS Linux VM.

use crate::capture::{
    full_directory as hyperv_full_capture_directory, remove_full as remove_hyperv_full_capture,
};
use crate::guardian::{
    EffectOutcome, Error as ControlError, GuardianEffect, GuestDriver, Result as ControlResult,
};
use crate::guest::{GuestClient, ManagedGuestClient, ManagementRebind, PendingRebind};
use sandsurf_image::{Architecture, ImageTrust, verify_image};
use sandsurf_machine::windows::{
    HyperVConfig, HyperVDisk, HyperVDriver, HyperVQualification, HyperVRestoreSource,
};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_native::storage::object_name;
use sandsurf_native::{HyperVChannel, virtual_disk};
use sandsurf_protocol::{AUTHENTICATION_MAGIC, GUEST_BOOTSTRAP_PORT, GUEST_CONTROL_PORT};
use sandsurf_protocol::{
    Counter, Digest, Domain, ExecutionDefaults, GuestCommand, GuestServiceRequest,
    GuestServiceResponse, LifecycleCommand, MachineId, MachineObservation, MachineState,
    NativeSnapshotRequest, NativeSnapshotResponse, Resources, RuntimeConfiguration,
    SnapshotArtifact, VmEngine, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONFIG_VERSION: u16 = 1;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Debug)]
pub enum WindowsError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandsurf_image::ImageError),
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
impl From<sandsurf_image::ImageError> for WindowsError {
    fn from(value: sandsurf_image::ImageError) -> Self {
        Self::Image(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsGuardianConfig {
    format_version: u16,
    machine_id: MachineId,
    image_digest: Digest,
    resources: Resources,
    image_manifest: PathBuf,
    vm_id: String,
    hvsock_security_descriptor: String,
}

pub fn prepare_config(
    host_root: &Path,
    machine_id: &MachineId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<WindowsGuardianConfig, WindowsError> {
    crate::resources::require_external_support("hyper-v")?;
    let path = host_root
        .join("machines")
        .join(object_name(machine_id.as_str()))
        .join("guardian/config.json");
    if path.exists() {
        let existing = read_config(&path, machine_id)?;
        if existing.image_digest != *image_digest {
            return Err(WindowsError::Invalid(
                "existing Machine configuration conflicts with create request".into(),
            ));
        }
        return Ok(existing);
    }
    let image = crate::images::resolve_native_image(host_root, image_digest)
        .map_err(|error| WindowsError::Invalid(error.to_string()))?;
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
        machine_id: machine_id.clone(),
        image_digest: image_digest.clone(),
        resources: resources.clone(),
        image_manifest: image.manifest_path,
        vm_id: deterministic_vm_id(host_root, machine_id),
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
    machine_id: &MachineId,
) -> Result<WindowsGuardianConfig, WindowsError> {
    let value: WindowsGuardianConfig = read_json(path, 1024 * 1024)?;
    if value.format_version != CONFIG_VERSION || value.machine_id != *machine_id {
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

pub fn execution_defaults(
    host_root: &Path,
    image_digest: &Digest,
) -> Result<ExecutionDefaults, WindowsError> {
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
    let defaults = image.manifest.system.defaults;
    Ok(ExecutionDefaults {
        environment: defaults.environment,
        user: defaults.user,
        working_directory: defaults.working_directory,
    })
}

pub struct WindowsGuardianEffect {
    machine_root: PathBuf,
    config: WindowsGuardianConfig,
    machine: HyperVDriver,
    guest_binding: Arc<Mutex<Option<ActiveGuest>>>,
    pending: Option<PendingGuest>,
    installed_runtime: Option<InstalledRuntime>,
    suspend_capture_operation: Option<sandsurf_protocol::OperationId>,
}

#[derive(Clone, PartialEq, Eq)]
struct ActiveGuest {
    rebind: Option<ManagementRebind>,
    bootstrap: Option<Vec<u8>>,
    vm_id: String,
    machine_id: MachineId,
    generation: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    boot_directory: PathBuf,
}

struct PendingGuest {
    active: ActiveGuest,
    authentication: Vec<u8>,
}

struct WindowsGuest {
    active: Arc<Mutex<Option<ActiveGuest>>>,
    remote: Option<(ActiveGuest, ManagedGuestClient<HyperVChannel>)>,
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

impl WindowsGuardianEffect {
    fn management_binding(&self) -> Option<ActiveGuest> {
        self.guest_binding.lock().ok()?.clone()
    }
    pub fn open(machine_root: &Path, config: WindowsGuardianConfig) -> Result<Self, WindowsError> {
        crate::resources::require_external_support("hyper-v")?;
        let image = verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        if image.manifest.boot_bundle.profile != sandsurf_image::boot::BootProfile::Pinned
            || image.manifest.system.clone_profile
                != sandsurf_image::identity::CloneProfile::Preserve
            || image.manifest.boot_bundle.initramfs.is_some()
        {
            return Err(WindowsError::Invalid("managed disk boot/clone profiles and initramfs require an isolated native Windows helper; unsupported on this host".into()));
        }
        let windows = image
            .windows_x64
            .ok_or_else(|| WindowsError::Invalid("image has no Windows boot artifacts".into()))?;
        let disks = machine_root.join("disks");
        sandsurf_native::local::ensure_private_directory(&disks)?;
        sandsurf_native::storage::sync_directory(machine_root)?;
        let system_disk = disks.join("system.vhdx");
        let ports = vec![GUEST_BOOTSTRAP_PORT, GUEST_CONTROL_PORT];
        let machine = HyperVDriver::new(HyperVConfig {
            machine_id: config.machine_id.clone(),
            vm_id: config.vm_id.clone(),
            guest_architecture: crate::service::native_guest_architecture(),
            memory_mib: config.resources.memory_mib.get(),
            vcpus: u32::try_from(config.resources.vcpus.get())
                .map_err(|_| WindowsError::Invalid("vCPU count overflow".into()))?,
            kernel: windows.kernel_path,
            command_line: sandsurf_machine::linux_boot_arguments("ttyS0", "/dev/sda"),
            disks: vec![HyperVDisk {
                path: system_disk,
                read_only: false,
            }],
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
            machine_root: machine_root.to_path_buf(),
            config,
            machine,
            guest_binding: active,
            pending: None,
            installed_runtime: None,
            suspend_capture_operation: None,
        })
    }

    fn prepare_boot(
        &mut self,
        command: &LifecycleCommand,
        generation: Counter,
    ) -> Result<(), Digest> {
        let image = verify_image(&self.config.image_manifest, ImageTrust::ExplicitLocal)
            .map_err(|_| bytes_digest(b"hyper-v-system-seed-unavailable"))?;
        let windows = image
            .windows_x64
            .ok_or_else(|| bytes_digest(b"hyper-v-system-seed-unavailable"))?;
        ensure_mutable_vhdx(
            &windows.system_path,
            &self.machine_root.join("disks/system.vhdx"),
            command.configuration.resources.disk_bytes.get(),
        )
        .map_err(|error| {
            eprintln!("sandsurf disk preparation failed: {error}");
            bytes_digest(b"hyper-v-system-disk-preparation-failed")
        })?;
        let capability = random_bytes().map_err(|_| bytes_digest(b"hyper-v-boot-entropy"))?;
        let nonce: String = capability.iter().map(|b| format!("{b:02x}")).collect();
        let boot_directory = self
            .machine_root
            .join("guardian")
            .join(format!("boot-{}-{nonce}", generation.get()));
        let boot = crate::storage::pin_boot(
            &windows.kernel_path,
            None,
            sandsurf_image::Architecture::X64,
            &boot_directory,
        )
        .map_err(|_| bytes_digest(b"hyper-v-boot-artifacts-invalid"))?;
        if boot.kernel.sha256
            != image
                .manifest
                .platform_artifacts
                .windows_x64
                .as_ref()
                .ok_or_else(|| bytes_digest(b"hyper-v-image-artifacts-missing"))?
                .kernel
                .sha256
        {
            return Err(bytes_digest(b"hyper-v-boot-identity-mismatch"));
        }
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-hyper-v-boot-v1",
                &command.machine_id,
                &boot,
                sandsurf_protocol::GUEST_PROTOCOL_MAJOR,
                sandsurf_protocol::GUEST_PROTOCOL_MINOR,
            ),
        )
        .map_err(|_| bytes_digest(b"hyper-v-boot-identity"))?;
        let authentication =
            authentication_record(&command.machine_id, generation, &boot_identity, &capability)
                .map_err(|_| bytes_digest(b"hyper-v-authentication-record"))?;
        self.pending = Some(PendingGuest {
            active: ActiveGuest {
                vm_id: self.machine.vm_id().to_owned(),
                machine_id: command.machine_id.clone(),
                generation,
                boot_identity,
                capability,
                boot_directory,
                rebind: None,
                bootstrap: None,
            },
            authentication,
        });
        let custody = crate::storage::attach_hyper_v(
            &self.machine_root.join("disks/system.vhdx"),
            self.machine.vm_id(),
        )
        .map_err(|_| bytes_digest(b"hyper-v-system-disk-attachment-failed"))?;
        self.machine
            .stage_storage_custody(custody)
            .map_err(|_| bytes_digest(b"hyper-v-system-disk-custody-conflict"))?;
        Ok(())
    }

    fn bind_pending(&mut self) -> Result<ActiveGuest, Digest> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"hyper-v-pending-binding-missing"))?;
        let mut active = pending.active;
        active.bootstrap = Some(pending.authentication);
        Ok(active)
    }

    fn bind_restored(&mut self, generation: Counter) -> Result<ActiveGuest, Digest> {
        let lineage = crate::restore::load::<RestoreLineage>(&self.machine_root)
            .map_err(|_| bytes_digest(b"hyper-v-restore-lineage-unavailable"))?
            .ok_or_else(|| bytes_digest(b"hyper-v-restore-lineage-missing"))?;
        let pending = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"hyper-v-restore-binding-missing"))?;
        let mut active = pending.active;
        if active.generation != generation {
            return Err(bytes_digest(b"hyper-v-restore-binding-generation-mismatch"));
        }
        active.bootstrap = None;
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
        crate::capture::CaptureBoundary::clear(&self.machine_root)
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
        let directory = hyperv_full_capture_directory(&self.machine_root, &operation_id);
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
                "HCS could not save full machine state",
            ));
        }
        let result = (|| -> Result<sandsurf_protocol::NativeFullCapture, WindowsError> {
            let active = self.management_binding().ok_or_else(|| {
                WindowsError::Invalid("guest reconnect state is unavailable".into())
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
            let state_digest = crate::snapshots::file_digest(&saved_state, state_bytes)
                .map_err(|error| WindowsError::Invalid(error.to_string()))?;
            let reconnect_bytes = fs::metadata(&reconnect_path)?.len();
            let reconnect_digest = crate::snapshots::file_digest(&reconnect_path, reconnect_bytes)
                .map_err(|error| WindowsError::Invalid(error.to_string()))?;
            let configuration_digest = hyperv_configuration_digest(&self.config)
                .map_err(|error| WindowsError::Invalid(error.to_string()))?;
            let generation = digest(
                Domain::Snapshot,
                &(
                    "sandsurf-hyper-v-full-capture-generation-v1",
                    &snapshot_id,
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
                executions,
                snapshot_state: SnapshotArtifact {
                    digest: state_digest,
                    bytes: Counter::try_from(state_bytes)
                        .map_err(|error| WindowsError::Invalid(error.to_string()))?,
                },
                memory: None,
                reconnect_state: SnapshotArtifact {
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
            Ok(capture) => Ok(NativeSnapshotResponse::Prepared { capture }),
            Err(error) => Err(ControlError::Rejected {
                category: "snapshot".into(),
                message: error.to_string(),
            }),
        }
    }

    fn stage_full_restore(
        &mut self,
        snapshot_id: sandsurf_protocol::SnapshotId,
        manifest_digest: Digest,
        system_disk: SnapshotArtifact,
        expected: sandsurf_protocol::FullSnapshotMetadata,
    ) -> ControlResult<NativeSnapshotResponse> {
        let configuration_digest = hyperv_configuration_digest(&self.config)
            .map_err(|_| ControlError::Protocol("restore configuration digest failed"))?;
        if expected.engine != VmEngine::HyperV
            || expected.engine_version != "hcs-schema-2.2-save-v1"
            || expected.architecture != "amd64"
            || expected.configuration_digest != configuration_digest
            || expected.memory.is_some()
        {
            return Err(ControlError::Unsupported(
                "full snapshot is incompatible with this Hyper-V configuration",
            ));
        }
        let directory = self
            .machine_root
            .join("snapshots")
            .join(object_name(snapshot_id.as_str()));
        for (name, artifact) in [
            ("system.ext4", &system_disk),
            ("snapshot.vmstate", &expected.snapshot_state),
            ("reconnect.json", &expected.reconnect_state),
        ] {
            let actual = crate::snapshots::file_digest(&directory.join(name), artifact.bytes.get())
                .map_err(|_| ControlError::Protocol("full snapshot artifact is corrupt"))?;
            if actual != artifact.digest {
                return Err(ControlError::Protocol(
                    "full snapshot artifact digest mismatch",
                ));
            }
        }
        if crate::snapshots::current_disk_digest(
            &self.machine_root.join("disks/system.vhdx"),
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
        let restore_root = self.machine_root.join("guardian/restores");
        crate::snapshots::private_directory(&restore_root)
            .map_err(|_| ControlError::Protocol("restore staging root is not private"))?;
        let staged_state = restore_root.join(format!("{}.vmrs", manifest_digest.as_str()));
        crate::snapshots::copy_and_verify(
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
        crate::restore::stage(&self.machine_root, manifest_digest.clone(), || {
            Ok(RestoreLineage {
                executions: expected.executions.clone(),
                snapshot_id: snapshot_id.clone(),
                source: reconnect,
                staged_state,
                generation_seed: random_bytes()
                    .map_err(|_| ControlError::Protocol("restore entropy unavailable"))?,
            })
        })?;
        Ok(NativeSnapshotResponse::Complete {
            evidence: digest(
                Domain::Snapshot,
                &(
                    "sandsurf-hyper-v-restore-staged-v1",
                    snapshot_id,
                    manifest_digest,
                    expected.generation,
                ),
            )
            .map_err(|_| ControlError::Protocol("restore stage evidence digest failed"))?,
        })
    }

    fn install_runtime(&mut self, configuration: &RuntimeConfiguration) -> RuntimeInstallation {
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
        if self
            .machine
            .configure_network(&configuration.network, &configuration.exposures)
            .is_err()
        {
            return RuntimeInstallation::NotApplied(bytes_digest(
                b"windows-native-external-network-unsupported",
            ));
        }
        let resource_evidence = digest(Domain::Resource, &configuration.resources)
            .map_err(|_| ())
            .ok();
        match digest(
            Domain::Authority,
            &(
                "sandsurf-hyper-v-runtime-configuration-v1",
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
    NotApplied(Digest),
    Unknown,
}

impl WindowsGuest {
    fn endpoint(&self) -> Option<ActiveGuest> {
        self.active.lock().ok()?.clone()
    }

    fn driver(&mut self) -> Option<&mut ManagedGuestClient<HyperVChannel>> {
        let active = self.endpoint();
        let Some(active) = active else {
            self.remote = None;
            return None;
        };
        if self
            .remote
            .as_ref()
            .is_none_or(|(cached, _)| cached != &active)
        {
            if let Some(authentication) = &active.bootstrap {
                let ready = guest_client(&active)
                    .call(&GuestServiceRequest::ProbeIdentity)
                    .is_ok();
                if !ready
                    && crate::guest::deliver_bootstrap(
                        HyperVChannel {
                            vm_id: active.vm_id.clone(),
                            guest_port: GUEST_BOOTSTRAP_PORT,
                            timeout: Duration::from_secs(10),
                        },
                        authentication,
                    )
                    .is_err()
                {
                    return None;
                }
            }
            self.remote = Some((active.clone(), managed_guest(&active)));
        }
        self.remote.as_mut().map(|(_, driver)| driver)
    }
}

impl GuestDriver for WindowsGuest {
    fn dispatch(&mut self, command: &GuestCommand) -> EffectOutcome {
        let Some(driver) = self.driver() else {
            return EffectOutcome::NotApplied(bytes_digest(b"hyper-v-guest-not-running"));
        };
        driver.dispatch(command)
    }

    fn poll(
        &mut self,
        hints: &crate::guest_worker::ExecutionHints,
    ) -> ControlResult<crate::guest_worker::GuestPoll> {
        self.driver()
            .ok_or(ControlError::Unsupported("guest management unavailable"))?
            .poll(hints)
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        let driver = self.driver().ok_or(ControlError::Unsupported(
            "guest is unavailable because the Hyper-V VM has no live owner",
        ))?;
        driver.query(request)
    }
}

impl GuardianEffect for WindowsGuardianEffect {
    fn capture_owner(&self) -> ControlResult<Option<sandsurf_protocol::OperationId>> {
        Ok(crate::capture::CaptureBoundary::read(&self.machine_root)?
            .map(|capture| capture.operation_id))
    }
    fn guest_driver(&mut self) -> Box<dyn GuestDriver> {
        Box::new(WindowsGuest {
            active: Arc::clone(&self.guest_binding),
            remote: None,
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
            if let Err(evidence) = self.prepare_boot(command, generation) {
                return MachineOutcome::NotApplied(evidence);
            }
        }
        let mut outcome = apply_lifecycle(&mut self.machine, command, current);
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
                    Domain::Authority,
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
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Suspended)
        ) && let Some(operation_id) = self.suspend_capture_operation.take()
            && let Err(error) = remove_hyperv_full_capture(&self.machine_root, &operation_id)
        {
            eprintln!("sandsurf retained Hyper-V suspend staging after cleanup failure: {error}");
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
        crate::resources::require_external_support("hyper-v")?;
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
            sandsurf_machine::ConfigurationOutcome::Applied(machine) => {
                match self.install_runtime(&command.configuration) {
                    RuntimeInstallation::Applied(runtime) => digest(
                        Domain::Authority,
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

    fn resource_usage(&mut self) -> ControlResult<sandsurf_protocol::ResourceUsage> {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ControlError::Protocol("host clock unavailable"))?
            .as_millis();
        let observed = Counter::try_from(
            u64::try_from(millis).map_err(|_| ControlError::Protocol("host time overflow"))?,
        )
        .map_err(|_| ControlError::Protocol("host time overflow"))?;
        Ok(sandsurf_protocol::ResourceUsage::host_observation(
            "host-native-windows",
            observed,
        ))
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
                    ControlError::Unsupported("Hyper-V VM could not resume after full capture")
                })?;
                remove_hyperv_full_capture(&self.machine_root, &operation_id)?;
                Ok(NativeSnapshotResponse::Complete {
                    evidence: bytes_digest(b"hyper-v-full-capture-finished-v1"),
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
                            "native suspend capture does not match the paused Hyper-V VM",
                        )
                    })?;
                self.suspend_capture_operation = Some(operation_id.clone());
                Ok(NativeSnapshotResponse::Complete {
                    evidence: digest(
                        Domain::Snapshot,
                        &(
                            "sandsurf-hyper-v-suspend-commit-v1",
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
    fn take_console(&mut self) -> Option<sandsurf_machine::NativeConsole> {
        self.machine.take_console()
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

fn hyperv_configuration_digest(
    config: &WindowsGuardianConfig,
) -> Result<Digest, sandsurf_protocol::Invalid> {
    digest(
        Domain::Snapshot,
        &(
            "sandsurf-hyper-v-configuration-v1",
            &config.image_digest,
            &config.resources,
            &config.vm_id,
            sandsurf_protocol::GUEST_PROTOCOL_MAJOR,
            sandsurf_protocol::GUEST_PROTOCOL_MINOR,
        ),
    )
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), WindowsError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn managed_guest(active: &ActiveGuest) -> ManagedGuestClient<HyperVChannel> {
    let pending = active.rebind.as_ref().map(|binding| {
        let source = ActiveGuest {
            machine_id: binding.machine_id.clone(),
            generation: binding.generation,
            boot_identity: binding.boot_identity.clone(),
            capability: binding.capability,
            rebind: None,
            bootstrap: None,
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

fn guest_client(active: &ActiveGuest) -> GuestClient<HyperVChannel> {
    GuestClient::new(
        HyperVChannel {
            vm_id: active.vm_id.clone(),
            guest_port: GUEST_CONTROL_PORT,
            timeout: Duration::from_secs(10),
        },
        active.machine_id.clone(),
        active.generation,
        active.boot_identity.clone(),
        active.capability,
    )
}

fn authentication_record(
    machine_id: &MachineId,
    generation: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
) -> Result<Vec<u8>, WindowsError> {
    let identity = machine_id.as_str().as_bytes();
    let size = u16::try_from(identity.len())
        .map_err(|_| WindowsError::Invalid("machine identity is too long".into()))?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(AUTHENTICATION_MAGIC);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(identity);
    bytes.extend_from_slice(&generation.get().to_be_bytes());
    bytes.extend_from_slice(&decode_hex(boot_identity.as_str())?);
    bytes.extend_from_slice(capability);
    bytes.resize(512, 0);
    Ok(bytes)
}

fn ensure_mutable_vhdx(source: &Path, destination: &Path, bytes: u64) -> Result<(), WindowsError> {
    if !bytes.is_multiple_of(1024 * 1024)
        || !(64 * 1024 * 1024..=MAX_ARTIFACT_BYTES).contains(&bytes)
    {
        return Err(WindowsError::Invalid(
            "persistent VHDX geometry is outside the envelope".into(),
        ));
    }
    crate::storage::materialize(
        source,
        destination,
        bytes,
        crate::storage::DiskFormat::Vhdx,
        |staged| virtual_disk::grow_virtual_disk(staged, bytes),
    )?;
    Ok(())
}

fn deterministic_vm_id(host_root: &Path, machine_id: &MachineId) -> String {
    let hash = Sha256::digest(format!("{}\0{}", host_root.display(), machine_id.as_str()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_identity_is_stable_and_canonical() {
        let machine: MachineId = "box".try_into().unwrap();
        let first = deterministic_vm_id(Path::new(r"C:\Sandsurf"), &machine);
        let second = deterministic_vm_id(Path::new(r"C:\Sandsurf"), &machine);
        assert_eq!(first, second);
        assert_eq!(first.len(), 36);
        assert_eq!(&first[14..15], "5");
    }
}
