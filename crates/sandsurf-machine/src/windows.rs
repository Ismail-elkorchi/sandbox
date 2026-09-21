//! Guardian-owned Hyper-V/HCS machine controller.
//!
//! API availability is only a prerequisite. The driver remains unavailable
//! until the exact engine/image/guest configuration has retained real-host
//! qualification evidence.

use crate::{
    ConfigurationOutcome, DriverQualification, GuestArchitecture, MachineDriver, MachineOutcome,
    MachineTransition,
};
use sandsurf_protocol::{
    ConfigurationCommand, Counter, Digest, LifecycleCommand, MachineObservation, MachineState,
    Qualification, SandboxId, VmEngine, bytes_digest,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::time::Duration;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::System::HostComputeSystem::{
    HCS_OPERATION, HCS_SYSTEM, HcsCloseComputeSystem, HcsCloseOperation, HcsCreateComputeSystem,
    HcsCreateEmptyRuntimeStateFile, HcsCreateOperation, HcsGrantVmAccess, HcsPauseComputeSystem,
    HcsResumeComputeSystem, HcsRevokeVmAccess, HcsSaveComputeSystem, HcsStartComputeSystem,
    HcsTerminateComputeSystem, HcsWaitForComputeSystemExit, HcsWaitForOperationResult,
};
use windows_sys::core::{HRESULT, PWSTR};

const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const OWNER: &str = "Sandsurf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperVQualification {
    /// Evidence from the real-host lifecycle/containment contract suite for the
    /// exact distributed driver and boot bundle.
    pub lifecycle: Option<Digest>,
    /// Separate configuration-specific save/restore evidence.
    pub full_state: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperVDisk {
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperVConfig {
    pub sandbox_id: SandboxId,
    /// Host/store-qualified HCS identity. Callers must not use a process ID or
    /// an unfenced display name here.
    pub vm_id: String,
    pub guest_architecture: GuestArchitecture,
    pub memory_mib: u64,
    pub vcpus: u32,
    /// Direct-boot bzImage containing built-in Hyper-V storage and vsock
    /// drivers. HCS, not the workload, receives this host path.
    pub kernel: PathBuf,
    pub command_line: String,
    /// Disks use stable SCSI attachment numbers and are never host-mounted by
    /// this driver. Each path names a verified VHDX artifact.
    pub disks: Vec<HyperVDisk>,
    /// Owner-only SDDL installed on this VM's Hyper-V socket service table.
    pub hvsock_security_descriptor: String,
    /// Linux AF_VSOCK ports translated through HV_GUID_VSOCK_TEMPLATE.
    pub hvsock_ports: Vec<u32>,
    pub operation_timeout: Duration,
    pub qualification: HyperVQualification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HyperVConfigError {
    InvalidVmId,
    InvalidMemory,
    InvalidCpuCount,
    MissingBootDisk,
    RelativeKernelPath,
    InvalidCommandLine,
    InvalidSocketSecurity,
    InvalidSocketPort,
    RelativeDiskPath,
    DuplicateDisk,
    TimeoutOutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HyperVOperationError {
    NoLiveMachine,
    DispatchRejected,
    OutcomeUnknown,
}

/// The exclusive guardian owner of one HCS compute-system handle.
pub struct HyperVDriver {
    config: HyperVConfig,
    system: Option<SystemHandle>,
    granted_disks: Vec<PathBuf>,
    epoch: Option<Counter>,
    applied_revision: Option<Counter>,
    capture_paused: bool,
    full_capture_operation: Option<sandsurf_protocol::OperationId>,
    full_capture_state: Option<PathBuf>,
    committed_suspend: Option<(sandsurf_protocol::OperationId, Digest)>,
    staged_restore: Option<HyperVRestoreSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperVRestoreSource {
    pub saved_state: PathBuf,
    pub manifest_digest: Digest,
}

impl HyperVConfig {
    pub fn validate(&self) -> Result<(), HyperVConfigError> {
        if !valid_guid(&self.vm_id) {
            return Err(HyperVConfigError::InvalidVmId);
        }
        if self.memory_mib < 256 || self.memory_mib > 1_048_576 {
            return Err(HyperVConfigError::InvalidMemory);
        }
        if self.vcpus == 0 || self.vcpus > 1024 {
            return Err(HyperVConfigError::InvalidCpuCount);
        }
        if self.disks.is_empty() {
            return Err(HyperVConfigError::MissingBootDisk);
        }
        if !self.kernel.is_absolute() {
            return Err(HyperVConfigError::RelativeKernelPath);
        }
        if self.command_line.is_empty()
            || self.command_line.len() > 4096
            || self.command_line.contains(['\0', '\r', '\n'])
        {
            return Err(HyperVConfigError::InvalidCommandLine);
        }
        if self.hvsock_security_descriptor.is_empty()
            || self.hvsock_security_descriptor.len() > 4096
            || self.hvsock_security_descriptor.contains(['\0', '\r', '\n'])
        {
            return Err(HyperVConfigError::InvalidSocketSecurity);
        }
        let mut ports = BTreeSet::new();
        for port in &self.hvsock_ports {
            if !(1024..=0x7fff_ffff).contains(port) || !ports.insert(*port) {
                return Err(HyperVConfigError::InvalidSocketPort);
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for disk in &self.disks {
            if !disk.path.is_absolute() {
                return Err(HyperVConfigError::RelativeDiskPath);
            }
            let normalized = disk.path.to_string_lossy().to_lowercase();
            if !seen.insert(normalized) {
                return Err(HyperVConfigError::DuplicateDisk);
            }
        }
        if self.operation_timeout.is_zero()
            || self.operation_timeout.as_millis() > u128::from(u32::MAX - 1)
        {
            return Err(HyperVConfigError::TimeoutOutOfRange);
        }
        Ok(())
    }
}

impl HyperVDriver {
    pub fn new(config: HyperVConfig) -> Result<Self, HyperVConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            system: None,
            granted_disks: Vec::new(),
            epoch: None,
            applied_revision: None,
            capture_paused: false,
            full_capture_operation: None,
            full_capture_state: None,
            committed_suspend: None,
            staged_restore: None,
        })
    }

    pub fn default_timeout() -> Duration {
        DEFAULT_OPERATION_TIMEOUT
    }

    #[must_use]
    pub fn vm_id(&self) -> &str {
        &self.config.vm_id
    }

    #[must_use]
    pub fn has_live_owner(&self) -> bool {
        self.system.is_some()
    }

    pub fn contain_unobserved(&mut self) {
        self.contain_uncertain_machine();
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.full_capture_state = None;
        self.committed_suspend = None;
        self.staged_restore = None;
    }

    pub fn pause_for_capture(&mut self) -> Result<(), HyperVOperationError> {
        if self.capture_paused {
            return Ok(());
        }
        self.run_operation("hcs-capture-pause", |system, operation| {
            // SAFETY: live owned handles and a bounded empty options document.
            unsafe { HcsPauseComputeSystem(system, operation, wide("{}").as_ptr()) }
        })
        .map(|_| self.capture_paused = true)
        .map_err(HyperVOperationError::from)
    }

    pub fn resume_after_capture(&mut self) -> Result<(), HyperVOperationError> {
        if !self.capture_paused {
            return Ok(());
        }
        self.run_operation("hcs-capture-resume", |system, operation| {
            // SAFETY: live owned handles and a bounded empty options document.
            unsafe { HcsResumeComputeSystem(system, operation, wide("{}").as_ptr()) }
        })
        .map_err(HyperVOperationError::from)?;
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.committed_suspend = None;
        if let Some(path) = self.full_capture_state.take()
            && !self.revoke_path_access(&path)
        {
            return Err(HyperVOperationError::OutcomeUnknown);
        }
        Ok(())
    }

    pub fn resume_public_pause_for_capture(&mut self) -> Result<(), HyperVOperationError> {
        if self.capture_paused {
            return Err(HyperVOperationError::DispatchRejected);
        }
        self.run_operation("hcs-public-pause-capture-resume", |system, operation| {
            // SAFETY: live owned handles and a bounded empty options document.
            unsafe { HcsResumeComputeSystem(system, operation, wide("{}").as_ptr()) }
        })
        .map(drop)
        .map_err(HyperVOperationError::from)
    }

    pub fn restore_public_pause_after_capture(&mut self) -> Result<(), HyperVOperationError> {
        if self.capture_paused {
            return Err(HyperVOperationError::DispatchRejected);
        }
        self.run_operation("hcs-public-pause-restore", |system, operation| {
            // SAFETY: live owned handles and a bounded empty options document.
            unsafe { HcsPauseComputeSystem(system, operation, wide("{}").as_ptr()) }
        })
        .map(drop)
        .map_err(HyperVOperationError::from)
    }

    pub fn save_full_state(
        &mut self,
        operation_id: &sandsurf_protocol::OperationId,
        destination: &Path,
    ) -> Result<(), HyperVOperationError> {
        if !destination.is_absolute()
            || self
                .full_capture_operation
                .as_ref()
                .is_some_and(|value| value != operation_id)
        {
            return Err(HyperVOperationError::DispatchRejected);
        }
        self.pause_for_capture()?;
        if destination.exists() {
            return Err(HyperVOperationError::DispatchRejected);
        }
        // SAFETY: the destination is an absolute host-owned UTF-16 path. HCS
        // creates the bounded runtime-state container synchronously.
        let created = unsafe { HcsCreateEmptyRuntimeStateFile(wide_path(destination).as_ptr()) };
        if failed(created) || !self.grant_path_access(destination) {
            let _ = std::fs::remove_file(destination);
            return Err(HyperVOperationError::DispatchRejected);
        }
        let options = serde_json::to_string(&SaveOptions {
            save_type: "ToFile",
            save_state_file_path: destination.to_string_lossy(),
        })
        .map_err(|_| HyperVOperationError::DispatchRejected)?;
        let saved = self.run_operation("hcs-save", |system, operation| {
            // SAFETY: live owned handles and a bounded NUL-terminated options
            // document naming the pre-created private runtime-state file.
            unsafe { HcsSaveComputeSystem(system, operation, wide(&options).as_ptr()) }
        });
        if let Err(error) = saved {
            let _ = self.revoke_path_access(destination);
            let _ = std::fs::remove_file(destination);
            return Err(error.into());
        }
        self.full_capture_operation = Some(operation_id.clone());
        self.full_capture_state = Some(destination.to_path_buf());
        Ok(())
    }

    pub fn commit_suspend(
        &mut self,
        operation_id: &sandsurf_protocol::OperationId,
        manifest_digest: Digest,
    ) -> Result<(), HyperVOperationError> {
        if !self.capture_paused
            || self.full_capture_operation.as_ref() != Some(operation_id)
            || self
                .committed_suspend
                .as_ref()
                .is_some_and(|(old, digest)| old != operation_id || digest != &manifest_digest)
        {
            return Err(HyperVOperationError::DispatchRejected);
        }
        self.committed_suspend = Some((operation_id.clone(), manifest_digest));
        Ok(())
    }

    pub fn stage_restore(
        &mut self,
        source: HyperVRestoreSource,
    ) -> Result<(), HyperVOperationError> {
        if self.system.is_some()
            || !source.saved_state.is_absolute()
            || self
                .staged_restore
                .as_ref()
                .is_some_and(|old| old.manifest_digest != source.manifest_digest)
        {
            return Err(HyperVOperationError::DispatchRejected);
        }
        self.staged_restore = Some(source);
        Ok(())
    }

    #[must_use]
    pub fn capture_is_paused(&self) -> bool {
        self.capture_paused
    }

    fn unavailable(&self, reason: &'static [u8]) -> MachineOutcome {
        MachineOutcome::NotApplied(bytes_digest(reason))
    }

    fn create_and_start(
        &mut self,
        command: &LifecycleCommand,
        epoch: Counter,
        restore_state: Option<&Path>,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        if self.system.is_some() {
            return MachineOutcome::Unknown;
        }
        if let Err(disposition) = self.grant_disk_access() {
            return disposition;
        }
        if let Some(path) = restore_state
            && !self.grant_path_access(path)
        {
            return self.rollback_grants_or(self.unavailable(b"hcs-restore-state-access"));
        }

        let configuration = match serde_json::to_string(&self.hcs_configuration(restore_state)) {
            Ok(value) => value,
            Err(_) => {
                return self.rollback_grants_or(self.unavailable(b"hyper-v-config-encoding"));
            }
        };
        let operation = match OperationHandle::new() {
            Some(value) => value,
            None => return self.rollback_grants_or(self.unavailable(b"hcs-operation-unavailable")),
        };
        let id = wide(&self.config.vm_id);
        let document = wide(&configuration);
        let mut raw_system: HCS_SYSTEM = ptr::null_mut();
        // SAFETY: both UTF-16 buffers are NUL terminated for the duration of the
        // call, the operation handle is owned and live, the security descriptor
        // must be null per HCS, and raw_system is a valid out pointer.
        let dispatched = unsafe {
            HcsCreateComputeSystem(
                id.as_ptr(),
                document.as_ptr(),
                operation.0.as_ptr(),
                ptr::null(),
                &mut raw_system,
            )
        };
        if failed(dispatched) {
            return self.rollback_grants_or(not_applied_hresult("hcs-create", dispatched));
        }
        let Some(system) = NonNull::new(raw_system).map(SystemHandle) else {
            return self.rollback_grants_or(MachineOutcome::Unknown);
        };
        self.system = Some(system);
        let create_result = operation.wait(self.timeout_ms());
        if create_result.is_err() {
            self.contain_uncertain_machine();
            return MachineOutcome::Unknown;
        }

        let start = self.run_operation("hcs-start", |system, operation| {
            // SAFETY: the handles are live and owned by this driver; null is the
            // only supported options value for this HCS operation.
            unsafe { HcsStartComputeSystem(system, operation, ptr::null()) }
        });
        if start.is_err() {
            self.contain_uncertain_machine();
            return MachineOutcome::Unknown;
        }
        self.epoch = Some(epoch);
        self.applied_revision = Some(command.revision);
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.full_capture_state = None;
        self.committed_suspend = None;
        if restore_state.is_some() {
            MachineOutcome::Observed(vec![
                transition(
                    command,
                    epoch,
                    MachineState::Restoring,
                    b"hcs-restore-create-complete",
                ),
                transition(
                    command,
                    epoch,
                    MachineState::Running,
                    b"hcs-restore-start-complete",
                ),
            ])
        } else {
            MachineOutcome::Observed(vec![
                transition(
                    command,
                    epoch,
                    MachineState::Creating,
                    b"hcs-create-complete",
                ),
                transition(command, epoch, MachineState::Running, b"hcs-start-complete"),
            ])
        }
    }

    fn run_operation(
        &self,
        _label: &'static str,
        dispatch: impl FnOnce(HCS_SYSTEM, HCS_OPERATION) -> HRESULT,
    ) -> Result<Vec<u8>, OperationFailure> {
        let system = self
            .system
            .as_ref()
            .ok_or(OperationFailure::NotDispatched)?;
        let operation = OperationHandle::new().ok_or(OperationFailure::NotDispatched)?;
        let result = dispatch(system.0.as_ptr(), operation.0.as_ptr());
        if failed(result) {
            return Err(OperationFailure::Dispatch);
        }
        operation
            .wait(self.timeout_ms())
            .map_err(|_| OperationFailure::Wait)
    }

    fn timeout_ms(&self) -> u32 {
        u32::try_from(self.config.operation_timeout.as_millis())
            .expect("validated HCS timeout fits u32")
    }

    fn grant_disk_access(&mut self) -> Result<(), MachineOutcome> {
        let vm_id = wide(&self.config.vm_id);
        let paths = std::iter::once(&self.config.kernel)
            .chain(self.config.disks.iter().map(|disk| &disk.path))
            .cloned()
            .collect::<Vec<_>>();
        for disk in paths {
            let path = wide_path(&disk);
            // SAFETY: the VM ID and path buffers are NUL terminated and live for
            // this synchronous HCS access-control call.
            let result = unsafe { HcsGrantVmAccess(vm_id.as_ptr(), path.as_ptr()) };
            if failed(result) {
                let disposition = not_applied_hresult("hcs-grant-vm-access", result);
                return Err(self.rollback_grants_or(disposition));
            }
            self.granted_disks.push(disk);
        }
        Ok(())
    }

    fn grant_path_access(&mut self, path: &Path) -> bool {
        if self.granted_disks.iter().any(|granted| {
            granted
                .to_string_lossy()
                .eq_ignore_ascii_case(&path.to_string_lossy())
        }) {
            return true;
        }
        let vm_id = wide(&self.config.vm_id);
        let encoded = wide_path(path);
        // SAFETY: the VM ID and absolute path are live NUL-terminated UTF-16
        // buffers for this synchronous access-control call.
        let result = unsafe { HcsGrantVmAccess(vm_id.as_ptr(), encoded.as_ptr()) };
        if failed(result) {
            false
        } else {
            self.granted_disks.push(path.to_path_buf());
            true
        }
    }

    fn revoke_path_access(&mut self, path: &Path) -> bool {
        let Some(index) = self.granted_disks.iter().position(|granted| {
            granted
                .to_string_lossy()
                .eq_ignore_ascii_case(&path.to_string_lossy())
        }) else {
            return true;
        };
        let path = self.granted_disks.remove(index);
        let vm_id = wide(&self.config.vm_id);
        let encoded = wide_path(&path);
        // SAFETY: the VM ID and formerly granted path are live NUL-terminated
        // UTF-16 buffers for this synchronous revocation call.
        !failed(unsafe { HcsRevokeVmAccess(vm_id.as_ptr(), encoded.as_ptr()) })
    }

    fn revoke_disk_access(&mut self) -> bool {
        let vm_id = wide(&self.config.vm_id);
        let mut complete = true;
        while let Some(path) = self.granted_disks.pop() {
            let path = wide_path(&path);
            // SAFETY: the VM ID and path buffers are NUL terminated and live for
            // this synchronous HCS access-control call.
            let result = unsafe { HcsRevokeVmAccess(vm_id.as_ptr(), path.as_ptr()) };
            if failed(result) {
                complete = false;
            }
        }
        complete
    }

    fn rollback_grants_or(&mut self, outcome: MachineOutcome) -> MachineOutcome {
        if self.revoke_disk_access() {
            outcome
        } else {
            MachineOutcome::Unknown
        }
    }

    fn terminate_and_release(&mut self) -> bool {
        let mut confirmed = true;
        if self.system.is_some() {
            let terminated = self.run_operation("hcs-terminate", |system, operation| {
                // SAFETY: the handles are live and owned by this driver; null is
                // the supported options value.
                unsafe { HcsTerminateComputeSystem(system, operation, ptr::null()) }
            });
            if terminated.is_err() {
                confirmed = false;
            }
            if let Some(system) = self.system.as_ref() {
                let mut result: PWSTR = ptr::null_mut();
                // SAFETY: the compute-system handle is still live and result is
                // a valid out pointer. HCS owns no pointer after LocalFree below.
                let wait = unsafe {
                    HcsWaitForComputeSystemExit(system.0.as_ptr(), self.timeout_ms(), &mut result)
                };
                free_result(result);
                if failed(wait) {
                    confirmed = false;
                }
            }
            self.system.take();
        }
        if !self.revoke_disk_access() {
            confirmed = false;
        }
        confirmed
    }

    fn contain_uncertain_machine(&mut self) {
        let _ = self.terminate_and_release();
    }

    fn hcs_configuration<'a>(&'a self, restore_state: Option<&'a Path>) -> HcsConfiguration<'a> {
        let attachments = self
            .config
            .disks
            .iter()
            .enumerate()
            .map(|(index, disk)| {
                (
                    index.to_string(),
                    Attachment {
                        kind: "VirtualDisk",
                        path: disk.path.to_string_lossy(),
                        read_only: disk.read_only.then_some(true),
                    },
                )
            })
            .collect();
        let services = self
            .config
            .hvsock_ports
            .iter()
            .map(|port| {
                (
                    service_id(*port),
                    HvSocketService {
                        allow_wildcard_binds: false,
                        bind_security_descriptor: &self.config.hvsock_security_descriptor,
                        connect_security_descriptor: &self.config.hvsock_security_descriptor,
                    },
                )
            })
            .collect();
        HcsConfiguration {
            schema_version: SchemaVersion { major: 2, minor: 2 },
            owner: OWNER,
            should_terminate_on_last_handle_closed: true,
            virtual_machine: VirtualMachine {
                stop_on_reset: true,
                restore_state: restore_state.map(|path| RestoreState {
                    save_state_file_path: path.to_string_lossy(),
                }),
                chipset: Chipset {
                    linux_kernel_direct: LinuxKernelDirect {
                        kernel_file_path: self.config.kernel.to_string_lossy(),
                        kernel_cmd_line: &self.config.command_line,
                    },
                },
                compute_topology: ComputeTopology {
                    memory: Memory {
                        size_in_mb: self.config.memory_mib,
                        allow_overcommit: false,
                    },
                    processor: Processor {
                        count: self.config.vcpus,
                    },
                },
                devices: Devices {
                    scsi: Scsi {
                        primary_disk: Controller { attachments },
                    },
                    hv_socket: HvSocket {
                        config: HvSocketConfig {
                            default_bind_security_descriptor: &self
                                .config
                                .hvsock_security_descriptor,
                            default_connect_security_descriptor: &self
                                .config
                                .hvsock_security_descriptor,
                            service_table: services,
                        },
                    },
                },
            },
        }
    }
}

impl MachineDriver for HyperVDriver {
    fn qualification(&self) -> DriverQualification {
        DriverQualification {
            engine: VmEngine::HyperV,
            guest_architecture: self.config.guest_architecture,
            lifecycle: qualification(
                self.config.qualification.lifecycle.clone(),
                "Hyper-V lifecycle contract has not passed on this host/configuration",
            ),
            full_state: qualification(
                self.config.qualification.full_state.clone(),
                "Hyper-V full-state contract has not passed on this host/configuration",
            ),
        }
    }

    fn configure(
        &mut self,
        command: &ConfigurationCommand,
        current: &MachineObservation,
    ) -> ConfigurationOutcome {
        let live = matches!(current.state, MachineState::Running | MachineState::Paused);
        if command.sandbox_id != self.config.sandbox_id
            || self.applied_revision != Some(current.applied_revision)
            || command.revision <= current.applied_revision
            || live != self.system.is_some()
            || matches!(
                current.state,
                MachineState::Creating
                    | MachineState::Starting
                    | MachineState::Restoring
                    | MachineState::Destroying
                    | MachineState::Destroyed
                    | MachineState::Failed
            )
        {
            return ConfigurationOutcome::NotApplied(bytes_digest(
                b"hyper-v-configuration-state-mismatch",
            ));
        }
        self.applied_revision = Some(command.revision);
        ConfigurationOutcome::Applied(bytes_digest(b"hyper-v-configuration-installed"))
    }

    fn create(&mut self, command: &LifecycleCommand) -> MachineOutcome {
        self.create_and_start(command, Counter::ONE, None)
    }

    fn reconfigure(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        if self.system.is_none()
            || self.applied_revision != Some(current.applied_revision)
            || command.revision <= current.applied_revision
        {
            return self.unavailable(b"hyper-v-live-reconfiguration-not-supported");
        }
        self.applied_revision = Some(command.revision);
        MachineOutcome::Observed(vec![transition(
            command,
            current.epoch,
            MachineState::Running,
            b"hcs-already-running",
        )])
    }

    fn start(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        let Ok(epoch) = current.epoch.next() else {
            return MachineOutcome::Unknown;
        };
        self.create_and_start(command, epoch, None)
    }

    fn pause(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        match self.run_operation("hcs-pause", |system, operation| {
            // SAFETY: the handles are live and owned by this driver; an empty
            // options object is accepted by the HCS pause contract.
            unsafe { HcsPauseComputeSystem(system, operation, wide("{}").as_ptr()) }
        }) {
            Ok(_) => MachineOutcome::Observed(vec![transition(
                command,
                current.epoch,
                MachineState::Paused,
                b"hcs-pause-complete",
            )]),
            Err(OperationFailure::NotDispatched | OperationFailure::Dispatch) => {
                self.unavailable(b"hcs-pause-not-dispatched")
            }
            Err(OperationFailure::Wait) => MachineOutcome::Unknown,
        }
    }

    fn resume(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        match self.run_operation("hcs-resume", |system, operation| {
            // SAFETY: the handles are live and owned by this driver; an empty
            // options object is accepted by the HCS resume contract.
            unsafe { HcsResumeComputeSystem(system, operation, wide("{}").as_ptr()) }
        }) {
            Ok(_) => MachineOutcome::Observed(vec![transition(
                command,
                current.epoch,
                MachineState::Running,
                b"hcs-resume-complete",
            )]),
            Err(OperationFailure::NotDispatched | OperationFailure::Dispatch) => {
                self.unavailable(b"hcs-resume-not-dispatched")
            }
            Err(OperationFailure::Wait) => MachineOutcome::Unknown,
        }
    }

    fn suspend(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id
            || !self.capture_paused
            || self.full_capture_operation.is_none()
            || self.committed_suspend.is_none()
            || self.system.is_none()
        {
            return self.unavailable(b"hyper-v-suspend-capture-not-committed");
        }
        let (_, manifest) = self
            .committed_suspend
            .take()
            .expect("committed suspend checked above");
        // HcsSaveComputeSystem has already durably saved the paused VM. Closing
        // its sole handle with last-handle termination configured releases the
        // native system without allowing further guest disk writes.
        self.system.take();
        if !self.revoke_disk_access() {
            return MachineOutcome::Unknown;
        }
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.full_capture_state = None;
        MachineOutcome::Observed(vec![transition_with_digest(
            command,
            current.epoch,
            MachineState::Suspended,
            b"hcs-saved-state-committed-and-system-released",
            &manifest,
        )])
    }

    fn restore(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id || self.system.is_some() {
            return self.unavailable(b"hyper-v-restore-state-mismatch");
        }
        let Some(source) = self.staged_restore.take() else {
            return self.unavailable(b"hyper-v-restore-not-staged");
        };
        let Ok(epoch) = current.epoch.next() else {
            return MachineOutcome::Unknown;
        };
        let manifest = source.manifest_digest.clone();
        let mut outcome = self.create_and_start(command, epoch, Some(&source.saved_state));
        if let MachineOutcome::Observed(values) = &mut outcome
            && let Some(last) = values.last_mut()
        {
            last.evidence_digest = transition_with_digest(
                command,
                epoch,
                MachineState::Running,
                b"hcs-restored-state-running",
                &manifest,
            )
            .evidence_digest;
        }
        outcome
    }

    fn stop(&mut self, command: &LifecycleCommand, current: &MachineObservation) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        if !self.terminate_and_release() {
            return MachineOutcome::Unknown;
        }
        MachineOutcome::Observed(vec![transition(
            command,
            current.epoch,
            MachineState::Stopped,
            b"hcs-exit-confirmed",
        )])
    }

    fn destroy(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        if !self.terminate_and_release() {
            return MachineOutcome::Unknown;
        }
        MachineOutcome::Observed(vec![
            transition(
                command,
                current.epoch,
                MachineState::Destroying,
                b"hcs-destroying",
            ),
            transition(
                command,
                current.epoch,
                MachineState::Destroyed,
                b"hcs-exit-and-access-revocation-confirmed",
            ),
        ])
    }
}

impl Drop for HyperVDriver {
    fn drop(&mut self) {
        // Last-handle termination is configured as a second containment layer;
        // explicit terminate/wait remains required for a confirmed outcome.
        self.contain_uncertain_machine();
    }
}

struct OperationHandle(NonNull<c_void>);

impl OperationHandle {
    fn new() -> Option<Self> {
        // SAFETY: null context/callback requests a synchronous-wait operation.
        NonNull::new(unsafe { HcsCreateOperation(ptr::null(), None) }).map(Self)
    }

    fn wait(&self, timeout_ms: u32) -> Result<Vec<u8>, HRESULT> {
        let mut document: PWSTR = ptr::null_mut();
        // SAFETY: this is an owned live HCS operation, timeout is bounded, and
        // document is a valid out pointer released below.
        let result =
            unsafe { HcsWaitForOperationResult(self.0.as_ptr(), timeout_ms, &mut document) };
        let bytes = wide_result_bytes(document);
        free_result(document);
        if failed(result) {
            Err(result)
        } else {
            Ok(bytes)
        }
    }
}

impl Drop for OperationHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one non-null HCS operation handle.
        unsafe { HcsCloseOperation(self.0.as_ptr()) };
    }
}

struct SystemHandle(NonNull<c_void>);

impl Drop for SystemHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one non-null HCS compute-system
        // handle. The VM configuration requests last-handle termination.
        unsafe { HcsCloseComputeSystem(self.0.as_ptr()) };
    }
}

#[derive(Debug)]
enum OperationFailure {
    NotDispatched,
    Dispatch,
    Wait,
}

impl From<OperationFailure> for HyperVOperationError {
    fn from(value: OperationFailure) -> Self {
        match value {
            OperationFailure::NotDispatched => Self::NoLiveMachine,
            OperationFailure::Dispatch => Self::DispatchRejected,
            OperationFailure::Wait => Self::OutcomeUnknown,
        }
    }
}

fn failed(result: HRESULT) -> bool {
    result < 0
}

fn qualification(evidence: Option<Digest>, reason: &str) -> Qualification {
    match evidence {
        Some(evidence) => Qualification::Qualified { evidence },
        None => Qualification::Unqualified {
            reasons: vec![reason.to_owned()],
        },
    }
}

fn transition(
    command: &LifecycleCommand,
    epoch: Counter,
    state: MachineState,
    native_evidence: &[u8],
) -> MachineTransition {
    let mut evidence = Vec::with_capacity(native_evidence.len() + 64);
    evidence.extend_from_slice(native_evidence);
    evidence.extend_from_slice(command.request_digest.as_str().as_bytes());
    MachineTransition {
        epoch,
        state,
        evidence_digest: bytes_digest(&evidence),
    }
}

fn transition_with_digest(
    command: &LifecycleCommand,
    epoch: Counter,
    state: MachineState,
    native_evidence: &[u8],
    bound: &Digest,
) -> MachineTransition {
    let mut evidence = Vec::with_capacity(native_evidence.len() + 128);
    evidence.extend_from_slice(native_evidence);
    evidence.extend_from_slice(command.request_digest.as_str().as_bytes());
    evidence.extend_from_slice(bound.as_str().as_bytes());
    MachineTransition {
        epoch,
        state,
        evidence_digest: bytes_digest(&evidence),
    }
}

fn not_applied_hresult(operation: &str, result: HRESULT) -> MachineOutcome {
    MachineOutcome::NotApplied(bytes_digest(format!("{operation}:{result:#x}").as_bytes()))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    wide(&path.to_string_lossy())
}

fn wide_result_bytes(value: PWSTR) -> Vec<u8> {
    if value.is_null() {
        return Vec::new();
    }
    let mut length = 0usize;
    // SAFETY: HCS returns a valid NUL-terminated result document or null. The
    // scan is performed before releasing that document.
    unsafe {
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length)).into_bytes()
    }
}

fn free_result(value: PWSTR) {
    if !value.is_null() {
        // SAFETY: HCS result documents are local-allocated and transferred to
        // the caller, which releases each returned pointer exactly once.
        unsafe { LocalFree(value.cast()) };
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HcsConfiguration<'a> {
    schema_version: SchemaVersion,
    owner: &'a str,
    should_terminate_on_last_handle_closed: bool,
    virtual_machine: VirtualMachine<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SchemaVersion {
    major: u8,
    minor: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VirtualMachine<'a> {
    stop_on_reset: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    restore_state: Option<RestoreState<'a>>,
    chipset: Chipset<'a>,
    compute_topology: ComputeTopology,
    devices: Devices<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RestoreState<'a> {
    save_state_file_path: std::borrow::Cow<'a, str>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SaveOptions<'a> {
    save_type: &'a str,
    save_state_file_path: std::borrow::Cow<'a, str>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Chipset<'a> {
    linux_kernel_direct: LinuxKernelDirect<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct LinuxKernelDirect<'a> {
    kernel_file_path: std::borrow::Cow<'a, str>,
    kernel_cmd_line: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ComputeTopology {
    memory: Memory,
    processor: Processor,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Memory {
    size_in_mb: u64,
    allow_overcommit: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Processor {
    count: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Devices<'a> {
    scsi: Scsi<'a>,
    #[serde(rename = "HvSocket")]
    hv_socket: HvSocket<'a>,
}

#[derive(Serialize)]
struct Scsi<'a> {
    #[serde(rename = "Primary SCSI Controller")]
    primary_disk: Controller<'a>,
}

#[derive(Serialize)]
struct HvSocket<'a> {
    #[serde(rename = "HvSocketConfig")]
    config: HvSocketConfig<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HvSocketConfig<'a> {
    default_bind_security_descriptor: &'a str,
    default_connect_security_descriptor: &'a str,
    service_table: BTreeMap<String, HvSocketService<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HvSocketService<'a> {
    allow_wildcard_binds: bool,
    bind_security_descriptor: &'a str,
    connect_security_descriptor: &'a str,
}

fn service_id(port: u32) -> String {
    format!("{port:08x}-facb-11e6-bd58-64006a7986d3")
}

fn valid_guid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Controller<'a> {
    attachments: std::collections::BTreeMap<String, Attachment<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Attachment<'a> {
    #[serde(rename = "Type")]
    kind: &'a str,
    path: std::borrow::Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_only: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::E_HANDLE;

    fn config() -> HyperVConfig {
        HyperVConfig {
            sandbox_id: SandboxId::try_from("box").unwrap(),
            vm_id: "da57a1f0-3ca8-4f20-9802-21e8df32a9b1".to_owned(),
            guest_architecture: GuestArchitecture::Amd64,
            memory_mib: 2048,
            vcpus: 2,
            kernel: PathBuf::from(r"C:\Sandsurf\kernel"),
            command_line: "console=ttyS0 root=/dev/sda ro init=/sbin/sandbox-guest".into(),
            disks: vec![HyperVDisk {
                path: PathBuf::from(r"C:\Sandsurf\box\boot.vhdx"),
                read_only: false,
            }],
            hvsock_security_descriptor: "D:P(A;;GA;;;SY)".into(),
            hvsock_ports: vec![10_789],
            operation_timeout: Duration::from_secs(30),
            qualification: HyperVQualification {
                lifecycle: None,
                full_state: None,
            },
        }
    }

    #[test]
    fn emits_closed_no_network_configuration() {
        let driver = HyperVDriver::new(config()).unwrap();
        let value = serde_json::to_value(driver.hcs_configuration(None)).unwrap();
        assert_eq!(value["SchemaVersion"]["Major"], 2);
        assert_eq!(value["ShouldTerminateOnLastHandleClosed"], true);
        assert_eq!(
            value["VirtualMachine"]["Devices"]["Scsi"]["Primary SCSI Controller"]["Attachments"]["0"]
                ["Path"],
            r"C:\Sandsurf\box\boot.vhdx"
        );
        assert!(
            value["VirtualMachine"]["Devices"]
                .get("NetworkAdapters")
                .is_none()
        );
    }

    #[test]
    fn qualification_evidence_is_required() {
        let driver = HyperVDriver::new(config()).unwrap();
        assert!(matches!(
            driver.qualification().lifecycle,
            Qualification::Unqualified { .. }
        ));
    }

    #[test]
    fn rejects_relative_and_duplicate_disk_paths() {
        let mut value = config();
        value.disks[0].path = PathBuf::from("boot.vhdx");
        assert_eq!(
            HyperVDriver::new(value).err(),
            Some(HyperVConfigError::RelativeDiskPath)
        );

        let mut value = config();
        value.disks.push(value.disks[0].clone());
        assert_eq!(
            HyperVDriver::new(value).err(),
            Some(HyperVConfigError::DuplicateDisk)
        );
    }

    #[test]
    fn emits_linux_direct_boot_and_vsock_services() {
        let driver = HyperVDriver::new(config()).unwrap();
        let value = serde_json::to_value(driver.hcs_configuration(None)).unwrap();
        assert_eq!(
            value["VirtualMachine"]["Chipset"]["LinuxKernelDirect"]["KernelFilePath"],
            r"C:\Sandsurf\kernel"
        );
        assert!(
            value["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"]
                .get("00002a25-facb-11e6-bd58-64006a7986d3")
                .is_some()
        );
    }

    #[test]
    fn emits_bound_save_and_restore_documents() {
        let driver = HyperVDriver::new(config()).unwrap();
        let restore = Path::new(r"C:\Sandsurf\checkpoint.vmrs");
        let value = serde_json::to_value(driver.hcs_configuration(Some(restore))).unwrap();
        assert_eq!(
            value["VirtualMachine"]["RestoreState"]["SaveStateFilePath"],
            restore.to_string_lossy().as_ref()
        );
        let save = serde_json::to_value(SaveOptions {
            save_type: "ToFile",
            save_state_file_path: restore.to_string_lossy(),
        })
        .unwrap();
        assert_eq!(save["SaveType"], "ToFile");
        assert_eq!(
            save["SaveStateFilePath"],
            restore.to_string_lossy().as_ref()
        );
    }

    #[test]
    fn uses_bounded_default_timeout() {
        assert_eq!(HyperVDriver::default_timeout(), Duration::from_secs(120));
    }

    #[test]
    fn hcs_handle_error_is_failure() {
        assert!(failed(E_HANDLE));
    }
}
