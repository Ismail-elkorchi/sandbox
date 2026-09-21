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
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::time::Duration;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::System::HostComputeSystem::{
    HCS_OPERATION, HCS_SYSTEM, HcsCloseComputeSystem, HcsCloseOperation, HcsCreateComputeSystem,
    HcsCreateOperation, HcsGrantVmAccess, HcsPauseComputeSystem, HcsResumeComputeSystem,
    HcsRevokeVmAccess, HcsStartComputeSystem, HcsTerminateComputeSystem,
    HcsWaitForComputeSystemExit, HcsWaitForOperationResult,
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
    /// The first disk is the UEFI boot disk. Further disks use stable SCSI
    /// attachment numbers and are never host-mounted by this driver.
    pub disks: Vec<HyperVDisk>,
    pub operation_timeout: Duration,
    pub qualification: HyperVQualification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HyperVConfigError {
    InvalidVmId,
    InvalidMemory,
    InvalidCpuCount,
    MissingBootDisk,
    RelativeDiskPath,
    DuplicateDisk,
    TimeoutOutOfRange,
}

/// The exclusive guardian owner of one HCS compute-system handle.
pub struct HyperVDriver {
    config: HyperVConfig,
    system: Option<SystemHandle>,
    granted_disks: Vec<PathBuf>,
    epoch: Option<Counter>,
    applied_revision: Option<Counter>,
}

impl HyperVConfig {
    pub fn validate(&self) -> Result<(), HyperVConfigError> {
        if self.vm_id.is_empty()
            || self.vm_id.len() > 128
            || !self
                .vm_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
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
        })
    }

    pub fn default_timeout() -> Duration {
        DEFAULT_OPERATION_TIMEOUT
    }

    fn is_lifecycle_qualified(&self) -> bool {
        self.config.qualification.lifecycle.is_some()
    }

    fn unavailable(&self, reason: &'static [u8]) -> MachineOutcome {
        MachineOutcome::NotApplied(bytes_digest(reason))
    }

    fn create_and_start(&mut self, command: &LifecycleCommand, epoch: Counter) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        if !self.is_lifecycle_qualified() {
            return self.unavailable(b"hyper-v-configuration-not-qualified");
        }
        if self.system.is_some() {
            return MachineOutcome::Unknown;
        }
        if let Err(disposition) = self.grant_disk_access() {
            return disposition;
        }

        let configuration = match serde_json::to_string(&self.hcs_configuration()) {
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
        for disk in &self.config.disks {
            let path = wide_path(&disk.path);
            // SAFETY: the VM ID and path buffers are NUL terminated and live for
            // this synchronous HCS access-control call.
            let result = unsafe { HcsGrantVmAccess(vm_id.as_ptr(), path.as_ptr()) };
            if failed(result) {
                let disposition = not_applied_hresult("hcs-grant-vm-access", result);
                return Err(self.rollback_grants_or(disposition));
            }
            self.granted_disks.push(disk.path.clone());
        }
        Ok(())
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

    fn hcs_configuration(&self) -> HcsConfiguration<'_> {
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
        HcsConfiguration {
            schema_version: SchemaVersion { major: 2, minor: 1 },
            owner: OWNER,
            should_terminate_on_last_handle_closed: true,
            virtual_machine: VirtualMachine {
                chipset: Chipset {
                    uefi: Uefi {
                        boot_this: BootDevice {
                            device_path: "Primary disk",
                            disk_number: 0,
                            device_type: "ScsiDrive",
                        },
                    },
                },
                compute_topology: ComputeTopology {
                    memory: Memory {
                        backing: "Virtual",
                        size_in_mb: self.config.memory_mib,
                    },
                    processor: Processor {
                        count: self.config.vcpus,
                    },
                },
                devices: Devices {
                    scsi: Scsi {
                        primary_disk: Controller { attachments },
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
        self.create_and_start(command, Counter::ONE)
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
        self.create_and_start(command, epoch)
    }

    fn pause(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return self.unavailable(b"hyper-v-sandbox-identity-mismatch");
        }
        if !self.is_lifecycle_qualified() {
            return self.unavailable(b"hyper-v-configuration-not-qualified");
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
        if !self.is_lifecycle_qualified() {
            return self.unavailable(b"hyper-v-configuration-not-qualified");
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
        _command: &LifecycleCommand,
        _current: &MachineObservation,
    ) -> MachineOutcome {
        // Save/restore requires a journaled, immutable capture location and an
        // exact compatibility manifest. Never substitute stop or cold boot.
        self.unavailable(b"hyper-v-full-state-capture-not-implemented")
    }

    fn restore(
        &mut self,
        _command: &LifecycleCommand,
        _current: &MachineObservation,
    ) -> MachineOutcome {
        self.unavailable(b"hyper-v-full-state-restore-not-implemented")
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
    chipset: Chipset<'a>,
    compute_topology: ComputeTopology<'a>,
    devices: Devices<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Chipset<'a> {
    uefi: Uefi<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Uefi<'a> {
    boot_this: BootDevice<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct BootDevice<'a> {
    device_path: &'a str,
    disk_number: u8,
    device_type: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ComputeTopology<'a> {
    memory: Memory<'a>,
    processor: Processor,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Memory<'a> {
    backing: &'a str,
    size_in_mb: u64,
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
}

#[derive(Serialize)]
struct Scsi<'a> {
    #[serde(rename = "Primary disk")]
    primary_disk: Controller<'a>,
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
            vm_id: "sandsurf-store-box".to_owned(),
            guest_architecture: GuestArchitecture::Amd64,
            memory_mib: 2048,
            vcpus: 2,
            disks: vec![HyperVDisk {
                path: PathBuf::from(r"C:\Sandsurf\box\boot.vhdx"),
                read_only: false,
            }],
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
        let value = serde_json::to_value(driver.hcs_configuration()).unwrap();
        assert_eq!(value["SchemaVersion"]["Major"], 2);
        assert_eq!(value["ShouldTerminateOnLastHandleClosed"], true);
        assert_eq!(
            value["VirtualMachine"]["Devices"]["Scsi"]["Primary disk"]["Attachments"]["0"]["Path"],
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
    fn unqualified_driver_never_touches_hcs() {
        let mut driver = HyperVDriver::new(config()).unwrap();
        let command = LifecycleCommand {
            sandbox_id: SandboxId::try_from("box").unwrap(),
            operation_id: "operation".try_into().unwrap(),
            desired: sandsurf_protocol::DesiredState::Running,
            revision: Counter::ONE,
            request_digest: bytes_digest(b"request"),
        };
        assert!(matches!(
            driver.create(&command),
            MachineOutcome::NotApplied(_)
        ));
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
