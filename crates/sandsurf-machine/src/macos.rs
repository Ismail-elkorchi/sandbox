//! Guardian-owned Apple Virtualization.framework machine controller.
//!
//! The signed helper owns the native `VZVirtualMachine`. Rust owns admission,
//! qualification, request bounds, lifecycle evidence, and helper containment.

use crate::{
    ConfigurationOutcome, DriverQualification, GuestArchitecture, MachineDriver, MachineOutcome,
    MachineTransition,
};
use sandsurf_protocol::{
    ConfigurationCommand, Counter, Digest, LifecycleCommand, MachineId, MachineObservation,
    MachineState, Qualification, VmEngine, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const MAX_HELPER_MESSAGE: usize = 1024 * 1024;
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const OBSERVATION_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleQualification {
    pub lifecycle: Option<Digest>,
    pub full_state: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppleDisk {
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleConfig {
    pub machine_id: MachineId,
    pub helper: PathBuf,
    pub helper_digest: Digest,
    pub guest_architecture: GuestArchitecture,
    pub kernel: PathBuf,
    pub initial_ramdisk: Option<PathBuf>,
    pub command_line: String,
    pub disks: Vec<AppleDisk>,
    pub memory_bytes: u64,
    pub vcpus: u32,
    /// Private guardian endpoint relayed to the guest's virtio-socket port.
    pub control_socket: PathBuf,
    pub host_connect_ports: Vec<u32>,
    pub guest_listen_ports: Vec<u32>,
    pub operation_timeout: Duration,
    pub qualification: AppleQualification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppleConfigError {
    RelativeHelper,
    RelativeKernel,
    RelativeInitialRamdisk,
    MissingDisk,
    RelativeDisk,
    DuplicateDisk,
    InvalidMemory,
    InvalidCpuCount,
    InvalidCommandLine,
    RelativeControlSocket,
    InvalidGuestPorts,
    TimeoutOutOfRange,
}

pub struct AppleDriver {
    config: AppleConfig,
    owner: Option<HelperOwner>,
    capture_paused: bool,
    full_capture_operation: Option<sandsurf_protocol::OperationId>,
    committed_suspend: Option<(sandsurf_protocol::OperationId, Digest)>,
    staged_restore: Option<AppleRestoreSource>,
    pending_storage_custody: Option<Arc<File>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleRestoreSource {
    pub saved_state: PathBuf,
    pub manifest_digest: Digest,
}

impl AppleConfig {
    pub fn validate(&self) -> Result<(), AppleConfigError> {
        if !self.helper.is_absolute() {
            return Err(AppleConfigError::RelativeHelper);
        }
        if !self.kernel.is_absolute() {
            return Err(AppleConfigError::RelativeKernel);
        }
        if self
            .initial_ramdisk
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(AppleConfigError::RelativeInitialRamdisk);
        }
        if self.disks.is_empty() {
            return Err(AppleConfigError::MissingDisk);
        }
        let mut seen = std::collections::BTreeSet::new();
        for disk in &self.disks {
            if !disk.path.is_absolute() {
                return Err(AppleConfigError::RelativeDisk);
            }
            if !seen.insert(disk.path.clone()) {
                return Err(AppleConfigError::DuplicateDisk);
            }
        }
        if self.memory_bytes < 256 * 1024 * 1024 || !self.memory_bytes.is_multiple_of(1024 * 1024) {
            return Err(AppleConfigError::InvalidMemory);
        }
        if self.vcpus == 0 || self.vcpus > 1024 {
            return Err(AppleConfigError::InvalidCpuCount);
        }
        if self.command_line.len() > 16 * 1024 || self.command_line.contains('\0') {
            return Err(AppleConfigError::InvalidCommandLine);
        }
        if !self.control_socket.is_absolute() {
            return Err(AppleConfigError::RelativeControlSocket);
        }
        if self.host_connect_ports.is_empty()
            || self
                .host_connect_ports
                .iter()
                .any(|port| *port < 1024 || *port == u32::MAX)
            || self
                .host_connect_ports
                .windows(2)
                .any(|ports| ports[0] >= ports[1])
            || self
                .guest_listen_ports
                .iter()
                .any(|port| *port < 1024 || *port == u32::MAX)
            || self
                .guest_listen_ports
                .windows(2)
                .any(|ports| ports[0] >= ports[1])
        {
            return Err(AppleConfigError::InvalidGuestPorts);
        }
        if self.operation_timeout.is_zero()
            || self.operation_timeout.as_millis() > u128::from(u32::MAX)
        {
            return Err(AppleConfigError::TimeoutOutOfRange);
        }
        Ok(())
    }
}

impl AppleDriver {
    pub fn new(config: AppleConfig) -> Result<Self, AppleConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            owner: None,
            capture_paused: false,
            full_capture_operation: None,
            committed_suspend: None,
            staged_restore: None,
            pending_storage_custody: None,
        })
    }

    pub fn default_timeout() -> Duration {
        DEFAULT_OPERATION_TIMEOUT
    }

    /// A pending native launch receives the storage owner's already-held
    /// custody. It is not a path-based second acquisition in the helper.
    pub fn stage_storage_custody(&mut self, custody: Arc<File>) -> io::Result<()> {
        if self.owner.is_some() || self.pending_storage_custody.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native storage custody is already installed",
            ));
        }
        self.pending_storage_custody = Some(custody);
        Ok(())
    }

    pub fn discard_pending_storage_custody(&mut self) {
        self.pending_storage_custody.take();
    }

    fn unavailable(reason: &'static [u8]) -> MachineOutcome {
        MachineOutcome::NotApplied(bytes_digest(reason))
    }

    fn helper_create(&self, machine_id: MachineId) -> HelperCreate {
        HelperCreate {
            machine_id,
            kernel: self.config.kernel.clone(),
            initial_ramdisk: self.config.initial_ramdisk.clone(),
            command_line: self.config.command_line.clone(),
            disks: self.config.disks.clone(),
            memory_bytes: self.config.memory_bytes,
            vcpus: self.config.vcpus,
            control_socket: self.config.control_socket.clone(),
            host_connect_ports: self.config.host_connect_ports.clone(),
            guest_listen_ports: self.config.guest_listen_ports.clone(),
        }
    }

    fn create_and_start(
        &mut self,
        command: &LifecycleCommand,
        generation: Counter,
    ) -> MachineOutcome {
        if command.machine_id != self.config.machine_id {
            return Self::unavailable(b"apple-machine-identity-mismatch");
        }
        if self.owner.is_some() {
            return MachineOutcome::Unknown;
        }
        let resources = &command.configuration.resources;
        let Some(memory_bytes) = resources.memory_mib.get().checked_mul(1024 * 1024) else {
            return Self::unavailable(b"apple-memory-overflow");
        };
        let Ok(vcpus) = u32::try_from(resources.vcpus.get()) else {
            return Self::unavailable(b"apple-vcpu-overflow");
        };
        self.config.memory_bytes = memory_bytes;
        self.config.vcpus = vcpus;
        if !file_digest_matches(&self.config.helper, &self.config.helper_digest) {
            return Self::unavailable(b"apple-helper-integrity-mismatch");
        }
        let Some(custody) = self.pending_storage_custody.take() else {
            return Self::unavailable(b"apple-storage-custody-missing");
        };
        let mut owner =
            match HelperOwner::spawn(&self.config.helper, self.config.operation_timeout, custody) {
                Ok(value) => value,
                Err(_) => return Self::unavailable(b"apple-helper-not-started"),
            };
        let response = owner.request(&HelperRequest::Create(Box::new(
            self.helper_create(command.machine_id.clone()),
        )));
        match response {
            Ok(value)
                if value.kind == ResponseKind::Observed && value.state == MachineState::Running =>
            {
                self.owner = Some(owner);
                self.capture_paused = false;
                self.committed_suspend = None;
                MachineOutcome::Observed(vec![
                    transition(
                        command,
                        generation,
                        if generation == Counter::ONE {
                            MachineState::Creating
                        } else {
                            MachineState::Starting
                        },
                        b"vz-create-complete",
                    ),
                    transition(
                        command,
                        generation,
                        MachineState::Running,
                        b"vz-start-complete",
                    ),
                ])
            }
            Ok(value) if value.kind == ResponseKind::NotApplied => {
                Self::unavailable(b"apple-create-not-applied")
            }
            Ok(_) | Err(_) => {
                owner.contain();
                MachineOutcome::Unknown
            }
        }
    }

    fn transition_owner(
        &mut self,
        command: &LifecycleCommand,
        generation: Counter,
        request: HelperRequest,
        expected: MachineState,
        evidence: &'static [u8],
    ) -> MachineOutcome {
        if command.machine_id != self.config.machine_id {
            return Self::unavailable(b"apple-machine-identity-mismatch");
        }
        let Some(owner) = self.owner.as_mut() else {
            return Self::unavailable(b"apple-machine-owner-unavailable");
        };
        match owner.request(&request) {
            Ok(value) if value.kind == ResponseKind::Observed && value.state == expected => {
                MachineOutcome::Observed(vec![transition(command, generation, expected, evidence)])
            }
            Ok(value) if value.kind == ResponseKind::NotApplied => {
                Self::unavailable(b"apple-transition-not-applied")
            }
            Ok(_) | Err(_) => MachineOutcome::Unknown,
        }
    }

    fn stop_owner(
        &mut self,
        command: &LifecycleCommand,
        generation: Counter,
        already_stopped: bool,
    ) -> MachineOutcome {
        if command.machine_id != self.config.machine_id {
            return Self::unavailable(b"apple-machine-identity-mismatch");
        }
        let Some(mut owner) = self.owner.take() else {
            return if already_stopped {
                MachineOutcome::Observed(vec![transition(
                    command,
                    generation,
                    MachineState::Stopped,
                    b"vz-already-stopped",
                )])
            } else {
                MachineOutcome::Unknown
            };
        };
        let result = owner.request(&HelperRequest::Stop);
        let exited = owner.finish();
        match (result, exited) {
            (Ok(value), true)
                if value.kind == ResponseKind::Observed && value.state == MachineState::Stopped =>
            {
                MachineOutcome::Observed(vec![transition(
                    command,
                    generation,
                    MachineState::Stopped,
                    b"vz-stop-complete",
                )])
            }
            _ => MachineOutcome::Unknown,
        }
    }

    pub fn pause_for_capture(&mut self) -> Result<(), AppleRuntimeError> {
        if self.capture_paused {
            return Ok(());
        }
        let owner = self
            .owner
            .as_mut()
            .ok_or(AppleRuntimeError::OwnerUnavailable)?;
        match owner.request(&HelperRequest::Pause) {
            Ok(value)
                if value.kind == ResponseKind::Observed && value.state == MachineState::Paused =>
            {
                self.capture_paused = true;
                Ok(())
            }
            _ => Err(AppleRuntimeError::TransitionFailed),
        }
    }

    pub fn resume_after_capture(&mut self) -> Result<(), AppleRuntimeError> {
        if !self.capture_paused {
            return Ok(());
        }
        let owner = self
            .owner
            .as_mut()
            .ok_or(AppleRuntimeError::OwnerUnavailable)?;
        match owner.request(&HelperRequest::Resume) {
            Ok(value)
                if value.kind == ResponseKind::Observed && value.state == MachineState::Running =>
            {
                self.capture_paused = false;
                self.full_capture_operation = None;
                self.committed_suspend = None;
                Ok(())
            }
            _ => Err(AppleRuntimeError::TransitionFailed),
        }
    }

    /// Adopt an already published native pause without executing guest code.
    pub fn adopt_pause_for_capture(&mut self) -> Result<(), AppleRuntimeError> {
        if self.owner.is_none() {
            return Err(AppleRuntimeError::OwnerUnavailable);
        }
        self.capture_paused = true;
        Ok(())
    }

    /// Finish a capture without silently resuming a publicly paused machine.
    pub fn finish_capture_preserving_pause(&mut self) -> Result<(), AppleRuntimeError> {
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.committed_suspend = None;
        Ok(())
    }

    pub fn save_full_state(
        &mut self,
        operation_id: &sandsurf_protocol::OperationId,
        destination: &Path,
    ) -> Result<(), AppleRuntimeError> {
        if !destination.is_absolute()
            || self
                .full_capture_operation
                .as_ref()
                .is_some_and(|value| value != operation_id)
        {
            return Err(AppleRuntimeError::InvalidCaptureState);
        }
        self.pause_for_capture()?;
        let owner = self
            .owner
            .as_mut()
            .ok_or(AppleRuntimeError::OwnerUnavailable)?;
        match owner.request(&HelperRequest::Save {
            saved_state: destination.to_path_buf(),
        }) {
            Ok(value)
                if value.kind == ResponseKind::Observed && value.state == MachineState::Paused =>
            {
                self.full_capture_operation = Some(operation_id.clone());
                Ok(())
            }
            _ => Err(AppleRuntimeError::TransitionFailed),
        }
    }

    pub fn commit_suspend(
        &mut self,
        operation_id: &sandsurf_protocol::OperationId,
        manifest_digest: Digest,
    ) -> Result<(), AppleRuntimeError> {
        if !self.capture_paused
            || self.full_capture_operation.as_ref() != Some(operation_id)
            || self
                .committed_suspend
                .as_ref()
                .is_some_and(|(old, digest)| old != operation_id || digest != &manifest_digest)
        {
            return Err(AppleRuntimeError::InvalidCaptureState);
        }
        self.committed_suspend = Some((operation_id.clone(), manifest_digest));
        Ok(())
    }

    pub fn stage_restore(&mut self, source: AppleRestoreSource) -> Result<(), AppleRuntimeError> {
        if self.owner.is_some()
            || !source.saved_state.is_absolute()
            || self
                .staged_restore
                .as_ref()
                .is_some_and(|old| old.manifest_digest != source.manifest_digest)
        {
            return Err(AppleRuntimeError::InvalidCaptureState);
        }
        self.staged_restore = Some(source);
        Ok(())
    }

    pub fn contain_unobserved(&mut self) {
        if let Some(mut owner) = self.owner.take() {
            owner.contain();
        }
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.committed_suspend = None;
        self.staged_restore = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleRuntimeError {
    OwnerUnavailable,
    TransitionFailed,
    InvalidCaptureState,
}

impl MachineDriver for AppleDriver {
    fn observe_power(&mut self) -> Result<Option<crate::NativePowerObservation>, Digest> {
        let Some(owner) = self.owner.as_mut() else {
            return Ok(None);
        };
        let response = owner
            .inspect()
            .map_err(|_| bytes_digest(b"apple-native-observation-unavailable"))?;
        if response.kind != ResponseKind::Observed
            || !matches!(
                response.state,
                MachineState::Running
                    | MachineState::Paused
                    | MachineState::Stopped
                    | MachineState::Failed
            )
        {
            return Err(bytes_digest(b"apple-native-observation-indeterminate"));
        }
        if response.state == MachineState::Stopped {
            let stopped = owner.request(&HelperRequest::Stop).is_ok_and(|value| {
                value.kind == ResponseKind::Observed && value.state == MachineState::Stopped
            });
            if !stopped || !owner.finish() {
                return Err(bytes_digest(b"apple-native-exit-unconfirmed"));
            }
            self.owner.take();
        }
        let evidence_digest = sandsurf_protocol::digest(
            sandsurf_protocol::Domain::Operation,
            &(
                "apple-native-power",
                &self.config.machine_id,
                response.state,
            ),
        )
        .map_err(|_| bytes_digest(b"apple-native-evidence-invalid"))?;
        Ok(Some(crate::NativePowerObservation {
            state: response.state,
            evidence_digest,
        }))
    }
    fn qualification(&self) -> DriverQualification {
        DriverQualification {
            engine: VmEngine::AppleVirtualization,
            guest_architecture: self.config.guest_architecture,
            lifecycle: qualification(
                self.config.qualification.lifecycle.clone(),
                "Apple lifecycle contract has not passed on this host/configuration",
            ),
            full_state: qualification(
                self.config.qualification.full_state.clone(),
                "Apple full-state contract has not passed on this host/configuration",
            ),
        }
    }

    fn configure(
        &mut self,
        command: &ConfigurationCommand,
        current: &MachineObservation,
    ) -> ConfigurationOutcome {
        let live = matches!(current.state, MachineState::Running | MachineState::Paused);
        if live
            && (command
                .configuration
                .resources
                .memory_mib
                .get()
                .checked_mul(1024 * 1024)
                != Some(self.config.memory_bytes)
                || command.configuration.resources.vcpus.get() != u64::from(self.config.vcpus))
        {
            return ConfigurationOutcome::NotApplied(bytes_digest(
                b"live-machine-geometry-change-unsupported",
            ));
        }
        if command.machine_id != self.config.machine_id
            || command.revision <= current.applied_revision
            || live != self.owner.is_some()
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
                b"apple-configuration-state-mismatch",
            ));
        }
        ConfigurationOutcome::Applied(bytes_digest(b"apple-configuration-installed"))
    }

    fn create(&mut self, command: &LifecycleCommand) -> MachineOutcome {
        self.create_and_start(command, Counter::ONE)
    }

    fn reconfigure(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.machine_id != self.config.machine_id {
            return Self::unavailable(b"apple-machine-identity-mismatch");
        }
        if self.owner.is_none() || command.revision <= current.applied_revision {
            return Self::unavailable(b"apple-live-reconfiguration-not-supported");
        }
        if !matches!(
            self.observe_power(),
            Ok(Some(crate::NativePowerObservation {
                state: MachineState::Running,
                ..
            }))
        ) {
            return MachineOutcome::Unknown;
        }
        MachineOutcome::Observed(vec![transition(
            command,
            current.generation,
            MachineState::Running,
            b"vz-already-running",
        )])
    }

    fn start(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        let Ok(generation) = current.generation.next() else {
            return MachineOutcome::Unknown;
        };
        self.create_and_start(command, generation)
    }

    fn pause(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        self.transition_owner(
            command,
            current.generation,
            HelperRequest::Pause,
            MachineState::Paused,
            b"vz-pause-complete",
        )
    }

    fn resume(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        self.transition_owner(
            command,
            current.generation,
            HelperRequest::Resume,
            MachineState::Running,
            b"vz-resume-complete",
        )
    }

    fn suspend(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.machine_id != self.config.machine_id
            || !self.capture_paused
            || self.full_capture_operation.is_none()
            || self.committed_suspend.is_none()
        {
            return Self::unavailable(b"apple-suspend-capture-not-committed");
        }
        let (_, manifest) = self
            .committed_suspend
            .take()
            .expect("committed suspend checked above");
        let Some(mut owner) = self.owner.take() else {
            return MachineOutcome::Unknown;
        };
        let released = owner.request(&HelperRequest::Release);
        let exited = owner.finish();
        if !matches!(
            released,
            Ok(HelperResponse {
                kind: ResponseKind::Observed,
                state: MachineState::Suspended,
            })
        ) || !exited
        {
            return MachineOutcome::Unknown;
        }
        self.capture_paused = false;
        self.full_capture_operation = None;
        MachineOutcome::Observed(vec![transition_with_digest(
            command,
            current.generation,
            MachineState::Suspended,
            b"vz-saved-state-committed-and-owner-released",
            &manifest,
        )])
    }

    fn restore(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.machine_id != self.config.machine_id || self.owner.is_some() {
            return Self::unavailable(b"apple-restore-state-mismatch");
        }
        let Some(source) = self.staged_restore.take() else {
            return Self::unavailable(b"apple-restore-not-staged");
        };
        let Ok(generation) = current.generation.next() else {
            return MachineOutcome::Unknown;
        };
        if !file_digest_matches(&self.config.helper, &self.config.helper_digest) {
            return Self::unavailable(b"apple-helper-integrity-mismatch");
        }
        let Some(custody) = self.pending_storage_custody.take() else {
            return Self::unavailable(b"apple-storage-custody-missing");
        };
        let mut owner =
            match HelperOwner::spawn(&self.config.helper, self.config.operation_timeout, custody) {
                Ok(value) => value,
                Err(_) => return Self::unavailable(b"apple-helper-not-started"),
            };
        let response = owner.request(&HelperRequest::Restore(Box::new(HelperRestore {
            machine: self.helper_create(command.machine_id.clone()),
            saved_state: source.saved_state,
        })));
        if !matches!(
            response,
            Ok(HelperResponse {
                kind: ResponseKind::Observed,
                state: MachineState::Running,
            })
        ) {
            owner.contain();
            return MachineOutcome::Unknown;
        }
        self.owner = Some(owner);
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.committed_suspend = None;
        MachineOutcome::Observed(vec![
            transition_with_digest(
                command,
                generation,
                MachineState::Restoring,
                b"vz-saved-state-loaded-paused",
                &source.manifest_digest,
            ),
            transition(
                command,
                generation,
                MachineState::Running,
                b"vz-saved-state-resumed",
            ),
        ])
    }

    fn stop(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        let generation = current.map_or(Counter::ONE, |value| value.generation);
        if current.is_some_and(|value| value.state == MachineState::Suspended)
            && self.owner.is_none()
        {
            self.staged_restore = None;
            return MachineOutcome::Observed(vec![transition(
                command,
                generation,
                MachineState::Stopped,
                b"vz-suspended-state-detached",
            )]);
        }
        self.stop_owner(
            command,
            generation,
            current.is_none_or(|value| value.state == MachineState::Stopped),
        )
    }

    fn destroy(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        let stopped = self.stop(command, current);
        if !matches!(stopped, MachineOutcome::Observed(_)) {
            return stopped;
        }
        let generation = current.map_or(Counter::ONE, |value| value.generation);
        MachineOutcome::Observed(vec![
            transition(
                command,
                generation,
                MachineState::Destroying,
                b"vz-destroying",
            ),
            transition(
                command,
                generation,
                MachineState::Destroyed,
                b"vz-owner-exited",
            ),
        ])
    }
}

impl Drop for AppleDriver {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.as_mut() {
            owner.contain();
        }
    }
}

struct HelperOwner {
    child: Child,
    input: Option<ChildStdin>,
    output: Arc<Mutex<ChildStdout>>,
    timeout: Duration,
    poisoned: bool,
    inspection: Option<PendingInspection>,
}

struct PendingInspection {
    reply: mpsc::Receiver<io::Result<HelperResponse>>,
    started: Instant,
}

impl HelperOwner {
    fn spawn(path: &Path, timeout: Duration, custody: Arc<File>) -> io::Result<Self> {
        let mut command = Command::new(path);
        command
            .arg("--sandsurf-owner-v2")
            .arg("--storage-custody-fd")
            .arg(custody.as_raw_fd().to_string())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // SAFETY: the post-fork child only changes a descriptor flag through
        // an async-signal-safe syscall; custody owns the inherited description.
        unsafe {
            command
                .pre_exec(move || sandsurf_native::storage::retain_descriptor_for_exec(&custody));
        }
        let mut child = command.spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("helper stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("helper stdout unavailable"))?;
        Ok(Self {
            child,
            input: Some(input),
            output: Arc::new(Mutex::new(output)),
            timeout,
            poisoned: false,
            inspection: None,
        })
    }

    fn request(&mut self, request: &HelperRequest) -> io::Result<HelperResponse> {
        // Drain exactly the outstanding read-only reply before writing a new
        // command. No duplicate request or second reader can steal its frame.
        if let Some(pending) = self.inspection.take() {
            match pending.reply.recv_timeout(self.timeout) {
                Ok(result) => {
                    if let Err(error) = result {
                        self.poisoned = true;
                        return Err(error);
                    }
                }
                Err(_) => {
                    self.inspection = Some(pending);
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Apple owner inspection remains pending; command was not dispatched",
                    ));
                }
            }
        }
        let receiver = self.send_request(request)?;
        match receiver.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(_) => {
                self.poisoned = true;
                self.contain();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Apple owner response timed out",
                ))
            }
        }
    }

    /// Observation is non-mutating even when the native helper is unavailable.
    /// Retain one unfinished read across probes instead of killing its owner,
    /// discarding a partial frame, or spawning an unbounded reader per poll.
    fn inspect(&mut self) -> io::Result<HelperResponse> {
        if self.poisoned {
            return Err(io::Error::other("Apple owner channel is poisoned"));
        }
        if let Some(pending) = self.inspection.as_ref()
            && pending.started.elapsed() >= OBSERVATION_TIMEOUT
        {
            match pending.reply.try_recv() {
                Ok(Ok(_)) => {
                    self.inspection.take();
                }
                Ok(Err(error)) => {
                    self.inspection.take();
                    self.poisoned = true;
                    return Err(error);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Apple observation reply remains pending",
                    ));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.inspection.take();
                    self.poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Apple inspection reader stopped",
                    ));
                }
            }
            // A late reply only repairs framing. Measure again rather than
            // promoting a timed-out sample to a current native observation.
        }
        if self.inspection.is_none() {
            match self.send_request(&HelperRequest::Inspect) {
                Ok(reply) => {
                    self.inspection = Some(PendingInspection {
                        reply,
                        started: Instant::now(),
                    })
                }
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            }
        }
        match self.inspection.as_ref().unwrap().reply.recv_timeout(
            OBSERVATION_TIMEOUT.saturating_sub(self.inspection.as_ref().unwrap().started.elapsed()),
        ) {
            Ok(result) => {
                self.inspection.take();
                if result.is_err() {
                    self.poisoned = true;
                }
                result
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Apple native observation unavailable; response remains pending",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.inspection.take();
                self.poisoned = true;
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Apple inspection reader stopped",
                ))
            }
        }
    }

    fn send_request(
        &mut self,
        request: &HelperRequest,
    ) -> io::Result<mpsc::Receiver<io::Result<HelperResponse>>> {
        if self.poisoned {
            return Err(io::Error::other("Apple owner channel is poisoned"));
        }
        let encoded = serde_json::to_vec(request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if encoded.len() > MAX_HELPER_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Apple owner request exceeds bound",
            ));
        }
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "helper input is closed"))?;
        input.write_all(&(encoded.len() as u32).to_be_bytes())?;
        input.write_all(&encoded)?;
        input.flush()?;

        let output = Arc::clone(&self.output);
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = output
                .lock()
                .map_err(|_| io::Error::other("helper output lock poisoned"))
                .and_then(|mut stream| read_response(&mut *stream));
            let _ = sender.send(result);
        });
        Ok(receiver)
    }

    fn contain(&mut self) {
        self.input.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn finish(&mut self) -> bool {
        self.input.take();
        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return false;
                }
            }
        }
    }
}

impl Drop for HelperOwner {
    fn drop(&mut self) {
        self.contain();
    }
}

fn read_response(stream: &mut impl Read) -> io::Result<HelperResponse> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_HELPER_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Apple owner response length is invalid",
        ));
    }
    let mut value = vec![0u8; length];
    stream.read_exact(&mut value)?;
    serde_json::from_slice(&value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum HelperRequest {
    Inspect,
    Create(Box<HelperCreate>),
    Restore(Box<HelperRestore>),
    Save { saved_state: PathBuf },
    Pause,
    Resume,
    Release,
    Stop,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperCreate {
    machine_id: MachineId,
    kernel: PathBuf,
    initial_ramdisk: Option<PathBuf>,
    command_line: String,
    disks: Vec<AppleDisk>,
    memory_bytes: u64,
    vcpus: u32,
    control_socket: PathBuf,
    host_connect_ports: Vec<u32>,
    guest_listen_ports: Vec<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperRestore {
    #[serde(flatten)]
    machine: HelperCreate,
    saved_state: PathBuf,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ResponseKind {
    Observed,
    NotApplied,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperResponse {
    kind: ResponseKind,
    state: MachineState,
}

fn file_digest_matches(path: &Path, expected: &Digest) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    bytes_digest(&bytes) == *expected
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
    generation: Counter,
    state: MachineState,
    native_evidence: &[u8],
) -> MachineTransition {
    let mut evidence = Vec::with_capacity(native_evidence.len() + 64);
    evidence.extend_from_slice(native_evidence);
    evidence.extend_from_slice(command.request_digest.as_str().as_bytes());
    MachineTransition {
        generation,
        state,
        evidence_digest: bytes_digest(&evidence),
    }
}

fn transition_with_digest(
    command: &LifecycleCommand,
    generation: Counter,
    state: MachineState,
    native_evidence: &[u8],
    bound: &Digest,
) -> MachineTransition {
    let mut evidence = Vec::with_capacity(native_evidence.len() + 128);
    evidence.extend_from_slice(native_evidence);
    evidence.extend_from_slice(command.request_digest.as_str().as_bytes());
    evidence.extend_from_slice(bound.as_str().as_bytes());
    MachineTransition {
        generation,
        state,
        evidence_digest: bytes_digest(&evidence),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_inherits_exclusive_storage_custody_until_confirmed_process_exit() {
        const FIXTURE: &str = "SANDSURF_APPLE_STORAGE_CUSTODY_FIXTURE";
        if std::env::var_os(FIXTURE).is_none() {
            // Other tests fork concurrently: until their exec, they correctly
            // retain every inherited file description, including this lease.
            // Isolate this close-lifetime assertion rather than unlocking a
            // potentially live native attachment or accepting a leaked lease.
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "macos::tests::helper_inherits_exclusive_storage_custody_until_confirmed_process_exit",
                    "--test-threads=1",
                ])
                .env(FIXTURE, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "isolated custody assertion failed: {}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr),
            );
            return;
        }
        use sandsurf_native::PrivateFileAccess;
        use sandsurf_native::local::{
            create_private_directory, create_private_file, open_private_file,
        };
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "sandsurf-apple-custody-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_private_directory(&root).unwrap();
        let helper = root.join("helper");
        // A process-only fixture exercises the production descriptor handoff;
        // it is not a fake VM or native virtualization qualification.
        create_private_file(&helper)
            .unwrap()
            .write_all(b"#!/bin/sh\nexec /bin/cat\n")
            .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("storage.lock");
        let custody = create_private_file(&path).unwrap();
        custody.try_lock().unwrap();
        let mut owner =
            HelperOwner::spawn(&helper, Duration::from_secs(1), Arc::new(custody)).unwrap();
        let next = open_private_file(&path, PrivateFileAccess::ReadWrite).unwrap();
        assert!(matches!(
            next.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        owner.contain();
        next.try_lock().unwrap();
        drop(owner);
        drop(next);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_relative_owner_and_disk_paths() {
        let value = AppleConfig {
            machine_id: "box".try_into().unwrap(),
            helper: PathBuf::from("helper"),
            helper_digest: bytes_digest(b"helper"),
            guest_architecture: GuestArchitecture::Arm64,
            kernel: PathBuf::from("/kernel"),
            initial_ramdisk: None,
            command_line: "console=hvc0".to_owned(),
            disks: vec![AppleDisk {
                path: PathBuf::from("/disk.raw"),
                read_only: false,
            }],
            memory_bytes: 1024 * 1024 * 1024,
            vcpus: 2,
            control_socket: PathBuf::from("/private/tmp/control.sock"),
            host_connect_ports: vec![52_001],
            guest_listen_ports: vec![],
            operation_timeout: Duration::from_secs(30),
            qualification: AppleQualification {
                lifecycle: None,
                full_state: None,
            },
        };
        assert_eq!(value.validate(), Err(AppleConfigError::RelativeHelper));
    }

    #[test]
    fn helper_response_is_bounded_and_strict() {
        let payload = br#"{"kind":"observed","state":"running"}"#;
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        let response = read_response(&mut framed.as_slice()).unwrap();
        assert_eq!(response.kind, ResponseKind::Observed);
        assert_eq!(response.state, MachineState::Running);

        let mut oversized = ((MAX_HELPER_MESSAGE + 1) as u32).to_be_bytes().to_vec();
        oversized.extend_from_slice(b"{}");
        assert!(read_response(&mut oversized.as_slice()).is_err());
    }

    #[test]
    fn timed_out_observation_preserves_owner_and_one_fragmented_reply_before_control() {
        let running = br#"{"kind":"observed","state":"running"}"#;
        let paused = br#"{"kind":"observed","state":"paused"}"#;
        let inspect_bytes = serde_json::to_vec(&HelperRequest::Inspect).unwrap().len() + 4;
        let pause_bytes = serde_json::to_vec(&HelperRequest::Pause).unwrap().len() + 4;
        // The helper consumes exactly one request before sending its fragmented
        // reply. A duplicate probe would be consumed as the later pause request.
        let script = format!(
            "request=$(dd bs=1 skip=4 count={} 2>/dev/null); test \"$request\" = '{{\"kind\":\"inspect\"}}' || exit 4; printf '\\000\\000\\000\\{:03o}{}'; sleep 0.7; printf '{}'; request=$(dd bs=1 skip=4 count={} 2>/dev/null); test \"$request\" = '{{\"kind\":\"pause\"}}' || exit 4; printf '\\000\\000\\000\\{:03o}{}'; sleep 5",
            inspect_bytes - 4,
            running.len(),
            std::str::from_utf8(&running[..10]).unwrap(),
            std::str::from_utf8(&running[10..]).unwrap(),
            pause_bytes - 4,
            paused.len(),
            std::str::from_utf8(paused).unwrap(),
        );
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut owner = HelperOwner {
            input: child.stdin.take(),
            output: Arc::new(Mutex::new(child.stdout.take().unwrap())),
            child,
            timeout: Duration::from_secs(2),
            poisoned: false,
            inspection: None,
        };
        for _ in 0..2 {
            assert_eq!(owner.inspect().unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert!(owner.inspection.is_some());
            assert!(!owner.poisoned);
            assert!(owner.child.try_wait().unwrap().is_none());
        }
        // Lifecycle control drains the outstanding reply and receives its own
        // result, not the observation that happened to finish first.
        let response = owner.request(&HelperRequest::Pause).unwrap();
        assert_eq!(response.state, MachineState::Paused);
        assert!(owner.inspection.is_none());
        assert!(owner.child.try_wait().unwrap().is_none());
    }

    #[test]
    fn a_late_power_reply_repairs_framing_but_is_not_current_evidence() {
        let paused = br#"{"kind":"observed","state":"paused"}"#;
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "printf '\\000\\000\\000\\{:03o}{}'; sleep 5",
                paused.len(),
                std::str::from_utf8(paused).unwrap()
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (sender, reply) = mpsc::sync_channel(1);
        sender
            .send(Ok(HelperResponse {
                kind: ResponseKind::Observed,
                state: MachineState::Running,
            }))
            .unwrap();
        let mut owner = HelperOwner {
            input: child.stdin.take(),
            output: Arc::new(Mutex::new(child.stdout.take().unwrap())),
            child,
            timeout: Duration::from_secs(2),
            poisoned: false,
            inspection: Some(PendingInspection {
                reply,
                started: Instant::now() - Duration::from_secs(1),
            }),
        };
        assert_eq!(owner.inspect().unwrap().state, MachineState::Paused);
        assert!(owner.inspection.is_none());
        assert!(!owner.poisoned);
        assert!(owner.child.try_wait().unwrap().is_none());
    }

    #[test]
    fn create_request_keeps_the_flat_helper_contract() {
        let machine = HelperCreate {
            machine_id: "box".try_into().unwrap(),
            kernel: "/kernel".into(),
            initial_ramdisk: None,
            command_line: "root=/dev/vda".into(),
            disks: vec![AppleDisk {
                path: "/disk".into(),
                read_only: true,
            }],
            memory_bytes: 512 * 1024 * 1024,
            vcpus: 2,
            control_socket: "/private/tmp/control.sock".into(),
            host_connect_ports: vec![10_789],
            guest_listen_ports: vec![12_080],
        };
        let request = HelperRequest::Create(Box::new(machine.clone()));
        let value = serde_json::to_value(request).unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../native/macos/fixtures/create.json"))
                .unwrap();
        assert_eq!(
            value, fixture,
            "Swift's contract fixture must be emitted by the production Rust request type"
        );
        assert_eq!(value["kind"], "create");
        assert_eq!(value["machineId"], "box");
        assert_eq!(value["hostConnectPorts"][0], 10_789);

        let restore = serde_json::to_value(HelperRequest::Restore(Box::new(HelperRestore {
            machine,
            saved_state: "/private/tmp/snapshot.vmstate".into(),
        })))
        .unwrap();
        assert_eq!(restore["kind"], "restore");
        assert_eq!(restore["machineId"], "box");
        assert_eq!(restore["savedState"], "/private/tmp/snapshot.vmstate");
    }

    #[test]
    fn unqualified_configuration_is_reported_not_assumed() {
        let value = qualification(None, "not tested");
        assert!(matches!(value, Qualification::Unqualified { .. }));
    }
}
