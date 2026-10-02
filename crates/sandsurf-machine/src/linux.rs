//! Guardian-owned Firecracker/KVM machine controller.
//!
//! This adapter reuses the verified VMM launch/confinement mechanism while
//! moving lifetime to a persistent guardian. Native power observations are
//! independent of the availability of guest-owned management software.

use crate::firecracker::{
    FirecrackerConfig, FirecrackerError, FirecrackerProcess, FirecrackerRestore,
    FirecrackerSnapshot,
};
use crate::{
    ConfigurationOutcome, DriverQualification, GuestArchitecture, MachineDriver, MachineOutcome,
    MachineTransition,
};
use sandsurf_protocol::{
    ConfigurationCommand, Counter, Digest, Domain, LifecycleCommand, MachineId, MachineObservation,
    MachineState, OperationId, Qualification, SnapshotId, VmEngine, bytes_digest, digest,
};
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirecrackerQualification {
    pub lifecycle: Option<Digest>,
    pub full_state: Option<Digest>,
}

#[derive(Debug, Clone)]
pub struct FirecrackerRestoreSource {
    pub snapshot_id: SnapshotId,
    pub capture_operation_id: OperationId,
    pub source_machine_id: MachineId,
    pub source_generation: Counter,
    pub manifest_digest: Digest,
    pub snapshot_state: std::path::PathBuf,
    pub snapshot_memory: std::path::PathBuf,
    pub reconnect_state: std::path::PathBuf,
}

/// Supplies a verified native boot configuration and binds the optional guest
/// management endpoint. Possession of guest-held keys is not guest attestation.
/// Endpoint availability never defines native machine power state.
pub trait FirecrackerGenerationFactory {
    fn configuration(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        resources: &sandsurf_protocol::Resources,
    ) -> Result<FirecrackerConfig, Digest>;

    fn bind_management(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest>;

    fn restore_configuration(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        source: &FirecrackerRestoreSource,
    ) -> Result<(FirecrackerConfig, FirecrackerRestore), Digest>;

    fn bind_restored_management(
        &mut self,
        machine_id: &MachineId,
        generation: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest>;
}

pub struct FirecrackerDriver<F> {
    machine_id: MachineId,
    guest_architecture: GuestArchitecture,
    qualification: FirecrackerQualification,
    factory: F,
    process: Option<FirecrackerProcess>,
    boot_resources: Option<sandsurf_protocol::Resources>,
    capture_paused: bool,
    full_capture_operation: Option<OperationId>,
    full_snapshot: Option<FirecrackerSnapshot>,
    committed_suspend: Option<(OperationId, Digest)>,
    staged_restore: Option<FirecrackerRestoreSource>,
    guest_reset: Option<Digest>,
}

impl<F: FirecrackerGenerationFactory> FirecrackerDriver<F> {
    /// The native owner stages immutable configuration inputs; this does not
    /// create virtual hardware or transfer lifecycle authority to the factory.
    pub fn generation_factory_mut(&mut self) -> &mut F {
        &mut self.factory
    }
    /// Native qualification changes whenever exact host device/resources
    /// configuration changes. A prior hardware run cannot qualify a new shape.
    pub fn set_qualification(&mut self, qualification: FirecrackerQualification) {
        self.qualification = qualification;
    }
    pub fn new(
        machine_id: MachineId,
        guest_architecture: GuestArchitecture,
        qualification: FirecrackerQualification,
        factory: F,
    ) -> Self {
        Self {
            machine_id,
            guest_architecture,
            qualification,
            factory,
            process: None,
            boot_resources: None,
            capture_paused: false,
            full_capture_operation: None,
            full_snapshot: None,
            committed_suspend: None,
            staged_restore: None,
            guest_reset: None,
        }
    }

    fn unavailable(reason: &'static [u8]) -> MachineOutcome {
        MachineOutcome::NotApplied(bytes_digest(reason))
    }

    fn identity_matches(&self, command: &LifecycleCommand) -> bool {
        command.machine_id == self.machine_id
    }

    fn boot(&mut self, command: &LifecycleCommand, generation: Counter) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-machine-identity-mismatch");
        }
        if self.process.is_some() {
            return MachineOutcome::Unknown;
        }
        let configuration = match self.factory.configuration(
            &self.machine_id,
            generation,
            &command.configuration.resources,
        ) {
            Ok(value) => value,
            Err(evidence) => return MachineOutcome::NotApplied(evidence),
        };
        let mut process = match FirecrackerProcess::spawn(&configuration) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("sandsurf Firecracker spawn failed: {error}");
                return MachineOutcome::Unknown;
            }
        };
        if let Err(error) = self
            .factory
            .bind_management(&self.machine_id, generation, &mut process)
        {
            eprintln!(
                "sandsurf management endpoint unavailable; native computer remains running: {error:?}"
            );
        }
        self.process = Some(process);
        self.boot_resources = Some(command.configuration.resources.clone());
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.full_snapshot = None;
        self.committed_suspend = None;
        self.staged_restore = None;
        let booting = if generation == Counter::ONE {
            MachineState::Creating
        } else {
            MachineState::Starting
        };
        MachineOutcome::Observed(vec![
            transition(command, generation, booting, b"firecracker-created"),
            transition(
                command,
                generation,
                MachineState::Running,
                b"native-machine-running",
            ),
        ])
    }

    fn stop_process(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-machine-identity-mismatch");
        }
        let generation = current.map_or(Counter::ONE, |value| value.generation);
        if self.process.is_none() {
            return if current.is_none_or(|value| {
                matches!(value.state, MachineState::Stopped | MachineState::Suspended)
                    || (value.state == MachineState::Failed
                        && value.cause == sandsurf_protocol::ObservationCause::Native {})
            }) {
                MachineOutcome::Observed(vec![transition(
                    command,
                    generation,
                    MachineState::Stopped,
                    b"firecracker-already-stopped",
                )])
            } else {
                MachineOutcome::Unknown
            };
        }
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.committed_suspend = None;
        let Some(mut process) = self.process.take() else {
            return MachineOutcome::Unknown;
        };
        if let Err(error) = process.terminate() {
            eprintln!("sandsurf VMM termination request failed: {error}");
            contain(&mut process);
            return MachineOutcome::Unknown;
        }
        if let Err(error) = process.wait() {
            eprintln!("sandsurf VMM termination confirmation failed: {error}");
            if matches!(&error, FirecrackerError::Io(io) if io.kind() == std::io::ErrorKind::TimedOut)
            {
                self.process = Some(process);
            } else {
                contain(&mut process);
            }
            return MachineOutcome::Unknown;
        }
        MachineOutcome::Observed(vec![transition(
            command,
            generation,
            MachineState::Stopped,
            b"firecracker-exit-confirmed",
        )])
    }

    /// A snapshot pause is internal to one capture transaction. It does not
    /// manufacture a host lifecycle intent or guardian machine observation.
    pub fn pause_for_capture(&mut self) -> Result<(), Digest> {
        if self.capture_paused {
            return Ok(());
        }
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| bytes_digest(b"firecracker-capture-owner-unavailable"))?;
        process
            .pause()
            .map_err(|_| bytes_digest(b"firecracker-capture-pause-failed"))?;
        self.capture_paused = true;
        Ok(())
    }

    /// Adopt an already published native pause without executing guest code.
    pub fn adopt_pause_for_capture(&mut self) -> Result<(), Digest> {
        if self.process.is_none() {
            return Err(bytes_digest(b"native-capture-owner-unavailable"));
        }
        self.capture_paused = true;
        Ok(())
    }

    /// Retire capture bookkeeping without changing observed native power. Also
    /// valid when preparation never paused or a lost resume already applied.
    pub fn finish_capture_without_resume(&mut self) -> Result<(), Digest> {
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.committed_suspend = None;
        self.remove_full_snapshot()
    }

    /// Create engine state for the exact already-frozen workload boundary.
    /// Repeating the same operation is safe; a different capture cannot replace
    /// an active paused transaction.
    pub fn create_full_snapshot(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<FirecrackerSnapshot, Digest> {
        if self
            .full_capture_operation
            .as_ref()
            .is_some_and(|value| value != operation_id)
        {
            return Err(bytes_digest(b"firecracker-full-capture-conflict"));
        }
        self.pause_for_capture()?;
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| bytes_digest(b"firecracker-capture-owner-unavailable"))?;
        let snapshot = process
            .create_full_snapshot(operation_id.as_str())
            .map_err(|_| bytes_digest(b"firecracker-full-snapshot-failed"))?;
        self.full_capture_operation = Some(operation_id.clone());
        self.full_snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    pub fn commit_suspend(
        &mut self,
        operation_id: &OperationId,
        manifest_digest: Digest,
    ) -> Result<(), Digest> {
        if !self.capture_paused
            || self.full_capture_operation.as_ref() != Some(operation_id)
            || self
                .committed_suspend
                .as_ref()
                .is_some_and(|(old, digest)| old != operation_id || digest != &manifest_digest)
        {
            return Err(bytes_digest(b"firecracker-suspend-capture-mismatch"));
        }
        self.committed_suspend = Some((operation_id.clone(), manifest_digest));
        Ok(())
    }

    pub fn stage_restore(&mut self, source: FirecrackerRestoreSource) -> Result<(), Digest> {
        if self.process.is_some()
            || self
                .staged_restore
                .as_ref()
                .is_some_and(|old| old.manifest_digest != source.manifest_digest)
        {
            return Err(bytes_digest(b"firecracker-restore-stage-conflict"));
        }
        self.staged_restore = Some(source);
        Ok(())
    }

    pub fn resume_after_capture(&mut self) -> Result<(), Digest> {
        if !self.capture_paused {
            return Ok(());
        }
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| bytes_digest(b"firecracker-capture-owner-unavailable"))?;
        process
            .resume()
            .map_err(|_| bytes_digest(b"firecracker-capture-resume-failed"))?;
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.committed_suspend = None;
        self.remove_full_snapshot()
    }

    /// Fail closed when a higher-level transaction cannot publish a machine
    /// that this driver has already started or restored. No observation is
    /// manufactured here; the guardian retains its previous observation and
    /// reports the attempted operation as indeterminate.
    pub fn contain_unobserved(&mut self) {
        if let Some(mut process) = self.process.take() {
            contain(&mut process);
        }
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.full_snapshot = None;
        self.committed_suspend = None;
        self.staged_restore = None;
    }

    fn remove_full_snapshot(&mut self) -> Result<(), Digest> {
        let Some(snapshot) = self.full_snapshot.as_ref() else {
            return Ok(());
        };
        for path in [&snapshot.snapshot_state, &snapshot.snapshot_memory] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(bytes_digest(b"firecracker-snapshot-cleanup-failed")),
            }
        }
        self.full_snapshot = None;
        Ok(())
    }
}

impl<F: FirecrackerGenerationFactory> MachineDriver for FirecrackerDriver<F> {
    fn take_console(&mut self) -> Option<crate::NativeConsole> {
        self.process
            .as_mut()
            .and_then(FirecrackerProcess::take_console)
    }
    fn take_guest_reset(&mut self) -> Option<Digest> {
        self.guest_reset.take()
    }
    fn observe_power(&mut self) -> Result<Option<crate::NativePowerObservation>, Digest> {
        let Some(process) = self.process.as_mut() else {
            return Ok(None);
        };
        let observation = process
            .observe_power()
            .map_err(|_| bytes_digest(b"firecracker-native-observation-unavailable"))?;
        if matches!(
            observation.state,
            MachineState::Stopped | MachineState::Failed
        ) {
            // observe_power confirmed and reaped the confined process tree.
            self.guest_reset = process.guest_reset_evidence();
            self.process.take();
            self.boot_resources = None;
            self.capture_paused = false;
            self.full_capture_operation = None;
            self.committed_suspend = None;
        }
        Ok(Some(observation))
    }
    fn qualification(&self) -> DriverQualification {
        DriverQualification {
            engine: VmEngine::Firecracker,
            guest_architecture: self.guest_architecture,
            lifecycle: qualification(
                self.qualification.lifecycle.clone(),
                "Firecracker lifecycle contract has not passed on this host/configuration",
            ),
            full_state: sandsurf_protocol::Capability::Supported {
                qualification: qualification(
                    self.qualification.full_state.clone(),
                    "Firecracker full-state contract has not passed on this host/configuration",
                ),
            },
        }
    }

    fn configure(
        &mut self,
        command: &ConfigurationCommand,
        current: &MachineObservation,
    ) -> ConfigurationOutcome {
        let live = matches!(current.state, MachineState::Running | MachineState::Paused);
        if live
            && self.boot_resources.as_ref().is_none_or(|resources| {
                resources.vcpus != command.configuration.resources.vcpus
                    || resources.memory_mib != command.configuration.resources.memory_mib
                    || resources.disk_bytes != command.configuration.resources.disk_bytes
            })
        {
            return ConfigurationOutcome::NotApplied(bytes_digest(
                b"live-machine-geometry-change-unsupported",
            ));
        }
        if command.machine_id != self.machine_id
            || command.revision <= current.applied_revision
            || live != self.process.is_some()
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
                b"firecracker-configuration-state-mismatch",
            ));
        }
        match digest(
            Domain::Authority,
            &(
                "firecracker-configuration-installed-v1",
                &command.machine_id,
                command.revision,
                &command.request_digest,
            ),
        ) {
            Ok(evidence) => ConfigurationOutcome::Applied(evidence),
            Err(_) => ConfigurationOutcome::Unknown,
        }
    }

    fn create(&mut self, command: &LifecycleCommand) -> MachineOutcome {
        self.boot(command, Counter::ONE)
    }

    fn reconfigure(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-machine-identity-mismatch");
        }
        if self.process.is_none() || command.revision <= current.applied_revision {
            return Self::unavailable(b"firecracker-live-reconfiguration-not-supported");
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
        // Grant policy is enforced by host/guardian services. The VM shape is
        // unchanged, so applying a newer authority revision is a control-plane
        // rebind rather than a reboot or unsupported resource hotplug.
        MachineOutcome::Observed(vec![transition(
            command,
            current.generation,
            MachineState::Running,
            b"firecracker-already-running",
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
        self.boot(command, generation)
    }

    fn pause(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-machine-identity-mismatch");
        }
        let Some(process) = self.process.as_ref() else {
            return Self::unavailable(b"firecracker-owner-unavailable");
        };
        match process.pause() {
            Ok(()) => MachineOutcome::Observed(vec![transition(
                command,
                current.generation,
                MachineState::Paused,
                b"firecracker-pause-complete",
            )]),
            Err(_) => MachineOutcome::Unknown,
        }
    }

    fn resume(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-machine-identity-mismatch");
        }
        let Some(process) = self.process.as_ref() else {
            return Self::unavailable(b"firecracker-owner-unavailable");
        };
        match process.resume() {
            Ok(()) => MachineOutcome::Observed(vec![transition(
                command,
                current.generation,
                MachineState::Running,
                b"firecracker-resume-complete",
            )]),
            Err(_) => MachineOutcome::Unknown,
        }
    }

    fn suspend(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if !self.identity_matches(command)
            || !self.capture_paused
            || self.committed_suspend.is_none()
            || self.process.is_none()
        {
            return Self::unavailable(b"firecracker-suspend-capture-not-committed");
        }
        let manifest = self
            .committed_suspend
            .as_ref()
            .expect("committed suspend checked above")
            .1
            .clone();
        let Some(mut process) = self.process.take() else {
            return MachineOutcome::Unknown;
        };
        if process.terminate().is_err() {
            contain(&mut process);
            return MachineOutcome::Unknown;
        }
        if let Err(error) = process.wait() {
            if matches!(&error, FirecrackerError::Io(io) if io.kind() == std::io::ErrorKind::TimedOut)
            {
                self.process = Some(process);
            } else {
                contain(&mut process);
            }
            return MachineOutcome::Unknown;
        }
        self.committed_suspend = None;
        self.capture_paused = false;
        self.full_capture_operation = None;
        if self.remove_full_snapshot().is_err() {
            return MachineOutcome::Unknown;
        }
        MachineOutcome::Observed(vec![transition_with_digest(
            command,
            current.generation,
            MachineState::Suspended,
            b"firecracker-snapshot-committed-and-vmm-released",
            &manifest,
        )])
    }

    fn restore(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if !self.identity_matches(command) || self.process.is_some() {
            return Self::unavailable(b"firecracker-restore-state-mismatch");
        }
        let Some(source) = self.staged_restore.take() else {
            return Self::unavailable(b"firecracker-restore-not-staged");
        };
        let Ok(generation) = current.generation.next() else {
            return MachineOutcome::Unknown;
        };
        let (configuration, restore) =
            match self
                .factory
                .restore_configuration(&self.machine_id, generation, &source)
            {
                Ok(value) => value,
                Err(evidence) => return MachineOutcome::NotApplied(evidence),
            };
        let mut process = match FirecrackerProcess::spawn_restore(&configuration, &restore) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("sandsurf Firecracker restore failed: {error}");
                return MachineOutcome::Unknown;
            }
        };
        if process.resume().is_err() {
            contain(&mut process);
            return MachineOutcome::Unknown;
        }
        let binding = match self.factory.bind_restored_management(
            &self.machine_id,
            generation,
            &mut process,
        ) {
            Ok(value) => value,
            Err(evidence) => {
                eprintln!(
                    "sandsurf restored management binding unavailable: {evidence:?}; native computer remains running"
                );
                evidence
            }
        };
        self.process = Some(process);
        self.boot_resources = Some(command.configuration.resources.clone());
        self.capture_paused = false;
        self.full_capture_operation = None;
        self.full_snapshot = None;
        self.committed_suspend = None;
        MachineOutcome::Observed(vec![
            transition_with_digest(
                command,
                generation,
                MachineState::Restoring,
                b"firecracker-snapshot-loaded-paused",
                &source.manifest_digest,
            ),
            transition_with_digest(
                command,
                generation,
                MachineState::Running,
                b"firecracker-native-restored",
                &binding,
            ),
        ])
    }

    fn stop(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        self.stop_process(command, current)
    }

    fn destroy(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        let stopped = self.stop_process(command, current);
        if !matches!(stopped, MachineOutcome::Observed(_)) {
            return stopped;
        }
        let generation = current.map_or(Counter::ONE, |value| value.generation);
        MachineOutcome::Observed(vec![
            transition(
                command,
                generation,
                MachineState::Destroying,
                b"firecracker-destroying",
            ),
            transition(
                command,
                generation,
                MachineState::Destroyed,
                b"firecracker-owner-released",
            ),
        ])
    }
}

impl<F> Drop for FirecrackerDriver<F> {
    fn drop(&mut self) {
        if let Some(process) = self.process.as_mut() {
            contain(process);
        }
    }
}

fn contain(process: &mut FirecrackerProcess) {
    let _ = process.terminate();
    let _ = process.wait();
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
    evidence: &[u8],
) -> MachineTransition {
    transition_with_digest(
        command,
        generation,
        state,
        evidence,
        &command.request_digest,
    )
}

fn transition_with_digest(
    command: &LifecycleCommand,
    generation: Counter,
    state: MachineState,
    evidence: &[u8],
    extra: &Digest,
) -> MachineTransition {
    let mut value = Vec::with_capacity(evidence.len() + 128);
    value.extend_from_slice(evidence);
    value.extend_from_slice(command.request_digest.as_str().as_bytes());
    value.extend_from_slice(extra.as_str().as_bytes());
    MachineTransition {
        generation,
        state,
        evidence_digest: bytes_digest(&value),
    }
}
