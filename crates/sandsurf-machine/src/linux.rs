//! Guardian-owned Firecracker/KVM machine controller.
//!
//! This adapter reuses the verified VMM launch/confinement mechanism while
//! moving lifetime to a persistent guardian. A machine is not observed running
//! until the trusted guest control channel has authenticated for its epoch.

use crate::{
    ConfigurationOutcome, DriverQualification, GuestArchitecture, MachineDriver, MachineOutcome,
    MachineTransition,
};
use sandbox_vm::{FirecrackerConfig, FirecrackerProcess};
use sandsurf_protocol::{
    ConfigurationCommand, Counter, Digest, Domain, LifecycleCommand, MachineObservation,
    MachineState, Qualification, SandboxId, VmEngine, bytes_digest, digest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirecrackerQualification {
    pub lifecycle: Option<Digest>,
    pub full_state: Option<Digest>,
}

/// Supplies one fresh, already verified epoch configuration and authenticates
/// the trusted guest supervisor. The factory may create an epoch authentication
/// disk, but it cannot publish a guardian observation.
pub trait FirecrackerEpochFactory {
    fn configuration(
        &mut self,
        sandbox_id: &SandboxId,
        epoch: Counter,
    ) -> Result<FirecrackerConfig, Digest>;

    fn authenticate(
        &mut self,
        sandbox_id: &SandboxId,
        epoch: Counter,
        process: &mut FirecrackerProcess,
    ) -> Result<Digest, Digest>;

    /// Establishes the guest's durable stop boundary before VMM termination.
    /// Returning an error leaves the live machine owned by this driver.
    fn prepare_stop(&mut self, sandbox_id: &SandboxId, epoch: Counter) -> Result<Digest, Digest>;
}

pub struct FirecrackerDriver<F> {
    sandbox_id: SandboxId,
    guest_architecture: GuestArchitecture,
    qualification: FirecrackerQualification,
    factory: F,
    process: Option<FirecrackerProcess>,
    applied_revision: Option<Counter>,
}

impl<F: FirecrackerEpochFactory> FirecrackerDriver<F> {
    pub fn new(
        sandbox_id: SandboxId,
        guest_architecture: GuestArchitecture,
        qualification: FirecrackerQualification,
        factory: F,
    ) -> Self {
        Self {
            sandbox_id,
            guest_architecture,
            qualification,
            factory,
            process: None,
            applied_revision: None,
        }
    }

    fn unavailable(reason: &'static [u8]) -> MachineOutcome {
        MachineOutcome::NotApplied(bytes_digest(reason))
    }

    fn identity_matches(&self, command: &LifecycleCommand) -> bool {
        command.sandbox_id == self.sandbox_id
    }

    fn boot(&mut self, command: &LifecycleCommand, epoch: Counter) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-sandbox-identity-mismatch");
        }
        if self.process.is_some() {
            return MachineOutcome::Unknown;
        }
        let configuration = match self.factory.configuration(&self.sandbox_id, epoch) {
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
        let authentication = match self
            .factory
            .authenticate(&self.sandbox_id, epoch, &mut process)
        {
            Ok(value) => value,
            Err(evidence) => {
                eprintln!("sandsurf guest authentication failed: {evidence:?}");
                contain(&mut process);
                return MachineOutcome::Unknown;
            }
        };
        self.process = Some(process);
        self.applied_revision = Some(command.revision);
        let booting = if epoch == Counter::ONE {
            MachineState::Creating
        } else {
            MachineState::Starting
        };
        MachineOutcome::Observed(vec![
            transition(command, epoch, booting, b"firecracker-created"),
            transition_with_digest(
                command,
                epoch,
                MachineState::Running,
                b"guest-authenticated",
                &authentication,
            ),
        ])
    }

    /// Whether this guardian still owns a live VMM for the current epoch. This
    /// is reachability evidence only; it never changes host lifecycle intent.
    pub fn has_live_owner(&mut self) -> bool {
        self.process
            .as_mut()
            .is_some_and(|process| matches!(process.has_exited(), Ok(false)))
    }

    fn stop_process(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-sandbox-identity-mismatch");
        }
        let Some(process) = self.process.as_ref() else {
            return if current.state == MachineState::Stopped {
                MachineOutcome::Observed(vec![transition(
                    command,
                    current.epoch,
                    MachineState::Stopped,
                    b"firecracker-already-stopped",
                )])
            } else {
                MachineOutcome::Unknown
            };
        };
        if current.state == MachineState::Paused && process.resume().is_err() {
            return MachineOutcome::Unknown;
        }
        let quiesce = match self.factory.prepare_stop(&self.sandbox_id, current.epoch) {
            Ok(value) => value,
            Err(_) => return MachineOutcome::Unknown,
        };
        let Some(mut process) = self.process.take() else {
            return MachineOutcome::Unknown;
        };
        if process.terminate().is_err() || process.wait().is_err() {
            contain(&mut process);
            return MachineOutcome::Unknown;
        }
        MachineOutcome::Observed(vec![transition_with_digest(
            command,
            current.epoch,
            MachineState::Stopped,
            b"firecracker-exit-confirmed",
            &quiesce,
        )])
    }
}

impl<F: FirecrackerEpochFactory> MachineDriver for FirecrackerDriver<F> {
    fn qualification(&self) -> DriverQualification {
        DriverQualification {
            engine: VmEngine::Firecracker,
            guest_architecture: self.guest_architecture,
            lifecycle: qualification(
                self.qualification.lifecycle.clone(),
                "Firecracker lifecycle contract has not passed on this host/configuration",
            ),
            full_state: qualification(
                self.qualification.full_state.clone(),
                "Firecracker full-state contract has not passed on this host/configuration",
            ),
        }
    }

    fn configure(
        &mut self,
        command: &ConfigurationCommand,
        current: &MachineObservation,
    ) -> ConfigurationOutcome {
        let live = matches!(current.state, MachineState::Running | MachineState::Paused);
        if command.sandbox_id != self.sandbox_id
            || self.applied_revision != Some(current.applied_revision)
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
        self.applied_revision = Some(command.revision);
        match digest(
            Domain::Grant,
            &(
                "firecracker-configuration-installed-v1",
                &command.sandbox_id,
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
            return Self::unavailable(b"firecracker-sandbox-identity-mismatch");
        }
        if self.process.is_none()
            || self.applied_revision != Some(current.applied_revision)
            || command.revision <= current.applied_revision
        {
            return Self::unavailable(b"firecracker-live-reconfiguration-not-supported");
        }
        // Grant policy is enforced by host/guardian services. The VM shape is
        // unchanged, so applying a newer authority revision is a control-plane
        // rebind rather than a reboot or unsupported resource hotplug.
        self.applied_revision = Some(command.revision);
        MachineOutcome::Observed(vec![transition(
            command,
            current.epoch,
            MachineState::Running,
            b"firecracker-already-running",
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
        self.boot(command, epoch)
    }

    fn pause(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if !self.identity_matches(command) {
            return Self::unavailable(b"firecracker-sandbox-identity-mismatch");
        }
        let Some(process) = self.process.as_ref() else {
            return Self::unavailable(b"firecracker-owner-unavailable");
        };
        match process.pause() {
            Ok(()) => MachineOutcome::Observed(vec![transition(
                command,
                current.epoch,
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
            return Self::unavailable(b"firecracker-sandbox-identity-mismatch");
        }
        let Some(process) = self.process.as_ref() else {
            return Self::unavailable(b"firecracker-owner-unavailable");
        };
        match process.resume() {
            Ok(()) => MachineOutcome::Observed(vec![transition(
                command,
                current.epoch,
                MachineState::Running,
                b"firecracker-resume-complete",
            )]),
            Err(_) => MachineOutcome::Unknown,
        }
    }

    fn suspend(
        &mut self,
        _command: &LifecycleCommand,
        _current: &MachineObservation,
    ) -> MachineOutcome {
        Self::unavailable(b"firecracker-full-state-capture-not-implemented")
    }

    fn restore(
        &mut self,
        _command: &LifecycleCommand,
        _current: &MachineObservation,
    ) -> MachineOutcome {
        Self::unavailable(b"firecracker-full-state-restore-not-implemented")
    }

    fn stop(&mut self, command: &LifecycleCommand, current: &MachineObservation) -> MachineOutcome {
        self.stop_process(command, current)
    }

    fn destroy(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if self.process.is_some() {
            let stopped = self.stop_process(command, current);
            if !matches!(stopped, MachineOutcome::Observed(_)) {
                return stopped;
            }
        } else if current.state != MachineState::Stopped {
            return MachineOutcome::Unknown;
        }
        MachineOutcome::Observed(vec![
            transition(
                command,
                current.epoch,
                MachineState::Destroying,
                b"firecracker-destroying",
            ),
            transition(
                command,
                current.epoch,
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
    epoch: Counter,
    state: MachineState,
    evidence: &[u8],
) -> MachineTransition {
    transition_with_digest(command, epoch, state, evidence, &command.request_digest)
}

fn transition_with_digest(
    command: &LifecycleCommand,
    epoch: Counter,
    state: MachineState,
    evidence: &[u8],
    extra: &Digest,
) -> MachineTransition {
    let mut value = Vec::with_capacity(evidence.len() + 128);
    value.extend_from_slice(evidence);
    value.extend_from_slice(command.request_digest.as_str().as_bytes());
    value.extend_from_slice(extra.as_str().as_bytes());
    MachineTransition {
        epoch,
        state,
        evidence_digest: bytes_digest(&value),
    }
}
