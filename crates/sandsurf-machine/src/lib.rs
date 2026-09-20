#![deny(unsafe_code)]

//! Narrow internal hardware-VM lifecycle contract.
//!
//! Drivers own native VM handles, but never grants, lifecycle intent, guardian
//! observations, or application acceptance. Results are evidence submitted to
//! the guardian; returning `Observed` is not itself a journal commit.

use sandsurf_protocol::{
    Counter, DesiredState, Digest, LifecycleCommand, MachineObservation, MachineState,
    Qualification, VmEngine,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArchitecture {
    Amd64,
    Arm64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverQualification {
    pub engine: VmEngine,
    pub guest_architecture: GuestArchitecture,
    pub lifecycle: Qualification,
    pub full_state: Qualification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTransition {
    pub epoch: Counter,
    pub state: MachineState,
    pub evidence_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineOutcome {
    Observed(Vec<MachineTransition>),
    NotApplied(Digest),
    Unknown,
}

/// One exclusively owned native VM. Implementations must not silently cold-boot
/// for restore, infer success from API request delivery, or return before the
/// reported native postcondition has been observed.
pub trait MachineDriver {
    fn qualification(&self) -> DriverQualification;
    fn create(&mut self, command: &LifecycleCommand) -> MachineOutcome;
    fn reconfigure(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome;
    fn start(&mut self, command: &LifecycleCommand, current: &MachineObservation)
    -> MachineOutcome;
    fn pause(&mut self, command: &LifecycleCommand, current: &MachineObservation)
    -> MachineOutcome;
    fn resume(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome;
    fn suspend(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome;
    fn restore(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome;
    fn stop(&mut self, command: &LifecycleCommand, current: &MachineObservation) -> MachineOutcome;
    fn destroy(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome;
}

/// Route host intent to one explicit native operation and validate the evidence
/// shape before it reaches the guardian journal. Native uncertainty is retained.
pub fn apply_lifecycle<D: MachineDriver>(
    driver: &mut D,
    command: &LifecycleCommand,
    current: Option<&MachineObservation>,
) -> MachineOutcome {
    let outcome = match (command.desired, current) {
        (DesiredState::Running, None) => driver.create(command),
        (DesiredState::Running, Some(value)) if value.state == MachineState::Running => {
            driver.reconfigure(command, value)
        }
        (DesiredState::Running, Some(value)) if value.state == MachineState::Paused => {
            driver.resume(command, value)
        }
        (DesiredState::Running, Some(value))
            if matches!(value.state, MachineState::Stopped | MachineState::Failed) =>
        {
            driver.start(command, value)
        }
        (DesiredState::Running, Some(value)) if value.state == MachineState::Suspended => {
            driver.restore(command, value)
        }
        (DesiredState::Paused, Some(value)) if value.state == MachineState::Running => {
            driver.pause(command, value)
        }
        (DesiredState::Stopped, Some(value)) if value.state != MachineState::Destroyed => {
            driver.stop(command, value)
        }
        (DesiredState::Suspended, Some(value))
            if matches!(value.state, MachineState::Running | MachineState::Paused) =>
        {
            driver.suspend(command, value)
        }
        (DesiredState::Destroyed, Some(value)) if value.state != MachineState::Destroyed => {
            driver.destroy(command, value)
        }
        _ => {
            return MachineOutcome::NotApplied(sandsurf_protocol::bytes_digest(
                b"incompatible-native-lifecycle-state",
            ));
        }
    };
    validate_outcome(command, current, outcome)
}

fn validate_outcome(
    command: &LifecycleCommand,
    current: Option<&MachineObservation>,
    outcome: MachineOutcome,
) -> MachineOutcome {
    let MachineOutcome::Observed(transitions) = &outcome else {
        return outcome;
    };
    if transitions.is_empty() || transitions.len() > 8 {
        return MachineOutcome::Unknown;
    }
    let expected_epoch = match current {
        None => Counter::ONE,
        Some(value)
            if command.desired == DesiredState::Running
                && matches!(
                    value.state,
                    MachineState::Stopped | MachineState::Failed | MachineState::Suspended
                ) =>
        {
            let Ok(next) = value.epoch.next() else {
                return MachineOutcome::Unknown;
            };
            next
        }
        Some(value) => value.epoch,
    };
    if transitions
        .iter()
        .any(|transition| transition.epoch != expected_epoch)
        || !transitions
            .last()
            .is_some_and(|last| last.state.satisfies(command.desired))
    {
        return MachineOutcome::Unknown;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::{OperationId, SandboxId, bytes_digest};

    #[derive(Default)]
    struct Driver {
        called: Option<&'static str>,
        output: Option<MachineOutcome>,
    }
    impl Driver {
        fn take(&mut self, called: &'static str) -> MachineOutcome {
            self.called = Some(called);
            self.output.take().unwrap()
        }
    }
    impl MachineDriver for Driver {
        fn qualification(&self) -> DriverQualification {
            DriverQualification {
                engine: VmEngine::Firecracker,
                guest_architecture: GuestArchitecture::Amd64,
                lifecycle: Qualification::Qualified {
                    evidence: hash("lifecycle"),
                },
                full_state: Qualification::Unqualified { reasons: vec![] },
            }
        }
        fn create(&mut self, _: &LifecycleCommand) -> MachineOutcome {
            self.take("create")
        }
        fn reconfigure(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("reconfigure")
        }
        fn start(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("start")
        }
        fn pause(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("pause")
        }
        fn resume(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("resume")
        }
        fn suspend(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("suspend")
        }
        fn restore(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("restore")
        }
        fn stop(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("stop")
        }
        fn destroy(&mut self, _: &LifecycleCommand, _: &MachineObservation) -> MachineOutcome {
            self.take("destroy")
        }
    }

    fn hash(value: &str) -> Digest {
        bytes_digest(value.as_bytes())
    }
    fn command(desired: DesiredState) -> LifecycleCommand {
        LifecycleCommand {
            sandbox_id: SandboxId::try_from("box").unwrap(),
            operation_id: OperationId::try_from("operation").unwrap(),
            desired,
            revision: Counter::ONE,
            request_digest: hash("request"),
        }
    }
    fn observation(state: MachineState, epoch: u64) -> MachineObservation {
        MachineObservation {
            sandbox_id: SandboxId::try_from("box").unwrap(),
            epoch: epoch.try_into().unwrap(),
            sequence: Counter::ONE,
            state,
            applied_revision: Counter::ONE,
            operation_id: OperationId::try_from("old").unwrap(),
            evidence_digest: hash("old"),
        }
    }
    fn output(epoch: u64, state: MachineState) -> MachineOutcome {
        MachineOutcome::Observed(vec![MachineTransition {
            epoch: epoch.try_into().unwrap(),
            state,
            evidence_digest: hash("native"),
        }])
    }

    #[test]
    fn routes_each_lifecycle_without_cold_boot_substitution() {
        for (desired, current, expected, epoch, terminal) in [
            (
                DesiredState::Running,
                None,
                "create",
                1,
                MachineState::Running,
            ),
            (
                DesiredState::Running,
                Some(observation(MachineState::Running, 1)),
                "reconfigure",
                1,
                MachineState::Running,
            ),
            (
                DesiredState::Running,
                Some(observation(MachineState::Paused, 1)),
                "resume",
                1,
                MachineState::Running,
            ),
            (
                DesiredState::Running,
                Some(observation(MachineState::Stopped, 1)),
                "start",
                2,
                MachineState::Running,
            ),
            (
                DesiredState::Running,
                Some(observation(MachineState::Suspended, 4)),
                "restore",
                5,
                MachineState::Running,
            ),
            (
                DesiredState::Paused,
                Some(observation(MachineState::Running, 1)),
                "pause",
                1,
                MachineState::Paused,
            ),
            (
                DesiredState::Stopped,
                Some(observation(MachineState::Paused, 1)),
                "stop",
                1,
                MachineState::Stopped,
            ),
            (
                DesiredState::Suspended,
                Some(observation(MachineState::Running, 1)),
                "suspend",
                1,
                MachineState::Suspended,
            ),
            (
                DesiredState::Destroyed,
                Some(observation(MachineState::Stopped, 1)),
                "destroy",
                1,
                MachineState::Destroyed,
            ),
        ] {
            let mut driver = Driver {
                called: None,
                output: Some(output(epoch, terminal)),
            };
            let actual = apply_lifecycle(&mut driver, &command(desired), current.as_ref());
            assert!(matches!(actual, MachineOutcome::Observed(_)));
            assert_eq!(driver.called, Some(expected));
        }
    }

    #[test]
    fn invalid_native_evidence_becomes_unknown_not_a_false_observation() {
        let mut driver = Driver {
            called: None,
            output: Some(output(1, MachineState::Running)),
        };
        let current = observation(MachineState::Stopped, 1);
        assert_eq!(
            apply_lifecycle(&mut driver, &command(DesiredState::Running), Some(&current)),
            MachineOutcome::Unknown
        );
        let mut driver = Driver {
            called: None,
            output: Some(MachineOutcome::Observed(Vec::new())),
        };
        assert_eq!(
            apply_lifecycle(&mut driver, &command(DesiredState::Running), None),
            MachineOutcome::Unknown
        );
    }
}
