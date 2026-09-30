#![deny(unsafe_op_in_unsafe_fn)]

//! Narrow internal hardware-VM lifecycle contract.
//!
//! Drivers own native VM handles, but never grants, lifecycle intent, guardian
//! observations, or application acceptance. Results are evidence submitted to
//! the guardian; returning `Observed` is not itself a journal commit.

use sandsurf_protocol::{
    Capability, ConfigurationCommand, Counter, DesiredState, Digest, GuestPowerCapabilities,
    LifecycleCommand, MachineObservation, MachineState, Qualification, VmEngine,
};

#[cfg(target_os = "linux")]
pub mod firecracker;
#[cfg(target_os = "linux")]
pub mod launcher;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(any(target_os = "macos", feature = "apple-source-check"))]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// Native adapters supply only virtual-hardware-specific device names. The
/// Linux OS policy is shared: root may administer its mounted block devices,
/// including growing the filesystem with ordinary e2fsprogs. This does not
/// confer host disk access; the adapter attaches only machine-owned disks.
pub fn linux_boot_arguments(console: &str, root_device: &str) -> String {
    format!(
        "console={console} reboot=k panic=1 root={root_device} rw init=/sbin/init bdev_allow_write_mounted=1"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArchitecture {
    Amd64,
    Arm64,
}

/// Native guest power mechanisms, not management-service health. A guest
/// reset which exits the VMM is not a supported ordinary computer reboot.
pub fn guest_power_capabilities() -> GuestPowerCapabilities {
    let shutdown = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Capability::Unsupported {
            reasons: vec![
                "Firecracker x86 has no ACPI power-management device; Linux poweroff can halt the guest without terminating the native VM".into(),
            ],
        }
    } else {
        Capability::Supported {
            qualification: Qualification::Unqualified {
                reasons: vec![
                    "Guest shutdown has no retained real-hardware qualification for this native driver, image and kernel configuration".into(),
                ],
            },
        }
    };
    GuestPowerCapabilities {
        shutdown,
        reboot: Capability::Unsupported {
            reasons: vec![
                "Ordinary guest reboot does not yet have native reset recovery and execution-generation rebinding; a native exit is observed as termination, not silently cold-booted".into(),
            ],
        },
    }
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
    pub generation: Counter,
    pub state: MachineState,
    pub evidence_digest: Digest,
}

/// A native-owner measurement, not a command outcome or a guest health report.
/// Generation and authority revision are assigned by the guardian, not drivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePowerObservation {
    pub state: MachineState,
    pub evidence_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineOutcome {
    Observed(Vec<MachineTransition>),
    NotApplied(Digest),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigurationOutcome {
    Applied(Digest),
    NotApplied(Digest),
    Unknown,
}

/// One exclusively owned native VM. Implementations must not silently cold-boot
/// for restore, infer success from API request delivery, or return before the
/// reported native postcondition has been observed.
pub trait MachineDriver {
    fn qualification(&self) -> DriverQualification;
    /// None means no live native attachment. Errors mean unavailable evidence,
    /// never a stopped computer. Observation must not start or replace a VM.
    fn observe_power(&mut self) -> Result<Option<NativePowerObservation>, Digest>;
    fn configure(
        &mut self,
        command: &ConfigurationCommand,
        current: &MachineObservation,
    ) -> ConfigurationOutcome;
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
    fn stop(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome;
    fn destroy(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome;
}

/// Route host intent to one explicit native operation and validate the evidence
/// shape before it reaches the guardian journal. Native uncertainty is retained.
pub fn apply_lifecycle<D: MachineDriver>(
    driver: &mut D,
    command: &LifecycleCommand,
    current: Option<&MachineObservation>,
) -> MachineOutcome {
    if current.is_some_and(|value| value.machine_id != command.machine_id) {
        return MachineOutcome::NotApplied(sandsurf_protocol::bytes_digest(
            b"native-lifecycle-machine-mismatch",
        ));
    }
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
        (DesiredState::Stopped, value)
            if value.is_none_or(|value| value.state != MachineState::Destroyed) =>
        {
            driver.stop(command, value)
        }
        (DesiredState::Suspended, Some(value))
            if matches!(value.state, MachineState::Running | MachineState::Paused) =>
        {
            driver.suspend(command, value)
        }
        (DesiredState::Destroyed, value)
            if value.is_none_or(|value| value.state != MachineState::Destroyed) =>
        {
            driver.destroy(command, value)
        }
        _ => {
            return MachineOutcome::NotApplied(sandsurf_protocol::bytes_digest(
                b"incompatible-native-lifecycle-state",
            ));
        }
    };
    let mut outcome = validate_outcome(command, current, outcome);
    if current.is_none()
        && matches!(
            command.desired,
            DesiredState::Stopped | DesiredState::Destroyed
        )
        && let MachineOutcome::Observed(transitions) = &mut outcome
    {
        // Creation identity does not claim a successful boot. It records the
        // native owner boundary before confirming termination of a partial VM.
        transitions.insert(
            0,
            MachineTransition {
                generation: Counter::ONE,
                state: MachineState::Creating,
                evidence_digest: sandsurf_protocol::bytes_digest(
                    b"native-unpublished-owner-contained",
                ),
            },
        );
    }
    outcome
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
    let expected_generation = match current {
        None => Counter::ONE,
        Some(value)
            if command.desired == DesiredState::Running
                && matches!(
                    value.state,
                    MachineState::Stopped | MachineState::Failed | MachineState::Suspended
                ) =>
        {
            let Ok(next) = value.generation.next() else {
                return MachineOutcome::Unknown;
            };
            next
        }
        Some(value) => value.generation,
    };
    if transitions
        .iter()
        .any(|transition| transition.generation != expected_generation)
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
    #[test]
    fn power_support_does_not_claim_guest_reset_recovery_or_acpi_on_firecracker_x86() {
        let capabilities = super::guest_power_capabilities();
        assert!(matches!(
            capabilities.reboot,
            super::Capability::Unsupported { .. }
        ));
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            assert!(matches!(
                capabilities.shutdown,
                super::Capability::Unsupported { .. }
            ));
        } else {
            assert!(matches!(
                capabilities.shutdown,
                super::Capability::Supported {
                    qualification: super::Qualification::Unqualified { .. }
                }
            ));
        }
    }

    use super::*;
    use sandsurf_protocol::{MachineId, OperationId, bytes_digest};

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
        fn observe_power(&mut self) -> Result<Option<NativePowerObservation>, Digest> {
            Ok(None)
        }
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
        fn configure(
            &mut self,
            _: &ConfigurationCommand,
            _: &MachineObservation,
        ) -> ConfigurationOutcome {
            ConfigurationOutcome::Applied(hash("configuration"))
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
        fn stop(&mut self, _: &LifecycleCommand, _: Option<&MachineObservation>) -> MachineOutcome {
            self.take("stop")
        }
        fn destroy(
            &mut self,
            _: &LifecycleCommand,
            _: Option<&MachineObservation>,
        ) -> MachineOutcome {
            self.take("destroy")
        }
    }

    fn hash(value: &str) -> Digest {
        bytes_digest(value.as_bytes())
    }
    fn command(desired: DesiredState) -> LifecycleCommand {
        LifecycleCommand {
            machine_id: MachineId::try_from("box").unwrap(),
            operation_id: OperationId::try_from("operation").unwrap(),
            desired,
            revision: Counter::ONE,
            request_digest: hash("request"),
            configuration: sandsurf_protocol::RuntimeConfiguration::default(),
        }
    }
    fn observation(state: MachineState, generation: u64) -> MachineObservation {
        MachineObservation {
            machine_id: MachineId::try_from("box").unwrap(),
            generation: generation.try_into().unwrap(),
            sequence: Counter::ONE,
            state,
            applied_revision: Counter::ONE,
            cause: sandsurf_protocol::ObservationCause::Lifecycle {
                operation_id: OperationId::try_from("old").unwrap(),
            },
            evidence_digest: hash("old"),
        }
    }
    fn output(generation: u64, state: MachineState) -> MachineOutcome {
        MachineOutcome::Observed(vec![MachineTransition {
            generation: generation.try_into().unwrap(),
            state,
            evidence_digest: hash("native"),
        }])
    }

    #[test]
    fn routes_each_lifecycle_without_cold_boot_substitution() {
        for (desired, current, expected, generation, terminal) in [
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
                output: Some(output(generation, terminal)),
            };
            let actual = apply_lifecycle(&mut driver, &command(desired), current.as_ref());
            assert!(matches!(actual, MachineOutcome::Observed(_)));
            assert_eq!(driver.called, Some(expected));
        }
    }

    #[test]
    fn unpublished_native_owner_can_be_terminated_without_a_boot_observation() {
        for (desired, terminal, operation) in [
            (DesiredState::Stopped, MachineState::Stopped, "stop"),
            (DesiredState::Destroyed, MachineState::Destroyed, "destroy"),
        ] {
            let mut driver = Driver {
                called: None,
                output: Some(output(1, terminal)),
            };
            let MachineOutcome::Observed(transitions) =
                apply_lifecycle(&mut driver, &command(desired), None)
            else {
                panic!("confirmed native containment must remain observable");
            };
            assert_eq!(driver.called, Some(operation));
            assert_eq!(transitions.first().unwrap().state, MachineState::Creating);
            assert_eq!(transitions.last().unwrap().state, terminal);
            assert!(
                transitions
                    .iter()
                    .all(|value| value.generation == Counter::ONE)
            );
            let mut uncertain = Driver {
                called: None,
                output: Some(MachineOutcome::Unknown),
            };
            assert_eq!(
                apply_lifecycle(&mut uncertain, &command(desired), None),
                MachineOutcome::Unknown
            );
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

    #[test]
    fn native_topologies_share_linux_administrator_boot_policy() {
        for (console, disk) in [
            ("ttyS0", "/dev/vda"),
            ("hvc0", "/dev/vda"),
            ("ttyS0", "/dev/sda"),
        ] {
            let arguments = linux_boot_arguments(console, disk);
            assert!(arguments.contains(&format!("console={console} ")));
            assert!(arguments.contains(&format!("root={disk} ")));
            assert!(arguments.contains("rw init=/sbin/init bdev_allow_write_mounted=1"));
        }
    }

    #[test]
    fn rejects_cross_machine_observations_before_driver_dispatch() {
        let mut driver = Driver {
            called: None,
            output: Some(output(1, MachineState::Stopped)),
        };
        let mut current = observation(MachineState::Running, 1);
        current.machine_id = MachineId::try_from("other").unwrap();
        assert!(matches!(
            apply_lifecycle(&mut driver, &command(DesiredState::Stopped), Some(&current)),
            MachineOutcome::NotApplied(_)
        ));
        assert_eq!(driver.called, None);
    }
}
