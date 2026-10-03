//! One hardware-only driver for HVF and WHPX. Native ownership and resource
//! allocation are independent of guest management, host intent and grants.
use crate::qemu::Accelerator;
use sandsurf_native::process_budget::ProcessBudget;
use sandsurf_protocol::Resources;
use std::io;

/// Strict disjoint native budgets; the sum never exceeds the admitted machine
/// envelope. Darwin includes two retained privileged parents. WHPX scheduling
/// is separate from native Job CPU time and is charged within the same total.
#[derive(Debug, Clone, Copy)]
pub struct QemuBudgets {
    pub guardian: ProcessBudget,
    pub virtual_machine: ProcessBudget,
    pub guest_cpu_quota_micros: u64,
}

impl QemuBudgets {
    pub fn derive(resources: &Resources, accelerator: Accelerator) -> io::Result<Self> {
        resources.validate().map_err(io::Error::other)?;
        crate::validate_hardware(
            &accelerator.engine(),
            resources.vcpus.get(),
            resources.memory_mib.get(),
        )?;
        let total_memory = resources
            .host_memory_bytes()
            .map_err(io::Error::other)?
            .get();
        let overhead = resources.host_overhead_bytes.get();
        if overhead < 256 * 1024 * 1024 {
            return Err(invalid(
                "native guardian, VMM and their owners require at least 256MiB overhead",
            ));
        }
        // A guardian's envelope is fixed across VM shape changes. Its retained
        // native owner cannot silently enlarge its limits when a new VM boots.
        let guardian_memory = 128 * 1024 * 1024;
        let quota = resources.cpu_quota_micros.get();
        let guardian = ProcessBudget {
            cpu_quota_micros: 25000,
            memory_bytes: guardian_memory,
            processes: if accelerator == Accelerator::Hvf {
                2
            } else {
                1
            },
        };
        let (vm_cpu, guest_cpu) = match accelerator {
            Accelerator::Hvf => (quota.checked_sub(guardian.cpu_quota_micros), 0),
            Accelerator::Whpx => (
                Some(25000),
                quota.checked_sub(50000).ok_or_else(|| {
                    invalid("CPU allowance cannot cover guardian, VMM and guest scheduling")
                })?,
            ),
        };
        let virtual_machine = ProcessBudget {
            cpu_quota_micros: vm_cpu
                .ok_or_else(|| invalid("CPU allowance cannot cover native control"))?,
            memory_bytes: total_memory - guardian_memory,
            processes: guardian.processes,
        };
        guardian.validate()?;
        virtual_machine.validate()?;
        if accelerator == Accelerator::Hvf {
            // This verifies the actual broker/worker ABI and its granularity,
            // not just a catalog reservation or an unchecked RLIMIT_AS.
            sandsurf_native::resource_broker::worker_budget(guardian)?;
            sandsurf_native::resource_broker::worker_budget(virtual_machine)?;
        } else if guest_cpu == 0 {
            return Err(invalid("WHPX guest scheduling allowance is empty"));
        }
        Ok(Self {
            guardian,
            virtual_machine,
            guest_cpu_quota_micros: guest_cpu,
        })
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(any(target_os = "macos", windows))]
mod native {
    use super::*;
    use crate::qemu::LaunchConfig;
    use crate::qemu_owner::QemuOwner;
    use crate::{DriverQualification, MachineDriver, MachineOutcome, MachineTransition};
    use sandsurf_native::serial_channel::SerialChannel;
    use sandsurf_protocol::{
        Capability, Counter, Digest, Domain, LifecycleCommand, MachineObservation, MachineState,
        OperationId, Qualification, VmEngine, bytes_digest, digest,
    };
    use std::fs::File;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    pub struct QemuConfig {
        pub launch: LaunchConfig,
        pub runtime_manifest: PathBuf,
        pub runtime_digest: Digest,
        pub capture_directory: PathBuf,
    }

    pub struct QemuRestoreSource {
        pub preparation_digest: Digest,
        pub saved_state: PathBuf,
        pub manifest_digest: Digest,
        pub disk_custody: Arc<File>,
        pub snapshot_custody: Arc<File>,
    }

    pub struct QemuDriver {
        config: QemuConfig,
        owner: Option<QemuOwner>,
        resources: Option<Resources>,
        pending_custody: Option<Vec<Arc<File>>>,
        capture_paused: bool,
        capture_operation: Option<OperationId>,
        committed_suspend: Option<(OperationId, Digest)>,
        restore: Option<QemuRestoreSource>,
        reset: Option<Digest>,
    }

    pub fn native_engine() -> VmEngine {
        if cfg!(target_os = "macos") {
            Accelerator::Hvf.engine()
        } else {
            Accelerator::Whpx.engine()
        }
    }

    pub fn full_state_capability() -> Capability {
        if cfg!(windows) {
            Capability::Unsupported { reasons: vec![
                "QEMU WHPX cannot serialize native partition register state and dirty-memory tracking; upstream blocks migration".into()
            ] }
        } else {
            Capability::Supported { qualification: Qualification::Unqualified { reasons: vec![
                "HVF file-state transfer needs qualification with this exact CPU, kernel, raw disks and virtual devices".into()
            ] } }
        }
    }

    impl QemuDriver {
        pub fn new(config: QemuConfig) -> io::Result<Self> {
            config.launch.validate()?;
            Ok(Self {
                config,
                owner: None,
                resources: None,
                pending_custody: None,
                capture_paused: false,
                capture_operation: None,
                committed_suspend: None,
                restore: None,
                reset: None,
            })
        }
        pub fn stage_boot_artifacts(
            &mut self,
            kernel: PathBuf,
            initramfs: Option<PathBuf>,
            authentication: PathBuf,
        ) -> io::Result<()> {
            if self.owner.is_some() {
                return Err(invalid("boot staging requires confirmed native detach"));
            }
            self.config.launch.kernel = kernel;
            self.config.launch.initramfs = initramfs;
            self.config.launch.authentication_disk = authentication;
            self.config.launch.validate()
        }
        pub fn stage_storage_custody(&mut self, custody: Vec<Arc<File>>) -> io::Result<()> {
            if custody.is_empty() || custody.len() > sandsurf_native::MAX_WORKER_CUSTODY {
                return Err(invalid("invalid native custody closure"));
            }
            if self.owner.is_some() || self.pending_custody.is_some() {
                return Err(invalid("native storage custody is already held"));
            }
            self.pending_custody = Some(custody);
            Ok(())
        }
        pub fn discard_pending_storage_custody(&mut self) {
            self.pending_custody.take();
        }
        pub fn network(&self) -> Option<Arc<sandsurf_network::NativeNetworkGateway>> {
            self.owner.as_ref().map(QemuOwner::network)
        }
        pub fn management_channel(&self) -> Option<SerialChannel> {
            self.owner.as_ref().map(QemuOwner::management_channel)
        }
        #[cfg(target_os = "macos")]
        pub fn resource_usage(
            &mut self,
        ) -> io::Result<Option<sandsurf_native::resource_broker::WorkerUsage>> {
            self.owner
                .as_mut()
                .map(QemuOwner::resource_usage)
                .transpose()
        }
        #[cfg(windows)]
        pub fn resource_usage(
            &mut self,
        ) -> io::Result<Option<sandsurf_native::process_budget::windows::JobUsage>> {
            self.owner
                .as_mut()
                .map(QemuOwner::resource_usage)
                .transpose()
        }
        #[cfg(windows)]
        pub fn partition_usage(&mut self) -> io::Result<Option<crate::qemu::PartitionUsage>> {
            self.owner
                .as_mut()
                .map(QemuOwner::partition_usage)
                .transpose()
        }
        pub fn pause_for_capture(&mut self) -> io::Result<()> {
            self.owner
                .as_mut()
                .ok_or_else(|| invalid("native capture owner unavailable"))?
                .pause()?;
            self.capture_paused = true;
            Ok(())
        }
        pub fn adopt_pause_for_capture(&mut self) -> io::Result<()> {
            if self
                .observe_power()
                .ok()
                .flatten()
                .is_none_or(|power| power.state != MachineState::Paused)
            {
                return Err(invalid("native paused capture boundary unavailable"));
            }
            self.capture_paused = true;
            Ok(())
        }
        pub fn resume_after_capture(&mut self) -> io::Result<()> {
            self.owner
                .as_mut()
                .ok_or_else(|| invalid("native capture owner unavailable"))?
                .resume()?;
            self.finish_capture_without_resume()
        }
        pub fn finish_capture_without_resume(&mut self) -> io::Result<()> {
            self.capture_paused = false;
            self.capture_operation = None;
            self.committed_suspend = None;
            Ok(())
        }
        pub fn save_full_state(
            &mut self,
            operation: &OperationId,
            destination: &Path,
        ) -> io::Result<()> {
            if matches!(full_state_capability(), Capability::Unsupported { .. }) {
                return Err(invalid("native accelerator cannot save full state"));
            }
            if !self.capture_paused
                || self
                    .capture_operation
                    .as_ref()
                    .is_some_and(|old| old != operation)
            {
                return Err(invalid("full capture does not own its native pause"));
            }
            self.owner
                .as_mut()
                .ok_or_else(|| invalid("full capture owner unavailable"))?
                .save_state(destination)?;
            self.capture_operation = Some(operation.clone());
            Ok(())
        }
        pub fn commit_suspend(
            &mut self,
            operation: &OperationId,
            manifest: Digest,
        ) -> io::Result<()> {
            if !self.capture_paused
                || self.capture_operation.as_ref() != Some(operation)
                || self
                    .committed_suspend
                    .as_ref()
                    .is_some_and(|old| old != &(operation.clone(), manifest.clone()))
            {
                return Err(invalid("suspend does not own the captured native state"));
            }
            self.committed_suspend = Some((operation.clone(), manifest));
            Ok(())
        }
        pub fn stage_restore(&mut self, source: QemuRestoreSource) -> io::Result<()> {
            if self.owner.is_some()
                || !source.saved_state.is_absolute()
                || matches!(full_state_capability(), Capability::Unsupported { .. })
                || self
                    .restore
                    .as_ref()
                    .is_some_and(|old| old.manifest_digest != source.manifest_digest)
            {
                return Err(invalid("native restore is incompatible or already owned"));
            }
            self.restore = Some(source);
            Ok(())
        }
        pub fn restore_custody(&self) -> Option<Vec<Arc<File>>> {
            self.restore.as_ref().map(|source| {
                vec![
                    Arc::clone(&source.disk_custody),
                    Arc::clone(&source.snapshot_custody),
                ]
            })
        }
        pub fn staged_restore_binding(&self) -> Option<&Digest> {
            self.restore
                .as_ref()
                .map(|source| &source.preparation_digest)
        }
        pub fn contain_unobserved(&mut self) {
            if let Some(owner) = &mut self.owner
                && owner.terminate().is_err()
            {
                return;
            }
            self.owner.take();
            self.pending_custody.take();
        }
        fn boot(&mut self, command: &LifecycleCommand, generation: Counter) -> MachineOutcome {
            if command.machine_id != self.config.launch.machine_id || self.owner.is_some() {
                return unavailable(b"qemu-boot-identity-or-owner-conflict");
            }
            let resources = &command.configuration.resources;
            let Ok(budgets) = QemuBudgets::derive(resources, self.config.launch.accelerator) else {
                return unavailable(b"qemu-native-budget-not-representable");
            };
            let (Ok(memory), Ok(vcpus)) = (
                u32::try_from(resources.memory_mib.get()),
                u32::try_from(resources.vcpus.get()),
            ) else {
                return unavailable(b"qemu-hardware-envelope-overflow");
            };
            self.config.launch.memory_mib = memory;
            self.config.launch.vcpus = vcpus;
            let Some(custody) = self.pending_custody.take() else {
                return unavailable(b"qemu-storage-custody-missing");
            };
            let mut owner = match QemuOwner::launch(
                &self.config,
                budgets.virtual_machine,
                budgets.guest_cpu_quota_micros,
                custody,
                self.restore
                    .as_ref()
                    .map(|source| source.saved_state.as_path()),
            ) {
                Ok(owner) => owner,
                Err(error) => {
                    eprintln!("sandsurf native launch failed: {error}");
                    return MachineOutcome::Unknown;
                }
            };
            // Current host authority, never saved guest policy, governs restore.
            let applied = owner
                .configure_network(
                    &command.configuration.network,
                    &command.configuration.exposures,
                )
                .and_then(|()| match &self.restore {
                    Some(source) => owner.load_state(&source.saved_state),
                    None => Ok(()),
                })
                .and_then(|()| owner.resume());
            if applied.is_err() {
                // Retain the owner on uncertain containment, so an absent public
                // boot observation cannot authorize another live attachment.
                if owner.terminate().is_err() {
                    self.owner = Some(owner);
                }
                return MachineOutcome::Unknown;
            }
            let restoring = self.restore.is_some();
            self.owner = Some(owner);
            self.resources = Some(resources.clone());
            self.restore = None;
            self.capture_paused = false;
            self.capture_operation = None;
            self.committed_suspend = None;
            observed_path(
                command,
                generation,
                &[
                    if restoring {
                        MachineState::Restoring
                    } else if generation == Counter::ONE {
                        MachineState::Creating
                    } else {
                        MachineState::Starting
                    },
                    MachineState::Running,
                ],
                b"qemu-native-running",
            )
        }
        fn change_power(
            &mut self,
            command: &LifecycleCommand,
            current: &MachineObservation,
            paused: bool,
        ) -> MachineOutcome {
            if command.machine_id != self.config.launch.machine_id {
                return unavailable(b"qemu-machine-mismatch");
            }
            let Some(owner) = &mut self.owner else {
                return unavailable(b"qemu-owner-unavailable");
            };
            let applied = if paused {
                owner.pause()
            } else {
                owner.resume()
            };
            if applied.is_err() {
                return MachineOutcome::Unknown;
            }
            observed(
                command,
                current.generation,
                if paused {
                    MachineState::Paused
                } else {
                    MachineState::Running
                },
                b"qemu-native-power-postcondition",
            )
        }
    }

    impl MachineDriver for QemuDriver {
        fn qualification(&self) -> DriverQualification {
            DriverQualification { engine: native_engine(), guest_architecture: self.config.launch.architecture,
                lifecycle: Qualification::Unqualified { reasons: vec!["owned QEMU hardware lifecycle has no retained qualification for this configuration".into()] },
                full_state: full_state_capability() }
        }
        fn take_console(&mut self) -> Option<crate::NativeConsole> {
            self.owner.as_mut()?.take_console()
        }
        fn take_guest_reset(&mut self) -> Option<Digest> {
            self.reset.take()
        }
        fn observe_power(&mut self) -> Result<Option<crate::NativePowerObservation>, Digest> {
            let Some(owner) = &mut self.owner else {
                return Ok(None);
            };
            let power = owner
                .observe_power()
                .map_err(|_| bytes_digest(b"qemu-power-observation-unavailable"))?;
            if matches!(power.state, MachineState::Stopped | MachineState::Failed) {
                // These states are returned only after original native exit.
                self.reset = owner.take_guest_reset();
                self.owner.take();
            }
            Ok(Some(power))
        }
        fn validate_attachment(
            &self,
            machine_id: &sandsurf_protocol::MachineId,
            revision: Counter,
            resources: &Resources,
            current: &MachineObservation,
        ) -> Result<(), Digest> {
            let live = matches!(current.state, MachineState::Running | MachineState::Paused);
            if *machine_id != self.config.launch.machine_id
                || current.machine_id != self.config.launch.machine_id
                || revision <= current.applied_revision
                || live != self.owner.is_some()
                || (live && self.resources.as_ref() != Some(resources))
                || !matches!(
                    current.state,
                    MachineState::Stopped
                        | MachineState::Failed
                        | MachineState::Running
                        | MachineState::Paused
                )
            {
                return Err(bytes_digest(
                    b"qemu-configuration-requires-detached-resource-change",
                ));
            }
            Ok(())
        }
        fn create(&mut self, command: &LifecycleCommand) -> MachineOutcome {
            self.boot(command, Counter::ONE)
        }
        fn install_network(
            &mut self,
            configuration: &sandsurf_protocol::RuntimeConfiguration,
        ) -> Result<(), Digest> {
            self.owner
                .as_ref()
                .ok_or_else(|| bytes_digest(b"qemu-network-owner-unavailable"))?
                .configure_network(&configuration.network, &configuration.exposures)
                .map_err(|_| bytes_digest(b"qemu-network-configuration-incomplete"))
        }
        fn start(
            &mut self,
            command: &LifecycleCommand,
            current: &MachineObservation,
        ) -> MachineOutcome {
            match current.generation.next() {
                Ok(generation) => self.boot(command, generation),
                Err(_) => MachineOutcome::Unknown,
            }
        }
        fn reconfigure(
            &mut self,
            command: &LifecycleCommand,
            current: &MachineObservation,
        ) -> MachineOutcome {
            if command.machine_id != self.config.launch.machine_id
                || self.resources.as_ref() != Some(&command.configuration.resources)
            {
                return unavailable(b"qemu-live-resource-change-requires-reboot");
            }
            match self.observe_power() {
                Ok(Some(power)) if power.state == MachineState::Running => observed(
                    command,
                    current.generation,
                    MachineState::Running,
                    b"qemu-current-envelope-running",
                ),
                _ => MachineOutcome::Unknown,
            }
        }
        fn pause(
            &mut self,
            command: &LifecycleCommand,
            current: &MachineObservation,
        ) -> MachineOutcome {
            self.change_power(command, current, true)
        }
        fn resume(
            &mut self,
            command: &LifecycleCommand,
            current: &MachineObservation,
        ) -> MachineOutcome {
            self.change_power(command, current, false)
        }
        fn stop(
            &mut self,
            command: &LifecycleCommand,
            current: Option<&MachineObservation>,
        ) -> MachineOutcome {
            if command.machine_id != self.config.launch.machine_id {
                return unavailable(b"qemu-machine-mismatch");
            }
            if let Some(owner) = &mut self.owner
                && owner.terminate().is_err()
            {
                return MachineOutcome::Unknown;
            }
            self.owner.take();
            self.restore.take();
            self.pending_custody.take();
            self.reset = None;
            observed(
                command,
                current.map_or(Counter::ONE, |value| value.generation),
                MachineState::Stopped,
                b"qemu-original-native-owner-contained",
            )
        }
        fn destroy(
            &mut self,
            command: &LifecycleCommand,
            current: Option<&MachineObservation>,
        ) -> MachineOutcome {
            if !matches!(self.stop(command, current), MachineOutcome::Observed(_)) {
                return MachineOutcome::Unknown;
            }
            observed_path(
                command,
                current.map_or(Counter::ONE, |value| value.generation),
                &[MachineState::Destroying, MachineState::Destroyed],
                b"qemu-native-attachment-released",
            )
        }
        fn suspend(
            &mut self,
            command: &LifecycleCommand,
            current: &MachineObservation,
        ) -> MachineOutcome {
            if self.committed_suspend.is_none() || !self.capture_paused {
                return unavailable(b"qemu-suspend-capture-not-committed");
            }
            if !matches!(
                self.stop(command, Some(current)),
                MachineOutcome::Observed(_)
            ) {
                return MachineOutcome::Unknown;
            }
            observed(
                command,
                current.generation,
                MachineState::Suspended,
                b"qemu-full-state-owner-released",
            )
        }
        fn restore(
            &mut self,
            command: &LifecycleCommand,
            current: &MachineObservation,
        ) -> MachineOutcome {
            if self.restore.is_none() {
                return unavailable(b"qemu-full-restore-source-missing");
            }
            self.start(command, current)
        }
    }

    fn unavailable(reason: &[u8]) -> MachineOutcome {
        MachineOutcome::NotApplied(bytes_digest(reason))
    }
    fn observed(
        command: &LifecycleCommand,
        generation: Counter,
        state: MachineState,
        native: &[u8],
    ) -> MachineOutcome {
        observed_path(command, generation, &[state], native)
    }
    fn observed_path(
        command: &LifecycleCommand,
        generation: Counter,
        states: &[MachineState],
        native: &[u8],
    ) -> MachineOutcome {
        let mut path = Vec::with_capacity(states.len());
        for state in states {
            let evidence = digest(
                Domain::Operation,
                &(
                    "qemu-native-transition-v1",
                    &command.machine_id,
                    &command.operation_id,
                    generation,
                    state,
                    bytes_digest(native),
                ),
            );
            match evidence {
                Ok(evidence_digest) => path.push(MachineTransition {
                    generation,
                    state: *state,
                    evidence_digest,
                }),
                Err(_) => return MachineOutcome::Unknown,
            }
        }
        MachineOutcome::Observed(path)
    }
}

#[cfg(any(target_os = "macos", windows))]
pub use native::*;

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::Counter;
    fn resources() -> Resources {
        Resources::from_geometry(
            Counter::ONE,
            512.try_into().unwrap(),
            (256 * 1024 * 1024).try_into().unwrap(),
            (32 * 1024 * 1024).try_into().unwrap(),
            16.try_into().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn native_budgets_cover_all_workers_without_expanding_authority() {
        let resources = resources();
        for accelerator in [Accelerator::Hvf, Accelerator::Whpx] {
            let budget = QemuBudgets::derive(&resources, accelerator).unwrap();
            assert_eq!(
                budget.guardian.cpu_quota_micros
                    + budget.virtual_machine.cpu_quota_micros
                    + budget.guest_cpu_quota_micros,
                resources.cpu_quota_micros.get()
            );
            assert_eq!(
                budget.guardian.memory_bytes + budget.virtual_machine.memory_bytes,
                resources.host_memory_bytes().unwrap().get()
            );
            assert!(
                budget.virtual_machine.memory_bytes >= resources.memory_mib.get() * 1024 * 1024
            );
        }
    }
    #[test]
    fn unrepresentable_limits_fail_before_native_launch() {
        let mut resources = resources();
        resources.cpu_quota_micros = 50000.try_into().unwrap();
        assert!(QemuBudgets::derive(&resources, Accelerator::Whpx).is_err());
        resources.cpu_quota_micros = 49990.try_into().unwrap();
        assert!(QemuBudgets::derive(&resources, Accelerator::Hvf).is_err());
        resources = self::resources();
        resources.host_overhead_bytes = (128 * 1024 * 1024).try_into().unwrap();
        assert!(QemuBudgets::derive(&resources, Accelerator::Hvf).is_err());
    }
}
