use super::*;
use sandsurf_state::{Approval, CatalogLimits, ImageRecord, MachineAdmission, RuntimeLimits};

struct NoGuest;
impl GuestDriver for NoGuest {
    fn dispatch(&mut self, _: &GuestCommand) -> EffectOutcome {
        EffectOutcome::Unknown
    }
}

struct Native {
    restore: Option<(Digest, PreparedRestore)>,
    root: PathBuf,
    measured: Option<MachineState>,
    reset: bool,
    installed: usize,
    started: usize,
    resource_checks: std::cell::RefCell<Vec<(&'static str, MachineObservation)>>,
    capture_publications: Vec<bool>,
}
impl GuardianEffect for Native {
    fn complete_capture(
        &mut self,
        _: Box<PreparedCapture>,
        publish: bool,
        _: &mut RuntimeJournal,
    ) -> Result<NativeSnapshotResponse> {
        self.capture_publications.push(publish);
        Ok(NativeSnapshotResponse::Complete {
            evidence: bytes_digest(b"fixture-completion"),
        })
    }
    fn staged_restore_binding(&self) -> Option<&Digest> {
        self.restore.as_ref().map(|(binding, _)| binding)
    }
    fn restore_preparation(
        &self,
        snapshot_id: SnapshotId,
        manifest_digest: Digest,
        system_disk: SnapshotArtifact,
        expected: FullSnapshotMetadata,
    ) -> Result<RestorePreparation> {
        Ok(RestorePreparation {
            machine_root: self.root.clone(),
            snapshot_id,
            manifest_digest,
            system_disk,
            expected,
        })
    }
    fn install_prepared_restore(
        &mut self,
        prepared: PreparedRestore,
    ) -> Result<NativeSnapshotResponse> {
        let response = prepared.input.evidence()?;
        self.restore = Some((prepared.input.binding()?, prepared));
        self.installed += 1;
        Ok(response)
    }
    fn validate_resources(
        &self,
        resources: &Resources,
        current: &MachineObservation,
    ) -> Result<()> {
        self.resource_checks
            .borrow_mut()
            .push(("validate", current.clone()));
        resources
            .validate()
            .map_err(|_| Error::Protocol("invalid resource fixture"))
    }
    fn assess_resources(
        &self,
        _: &Resources,
        current: &MachineObservation,
    ) -> ResourceChangeAssessment {
        self.resource_checks
            .borrow_mut()
            .push(("assess", current.clone()));
        ResourceChangeAssessment {
            mode: ResourceChangeMode::Live,
            reasons: vec![format!("native generation {}", current.generation.get())],
        }
    }
    fn capture_owner(&self) -> Result<Option<OperationId>> {
        Ok(crate::capture::CaptureBoundary::read(&self.root)?.map(|value| value.operation_id))
    }
    fn native_snapshot(
        &mut self,
        request: NativeSnapshotRequest,
        journal: &mut RuntimeJournal,
    ) -> Result<NativeSnapshotResponse> {
        match request {
            NativeSnapshotRequest::PrepareDisk { operation_id, .. } => {
                let current = journal.last_observation()?.unwrap();
                crate::capture::CaptureBoundary::begin(
                    &self.root,
                    operation_id,
                    current.value(),
                    journal.accepted_revision()?,
                )?;
                self.measured = Some(MachineState::Paused);
            }
            NativeSnapshotRequest::FinishDisk { operation_id } => {
                if let Some(boundary) =
                    crate::capture::CaptureBoundary::require(&self.root, &operation_id)?
                {
                    let current = journal.last_observation()?.unwrap();
                    if boundary.needs_resume(
                        self.measured.unwrap(),
                        current.value(),
                        journal.accepted_revision()?,
                    )? {
                        self.measured = Some(MachineState::Running);
                    }
                    crate::capture::CaptureBoundary::clear(&self.root)?;
                }
            }
            _ => {
                return Err(Error::Unsupported(
                    "fixture snapshot operation is unsupported",
                ));
            }
        }
        Ok(NativeSnapshotResponse::Complete {
            evidence: bytes_digest(b"fixture-native-capture"),
        })
    }
    fn guest_driver(&mut self) -> Box<dyn GuestDriver> {
        Box::new(NoGuest)
    }
    fn boot_preparation(
        &self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> Result<Option<BootPreparation>> {
        if command.desired != DesiredState::Running
            || current.is_some_and(|value| {
                !matches!(value.state, MachineState::Stopped | MachineState::Failed)
            })
        {
            return Ok(None);
        }
        Ok(Some(BootPreparation {
            machine_root: self.root.clone(),
            machine_id: command.machine_id.clone(),
            generation: current
                .map_or(Ok(Counter::ONE), |value| value.generation.next())
                .map_err(|_| Error::Protocol("generation overflow"))?,
            image_digest: bytes_digest(b"image"),
            disk_bytes: command.configuration.resources.disk_bytes.get(),
        }))
    }
    fn install_prepared_boot(&mut self, _: PreparedBoot) -> Result<()> {
        self.installed += 1;
        Ok(())
    }
    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> LifecycleEffect {
        let generation = if command.desired == DesiredState::Running {
            self.started += 1;
            current.map_or(Counter::ONE, |value| value.generation.next().unwrap())
        } else {
            current.map_or(Counter::ONE, |value| value.generation)
        };
        let target = match command.desired {
            DesiredState::Running => MachineState::Running,
            DesiredState::Stopped => MachineState::Stopped,
            DesiredState::Paused => MachineState::Paused,
            DesiredState::Destroyed => MachineState::Destroyed,
            _ => panic!("unsupported fixture lifecycle"),
        };
        if matches!(target, MachineState::Stopped | MachineState::Destroyed) {
            self.restore = None;
        }
        let mut states = Vec::new();
        if current.is_none() {
            states.push(MachineState::Creating);
        }
        if target == MachineState::Running && current.is_some() {
            states.push(MachineState::Starting);
        }
        if target == MachineState::Destroyed {
            states.push(MachineState::Destroying);
        }
        states.push(target);
        self.measured = (target != MachineState::Destroyed).then_some(target);
        LifecycleEffect::Observed(
            states
                .into_iter()
                .map(|state| MachineTransition {
                    generation,
                    state,
                    evidence_digest: bytes_digest(b"fixture-native-effect"),
                })
                .collect(),
        )
    }
    fn observe_power(&mut self) -> Result<Option<sandsurf_machine::NativePowerObservation>> {
        Ok(self
            .measured
            .map(|state| sandsurf_machine::NativePowerObservation {
                state,
                evidence_digest: bytes_digest(b"fixture-native-power"),
            }))
    }
    fn observe_detachment(&self) -> Result<Option<Digest>> {
        Ok(crate::storage::observe_detached(
            &self.root.join("system.ext4"),
        )?)
    }
    fn take_guest_reset(&mut self) -> Option<Digest> {
        std::mem::take(&mut self.reset).then(|| bytes_digest(b"fixture-native-reset"))
    }
    fn guest_reset_configuration(&self) -> Result<RuntimeConfiguration> {
        Ok(RuntimeConfiguration::default())
    }
    fn recover_guest_reset(&mut self, current: &MachineObservation) -> Result<Digest> {
        restart_after_native_reset(self, current, RuntimeConfiguration::default())
    }
}

struct Fixture {
    guardian: Guardian<Native>,
    host: HostCatalog,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "ssf-boot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        sandsurf_native::local::create_private_directory(&root).unwrap();
        let mut host = HostCatalog::create(
            &root.join("host"),
            "host".try_into().unwrap(),
            CatalogLimits {
                identities: n(16),
                operations: n(64),
                usage_records: n(64),
                image_bytes: n(1 << 20),
                cpu_quota_micros: n(800_000),
                host_memory_bytes: n(16 * 1024 * 1024 * 1024),
            },
        )
        .unwrap();
        let image = bytes_digest(b"image");
        let operation: OperationId = "image".try_into().unwrap();
        let input = sandsurf_state::ImageImportInput::Native {
            manifest_path: root.join("seed-manifest.json"),
            manifest_digest: image.clone(),
        };
        let request = input.request_digest(&operation).unwrap();
        host.admit_image_import(
            operation.clone(),
            input,
            Approval {
                id: "approve-image".try_into().unwrap(),
                request_digest: request.clone(),
            },
        )
        .unwrap();
        let candidate = ImageRecord {
            digest: image.clone(),
            source_digest: image.clone(),
            platform: "linux".into(),
            architecture: "amd64".into(),
            logical_bytes: n(1),
            storage_bytes: n(1),
            provenance_digest: image.clone(),
            sensitive: false,
        };
        host.prepare_image_import(&operation, &request, candidate.clone())
            .unwrap();
        host.complete_image_import(&operation, &request, candidate)
            .unwrap();
        let machine: MachineId = "computer".try_into().unwrap();
        let operation: OperationId = "create".try_into().unwrap();
        let resources = RuntimeConfiguration::default().resources;
        let defaults = ExecutionDefaults::default();
        let lifetime = MachineLifetime::default();
        let request_digest = digest(
            Domain::Machine,
            &(
                &machine, &image, &resources, &defaults, &lifetime, &operation,
            ),
        )
        .unwrap();
        host.create_machine(
            MachineAdmission {
                image_defaults: defaults.clone(),
                id: machine.clone(),
                image,
                resources,
                defaults,
                lifetime,
                operation,
            },
            Approval {
                id: "approve-create".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
        let journal = RuntimeJournal::create(
            &root.join("runtime"),
            machine,
            RuntimeLimits {
                identities: n(16),
                managed_executions: n(8),
                operations: n(64),
                observations: n(64),
                events: n(256),
                chunks: n(64),
                output_segments: n(16),
                output_bytes: n(4096),
            },
            host.authority_binding().clone(),
        )
        .unwrap();
        let guardian = Guardian::new(
            journal,
            Native {
                restore: None,
                root: root.clone(),
                measured: None,
                reset: false,
                installed: 0,
                started: 0,
                resource_checks: Default::default(),
                capture_publications: Vec::new(),
            },
        );
        Self {
            guardian,
            host,
            root,
        }
    }
    fn create(&self) -> AuthorizedLifecycle {
        self.host
            .authorize_lifecycle(&"create".try_into().unwrap())
            .unwrap()
    }
    fn intent(&mut self, name: &str, desired: DesiredState) -> AuthorizedLifecycle {
        let machine = self.guardian.journal.machine_id().clone();
        let revision = self
            .host
            .machine(&machine)
            .unwrap()
            .unwrap()
            .configuration_revision;
        let operation: OperationId = name.try_into().unwrap();
        let request_digest = digest(
            Domain::Operation,
            &(&machine, &operation, revision, desired),
        )
        .unwrap();
        self.host
            .request_lifecycle(
                &machine,
                operation.clone(),
                revision,
                desired,
                Approval {
                    id: format!("approve-{name}").try_into().unwrap(),
                    request_digest,
                },
            )
            .unwrap();
        self.host.authorize_lifecycle(&operation).unwrap()
    }
    fn start(&mut self) {
        let BootAdmission::Queued { input, pending } =
            self.guardian.begin_boot(self.create()).unwrap()
        else {
            panic!("cold boot must prepare off-owner");
        };
        let response = self
            .guardian
            .finish_boot(pending, Ok(prepared(input)))
            .unwrap()
            .unwrap();
        assert_eq!(delivery(response), Delivery::Applied);
    }
}
fn n(value: u64) -> Counter {
    value.try_into().unwrap()
}
fn prepared(input: BootPreparation) -> PreparedBoot {
    PreparedBoot {
        directory: input.machine_root.join("frozen"),
        boot: sandsurf_image::boot::FrozenBoot {
            architecture: sandsurf_image::Architecture::X64,
            kernel: sandsurf_image::ImageArtifact {
                path: "kernel".into(),
                sha256: "a".repeat(64),
            },
            initramfs: None,
        },
        input,
    }
}
fn delivery(response: GuardianResponse) -> Delivery {
    let GuardianResponse::Lifecycle { operation } = response else {
        panic!("expected lifecycle")
    };
    operation.delivery
}
fn retire(fixture: Fixture) {
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn detached_full_capture_cannot_publish_after_forced_stop_pause_or_native_exit() {
    for change in ["stop", "pause", "native-exit", "unchanged"] {
        let mut f = Fixture::new();
        f.start();
        let observation = f
            .guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value()
            .clone();
        let pending = CapturePending {
            accepted_revision: f.guardian.journal.accepted_revision().unwrap(),
            observation,
        };
        f.guardian.offline_in_flight = true;
        let prepared = crate::capture_preparation::completion_fixture(&f.root);
        match change {
            "stop" | "pause" => {
                let desired = if change == "stop" {
                    DesiredState::Stopped
                } else {
                    DesiredState::Paused
                };
                let authorization = f.intent(change, desired);
                let BootAdmission::Ready(response) = f.guardian.begin_boot(authorization).unwrap()
                else {
                    panic!("native control must not wait for the save worker");
                };
                assert_eq!(delivery(response), Delivery::Applied);
                assert!(
                    f.guardian.offline_in_flight,
                    "capture remains accounted until actual completion"
                );
            }
            "native-exit" => {
                f.guardian.effect.as_mut().unwrap().measured = Some(MachineState::Failed)
            }
            _ => {}
        }
        let result = f.guardian.finish_capture(pending, Ok(prepared));
        assert_eq!(result.is_ok(), change == "unchanged");
        assert_eq!(
            f.guardian.effect.as_ref().unwrap().capture_publications,
            [change == "unchanged"]
        );
        assert!(!f.guardian.offline_in_flight);
        retire(f);
    }
}

#[test]
fn detached_full_capture_cannot_publish_after_accepted_unapplied_authority() {
    let mut f = Fixture::new();
    f.start();
    let observation = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    let pending = CapturePending {
        accepted_revision: f.guardian.journal.accepted_revision().unwrap(),
        observation: observation.clone(),
    };
    let authorization = f.intent("pending-stop", DesiredState::Stopped);
    f.guardian.journal.admit_lifecycle(authorization).unwrap();
    f.guardian.offline_in_flight = true;
    let prepared = crate::capture_preparation::completion_fixture(&f.root);
    assert!(f.guardian.finish_capture(pending, Ok(prepared)).is_err());
    assert_eq!(
        f.guardian.effect.as_ref().unwrap().capture_publications,
        [false]
    );
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value(),
        &observation
    );
    assert_eq!(
        f.guardian.effect.as_ref().unwrap().measured,
        Some(MachineState::Running)
    );
    retire(f);
}

#[test]
fn capture_release_preserves_applied_pause_and_never_replays_pending_running_authority() {
    for desired in [DesiredState::Paused, DesiredState::Running] {
        let mut f = Fixture::new();
        f.start();
        let current = f
            .guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value()
            .clone();
        let operation_id: OperationId = "capture".try_into().unwrap();
        let response = f.guardian.handle(GuardianRequest::NativeSnapshot {
            machine_id: current.machine_id.clone(),
            request: NativeSnapshotRequest::PrepareDisk {
                snapshot_id: "snapshot".try_into().unwrap(),
                operation_id: operation_id.clone(),
                expected_generation: current.generation,
                expected_revision: current.applied_revision,
            },
        });
        assert!(
            matches!(
                response,
                GuardianResponse::NativeSnapshot {
                    response: NativeSnapshotResponse::Complete { .. }
                }
            ),
            "{response:?}"
        );
        assert_eq!(
            f.guardian.effect.as_ref().unwrap().measured,
            Some(MachineState::Paused)
        );
        assert_eq!(
            f.guardian
                .journal
                .last_observation()
                .unwrap()
                .unwrap()
                .value(),
            &current,
            "temporary capture pause is not public lifecycle intent"
        );
        let authorization = f.intent("during-capture", desired);
        let response = f.guardian.transition(authorization.clone(), None).unwrap();
        assert_eq!(
            delivery(response),
            if desired == DesiredState::Paused {
                Delivery::Applied
            } else {
                Delivery::NotApplied
            }
        );
        let finish = GuardianRequest::NativeSnapshot {
            machine_id: current.machine_id.clone(),
            request: NativeSnapshotRequest::FinishDisk { operation_id },
        };
        let response = f.guardian.handle(finish.clone());
        assert!(
            matches!(
                response,
                GuardianResponse::NativeSnapshot {
                    response: NativeSnapshotResponse::Complete { .. }
                }
            ),
            "{response:?}"
        );
        let after = f
            .guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value()
            .clone();
        assert_eq!(after.state, MachineState::Paused);
        assert_eq!(after.generation, current.generation);
        assert!(
            f.guardian
                .effect
                .as_ref()
                .unwrap()
                .capture_owner()
                .unwrap()
                .is_none()
        );
        if desired == DesiredState::Paused {
            assert_eq!(
                after.applied_revision,
                authorization.statement.command.revision
            );
            assert_eq!(
                after.cause,
                ObservationCause::Lifecycle {
                    operation_id: "during-capture".try_into().unwrap()
                }
            );
        } else {
            assert_eq!(after.applied_revision, current.applied_revision);
            assert_eq!(after.cause, ObservationCause::Native {});
            assert_eq!(
                f.guardian
                    .journal
                    .lifecycle_operation(&"during-capture".try_into().unwrap())
                    .unwrap()
                    .unwrap()
                    .delivery,
                Delivery::NotApplied
            );
        }
        let response = f.guardian.handle(finish);
        assert!(
            matches!(
                response,
                GuardianResponse::NativeSnapshot {
                    response: NativeSnapshotResponse::Complete { .. }
                }
            ),
            "{response:?}"
        );
        assert_eq!(
            f.guardian
                .journal
                .last_observation()
                .unwrap()
                .unwrap()
                .value(),
            &after,
            "lost finish response must not resume or append another native observation"
        );
        retire(f);
    }
}

fn restore_request(f: &mut Fixture) -> NativeSnapshotRequest {
    f.start();
    let current = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    f.guardian
        .journal
        .observe(MachineObservation {
            sequence: current.sequence.next().unwrap(),
            state: MachineState::Suspended,
            cause: ObservationCause::Native {},
            evidence_digest: bytes_digest(b"native-suspension-fixture"),
            ..current
        })
        .unwrap();
    f.guardian.effect.as_mut().unwrap().measured = None;
    let input = crate::restore_preparation::tests::fixture(&f.root, VmEngine::Firecracker);
    NativeSnapshotRequest::StageRestore {
        snapshot_id: input.snapshot_id,
        manifest_digest: input.manifest_digest,
        system_disk: input.system_disk,
        expected: Box::new(input.expected),
    }
}

#[test]
fn unapplied_host_authority_prevents_restore_admission_and_staged_response_retry() {
    for stage_first in [false, true] {
        let mut f = Fixture::new();
        let request = restore_request(&mut f);
        let machine = f.guardian.journal.machine_id().clone();
        if stage_first {
            let RestoreAdmission::Queued { input, pending } = f
                .guardian
                .begin_restore(machine.clone(), request.clone())
                .unwrap()
            else {
                panic!("restore must prepare off owner");
            };
            f.guardian.finish_restore(pending, input.execute()).unwrap();
        }
        let stop = f.intent("accepted-stop-before-restore", DesiredState::Stopped);
        f.guardian.journal.admit_lifecycle(stop).unwrap();
        assert!(f.guardian.begin_restore(machine, request).is_err());
        assert!(!f.guardian.offline_in_flight);
        assert_eq!(
            f.guardian.effect.as_ref().unwrap().installed,
            1 + usize::from(stage_first)
        );
        retire(f);
    }
}

#[test]
fn restore_preparation_is_fenced_by_new_authority_even_without_a_changed_native_observation() {
    let mut f = Fixture::new();
    let request = restore_request(&mut f);
    let machine = f.guardian.journal.machine_id().clone();
    let RestoreAdmission::Queued { input, pending } = f
        .guardian
        .begin_restore(machine.clone(), request.clone())
        .unwrap()
    else {
        panic!("restore must prepare off owner");
    };
    assert!(f.guardian.begin_restore(machine, request).is_err());
    let prepared = input.execute().unwrap();
    let before = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .map(|v| v.value().clone());
    let stop = f.intent("stop-before-delivery", DesiredState::Stopped);
    f.guardian.journal.admit_lifecycle(stop).unwrap();
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .map(|v| v.value().clone()),
        before
    );
    assert!(f.guardian.finish_restore(pending, Ok(prepared)).is_err());
    assert_eq!(f.guardian.effect.as_ref().unwrap().installed, 1);
    assert!(!f.guardian.offline_in_flight);
    assert!(crate::storage::attach(&f.root.join("disks/system.ext4")).is_ok());
    retire(f);
}

#[test]
fn native_stop_overtakes_detached_restore_and_a_late_completion_cannot_stage_state() {
    let mut f = Fixture::new();
    let request = restore_request(&mut f);
    let machine = f.guardian.journal.machine_id().clone();
    let RestoreAdmission::Queued { input, pending } =
        f.guardian.begin_restore(machine, request).unwrap()
    else {
        panic!("restore must prepare off owner");
    };
    let prepared = input.execute().unwrap();
    let stop = f.intent("force-stop", DesiredState::Stopped);
    let BootAdmission::Ready(response) = f.guardian.begin_boot(stop).unwrap() else {
        panic!("stop must not queue behind restore");
    };
    assert_eq!(delivery(response), Delivery::Applied);
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value()
            .state,
        MachineState::Stopped
    );
    assert!(f.guardian.finish_restore(pending, Ok(prepared)).is_err());
    assert!(f.guardian.effect.as_ref().unwrap().restore.is_none());
    assert!(crate::storage::attach(&f.root.join("disks/system.ext4")).is_ok());
    retire(f);
}

#[test]
fn prepared_restore_installs_once_and_exact_response_retry_retains_actual_custody() {
    let mut f = Fixture::new();
    let request = restore_request(&mut f);
    let machine = f.guardian.journal.machine_id().clone();
    let RestoreAdmission::Queued { input, pending } = f
        .guardian
        .begin_restore(machine.clone(), request.clone())
        .unwrap()
    else {
        panic!("restore must prepare off owner");
    };
    let prepared = input.execute().unwrap();
    let response = f.guardian.finish_restore(pending, Ok(prepared)).unwrap();
    let RestoreAdmission::Ready(retried) = f
        .guardian
        .begin_restore(machine.clone(), request.clone())
        .unwrap()
    else {
        panic!("lost response must not release and reacquire original storage");
    };
    assert_eq!(response, retried);
    assert_eq!(f.guardian.effect.as_ref().unwrap().installed, 2);
    assert!(crate::storage::attach(&f.root.join("disks/system.ext4")).is_err());
    let NativeSnapshotRequest::StageRestore {
        mut expected,
        snapshot_id,
        manifest_digest,
        system_disk,
    } = request
    else {
        unreachable!()
    };
    expected.generation = bytes_digest(b"substituted-generation");
    assert!(
        f.guardian
            .begin_restore(
                machine,
                NativeSnapshotRequest::StageRestore {
                    expected,
                    snapshot_id,
                    manifest_digest,
                    system_disk
                }
            )
            .is_err()
    );
    let stop = f.intent("stop-staged-restore", DesiredState::Stopped);
    let BootAdmission::Ready(response) = f.guardian.begin_boot(stop).unwrap() else {
        panic!("stop must not need an offline job");
    };
    assert_eq!(delivery(response), Delivery::Applied);
    assert!(crate::storage::attach(&f.root.join("disks/system.ext4")).is_ok());
    retire(f);
}

#[test]
fn substituted_prepared_restore_is_rejected_without_consuming_native_custody() {
    let mut f = Fixture::new();
    let request = restore_request(&mut f);
    let machine = f.guardian.journal.machine_id().clone();
    let RestoreAdmission::Queued { input, pending } =
        f.guardian.begin_restore(machine, request).unwrap()
    else {
        panic!("restore must prepare off owner");
    };
    let mut prepared = input.execute().unwrap();
    prepared.input.manifest_digest = bytes_digest(b"substituted-capture");
    assert!(f.guardian.finish_restore(pending, Ok(prepared)).is_err());
    assert!(f.guardian.effect.as_ref().unwrap().restore.is_none());
    assert!(crate::storage::attach(&f.root.join("disks/system.ext4")).is_ok());
    retire(f);
}

#[test]
fn lost_native_handle_requires_original_custody_release_and_never_replays_boot() {
    let mut f = Fixture::new();
    f.start();
    let disk = f.root.join("system.ext4");
    crate::storage::publish_disk(&disk, 4096, |stage, _custody| {
        sandsurf_native::local::create_private_file(stage)?.set_len(4096)
    })
    .unwrap();
    let custody = crate::storage::attach(&disk).unwrap();
    let native_custody = custody.try_clone().unwrap();
    drop(custody);
    let before = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    let machine = before.machine_id.clone();
    // Reopen after losing the volatile owner. A surviving actual VMM still
    // owns the original open description; a new guardian must not adopt its
    // PID, declare it stopped, or create a replacement.
    let Fixture {
        guardian,
        host,
        root,
    } = f;
    drop(guardian);
    f = Fixture {
        host,
        root: root.clone(),
        guardian: Guardian::new(
            RuntimeJournal::open(&root.join("runtime"), &machine).unwrap(),
            Native {
                root,
                restore: None,
                measured: None,
                reset: false,
                installed: 0,
                started: 0,
                resource_checks: Default::default(),
                capture_publications: Vec::new(),
            },
        ),
    };
    assert!(!f.guardian.refresh_native_observation().unwrap());
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value(),
        &before
    );
    drop(native_custody);
    // Disk corruption is not evidence of live hardware and cannot prevent
    // native containment recovery. No filesystem parser is involved.
    sandsurf_native::local::open_private_file(&disk, sandsurf_native::PrivateFileAccess::ReadWrite)
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(f.guardian.refresh_native_observation().unwrap());
    let stopped = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    assert_eq!(stopped.state, MachineState::Stopped);
    assert_eq!(stopped.generation, before.generation);
    assert_eq!(stopped.applied_revision, before.applied_revision);
    assert_eq!(stopped.sequence, before.sequence.next().unwrap());
    assert_eq!(stopped.cause, ObservationCause::Native {});
    assert_eq!(f.guardian.effect.as_ref().unwrap().started, 0);
    assert!(f.guardian.refresh_native_observation().unwrap());
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value(),
        &stopped
    );
    // Host intent remains its separate authority; no stop command or new
    // revision was fabricated by native observation.
    assert_eq!(
        f.host
            .machine(&machine)
            .unwrap()
            .unwrap()
            .latest_intent
            .desired,
        DesiredState::Running
    );
    retire(f);
}

#[test]
fn interrupted_destruction_detachment_is_failure_not_successful_destroy() {
    let mut f = Fixture::new();
    f.start();
    let disk = f.root.join("system.ext4");
    crate::storage::publish_disk(&disk, 4096, |stage, _custody| {
        sandsurf_native::local::create_private_file(stage)?.set_len(4096)
    })
    .unwrap();
    let authorization = f.intent("destroy", DesiredState::Destroyed);
    let operation = authorization.statement.command.operation_id.clone();
    f.guardian
        .journal
        .admit_lifecycle(authorization.clone())
        .unwrap();
    assert!(matches!(
        f.guardian.journal.begin_lifecycle(authorization).unwrap(),
        sandsurf_state::LifecycleDecision::Perform(_)
    ));
    let mut destroying = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    destroying.sequence = destroying.sequence.next().unwrap();
    destroying.state = MachineState::Destroying;
    destroying.cause = ObservationCause::Lifecycle {
        operation_id: operation.clone(),
    };
    f.guardian.journal.observe(destroying.clone()).unwrap();
    f.guardian.effect.as_mut().unwrap().measured = None;
    assert!(f.guardian.refresh_native_observation().unwrap());
    let failed = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    assert_eq!(failed.state, MachineState::Failed);
    assert_eq!(failed.generation, destroying.generation);
    assert_eq!(failed.applied_revision, destroying.applied_revision);
    assert_eq!(failed.cause, ObservationCause::Native {});
    assert_eq!(
        f.guardian
            .journal
            .lifecycle_operation(&operation)
            .unwrap()
            .unwrap()
            .delivery,
        Delivery::Dispatched
    );
    assert!(
        disk.exists(),
        "native detachment must not delete persistent data"
    );
    retire(f);
}

#[test]
fn missing_or_invalid_custody_record_cannot_turn_handle_loss_into_shutdown() {
    let mut f = Fixture::new();
    f.start();
    let before = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    f.guardian.effect.as_mut().unwrap().measured = None;
    assert!(!f.guardian.refresh_native_observation().unwrap());
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value(),
        &before
    );
    let record = f.root.join("system.storage.json");
    use std::io::Write;
    sandsurf_native::local::create_private_file(&record)
        .unwrap()
        .write_all(b"invalid")
        .unwrap();
    assert!(!f.guardian.refresh_native_observation().unwrap());
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value(),
        &before
    );
    assert_eq!(std::fs::read(record).unwrap(), b"invalid");
    retire(f);
}

#[test]
fn resource_update_validation_returns_the_assessment_from_the_same_native_observation() {
    let mut f = Fixture::new();
    f.start();
    let machine = f.guardian.journal.machine_id().clone();
    let before = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    let response = f.guardian.handle(GuardianRequest::Runtime {
        machine_id: machine.clone(),
        request: RuntimeRequest::ValidateResources {
            resources: RuntimeConfiguration::default().resources,
        },
    });
    assert!(matches!(response, GuardianResponse::Runtime {
        response: RuntimeResponse::ResourceAssessment { assessment }
    } if assessment.mode == ResourceChangeMode::Live && assessment.reasons == ["native generation 1"]));
    assert_eq!(
        *f.guardian.effect.as_ref().unwrap().resource_checks.borrow(),
        vec![("validate", before.clone()), ("assess", before.clone())]
    );
    assert_eq!(
        f.host
            .machine(&machine)
            .unwrap()
            .unwrap()
            .configuration_revision,
        Counter::ONE
    );
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value(),
        &before
    );
    // Capacity refusal is not a successful assessment/validation, and never
    // becomes host authority. Preview remains a separate read-only operation.
    let mut excluded = RuntimeConfiguration::default().resources;
    excluded.output_bytes = Counter::ZERO;
    assert!(matches!(
        f.guardian.handle(GuardianRequest::Runtime {
            machine_id: machine.clone(),
            request: RuntimeRequest::ValidateResources {
                resources: excluded
            },
        }),
        GuardianResponse::Rejected { .. }
    ));
    assert_eq!(
        f.guardian
            .effect
            .as_ref()
            .unwrap()
            .resource_checks
            .borrow()
            .len(),
        2
    );
    assert!(matches!(
        f.guardian.handle(GuardianRequest::Runtime {
            machine_id: machine,
            request: RuntimeRequest::AssessResources {
                resources: RuntimeConfiguration::default().resources
            },
        }),
        GuardianResponse::Runtime {
            response: RuntimeResponse::ResourceAssessment { .. }
        }
    ));
    assert_eq!(
        f.guardian
            .effect
            .as_ref()
            .unwrap()
            .resource_checks
            .borrow()
            .len(),
        3
    );
    retire(f);
}

#[test]
fn stop_and_destroy_overtake_offline_boot_without_dispatching_its_completion() {
    for desired in [DesiredState::Stopped, DesiredState::Destroyed] {
        let mut f = Fixture::new();
        let authorization = f.create();
        let BootAdmission::Queued { input, pending } =
            f.guardian.begin_boot(authorization.clone()).unwrap()
        else {
            panic!("cold boot should be queued");
        };
        assert_eq!(
            f.guardian
                .journal
                .lifecycle_operation(&authorization.statement.command.operation_id)
                .unwrap()
                .unwrap()
                .delivery,
            Delivery::Admitted
        );
        assert_eq!(f.guardian.effect.as_ref().unwrap().started, 0);
        assert!(matches!(
            f.guardian.begin_boot(authorization.clone()).unwrap(),
            BootAdmission::Ready(_)
        ));
        let containment = f.intent("contain", desired);
        let BootAdmission::Ready(response) = f.guardian.begin_boot(containment).unwrap() else {
            panic!("containment must not wait for offline boot");
        };
        assert_eq!(delivery(response), Delivery::Applied);
        let BootAdmission::Ready(response) = f.guardian.begin_boot(authorization).unwrap() else {
            panic!("superseded authority must not schedule another disk worker");
        };
        assert_eq!(delivery(response), Delivery::NotApplied);
        assert!(
            !f.guardian.can_retire().unwrap(),
            "disk worker still holds work custody"
        );
        let response = f
            .guardian
            .finish_boot(pending, Ok(prepared(input)))
            .unwrap()
            .unwrap();
        assert_eq!(delivery(response), Delivery::NotApplied);
        let native = f.guardian.effect.as_ref().unwrap();
        assert_eq!(native.installed, 0);
        assert_eq!(native.started, 0);
        assert!(
            f.guardian
                .journal
                .last_observation()
                .unwrap()
                .unwrap()
                .value()
                .state
                .satisfies(desired)
        );
        retire(f);
    }
}

#[test]
fn failed_preparation_is_not_applied_and_exact_retry_still_has_one_dispatch_gate() {
    let mut f = Fixture::new();
    let authorization = f.create();
    let BootAdmission::Queued { pending, .. } =
        f.guardian.begin_boot(authorization.clone()).unwrap()
    else {
        panic!("expected preparation");
    };
    let response = f
        .guardian
        .finish_boot(pending, Err(Error::Protocol("offline failure")))
        .unwrap()
        .unwrap();
    assert_eq!(delivery(response), Delivery::NotApplied);
    assert!(f.guardian.journal.last_observation().unwrap().is_none());
    assert_eq!(f.guardian.effect.as_ref().unwrap().started, 0);
    let BootAdmission::Queued { pending, .. } =
        f.guardian.begin_boot(authorization.clone()).unwrap()
    else {
        panic!("exact retry must prepare again");
    };
    let response = f
        .guardian
        .finish_boot(pending, Err(Error::Protocol("second offline failure")))
        .unwrap()
        .unwrap();
    assert_eq!(delivery(response), Delivery::NotApplied);
    let BootAdmission::Queued { input, pending } =
        f.guardian.begin_boot(authorization.clone()).unwrap()
    else {
        panic!("exact retry must prepare again");
    };
    let response = f
        .guardian
        .finish_boot(pending, Ok(prepared(input)))
        .unwrap()
        .unwrap();
    assert_eq!(delivery(response), Delivery::Applied);
    assert!(matches!(
        f.guardian.begin_boot(authorization).unwrap(),
        BootAdmission::Ready(_)
    ));
    assert_eq!(f.guardian.effect.as_ref().unwrap().started, 1);
    assert_eq!(f.guardian.effect.as_ref().unwrap().installed, 1);
    retire(f);
}

#[test]
fn prepared_artifacts_are_bound_to_the_machine_image_geometry_and_generation() {
    let input = BootPreparation {
        machine_root: PathBuf::from("/owned/computer"),
        machine_id: "computer".try_into().unwrap(),
        generation: Counter::ONE,
        image_digest: bytes_digest(b"image"),
        disk_bytes: 4096,
    };
    let changes = [
        BootPreparation {
            machine_root: PathBuf::from("/other/computer"),
            ..input.clone()
        },
        BootPreparation {
            machine_id: "other".try_into().unwrap(),
            ..input.clone()
        },
        BootPreparation {
            generation: n(2),
            ..input.clone()
        },
        BootPreparation {
            image_digest: bytes_digest(b"other-image"),
            ..input.clone()
        },
        BootPreparation {
            disk_bytes: 8192,
            ..input.clone()
        },
    ];
    for expected in changes {
        assert!(
            prepared(input.clone())
                .consume(
                    &expected.machine_root,
                    &expected.machine_id,
                    expected.generation,
                    &expected.image_digest,
                    expected.disk_bytes,
                )
                .is_err()
        );
    }
    assert!(
        prepared(input.clone())
            .consume(
                &input.machine_root,
                &input.machine_id,
                input.generation,
                &input.image_digest,
                input.disk_bytes,
            )
            .is_ok()
    );
}

#[test]
fn admitted_boot_recovers_after_owner_restart_without_any_dispatch_evidence() {
    let mut f = Fixture::new();
    let authorization = f.create();
    assert!(matches!(
        f.guardian.begin_boot(authorization.clone()).unwrap(),
        BootAdmission::Queued { .. }
    ));
    let retained = RuntimeJournal::open(&f.root.join("runtime"), f.guardian.journal.machine_id());
    assert!(retained.is_err(), "a second journal writer is forbidden");
    let machine = f.guardian.journal.machine_id().clone();
    // Replace the owner only after dropping the old writer.
    let Fixture {
        guardian,
        host,
        root,
    } = f;
    drop(guardian);
    let journal = RuntimeJournal::open(&root.join("runtime"), &machine).unwrap();
    f = Fixture {
        host,
        root: root.clone(),
        guardian: Guardian::new(
            journal,
            Native {
                root,
                restore: None,
                measured: None,
                reset: false,
                installed: 0,
                started: 0,
                resource_checks: Default::default(),
                capture_publications: Vec::new(),
            },
        ),
    };
    let BootAdmission::Queued { input, pending } = f.guardian.begin_boot(authorization).unwrap()
    else {
        panic!("admitted operation must rebuild preparation");
    };
    let response = f
        .guardian
        .finish_boot(pending, Ok(prepared(input)))
        .unwrap()
        .unwrap();
    assert_eq!(delivery(response), Delivery::Applied);
    assert_eq!(f.guardian.effect.as_ref().unwrap().started, 1);
    retire(f);
}

#[test]
fn reset_preparation_is_fenced_by_new_authority_even_before_native_stop_delivery() {
    let mut f = Fixture::new();
    f.start();
    let native = f.guardian.effect.as_mut().unwrap();
    native.measured = Some(MachineState::Stopped);
    native.reset = true;
    f.guardian.refresh_native_observation().unwrap();
    let starting = f
        .guardian
        .journal
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    assert_eq!(starting.state, MachineState::Starting);
    assert_eq!(starting.generation, n(2));
    let (input, pending) = f.guardian.begin_reset_boot().unwrap().unwrap();
    assert_eq!(input.generation, n(2));
    assert!(f.guardian.begin_reset_boot().unwrap().is_none());
    let stop = f.intent("stop-reset", DesiredState::Stopped);
    f.guardian.journal.admit_lifecycle(stop.clone()).unwrap();
    assert!(
        !f.guardian
            .journal
            .native_reset_is_current(&starting)
            .unwrap()
    );
    assert!(
        f.guardian
            .finish_boot(pending, Ok(prepared(input)))
            .unwrap()
            .is_none()
    );
    assert_eq!(f.guardian.effect.as_ref().unwrap().started, 1);
    assert_eq!(f.guardian.effect.as_ref().unwrap().installed, 1);
    let BootAdmission::Ready(response) = f.guardian.begin_boot(stop).unwrap() else {
        panic!("stop must not prepare");
    };
    assert_eq!(delivery(response), Delivery::Applied);
    assert_eq!(
        f.guardian
            .journal
            .last_observation()
            .unwrap()
            .unwrap()
            .value()
            .generation,
        n(2)
    );
    retire(f);
}

#[test]
fn reboot_preparation_and_failure_keep_the_committed_generation_and_native_facts() {
    for fail in [false, true] {
        let mut f = Fixture::new();
        f.start();
        let native = f.guardian.effect.as_mut().unwrap();
        native.measured = Some(MachineState::Stopped);
        native.reset = true;
        f.guardian.refresh_native_observation().unwrap();
        let (input, pending) = f.guardian.begin_reset_boot().unwrap().unwrap();
        let result = if fail {
            Err(Error::Protocol("offline reset failure"))
        } else {
            Ok(prepared(input))
        };
        assert!(f.guardian.finish_boot(pending, result).unwrap().is_none());
        let current = f.guardian.journal.last_observation().unwrap().unwrap();
        assert_eq!(current.value().generation, n(2));
        assert_eq!(current.value().applied_revision, Counter::ONE);
        assert_eq!(current.value().cause, ObservationCause::GuestReset {});
        assert_eq!(
            current.value().state,
            if fail {
                MachineState::Failed
            } else {
                MachineState::Running
            }
        );
        assert_eq!(
            f.guardian.effect.as_ref().unwrap().started,
            if fail { 1 } else { 2 }
        );
        retire(f);
    }
}
