//! Fault evidence tests use a native-effect fixture, not hardware qualification.
use sandsurf_host::guardian::*;
use sandsurf_protocol::*;
use sandsurf_state::{CatalogLimits, HostCatalog, RuntimeJournal, RuntimeLimits};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct NoManagement;
impl GuestDriver for NoManagement {
    fn dispatch(&mut self, _: &GuestCommand) -> EffectOutcome {
        EffectOutcome::Unknown
    }
}
struct Power {
    measured: MachineState,
    reset: bool,
    recovered: Arc<AtomicUsize>,
}
impl GuardianEffect for Power {
    fn capture_owner(&self) -> Result<Option<OperationId>> {
        Ok(None)
    }
    fn guest_driver(&mut self) -> Box<dyn GuestDriver> {
        Box::new(NoManagement)
    }
    fn transition(
        &mut self,
        _: &LifecycleCommand,
        _: Option<&MachineObservation>,
    ) -> LifecycleEffect {
        LifecycleEffect::Unknown
    }
    fn observe_power(&mut self) -> Result<Option<sandsurf_machine::NativePowerObservation>> {
        Ok(Some(sandsurf_machine::NativePowerObservation {
            state: self.measured,
            evidence_digest: bytes_digest(b"fixture-native-power"),
        }))
    }
    fn take_guest_reset(&mut self) -> Option<Digest> {
        std::mem::take(&mut self.reset).then(|| bytes_digest(b"fixture-native-reset"))
    }
    fn recover_guest_reset(&mut self, current: &MachineObservation) -> Result<Digest> {
        assert_eq!(current.state, MachineState::Starting);
        assert_eq!(current.generation.get(), 2);
        assert_eq!(current.applied_revision, Counter::ONE);
        self.recovered.fetch_add(1, Ordering::SeqCst);
        self.measured = MachineState::Running;
        Ok(bytes_digest(b"fixture-native-recovered"))
    }
}
fn n(value: u64) -> Counter {
    value.try_into().unwrap()
}

fn exercise(measured: MachineState, reset: bool) -> (MachineObservation, usize) {
    let root = std::env::temp_dir().join(format!(
        "sandsurf-native-power-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    let host = HostCatalog::create(
        &root.join("host"),
        "native-power-host".try_into().unwrap(),
        CatalogLimits {
            identities: n(8),
            operations: n(32),
            usage_records: n(32),
            image_bytes: n(1024 * 1024),
            resources: RuntimeConfiguration::default().resources,
        },
    )
    .unwrap();
    let machine_id: MachineId = "computer".try_into().unwrap();
    let mut journal = RuntimeJournal::create(
        &root.join("runtime"),
        machine_id.clone(),
        RuntimeLimits {
            identities: n(16),
            managed_executions: n(8),
            operations: n(32),
            observations: n(64),
            events: n(128),
            chunks: n(64),
            output_segments: n(16),
            output_bytes: n(1024 * 1024),
        },
        host.authority_binding().clone(),
    )
    .unwrap();
    let initial = MachineObservation {
        machine_id: machine_id.clone(),
        generation: Counter::ONE,
        sequence: Counter::ONE,
        state: MachineState::Creating,
        applied_revision: Counter::ONE,
        cause: ObservationCause::Lifecycle {
            operation_id: "create".try_into().unwrap(),
        },
        evidence_digest: bytes_digest(b"fixture-created"),
    };
    journal.observe(initial.clone()).unwrap();
    journal
        .observe(MachineObservation {
            sequence: n(2),
            state: MachineState::Running,
            ..initial
        })
        .unwrap();
    let recovered = Arc::new(AtomicUsize::new(0));
    let mut guardian = Guardian::new(
        journal,
        Power {
            measured,
            reset,
            recovered: recovered.clone(),
        },
    );
    let GuardianResponse::Inspection { value } = guardian.handle(GuardianRequest::Inspect {
        machine_id: machine_id.clone(),
        operation_id: None,
    }) else {
        panic!("native inspection failed");
    };
    let Observation::Current { value: observation } = value.observation else {
        panic!("native evidence unavailable");
    };
    let stale = guardian.handle(GuardianRequest::Runtime {
        machine_id,
        request: RuntimeRequest::WriteConsole {
            generation: Counter::ONE,
            bytes: vec![b'x'],
        },
    });
    if reset && measured == MachineState::Stopped {
        assert!(
            matches!(stale, GuardianResponse::Rejected { category, .. } if category == "stale-generation")
        );
    }
    let count = recovered.load(Ordering::SeqCst);
    drop(guardian);
    drop(host);
    std::fs::remove_dir_all(root).unwrap();
    (observation, count)
}

#[test]
fn distinct_native_reset_advances_generation_and_fences_old_console_input() {
    let (observation, count) = exercise(MachineState::Stopped, true);
    assert_eq!(count, 1);
    assert_eq!(observation.generation.get(), 2);
    assert_eq!(observation.state, MachineState::Running);
    assert_eq!(observation.cause, ObservationCause::GuestReset {});
}

#[test]
fn native_exit_and_management_loss_never_authorize_reboot() {
    for state in [
        MachineState::Running,
        MachineState::Stopped,
        MachineState::Failed,
    ] {
        let (observation, count) = exercise(state, false);
        assert_eq!(count, 0);
        assert_eq!(observation.generation, Counter::ONE);
        assert_eq!(observation.state, state);
    }
    let (observation, count) = exercise(MachineState::Failed, true);
    assert_eq!(
        count, 0,
        "a crash cannot be recovered even with a reset witness"
    );
    assert_eq!(observation.state, MachineState::Failed);
    assert_eq!(observation.generation, Counter::ONE);
}
