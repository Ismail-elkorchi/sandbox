#![cfg(any(unix, windows))]

use sandsurf_host::guardian::*;
use sandsurf_native::local::LocalConnection;
use sandsurf_protocol::*;
use sandsurf_state::*;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        #[cfg(target_os = "macos")]
        let temporary = PathBuf::from("/tmp");
        #[cfg(not(target_os = "macos"))]
        let temporary = std::env::temp_dir();
        let path = temporary.join(format!(
            "ssf-g-{}-{:x}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        #[cfg(unix)]
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        #[cfg(windows)]
        sandsurf_native::local::create_private_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn n(value: u64) -> Counter {
    value.try_into().unwrap()
}
fn hash(value: &str) -> Digest {
    bytes_digest(value.as_bytes())
}
fn resources() -> Resources {
    Resources {
        vcpus: n(2),
        memory_mib: n(2048),
        disk_bytes: n(100_000),
        output_bytes: n(1000),
        managed_executions: n(8),
    }
}
fn catalog_limits() -> CatalogLimits {
    CatalogLimits {
        identities: n(8),
        operations: n(64),
        usage_records: n(64),
        image_bytes: n(400_000),
        resources: Resources {
            vcpus: n(8),
            memory_mib: n(8192),
            disk_bytes: n(400_000),
            output_bytes: n(4000),
            managed_executions: n(32),
        },
    }
}
fn runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        identities: n(16),
        managed_executions: n(8),
        operations: n(64),
        observations: n(64),
        events: n(256),
        chunks: n(64),
        pins: n(16),
        output_bytes: n(4096),
    }
}

struct Fixture {
    host: HostCatalog,
    machine: MachineId,
    command: GuestCommand,
    // Release protected database handles before retiring their storage.
    root: Root,
}

impl Fixture {
    fn new() -> Self {
        let root = Root::new();
        let mut host = HostCatalog::create(
            &root.0.join("host"),
            "host".try_into().unwrap(),
            catalog_limits(),
        )
        .unwrap();
        let machine: MachineId = "box".try_into().unwrap();
        let create: OperationId = "create".try_into().unwrap();
        let image = hash("image");
        let defaults = ExecutionDefaults::default();
        let request_digest = digest(
            Domain::Machine,
            &(
                &machine,
                &image,
                resources(),
                &defaults,
                &MachineLifetime::default(),
                &create,
            ),
        )
        .unwrap();
        host.create_machine(
            MachineAdmission {
                image_defaults: ExecutionDefaults::default(),
                id: machine.clone(),
                image,
                resources: resources(),
                defaults,
                lifetime: MachineLifetime::default(),
                operation: create.clone(),
            },
            Approval {
                id: "approve-create".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
        let mut runtime = RuntimeJournal::create(
            &root.0.join("runtime"),
            machine.clone(),
            runtime_limits(),
            host.authority_binding().clone(),
        )
        .unwrap();
        runtime
            .observe(MachineObservation {
                machine_id: machine.clone(),
                generation: Counter::ONE,
                sequence: Counter::ONE,
                state: MachineState::Creating,
                applied_revision: Counter::ONE,
                cause: sandsurf_protocol::ObservationCause::Lifecycle {
                    operation_id: create.clone(),
                },
                evidence_digest: hash("owned"),
            })
            .unwrap();
        let running = runtime
            .observe(MachineObservation {
                machine_id: machine.clone(),
                generation: Counter::ONE,
                sequence: n(2),
                state: MachineState::Running,
                applied_revision: Counter::ONE,
                cause: sandsurf_protocol::ObservationCause::Lifecycle {
                    operation_id: create,
                },
                evidence_digest: hash("booted"),
            })
            .unwrap();
        host.complete_intent(&running).unwrap();
        let configuration = host
            .machine(&machine)
            .unwrap()
            .unwrap()
            .runtime_configuration;
        let request_digest = hash("fixture-configuration");
        host.set_runtime_configuration(
            &machine,
            &"configure-fixture".try_into().unwrap(),
            Counter::ONE,
            configuration,
            request_digest.clone(),
            Approval {
                id: "approve-configuration".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
        runtime
            .observe(MachineObservation {
                machine_id: machine.clone(),
                generation: Counter::ONE,
                sequence: n(3),
                state: MachineState::Running,
                applied_revision: n(2),
                cause: ObservationCause::Configuration {
                    operation_id: "configure-fixture".try_into().unwrap(),
                },
                evidence_digest: hash("revision-2"),
            })
            .unwrap();
        drop(runtime);
        let operation_id: OperationId = "dispatch-once".try_into().unwrap();
        let command = GuestCommand::new(
            machine.clone(),
            Counter::ONE,
            operation_id.clone(),
            GuestRequest::Spawn {
                request: Box::new(SpawnRequest {
                    machine_id: machine.clone(),
                    generation: Counter::ONE,
                    execution_id: "dispatch-process".try_into().unwrap(),
                    operation_id,
                    argv: vec!["/bin/true".into()],
                    cwd: "/workspace".into(),
                    environment: Default::default(),
                    user: Some("agent".into()),
                    stdio: StdioMode::Pipes,
                    terminal_size: None,
                    active_deadline_millis: None,
                    elapsed_deadline_unix_millis: None,
                    output_bytes: n(1024),
                }),
            },
        )
        .unwrap();
        Self {
            root,
            host,
            machine,
            command,
        }
    }
}

struct FileEffect {
    path: PathBuf,
}
struct FileGuest {
    path: PathBuf,
}
impl GuestDriver for FileGuest {
    fn poll(&mut self, _hints: &ExecutionHints) -> sandsurf_host::guardian::Result<GuestPoll> {
        if self.path.parent().unwrap().join("management-down").exists() {
            return Err(sandsurf_host::guardian::Error::Protocol(
                "fixture management is unavailable",
            ));
        }
        Ok(GuestPoll {
            identity: Some(GuestManagementIdentity {
                boot_id: "fixture-boot".try_into().unwrap(),
                instance_id: "fixture-management".try_into().unwrap(),
            }),
            executions: Vec::new(),
        })
    }
    fn dispatch(&mut self, command: &GuestCommand) -> EffectOutcome {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        writeln!(file, "{}", command.operation_id.as_str()).unwrap();
        file.sync_all().unwrap();
        EffectOutcome::Applied(
            digest(
                Domain::Operation,
                &(&command.operation_id, &command.request_digest),
            )
            .unwrap(),
        )
    }

    fn query(
        &mut self,
        request: GuestServiceRequest,
    ) -> sandsurf_host::guardian::Result<GuestServiceResponse> {
        if std::env::var_os("SANDSURF_TEST_BLOCK_GUEST_QUERY").is_some() {
            let root = self.path.parent().unwrap();
            fs::write(root.join("guest-query-entered"), []).unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            while !root.join("release-guest-query").exists() {
                if Instant::now() >= deadline {
                    fs::write(root.join("guest-query-timed-out"), []).unwrap();
                    return Err(sandsurf_host::guardian::Error::Protocol(
                        "blocked guest fixture deadline",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(request, GuestServiceRequest::ProbeIdentity);
        Ok(GuestServiceResponse::Identity {
            machine_id: "box".try_into().unwrap(),
            generation: Counter::ONE,
            boot_identity: hash("fixture-guest"),
            management: GuestManagementIdentity {
                boot_id: "fixture-boot".try_into().unwrap(),
                instance_id: "fixture-management".try_into().unwrap(),
            },
        })
    }
}
impl GuardianEffect for FileEffect {
    fn observe_power(
        &mut self,
    ) -> sandsurf_host::guardian::Result<Option<sandsurf_machine::NativePowerObservation>> {
        let root = self.path.parent().unwrap();
        if root.join("native-unavailable").exists() {
            return Err(sandsurf_host::guardian::Error::Protocol(
                "native owner unavailable",
            ));
        }
        let state = match fs::read(root.join("native-power")) {
            Ok(bytes) => serde_json::from_slice::<MachineState>(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => MachineState::Running,
            Err(error) => return Err(error.into()),
        };
        Ok(
            (!matches!(state, MachineState::Destroyed | MachineState::Suspended)).then(|| {
                sandsurf_machine::NativePowerObservation {
                    state,
                    evidence_digest: hash("measured-native-power"),
                }
            }),
        )
    }
    fn capture_owner(&self) -> sandsurf_host::guardian::Result<Option<OperationId>> {
        if self
            .path
            .parent()
            .unwrap()
            .join("capture-owner-unavailable")
            .exists()
        {
            return Err(sandsurf_host::guardian::Error::Protocol(
                "capture owner unavailable",
            ));
        }
        Ok(self
            .path
            .parent()
            .unwrap()
            .join("capture-owned")
            .exists()
            .then(|| "capture".try_into().unwrap()))
    }
    fn guest_driver(&mut self) -> Box<dyn GuestDriver> {
        Box::new(FileGuest {
            path: self.path.clone(),
        })
    }
    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> LifecycleEffect {
        let generation = current.map_or(Counter::ONE, |value| value.generation);
        let transition = |state| MachineTransition {
            generation,
            state,
            evidence_digest: digest(
                Domain::Operation,
                &(&command.operation_id, state, "mock-machine-observation"),
            )
            .unwrap(),
        };
        let states = match command.desired {
            DesiredState::Running if current.is_none() => {
                vec![
                    transition(MachineState::Creating),
                    transition(MachineState::Running),
                ]
            }
            DesiredState::Running => vec![transition(MachineState::Running)],
            DesiredState::Paused => vec![transition(MachineState::Paused)],
            DesiredState::Stopped => vec![transition(MachineState::Stopped)],
            DesiredState::Suspended => vec![transition(MachineState::Suspended)],
            DesiredState::Destroyed => vec![
                transition(MachineState::Destroying),
                transition(MachineState::Destroyed),
            ],
        };
        fs::write(
            self.path.parent().unwrap().join("native-power"),
            serde_json::to_vec(&states.last().unwrap().state).unwrap(),
        )
        .unwrap();
        LifecycleEffect::Observed(states)
    }
}

#[test]
fn native_measurements_are_durable_independent_facts_and_unavailability_is_not_shutdown() {
    let fixture = Fixture::new();
    let endpoint = fixture.root.0.join("endpoint");
    sandsurf_native::local::create_private_directory(&endpoint).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "guardian_process_fixture", "--test-threads=1"])
        .env("SANDSURF_GUARDIAN_TEST_ROOT", &fixture.root.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _child = ChildGuard(child);
    drop(wait_for_guardian(&endpoint));
    let client = GuardianClient::new(endpoint);
    client.dispatch(fixture.command.clone()).unwrap();
    let execution: ExecutionId = "dispatch-process".try_into().unwrap();
    let RuntimeResponse::Processes { processes } = client
        .runtime(fixture.machine.clone(), RuntimeRequest::Processes)
        .unwrap()
    else {
        panic!("execution list");
    };
    assert_eq!(processes.len(), 1);
    assert_eq!(processes[0].execution_id, execution);
    assert!(matches!(
        processes[0].report,
        Observation::Unavailable { last_known: None }
    ));
    assert_eq!(processes[0].interruption, None);
    let initial = client.inspect(fixture.machine.clone(), None).unwrap();
    let Observation::Current { value: initial } = initial.observation else {
        panic!("owned machine");
    };
    fs::write(fixture.root.0.join("native-unavailable"), []).unwrap();
    let unavailable = client.inspect(fixture.machine.clone(), None).unwrap();
    assert!(
        matches!(unavailable.observation, Observation::Unavailable { last_known: Some(value) } if value == initial)
    );
    fs::remove_file(fixture.root.0.join("native-unavailable")).unwrap();
    fs::write(
        fixture.root.0.join("native-power"),
        serde_json::to_vec(&MachineState::Stopped).unwrap(),
    )
    .unwrap();
    // Observe the event ledger, not Inspect: periodic native sampling must run
    // without a client requesting a machine-state refresh or any guest report.
    let deadline = Instant::now() + Duration::from_secs(8);
    let measured = loop {
        let RuntimeResponse::Events { page } = client
            .runtime(
                fixture.machine.clone(),
                RuntimeRequest::Events {
                    after: Counter::ZERO,
                    maximum: 256,
                },
            )
            .unwrap()
        else {
            panic!("event ledger");
        };
        if let Some(value) = page.events.into_iter().find_map(|event| match event.value {
            RuntimeEventValue::Machine { observation }
                if observation.cause == ObservationCause::Native {} =>
            {
                Some(observation)
            }
            _ => None,
        }) {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "native state must be sampled independently"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(measured.state, MachineState::Stopped);
    assert_eq!(measured.generation, initial.generation);
    assert_eq!(measured.applied_revision, initial.applied_revision);
    let RuntimeResponse::Process { process, .. } = client
        .runtime(
            fixture.machine.clone(),
            RuntimeRequest::Process {
                execution_id: execution.clone(),
            },
        )
        .unwrap()
    else {
        panic!("execution status");
    };
    assert_eq!(process.execution_id, execution);
    assert_eq!(process.generation, Counter::ONE);
    assert_eq!(process.interruption, Some(measured.clone()));
    assert!(matches!(
        process.report,
        Observation::Unavailable { last_known: None }
    ));
    assert!(matches!(
        client
            .runtime(
                fixture.machine.clone(),
                RuntimeRequest::Receipt {
                    execution_id: execution
                }
            )
            .unwrap(),
        RuntimeResponse::Receipt {
            receipt: None,
            digest: None
        }
    ));
    let host = fixture.host.machine(&fixture.machine).unwrap().unwrap();
    assert_eq!(host.latest_intent.desired, DesiredState::Running);
    assert_eq!(fixture.host.revision(&fixture.machine).unwrap(), n(2));
    assert_eq!(
        client
            .inspect(fixture.machine.clone(), None)
            .unwrap()
            .observation,
        Observation::Current {
            value: measured.clone()
        }
    );
    let RuntimeResponse::Events { page } = client
        .runtime(
            fixture.machine,
            RuntimeRequest::Events {
                after: Counter::ZERO,
                maximum: 256,
            },
        )
        .unwrap()
    else {
        panic!("event ledger");
    };
    assert_eq!(page.events.iter().filter(|event| matches!(&event.value, RuntimeEventValue::Machine { observation } if observation.cause == ObservationCause::Native {})).count(), 1, "unchanged measurements do not bloat durable history");
}

#[test]
fn retained_ledger_requires_destroyed_evidence_and_has_no_native_or_guest_owner() {
    let fixture = Fixture::new();
    let path = fixture.root.0.join("runtime");
    let mut runtime = RuntimeJournal::open(&path, &fixture.machine).unwrap();
    assert!(Guardian::<FileEffect>::retained(runtime).is_err());
    runtime = RuntimeJournal::open(&path, &fixture.machine).unwrap();
    let mut last = runtime.last_observation().unwrap().unwrap().value().clone();
    for state in [MachineState::Destroying, MachineState::Destroyed] {
        last.state = state;
        last.cause = ObservationCause::Lifecycle {
            operation_id: "destroy-retained-fixture".try_into().unwrap(),
        };
        last.sequence = last.sequence.next().unwrap();
        runtime.observe(last.clone()).unwrap();
    }
    drop(runtime);
    let runtime = RuntimeJournal::open(&path, &fixture.machine).unwrap();
    let mut guardian = Guardian::<FileEffect>::retained(runtime).unwrap();
    assert!(matches!(guardian.handle(GuardianRequest::Inspect {
        machine_id: fixture.machine.clone(), operation_id: None,
    }), GuardianResponse::Inspection { value } if matches!(value.observation, Observation::Current { value: MachineObservation { state: MachineState::Destroyed, .. }})));
    assert!(matches!(
        guardian.handle(GuardianRequest::NativeSnapshot {
            machine_id: fixture.machine.clone(),
            request: NativeSnapshotRequest::PrepareDisk {
                operation_id: "capture-retired".try_into().unwrap()
            },
        }),
        GuardianResponse::Rejected { .. }
    ));
    assert!(guardian.can_retire().unwrap());
    assert!(!fixture.root.0.join("effects.log").exists());
}

#[test]
fn guardian_process_fixture() {
    let Some(root) = std::env::var_os("SANDSURF_GUARDIAN_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let machine: MachineId = "box".try_into().unwrap();
    let runtime = RuntimeJournal::open(&root.join("runtime"), &machine).unwrap();
    let mut guardian = Guardian::new(
        runtime,
        FileEffect {
            path: root.join("effects.log"),
        },
    );
    serve_guardian(&root.join("endpoint"), &mut guardian).unwrap();
}

#[test]
fn journal_stream_resumes_after_owner_restart_and_never_blocks_control() {
    let fixture = Fixture::new();
    let endpoint = fixture.root.0.join("endpoint");
    sandsurf_native::local::ensure_private_directory(&endpoint).unwrap();
    let spawn = || {
        ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "guardian_process_fixture", "--test-threads=1"])
                .env("SANDSURF_GUARDIAN_TEST_ROOT", &fixture.root.0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        )
    };
    let mut child = spawn();
    drop(wait_for_guardian(&endpoint));
    let client = GuardianClient::new(endpoint.clone());
    let mut stream =
        EventStream::open(&endpoint, fixture.machine.clone(), Counter::ZERO, 1).unwrap();
    let first = stream.read_page().unwrap();
    assert_eq!(first.cursor, Counter::ONE);
    assert_eq!(first.events.len(), 1);
    // No next credit: a stalled observer cannot hold the journal or VM owner.
    client.inspect(fixture.machine.clone(), None).unwrap();
    drop(stream);
    let mut resumed =
        EventStream::open(&endpoint, fixture.machine.clone(), first.cursor, 256).unwrap();
    let history = resumed.read_page().unwrap();
    assert_eq!(history.events.first().unwrap().cursor, n(2));
    assert_eq!(history.cursor, history.available);
    drop(resumed);

    let mut idle =
        EventStream::open(&endpoint, fixture.machine.clone(), history.available, 256).unwrap();
    idle.read_page().unwrap();
    // The management poll can append independent observations concurrently.
    fs::write(
        fixture.root.0.join("native-power"),
        serde_json::to_vec(&MachineState::Paused).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let (measured, cursor) = loop {
        let page = idle.read_page().unwrap();
        let cursor = page.cursor;
        if let Some(event) = page.events.into_iter().find(|event| matches!(
            &event.value, RuntimeEventValue::Machine { observation }
                if observation.state == MachineState::Paused && observation.cause == ObservationCause::Native {}
        )) { break (event, cursor); }
        assert!(
            Instant::now() < deadline,
            "committed native fact did not wake observer"
        );
    };
    drop(idle);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let _restarted = spawn();
    drop(wait_for_guardian(&endpoint));
    let mut replay =
        EventStream::open(&endpoint, fixture.machine.clone(), measured.cursor, 256).unwrap();
    let after = replay.read_page().unwrap();
    assert!(after.cursor >= cursor);
    drop(replay);
    let mut replay = EventStream::open(
        &endpoint,
        fixture.machine.clone(),
        n(measured.cursor.get() - 1),
        1,
    )
    .unwrap();
    assert_eq!(replay.read_page().unwrap().events, vec![measured]);
}

#[test]
fn journal_stream_capacity_preserves_non_streaming_control_connections() {
    let fixture = Fixture::new();
    let endpoint = fixture.root.0.join("endpoint");
    sandsurf_native::local::ensure_private_directory(&endpoint).unwrap();
    let _child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "guardian_process_fixture", "--test-threads=1"])
            .env("SANDSURF_GUARDIAN_TEST_ROOT", &fixture.root.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    drop(wait_for_guardian(&endpoint));
    let streams = (0..8)
        .map(|_| {
            let mut stream =
                EventStream::open(&endpoint, fixture.machine.clone(), Counter::ZERO, 1).unwrap();
            stream.read_page().unwrap();
            stream
        })
        .collect::<Vec<_>>();
    let mut denied =
        EventStream::open(&endpoint, fixture.machine.clone(), Counter::ZERO, 1).unwrap();
    assert!(
        matches!(denied.read_page(), Err(sandsurf_host::guardian::Error::Rejected { category, .. }) if category == "capacity")
    );
    GuardianClient::new(endpoint)
        .inspect(fixture.machine.clone(), None)
        .unwrap();
    drop(streams);
}

#[test]
fn guardian_survives_host_restart_and_never_replays_a_lost_dispatch_response() {
    let fixture = Fixture::new();
    let endpoint = fixture.root.0.join("endpoint");
    #[cfg(unix)]
    fs::DirBuilder::new().mode(0o700).create(&endpoint).unwrap();
    #[cfg(windows)]
    sandsurf_native::local::create_private_directory(&endpoint).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("guardian_process_fixture")
        .arg("--test-threads=1")
        .env("SANDSURF_GUARDIAN_TEST_ROOT", &fixture.root.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _child = ChildGuard(child);
    let authorization = fixture.command.clone();
    let payload = serde_json::to_vec(&(
        SERVICE_VERSION,
        sandsurf_protocol::RequestEnvelope::split(GuardianRequest::Dispatch {
            command: authorization.clone(),
        })
        .unwrap()
        .0,
    ))
    .unwrap();
    // A connected but idle client must not block a separate authorized
    // dispatch or guardian journal reconciliation.
    let idle = wait_for_guardian(&endpoint);
    let mut connection = wait_for_guardian(&endpoint);
    connection
        .write_frame(
            &Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: Counter::ONE,
                authentication: [0; AUTHENTICATION_BYTES],
                payload,
            },
            Duration::from_secs(2),
        )
        .unwrap();
    wait_for(&fixture.root.0.join("effects.log"));
    drop(idle);
    drop(connection); // The effect committed, but its reply is deliberately lost.

    let host_path = fixture.root.0.join("host");
    drop(fixture.host);
    let mut host = HostCatalog::open(&host_path).unwrap();
    let link = HostGuardianLink::new(&host, endpoint.clone());
    let operation = GuardianClient::new(endpoint.clone())
        .dispatch(fixture.command.clone())
        .unwrap();
    assert_eq!(operation.delivery, Delivery::Applied);
    assert_eq!(
        fs::read_to_string(fixture.root.0.join("effects.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    let inspection = link
        .inspect(
            fixture.machine.clone(),
            Some(fixture.command.operation_id.clone()),
        )
        .unwrap();
    assert!(matches!(
        inspection.observation,
        Observation::Current {
            value: MachineObservation {
                state: MachineState::Running,
                ..
            }
        }
    ));
    assert_eq!(inspection.operation, Some(operation));
    assert_eq!(inspection.lifecycle_operation, None);
    drop(link);

    let pause: OperationId = "pause-machine".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&fixture.machine, &pause, n(2), DesiredState::Paused),
    )
    .unwrap();
    host.request_lifecycle(
        &fixture.machine,
        pause.clone(),
        n(2),
        DesiredState::Paused,
        Approval {
            id: "approve-pause-machine".try_into().unwrap(),
            request_digest,
        },
    )
    .unwrap();
    assert_eq!(host.intent(&pause).unwrap().unwrap().completion, None);
    let result = apply_lifecycle(&mut host, endpoint.clone(), &pause).unwrap();
    let lifecycle = result.guardian_operation;
    assert_eq!(lifecycle.delivery, Delivery::Applied);
    assert!(result.completed_intent.unwrap().completion.is_some());
    let link = HostGuardianLink::new(&host, endpoint.clone());
    let inspection = link
        .inspect(fixture.machine.clone(), Some(pause.clone()))
        .unwrap();
    assert!(matches!(
        inspection.observation,
        Observation::Current {
            value: MachineObservation {
                state: MachineState::Paused,
                ..
            }
        }
    ));
    assert_eq!(inspection.lifecycle_operation, Some(lifecycle.clone()));
    assert!(host.intent(&pause).unwrap().unwrap().completion.is_some());
    drop(link);

    let resume: OperationId = "resume-machine".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&fixture.machine, &resume, n(3), DesiredState::Running),
    )
    .unwrap();
    host.request_lifecycle(
        &fixture.machine,
        resume.clone(),
        n(3),
        DesiredState::Running,
        Approval {
            id: "approve-resume-machine".try_into().unwrap(),
            request_digest,
        },
    )
    .unwrap();
    let resumed = apply_lifecycle(&mut host, endpoint.clone(), &resume).unwrap();
    assert_eq!(resumed.guardian_operation.delivery, Delivery::Applied);

    let replayed = apply_lifecycle(&mut host, endpoint.clone(), &pause).unwrap();
    assert_eq!(replayed.guardian_operation, lifecycle);
    assert_eq!(replayed.completed_intent, host.intent(&pause).unwrap());
    let current = HostGuardianLink::new(&host, endpoint)
        .inspect(fixture.machine.clone(), None)
        .unwrap();
    assert!(matches!(
        current.observation,
        Observation::Current {
            value: MachineObservation {
                state: MachineState::Running,
                ..
            }
        }
    ));
}

#[test]
fn blocked_guest_io_cannot_block_native_observation_or_power_off() {
    let mut fixture = Fixture::new();
    let endpoint = fixture.root.0.join("endpoint");
    #[cfg(unix)]
    fs::DirBuilder::new().mode(0o700).create(&endpoint).unwrap();
    #[cfg(windows)]
    sandsurf_native::local::create_private_directory(&endpoint).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "guardian_process_fixture", "--test-threads=1"])
        .env("SANDSURF_GUARDIAN_TEST_ROOT", &fixture.root.0)
        .env("SANDSURF_TEST_BLOCK_GUEST_QUERY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _child = ChildGuard(child);
    drop(wait_for_guardian(&endpoint));
    let client = GuardianClient::new(endpoint.clone());
    let machine = fixture.machine.clone();
    let guest_query =
        std::thread::spawn(move || client.guest(machine, GuestServiceRequest::ProbeIdentity));
    wait_for(&fixture.root.0.join("guest-query-entered"));
    let inspection = GuardianClient::new(endpoint.clone())
        .inspect(fixture.machine.clone(), None)
        .unwrap();
    assert!(matches!(
        inspection.observation,
        Observation::Current {
            value: MachineObservation {
                state: MachineState::Running,
                ..
            }
        }
    ));
    let operation: OperationId = "power-off-while-guest-blocked".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&fixture.machine, &operation, n(2), DesiredState::Stopped),
    )
    .unwrap();
    fixture
        .host
        .request_lifecycle(
            &fixture.machine,
            operation.clone(),
            n(2),
            DesiredState::Stopped,
            Approval {
                id: "approve-native-stop".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    let result = apply_lifecycle(&mut fixture.host, endpoint, &operation).unwrap();
    assert_eq!(result.guardian_operation.delivery, Delivery::Applied);
    // Assert the dependency, not filesystem throughput on a shared runner:
    // native completion must precede either release or timeout of guest I/O.
    assert!(!fixture.root.0.join("guest-query-timed-out").exists());
    assert!(
        !guest_query.is_finished(),
        "native control waited on guest I/O"
    );
    assert!(!fixture.root.0.join("release-guest-query").exists());
    fs::write(fixture.root.0.join("release-guest-query"), []).unwrap();
    assert!(guest_query.join().unwrap().is_ok());
}

#[test]
fn durable_capture_ownership_fences_native_delivery_and_never_blocks_forced_containment() {
    for marker in ["capture-owned", "capture-owner-unavailable"] {
        let mut fixture = Fixture::new();
        let endpoint = fixture.root.0.join("endpoint");
        sandsurf_native::local::ensure_private_directory(&endpoint).unwrap();
        // The ownership record precedes a confirmed pause; the last native
        // postcondition is still Running. No volatile pause flag may override it.
        fs::write(fixture.root.0.join(marker), []).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "guardian_process_fixture", "--test-threads=1"])
            .env("SANDSURF_GUARDIAN_TEST_ROOT", &fixture.root.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let _child = ChildGuard(child);
        drop(wait_for_guardian(&endpoint));
        for (name, desired, expected) in [
            (
                "captured-start",
                DesiredState::Running,
                Delivery::NotApplied,
            ),
            ("captured-pause", DesiredState::Paused, Delivery::NotApplied),
            (
                "captured-power-off",
                DesiredState::Stopped,
                Delivery::Applied,
            ),
        ] {
            let operation: OperationId = name.try_into().unwrap();
            let revision = fixture.host.revision(&fixture.machine).unwrap();
            let request_digest = digest(
                Domain::Operation,
                &(&fixture.machine, &operation, revision, desired),
            )
            .unwrap();
            fixture
                .host
                .request_lifecycle(
                    &fixture.machine,
                    operation.clone(),
                    revision,
                    desired,
                    Approval {
                        id: format!("approve-{name}").try_into().unwrap(),
                        request_digest,
                    },
                )
                .unwrap();
            let outcome = apply_lifecycle(&mut fixture.host, endpoint.clone(), &operation).unwrap();
            assert_eq!(outcome.guardian_operation.delivery, expected);
        }
        let inspection = GuardianClient::new(endpoint)
            .inspect(fixture.machine.clone(), None)
            .unwrap();
        assert!(matches!(
            inspection.observation,
            Observation::Current {
                value: MachineObservation {
                    state: MachineState::Stopped,
                    ..
                }
            }
        ));
    }
}

#[test]
fn management_failure_preserves_native_running_state_and_last_report() {
    let fixture = Fixture::new();
    let endpoint = fixture.root.0.join("endpoint");
    sandsurf_native::local::ensure_private_directory(&endpoint).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "guardian_process_fixture", "--test-threads=1"])
        .env("SANDSURF_GUARDIAN_TEST_ROOT", &fixture.root.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _child = ChildGuard(child);
    drop(wait_for_guardian(&endpoint));
    let client = GuardianClient::new(endpoint);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(
            client
                .inspect(fixture.machine.clone(), None)
                .unwrap()
                .management,
            Observation::Current { .. }
        ) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "guest management report never became available"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::write(fixture.root.0.join("management-down"), []).unwrap();
    loop {
        let inspection = client.inspect(fixture.machine.clone(), None).unwrap();
        assert!(matches!(
            inspection.observation,
            Observation::Current {
                value: MachineObservation {
                    state: MachineState::Running,
                    ..
                }
            }
        ));
        if let Observation::Unavailable {
            last_known: Some(report),
        } = inspection.management
        {
            assert_eq!(report.identity.boot_id.as_str(), "fixture-boot");
            assert_eq!(report.generation, Counter::ONE);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "failed guest management stayed current"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_guardian(endpoint: &Path) -> LocalConnection {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match LocalConnection::connect(endpoint, Duration::from_millis(100)) {
            Ok(connection) => return connection,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("timed out waiting for guardian at {endpoint:?}: {error}"),
        }
    }
}
