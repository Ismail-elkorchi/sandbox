#![cfg(any(unix, windows))]

use sandsurf_control::*;
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
        processes: n(8),
    }
}
fn catalog_limits() -> CatalogLimits {
    CatalogLimits {
        identities: n(8),
        operations: n(64),
        grants: n(64),
        usage_records: n(64),
        resources: Resources {
            vcpus: n(8),
            memory_mib: n(8192),
            disk_bytes: n(400_000),
            output_bytes: n(4000),
            processes: n(32),
        },
    }
}
fn runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        identities: n(16),
        operations: n(64),
        observations: n(64),
        chunks: n(64),
        pins: n(16),
        output_bytes: n(4096),
        disks: n(8),
        disk_bytes: n(1024 * 1024),
        disk_headroom_bytes: n(1024 * 1024),
    }
}

struct Fixture {
    root: Root,
    host: HostCatalog,
    sandbox: SandboxId,
    mutation: Mutation,
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
        let sandbox: SandboxId = "box".try_into().unwrap();
        let create: OperationId = "create".try_into().unwrap();
        let image = hash("image");
        let request_digest =
            digest(Domain::Sandbox, &(&sandbox, &image, resources(), &create)).unwrap();
        host.create_sandbox(
            sandbox.clone(),
            image,
            resources(),
            create.clone(),
            Approval {
                id: "approve-create".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
        let mut runtime = RuntimeJournal::create(
            &root.0.join("runtime"),
            sandbox.clone(),
            runtime_limits(),
            host.authority_binding().clone(),
        )
        .unwrap();
        runtime
            .observe(MachineObservation {
                sandbox_id: sandbox.clone(),
                epoch: Counter::ONE,
                sequence: Counter::ONE,
                state: MachineState::Creating,
                applied_revision: Counter::ONE,
                operation_id: create.clone(),
                evidence_digest: hash("owned"),
            })
            .unwrap();
        let running = runtime
            .observe(MachineObservation {
                sandbox_id: sandbox.clone(),
                epoch: Counter::ONE,
                sequence: n(2),
                state: MachineState::Running,
                applied_revision: Counter::ONE,
                operation_id: create,
                evidence_digest: hash("booted"),
            })
            .unwrap();
        host.complete_intent(&running).unwrap();
        let scope = hash("workload");
        let grant: GrantId = "spawn".try_into().unwrap();
        let request_digest = digest(
            Domain::Grant,
            &(
                &sandbox,
                &grant,
                Counter::ONE,
                Capability::Spawn,
                &scope,
                false,
            ),
        )
        .unwrap();
        host.set_grant(
            GrantChange {
                sandbox_id: sandbox.clone(),
                id: grant.clone(),
                expected_revision: Counter::ONE,
                capability: Capability::Spawn,
                scope_digest: scope,
                revoked: false,
            },
            Approval {
                id: "approve-spawn".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
        runtime
            .observe(MachineObservation {
                sandbox_id: sandbox.clone(),
                epoch: Counter::ONE,
                sequence: n(3),
                state: MachineState::Running,
                applied_revision: n(2),
                operation_id: "install-grant".try_into().unwrap(),
                evidence_digest: hash("revision-2"),
            })
            .unwrap();
        drop(runtime);
        let mutation = Mutation {
            sandbox_id: sandbox.clone(),
            epoch: Counter::ONE,
            operation_id: "dispatch-once".try_into().unwrap(),
            grant_id: grant,
            expected_revision: n(2),
            request_digest: hash("argv-cwd-environment"),
        };
        Self {
            root,
            host,
            sandbox,
            mutation,
        }
    }
}

struct FileEffect {
    path: PathBuf,
}
impl GuardianEffect for FileEffect {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        writeln!(file, "{}:{capability:?}", mutation.operation_id.as_str()).unwrap();
        file.sync_all().unwrap();
        EffectOutcome::Applied(
            digest(
                Domain::Operation,
                &(&mutation.operation_id, &mutation.request_digest, capability),
            )
            .unwrap(),
        )
    }

    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> LifecycleEffect {
        let epoch = current.map_or(Counter::ONE, |value| value.epoch);
        let transition = |state| MachineTransition {
            epoch,
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
        LifecycleEffect::Observed(states)
    }
}

#[test]
fn guardian_process_fixture() {
    let Some(root) = std::env::var_os("SANDSURF_GUARDIAN_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let sandbox: SandboxId = "box".try_into().unwrap();
    let runtime = RuntimeJournal::open(&root.join("runtime"), &sandbox).unwrap();
    let mut guardian = Guardian::new(
        runtime,
        FileEffect {
            path: root.join("effects.log"),
        },
    );
    serve_guardian(&root.join("endpoint"), &mut guardian).unwrap();
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
    let authorization = fixture
        .host
        .authorize(
            fixture.mutation.clone(),
            Capability::Spawn,
            &hash("workload"),
        )
        .unwrap();
    let payload = serde_json::to_vec(&(
        1_u16,
        GuardianRequest::Dispatch {
            authorization: authorization.clone(),
        },
    ))
    .unwrap();
    let mut connection = wait_for_guardian(&endpoint);
    connection
        .write_frame(
            &Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: Counter::ONE,
                payload,
            },
            Duration::from_secs(2),
        )
        .unwrap();
    wait_for(&fixture.root.0.join("effects.log"));
    drop(connection); // The effect committed, but its reply is deliberately lost.

    let host_path = fixture.root.0.join("host");
    drop(fixture.host);
    let mut host = HostCatalog::open(&host_path).unwrap();
    let link = HostGuardianLink::new(&host, endpoint.clone());
    let operation = link
        .dispatch(
            fixture.mutation.clone(),
            Capability::Spawn,
            &hash("workload"),
        )
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
            fixture.sandbox.clone(),
            Some(fixture.mutation.operation_id.clone()),
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
        &(&fixture.sandbox, &pause, n(2), DesiredState::Paused),
    )
    .unwrap();
    host.request_lifecycle(
        &fixture.sandbox,
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
    let link = HostGuardianLink::new(&host, endpoint);
    let inspection = link
        .inspect(fixture.sandbox.clone(), Some(pause.clone()))
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
    assert_eq!(inspection.lifecycle_operation, Some(lifecycle));
    assert!(host.intent(&pause).unwrap().unwrap().completion.is_some());
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
