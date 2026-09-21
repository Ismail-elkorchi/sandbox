#![cfg(unix)]

use sandsurf_protocol::*;
use sandsurf_state::*;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct TempRoot(PathBuf);
impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sandsurf-authority-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
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
        memory_mib: n(4096),
        disk_bytes: n(100_000),
        output_bytes: n(1000),
        processes: n(8),
    }
}
fn catalog_limits() -> CatalogLimits {
    CatalogLimits {
        identities: n(10),
        operations: n(100),
        grants: n(100),
        usage_records: n(100),
        resources: Resources {
            vcpus: n(8),
            memory_mib: n(16384),
            disk_bytes: n(400_000),
            output_bytes: n(4000),
            processes: n(32),
        },
    }
}

#[test]
fn image_import_admission_and_publication_are_durable_and_idempotent() {
    let root = TempRoot::new();
    let path = root.0.join("host");
    let mut host =
        HostCatalog::create(&path, "image-host".try_into().unwrap(), catalog_limits()).unwrap();
    let operation: OperationId = "import-image".try_into().unwrap();
    let request = hash("exact-import-request");
    let admitted = host
        .admit_image_import(
            operation.clone(),
            request.clone(),
            Approval {
                id: "approve-image".try_into().unwrap(),
                request_digest: request.clone(),
            },
        )
        .unwrap();
    assert_eq!(admitted.phase, ImageImportPhase::Admitted);
    assert!(admitted.image.is_none());
    let image = ImageRecord {
        digest: hash("vm-native-image"),
        source_digest: hash("oci-manifest"),
        platform: "linux".into(),
        architecture: "amd64".into(),
        logical_bytes: n(4096),
        provenance_digest: hash("conversion"),
    };
    let published = host
        .complete_image_import(&operation, &request, image.clone())
        .unwrap();
    assert_eq!(published.phase, ImageImportPhase::Published);
    assert_eq!(published.image, Some(image.clone()));
    assert_eq!(host.images(None, n(10)).unwrap(), vec![image.clone()]);
    drop(host);
    let host = HostCatalog::open(&path).unwrap();
    assert_eq!(host.image(&image.digest).unwrap(), Some(image.clone()));
    assert_eq!(
        host.image_import(&operation).unwrap().unwrap().image,
        Some(image)
    );
}

#[test]
fn private_catalog_cannot_be_admitted_below_replaceable_ancestry() {
    let root = TempRoot::new();
    let catalog = root.0.join("catalog");
    drop(HostCatalog::create(&catalog, "ancestry".try_into().unwrap(), catalog_limits()).unwrap());
    let before = fs::read(catalog.join("authority.sqlite")).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
    let reopened = HostCatalog::open(&catalog);
    let fresh = root.0.join("new-catalog");
    let created = HostCatalog::create(&fresh, "new".try_into().unwrap(), catalog_limits());
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(reopened.is_err());
    assert!(created.is_err());
    assert_eq!(fs::read(catalog.join("authority.sqlite")).unwrap(), before);
    assert!(!fresh.join("writer.lock").exists());
    assert!(!fresh.join("authority.sqlite").exists());
    drop(HostCatalog::open(&catalog).unwrap());
}
fn runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        identities: n(16),
        operations: n(64),
        observations: n(1000),
        chunks: n(1000),
        pins: n(64),
        output_bytes: n(1000),
        disks: n(8),
        disk_bytes: n(1024 * 1024),
        disk_headroom_bytes: n(1024 * 1024),
    }
}

struct Fixture {
    runtime: RuntimeJournal,
    host: HostCatalog,
    root: TempRoot,
    sandbox: SandboxId,
    process: ProcessId,
    mutation: Mutation,
}
impl Fixture {
    fn new() -> Self {
        let root = TempRoot::new();
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
                epoch: n(1),
                sequence: n(1),
                state: MachineState::Creating,
                applied_revision: n(1),
                operation_id: create.clone(),
                evidence_digest: hash("owned"),
            })
            .unwrap();
        let evidence = runtime
            .observe(MachineObservation {
                sandbox_id: sandbox.clone(),
                epoch: n(1),
                sequence: n(2),
                state: MachineState::Running,
                applied_revision: n(1),
                operation_id: create,
                evidence_digest: hash("booted"),
            })
            .unwrap();
        host.complete_intent(&evidence).unwrap();
        let grant_id: GrantId = "spawn".try_into().unwrap();
        let scope = hash("workload");
        let request_digest = digest(
            Domain::Grant,
            &(&sandbox, &grant_id, n(1), Capability::Spawn, &scope, false),
        )
        .unwrap();
        host.set_grant(
            GrantChange {
                sandbox_id: sandbox.clone(),
                id: grant_id.clone(),
                expected_revision: n(1),
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
        let mut observed = evidence.value().clone();
        observed.sequence = n(3);
        observed.applied_revision = n(2);
        observed.evidence_digest = hash("installed-revision");
        runtime.observe(observed).unwrap();
        let operation_id: OperationId = "command".try_into().unwrap();
        let mutation = Mutation::new(
            sandbox.clone(),
            n(1),
            operation_id.clone(),
            grant_id,
            n(2),
            WorkloadRequest::Spawn {
                request: Box::new(SpawnRequest {
                    sandbox_id: sandbox.clone(),
                    epoch: n(1),
                    process_id: "process".try_into().unwrap(),
                    operation_id,
                    argv: vec!["/bin/true".into()],
                    cwd: "/workspace".into(),
                    environment: Default::default(),
                    user: Some("agent".into()),
                    stdio: StdioMode::Pipes,
                    terminal_size: None,
                    lifetime: ProcessLifetime::Job,
                    output_bytes: n(100),
                }),
            },
        )
        .unwrap();
        let authorization = host
            .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
            .unwrap();
        runtime.admit(authorization).unwrap();
        let process: ProcessId = "process".try_into().unwrap();
        runtime
            .admit_process(process.clone(), &mutation.operation_id, n(100), false)
            .unwrap();
        dispatch(&mut runtime, &host, &mutation);
        Self {
            runtime,
            host,
            root,
            sandbox,
            process,
            mutation,
        }
    }
    fn terminal(&mut self) -> (Receipt, Digest) {
        self.runtime
            .append_output(&self.process, n(1), Stream::Stdout, b"hello\0\xff")
            .unwrap();
        self.runtime
            .append_output(&self.process, n(2), Stream::Stderr, b"stderr")
            .unwrap();
        self.runtime
            .publish_receipt(
                &self.process,
                ProcessOutcome::Exit { code: 0 },
                hash("reaped"),
                hash("accounted"),
            )
            .unwrap()
    }
    fn capture_release(&mut self) -> ReleaseRequest {
        use std::io::Write;
        let (receipt, receipt_digest) = self.terminal();
        let page = self.runtime.read_output(&self.process, n(0), 64).unwrap();
        let mut originals = fs::File::create_new(self.root.0.join("captured.output")).unwrap();
        let mut chunks = Vec::new();
        for chunk in page.chunks {
            originals.write_all(&chunk.bytes).unwrap();
            chunks.push((
                chunk.sequence,
                chunk.offset,
                chunk.stream,
                chunk.bytes_digest,
            ));
        }
        originals.sync_all().unwrap();
        let manifest = serde_json::to_vec(&(&receipt, &receipt_digest, chunks)).unwrap();
        let mut commitment = fs::File::create_new(self.root.0.join("capture.manifest")).unwrap();
        commitment.write_all(&manifest).unwrap();
        commitment.sync_all().unwrap();
        fs::File::open(&self.root.0).unwrap().sync_all().unwrap();
        ReleaseRequest {
            receipt_digest: receipt_digest.clone(),
            output: receipt.output.clone(),
            disposition: ReleaseDisposition::CompleteCapture {
                commitment: CaptureCommitment {
                    store_id: "application-store".try_into().unwrap(),
                    commitment_id: "capture-commit".try_into().unwrap(),
                    manifest_digest: bytes_digest(&manifest),
                    receipt_digest,
                    output: receipt.output,
                },
            },
        }
    }
}

fn dispatch(runtime: &mut RuntimeJournal, host: &HostCatalog, mutation: &Mutation) {
    let authorization = host
        .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
        .unwrap();
    match runtime.begin_dispatch(authorization).unwrap() {
        DispatchDecision::Perform(permit) => permit.perform(|actual, capability| {
            assert_eq!(actual, mutation);
            assert_eq!(*capability, Capability::Spawn);
        }),
        DispatchDecision::Reconcile(_) => panic!("first dispatch unexpectedly reconciled"),
    }
}

fn rebind_mutation(value: &Mutation, identity: &str) -> Mutation {
    let operation_id: OperationId = identity.try_into().unwrap();
    let mut request = value.request.clone();
    if let WorkloadRequest::Spawn { request } = &mut request {
        request.operation_id = operation_id.clone();
        request.process_id = identity.try_into().unwrap();
    }
    Mutation::new(
        value.sandbox_id.clone(),
        value.epoch,
        operation_id,
        value.grant_id.clone(),
        value.expected_revision,
        request,
    )
    .unwrap()
}

fn process_mutation(
    value: &Mutation,
    identity: &str,
    output_bytes: Counter,
    stdio: StdioMode,
) -> Mutation {
    let rebound = rebind_mutation(value, identity);
    let mut request = rebound.request.clone();
    let WorkloadRequest::Spawn { request: spawn } = &mut request else {
        panic!("fixture mutation is not a spawn");
    };
    spawn.output_bytes = output_bytes;
    spawn.stdio = stdio;
    spawn.terminal_size = (stdio == StdioMode::Terminal).then_some(TerminalSize {
        columns: 80,
        rows: 24,
        pixel_width: 0,
        pixel_height: 0,
    });
    Mutation::new(
        rebound.sandbox_id,
        rebound.epoch,
        rebound.operation_id,
        rebound.grant_id,
        rebound.expected_revision,
        request,
    )
    .unwrap()
}

#[test]
fn dispatch_permission_is_single_use_and_reopen_does_not_replay() {
    let mut f = Fixture::new();
    let mutation = rebind_mutation(&f.mutation, "once");
    let authorize = || {
        f.host
            .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
            .unwrap()
    };
    f.runtime.admit(authorize()).unwrap();
    let mut effects = 0;
    match f.runtime.begin_dispatch(authorize()).unwrap() {
        DispatchDecision::Perform(permit) => permit.perform(|_, _| effects += 1),
        DispatchDecision::Reconcile(_) => panic!("first dispatch must be new"),
    }
    assert_eq!(effects, 1);
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut reopened = RuntimeJournal::open(&path, &f.sandbox).unwrap();
    match reopened.begin_dispatch(authorize()).unwrap() {
        DispatchDecision::Perform(_) => panic!("dispatched operation cannot execute twice"),
        DispatchDecision::Reconcile(old) => assert_eq!(old.delivery, Delivery::Dispatched),
    }
    reopened
        .record_delivery(
            &mutation.operation_id,
            &mutation.request_digest,
            Delivery::Unknown,
            None,
        )
        .unwrap();
    assert!(matches!(
        reopened.begin_dispatch(authorize()).unwrap(),
        DispatchDecision::Reconcile(Operation {
            delivery: Delivery::Unknown,
            ..
        })
    ));
}

#[test]
fn host_signed_authority_survives_api_restart_and_rejects_tampering() {
    let mut f = Fixture::new();
    let mutation = rebind_mutation(&f.mutation, "signed-across-restart");
    let authorized = f
        .host
        .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
        .unwrap();

    let mut changed_scope = authorized.clone();
    changed_scope.statement.scope_digest = hash("broader-scope");
    assert!(f.runtime.admit(changed_scope).is_err());

    let mut changed_signature = authorized.clone();
    changed_signature.signature = "0".repeat(128).try_into().unwrap();
    assert!(f.runtime.admit(changed_signature).is_err());

    let host_path = f.root.0.join("host");
    let binding = f.host.authority_binding().clone();
    drop(f.host);
    assert_eq!(f.runtime.authority_binding(), &binding);
    assert_eq!(
        f.runtime.admit(authorized).unwrap().delivery,
        Delivery::Admitted
    );

    let host = HostCatalog::open(&host_path).unwrap();
    assert_eq!(host.authority_binding(), &binding);
    let after_restart = rebind_mutation(&mutation, "signed-after-restart");
    let authorized = host
        .authorize(after_restart, Capability::Spawn, &hash("workload"))
        .unwrap();
    assert_eq!(
        f.runtime.admit(authorized).unwrap().delivery,
        Delivery::Admitted
    );
}

#[test]
fn dropped_dispatch_permission_preserves_uncertainty_instead_of_retrying() {
    let mut f = Fixture::new();
    let mutation = rebind_mutation(&f.mutation, "interrupted-native-dispatch");
    f.runtime
        .admit(
            f.host
                .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
                .unwrap(),
        )
        .unwrap();
    // The durable dispatch commit can precede a crash before any native effect.
    drop(
        f.runtime
            .begin_dispatch(
                f.host
                    .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
                    .unwrap(),
            )
            .unwrap(),
    );
    assert_eq!(
        f.runtime
            .operation(&mutation.operation_id)
            .unwrap()
            .unwrap()
            .delivery,
        Delivery::Dispatched
    );
    assert!(matches!(
        f.runtime
            .begin_dispatch(
                f.host
                    .authorize(mutation, Capability::Spawn, &hash("workload"))
                    .unwrap()
            )
            .unwrap(),
        DispatchDecision::Reconcile(_)
    ));
}

#[test]
fn admitted_work_does_not_bypass_a_later_machine_barrier() {
    let mut f = Fixture::new();
    let mutation = rebind_mutation(&f.mutation, "queued");
    f.runtime
        .admit(
            f.host
                .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
                .unwrap(),
        )
        .unwrap();
    let mut observation = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    observation.sequence = n(4);
    observation.state = MachineState::Paused;
    f.runtime.observe(observation).unwrap();
    assert!(
        f.runtime
            .begin_dispatch(
                f.host
                    .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
                    .unwrap()
            )
            .is_err()
    );
    assert_eq!(
        f.runtime
            .operation(&mutation.operation_id)
            .unwrap()
            .unwrap()
            .delivery,
        Delivery::Admitted
    );
}

#[test]
fn system_ancestor_aliases_do_not_disable_final_component_protection() {
    use std::os::unix::fs::symlink;
    let root = TempRoot::new();
    let real_parent = root.0.join("real-parent");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&real_parent)
        .unwrap();
    let alias = root.0.join("system-alias");
    symlink(&real_parent, &alias).unwrap();
    let path = alias.join("host");
    let host =
        HostCatalog::create(&path, "alias-host".try_into().unwrap(), catalog_limits()).unwrap();
    assert!(HostCatalog::open(&real_parent.join("host")).is_err());
    drop(host);
    let host = HostCatalog::open(&path).unwrap();
    assert_eq!(host.host_id().as_str(), "alias-host");
    drop(host);
    let final_alias = root.0.join("forbidden-state-alias");
    symlink(real_parent.join("host"), &final_alias).unwrap();
    assert!(HostCatalog::open(&final_alias).is_err());
    let database = path.join("authority.sqlite");
    fs::rename(&database, path.join("real.sqlite")).unwrap();
    symlink(path.join("real.sqlite"), &database).unwrap();
    assert!(HostCatalog::open(&path).is_err());
}

#[test]
fn exclusive_writers_and_role_separation() {
    let fixture = Fixture::new();
    assert!(HostCatalog::open(&fixture.root.0.join("host")).is_err());
    assert!(RuntimeJournal::open(&fixture.root.0.join("runtime"), &fixture.sandbox).is_err());
    let path = fixture.root.0.join("host");
    drop(fixture.host);
    assert!(RuntimeJournal::open(&path, &fixture.sandbox).is_err());
    assert_eq!(HostCatalog::open(&path).unwrap().host_id().as_str(), "host");
}

#[test]
fn stop_intent_is_not_stopped_observation() {
    let mut f = Fixture::new();
    let operation: OperationId = "stop".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&f.sandbox, &operation, n(2), DesiredState::Stopped),
    )
    .unwrap();
    let intent = f
        .host
        .request_lifecycle(
            &f.sandbox,
            operation.clone(),
            n(2),
            DesiredState::Stopped,
            Approval {
                id: "approve-stop".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    assert_eq!(intent.completion, None);
    let authorization = f.host.authorize_lifecycle(&operation).unwrap();
    assert_eq!(
        f.runtime
            .admit_lifecycle(authorization.clone())
            .unwrap()
            .delivery,
        Delivery::Admitted
    );
    match f.runtime.begin_lifecycle(authorization).unwrap() {
        LifecycleDecision::Perform(permit) => permit.perform(|command| {
            assert_eq!(command.operation_id, operation);
            assert_eq!(command.desired, DesiredState::Stopped);
        }),
        LifecycleDecision::Reconcile(_) => panic!("first lifecycle dispatch must be new"),
    }
    let mut fresh = f.mutation.clone();
    fresh.expected_revision = n(3);
    assert!(
        f.host
            .authorize(fresh, Capability::Spawn, &hash("workload"))
            .is_err()
    );
    let old = f.runtime.last_observation().unwrap().unwrap();
    assert_eq!(old.value().state, MachineState::Running);
    let mut observation = old.value().clone();
    observation.sequence = n(4);
    observation.applied_revision = n(3);
    observation.operation_id = operation.clone();
    let evidence = f.runtime.observe(observation.clone()).unwrap();
    assert!(f.host.complete_intent(&evidence).is_err());
    observation.sequence = n(5);
    observation.state = MachineState::Stopped;
    let evidence = f.runtime.observe(observation).unwrap();
    let reference = evidence.reference().unwrap();
    let lifecycle = f
        .runtime
        .record_lifecycle_delivery(
            &operation,
            &intent.request_digest,
            Delivery::Applied,
            Some(hash("native-stop")),
            Some(reference),
        )
        .unwrap();
    assert_eq!(lifecycle.delivery, Delivery::Applied);
    assert!(
        f.host
            .complete_lifecycle_operation(&lifecycle, evidence.value())
            .unwrap()
            .completion
            .is_some()
    );
    assert_eq!(
        f.host.intent(&operation).unwrap().unwrap().desired,
        DesiredState::Stopped
    );
}

#[test]
fn interrupted_lifecycle_dispatch_is_reconciled_without_replay() {
    let mut f = Fixture::new();
    let operation: OperationId = "pause-with-lost-response".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&f.sandbox, &operation, n(2), DesiredState::Paused),
    )
    .unwrap();
    f.host
        .request_lifecycle(
            &f.sandbox,
            operation.clone(),
            n(2),
            DesiredState::Paused,
            Approval {
                id: "approve-pause".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    let authorization = f.host.authorize_lifecycle(&operation).unwrap();
    f.runtime.admit_lifecycle(authorization.clone()).unwrap();
    drop(f.runtime.begin_lifecycle(authorization.clone()).unwrap());
    assert!(matches!(
        f.runtime.begin_lifecycle(authorization).unwrap(),
        LifecycleDecision::Reconcile(LifecycleOperation {
            delivery: Delivery::Dispatched,
            ..
        })
    ));

    let mut tampered = f.host.authorize_lifecycle(&operation).unwrap();
    tampered.statement.command.desired = DesiredState::Destroyed;
    assert!(f.runtime.admit_lifecycle(tampered).is_err());
}

#[test]
fn revoked_grants_and_stale_revisions_cannot_authorize() {
    let mut f = Fixture::new();
    let scope = hash("workload");
    let request_digest = digest(
        Domain::Grant,
        &(
            &f.sandbox,
            &f.mutation.grant_id,
            n(2),
            Capability::Spawn,
            &scope,
            true,
        ),
    )
    .unwrap();
    f.host
        .set_grant(
            GrantChange {
                sandbox_id: f.sandbox.clone(),
                id: f.mutation.grant_id.clone(),
                expected_revision: n(2),
                capability: Capability::Spawn,
                scope_digest: scope.clone(),
                revoked: true,
            },
            Approval {
                id: "revoke".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    assert!(
        f.host
            .authorize(f.mutation.clone(), Capability::Spawn, &scope)
            .is_err()
    );
    f.mutation.expected_revision = n(3);
    assert!(
        f.host
            .authorize(f.mutation.clone(), Capability::Spawn, &scope)
            .is_err()
    );
    let request_digest = digest(
        Domain::Grant,
        &(
            &f.sandbox,
            &f.mutation.grant_id,
            n(3),
            Capability::Spawn,
            &scope,
            false,
        ),
    )
    .unwrap();
    assert!(
        f.host
            .set_grant(
                GrantChange {
                    sandbox_id: f.sandbox.clone(),
                    id: f.mutation.grant_id.clone(),
                    expected_revision: n(3),
                    capability: Capability::Spawn,
                    scope_digest: scope,
                    revoked: false
                },
                Approval {
                    id: "revive".try_into().unwrap(),
                    request_digest
                }
            )
            .is_err()
    );
}

#[test]
fn unknown_dispatch_is_not_replayed_on_reconnect() {
    let mut f = Fixture::new();
    f.runtime
        .record_delivery(
            &f.mutation.operation_id,
            &f.mutation.request_digest,
            Delivery::Unknown,
            None,
        )
        .unwrap();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut runtime = RuntimeJournal::open(&path, &f.sandbox).unwrap();
    let authorization = f
        .host
        .authorize(f.mutation.clone(), Capability::Spawn, &hash("workload"))
        .unwrap();
    assert_eq!(
        runtime.admit(authorization).unwrap().delivery,
        Delivery::Unknown
    );
    assert!(
        runtime
            .record_delivery(
                &f.mutation.operation_id,
                &f.mutation.request_digest,
                Delivery::Dispatched,
                None
            )
            .is_err()
    );
    assert!(
        runtime
            .record_delivery(
                &f.mutation.operation_id,
                &f.mutation.request_digest,
                Delivery::Applied,
                None
            )
            .is_err()
    );
    runtime
        .record_delivery(
            &f.mutation.operation_id,
            &f.mutation.request_digest,
            Delivery::Applied,
            Some(hash("guest-completion")),
        )
        .unwrap();
}

#[test]
fn admission_reservations_are_transactional_and_no_eviction_occurs() {
    let mut f = Fixture::new();
    let sandbox: SandboxId = "over-budget".try_into().unwrap();
    let operation: OperationId = "over-budget".try_into().unwrap();
    let mut resources = resources();
    resources.vcpus = n(8);
    let image = hash("image");
    let request_digest =
        digest(Domain::Sandbox, &(&sandbox, &image, &resources, &operation)).unwrap();
    assert!(
        f.host
            .create_sandbox(
                sandbox,
                image,
                resources,
                operation.clone(),
                Approval {
                    id: "approve-too-large".try_into().unwrap(),
                    request_digest
                }
            )
            .is_err()
    );
    assert!(f.host.intent(&operation).unwrap().is_none());
    f.runtime
        .append_output(&f.process, n(1), Stream::Stdout, &[4; 100])
        .unwrap();
    assert!(
        f.runtime
            .append_output(&f.process, n(2), Stream::Stdout, b"overflow")
            .is_err()
    );
    assert_eq!(
        f.runtime.read_output(&f.process, n(0), 256).unwrap().chunks[0].bytes,
        vec![4; 100]
    );
}

#[test]
fn acknowledgement_and_disconnect_never_release_bytes() {
    let mut f = Fixture::new();
    let (receipt, identity) = f.terminal();
    f.runtime
        .acknowledge_receipt(&f.process, &identity)
        .unwrap();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let runtime = RuntimeJournal::open(&path, &f.sandbox).unwrap();
    assert_eq!(
        runtime.receipt(&f.process).unwrap(),
        Some((receipt, identity))
    );
    assert_eq!(
        runtime.read_output(&f.process, n(0), 256).unwrap().cursor,
        n(13)
    );
}

#[test]
fn original_binary_bytes_are_incremental_and_sequence_retries_are_idempotent() {
    let mut f = Fixture::new();
    f.terminal();
    assert!(
        f.runtime
            .append_output(&f.process, n(1), Stream::Stdout, b"wrong")
            .is_err()
    );
    let mut cursor = n(0);
    let mut bytes = Vec::new();
    let mut streams = Vec::new();
    while cursor < n(13) {
        let page = f.runtime.read_output(&f.process, cursor, 2).unwrap();
        assert!(page.cursor > cursor);
        for chunk in page.chunks {
            bytes.extend_from_slice(&chunk.bytes);
            streams.push(chunk.stream);
        }
        cursor = page.cursor;
    }
    assert_eq!(bytes, b"hello\0\xffstderr");
    assert!(streams.contains(&Stream::Stdout));
    assert!(streams.contains(&Stream::Stderr));
    assert!(f.runtime.read_output(&f.process, n(14), 2).is_err());
    assert!(
        f.runtime
            .read_output(&f.process, n(0), MAX_CONTROL_BYTES + 1)
            .is_err()
    );
    assert!(
        f.runtime
            .read_output(&f.process, n(13), 2)
            .unwrap()
            .chunks
            .is_empty()
    );
}

#[test]
fn incomplete_capture_wrong_hash_and_unbacked_reference_cannot_release() {
    let mut f = Fixture::new();
    let request = f.capture_release();
    let mut incomplete = request.clone();
    incomplete.output.final_cursor = n(1);
    assert!(f.runtime.release(&f.process, incomplete).is_err());
    let mut incomplete = request.clone();
    if let ReleaseDisposition::CompleteCapture { commitment } = &mut incomplete.disposition {
        commitment.output.stderr_bytes = n(0);
    }
    assert!(f.runtime.release(&f.process, incomplete).is_err());
    let mut reference = request.clone();
    reference.disposition = ReleaseDisposition::ContinuingRetention {
        pin: "url-is-not-retention".try_into().unwrap(),
    };
    assert!(f.runtime.release(&f.process, reference).is_err());
    let mut wrong = request.clone();
    wrong.receipt_digest = hash("wrong-receipt");
    assert!(f.runtime.release(&f.process, wrong).is_err());
    let mut loss = request;
    loss.disposition = ReleaseDisposition::AuthorizedLoss {
        authorization: "not-approved".try_into().unwrap(),
    };
    assert!(f.runtime.release(&f.process, loss).is_err());
    assert_eq!(
        f.runtime.read_output(&f.process, n(0), 64).unwrap().cursor,
        n(13)
    );
}

#[test]
fn retirement_precedes_cleanup_and_recovery_keeps_identity() {
    let mut f = Fixture::new();
    let request = f.capture_release();
    let status = f.runtime.release(&f.process, request.clone()).unwrap();
    assert!(status.cleanup_pending);
    assert!(f.root.0.join("runtime/process.output").exists());
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut runtime = RuntimeJournal::open(&path, &f.sandbox).unwrap();
    assert_eq!(
        runtime.release(&f.process, request.clone()).unwrap(),
        status
    );
    let cleaned = runtime
        .cleanup_released(&f.process, &status.request_digest)
        .unwrap();
    assert!(!cleaned.cleanup_pending);
    assert!(!path.join("process.output").exists());
    assert_eq!(
        fs::read(f.root.0.join("captured.output")).unwrap(),
        b"hello\0\xffstderr"
    );
    assert_eq!(
        runtime
            .cleanup_released(&f.process, &status.request_digest)
            .unwrap(),
        cleaned
    );
    assert!(runtime.read_output(&f.process, n(0), 64).is_err());
    assert!(runtime.receipt(&f.process).unwrap().is_some());
    let mut conflict = request;
    conflict.disposition = ReleaseDisposition::AuthorizedLoss {
        authorization: "changed".try_into().unwrap(),
    };
    assert!(runtime.release(&f.process, conflict).is_err());
    let authorization = f
        .host
        .authorize(f.mutation.clone(), Capability::Spawn, &hash("workload"))
        .unwrap();
    assert_eq!(
        runtime.admit(authorization).unwrap().delivery,
        Delivery::Applied
    );
    assert!(
        runtime
            .admit_process(f.process, &f.mutation.operation_id, n(100), false)
            .is_err()
    );
}

#[test]
fn continuing_retention_keeps_actual_originals_after_source_release() {
    let mut f = Fixture::new();
    let mut request = f.capture_release();
    let pin: PinId = "archive-owner".try_into().unwrap();
    f.runtime
        .pin(&f.process, &request.receipt_digest, pin.clone())
        .unwrap();
    request.disposition = ReleaseDisposition::ContinuingRetention { pin: pin.clone() };
    let status = f.runtime.release(&f.process, request).unwrap();
    f.runtime
        .cleanup_released(&f.process, &status.request_digest)
        .unwrap();
    assert!(f.root.0.join("runtime/process.output").exists());
    assert!(f.runtime.read_output(&f.process, n(0), 64).is_err());
    assert_eq!(f.runtime.read_pin(&pin, n(0), 64).unwrap().cursor, n(13));
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    assert_eq!(
        RuntimeJournal::open(&path, &f.sandbox)
            .unwrap()
            .read_pin(&pin, n(0), 64)
            .unwrap()
            .cursor,
        n(13)
    );
}

#[test]
fn explicit_loss_is_exactly_scoped_and_recorded() {
    let mut f = Fixture::new();
    let mut request = f.capture_release();
    let authorization: CommitmentId = "loss-approved".try_into().unwrap();
    let approval = Approval {
        id: authorization.clone(),
        request_digest: digest(
            Domain::Release,
            &(
                &f.sandbox,
                &f.process,
                &request.receipt_digest,
                &request.output,
                "loss",
            ),
        )
        .unwrap(),
    };
    let authorized = f
        .host
        .authorize_output_loss(
            &f.sandbox,
            &f.process,
            &request.receipt_digest,
            &request.output,
            approval,
        )
        .unwrap();
    let mut incomplete = authorized.clone();
    incomplete.statement.output.final_cursor = n(1);
    assert!(f.runtime.record_loss_authorization(incomplete).is_err());
    f.runtime.record_loss_authorization(authorized).unwrap();
    request.disposition = ReleaseDisposition::AuthorizedLoss { authorization };
    let status = f.runtime.release(&f.process, request.clone()).unwrap();
    f.runtime
        .cleanup_released(&f.process, &status.request_digest)
        .unwrap();
    assert!(
        !f.runtime
            .release(&f.process, request)
            .unwrap()
            .cleanup_pending
    );
}

#[test]
fn corrupt_output_does_not_rewrite_terminal_truth_or_support_new_pin() {
    let mut f = Fixture::new();
    let receipt = f.terminal();
    fs::write(f.root.0.join("runtime/process.output"), b"corrupt bytes").unwrap();
    assert_eq!(
        f.runtime.receipt(&f.process).unwrap(),
        Some(receipt.clone())
    );
    assert!(f.runtime.read_output(&f.process, n(0), 64).is_err());
    assert!(
        f.runtime
            .append_output(&f.process, n(1), Stream::Stdout, b"hello\0\xff")
            .is_err()
    );
    assert!(
        f.runtime
            .pin(&f.process, &receipt.1, "bad-pin".try_into().unwrap())
            .is_err()
    );
}

#[test]
fn stream_label_corruption_is_detected() {
    let mut f = Fixture::new();
    let receipt = f.terminal();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let db = rusqlite::Connection::open(path.join("authority.sqlite")).unwrap();
    db.execute("UPDATE chunks SET stream='\"stderr\"' WHERE sequence=1", [])
        .unwrap();
    drop(db);
    let runtime = RuntimeJournal::open(&path, &f.sandbox).unwrap();
    assert_eq!(runtime.receipt(&f.process).unwrap(), Some(receipt));
    assert!(runtime.read_output(&f.process, n(0), 64).is_err());
}

#[test]
fn uncommitted_output_tail_is_not_exposed_and_is_reconciled_before_append() {
    use std::io::Write;
    let mut f = Fixture::new();
    f.runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"committed")
        .unwrap();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(path.join("process.output"))
        .unwrap();
    file.write_all(b"uncommitted").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut runtime = RuntimeJournal::open(&path, &f.sandbox).unwrap();
    assert_eq!(
        runtime.read_output(&f.process, n(0), 64).unwrap().cursor,
        n(9)
    );
    runtime
        .append_output(&f.process, n(2), Stream::Stderr, b"next")
        .unwrap();
    assert_eq!(
        fs::read(path.join("process.output")).unwrap(),
        b"committednext"
    );
}

#[test]
fn usage_is_monotonic_and_duplicate_delivery_does_not_double_charge() {
    let mut f = Fixture::new();
    let id: OperationId = "usage-1".try_into().unwrap();
    f.host.account(&id, &f.sandbox, n(10), n(20)).unwrap();
    f.host.account(&id, &f.sandbox, n(10), n(20)).unwrap();
    assert!(f.host.account(&id, &f.sandbox, n(11), n(20)).is_err());
    assert_eq!(f.host.usage(&f.sandbox).unwrap(), (n(10), n(20)));
}

#[test]
fn missing_catalog_symlinks_and_foreign_permissions_are_refused_intact() {
    let f = Fixture::new();
    let path = f.root.0.join("host");
    drop(f.host);
    fs::rename(path.join("authority.sqlite"), path.join("evidence.sqlite")).unwrap();
    assert!(HostCatalog::open(&path).is_err());
    assert!(!path.join("authority.sqlite").exists());
    std::os::unix::fs::symlink(path.join("evidence.sqlite"), path.join("authority.sqlite"))
        .unwrap();
    assert!(HostCatalog::open(&path).is_err());
    assert!(path.join("evidence.sqlite").exists());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(HostCatalog::open(&path).is_err());
}

#[test]
fn historical_intent_references_resolve_after_new_observations() {
    let f = Fixture::new();
    let create: OperationId = "create".try_into().unwrap();
    let reference = f.host.intent(&create).unwrap().unwrap().completion.unwrap();
    let historical = f.runtime.observation_at(&reference).unwrap();
    assert_eq!(historical.value().sequence, n(2));
    assert_eq!(
        f.runtime
            .last_observation()
            .unwrap()
            .unwrap()
            .value()
            .sequence,
        n(3)
    );
}

#[test]
fn catalog_listing_keeps_intent_separate_and_releases_only_after_destroy_observation() {
    let mut f = Fixture::new();
    let record = f.host.sandbox(&f.sandbox).unwrap().unwrap();
    assert_eq!(record.id, f.sandbox);
    assert_eq!(record.configuration_revision, n(2));
    assert_eq!(record.reservation, ReservationState::Held);
    assert_eq!(record.latest_intent.desired, DesiredState::Running);
    assert_eq!(f.host.sandboxes(None, n(10)).unwrap(), vec![record]);
    assert!(f.host.sandboxes(None, Counter::ZERO).is_err());
    assert!(f.host.sandboxes(None, n(257)).is_err());

    let operation: OperationId = "destroy-machine".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&f.sandbox, &operation, n(2), DesiredState::Destroyed),
    )
    .unwrap();
    f.host
        .request_lifecycle(
            &f.sandbox,
            operation.clone(),
            n(2),
            DesiredState::Destroyed,
            Approval {
                id: "approve-destroy".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    let pending = f.host.sandbox(&f.sandbox).unwrap().unwrap();
    assert_eq!(pending.reservation, ReservationState::Held);
    assert_eq!(pending.latest_intent.desired, DesiredState::Destroyed);
    assert_eq!(pending.latest_intent.completion, None);

    let mut observation = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    observation.sequence = n(4);
    observation.state = MachineState::Destroying;
    observation.applied_revision = n(3);
    observation.operation_id = operation.clone();
    observation.evidence_digest = hash("destroying");
    f.runtime.observe(observation.clone()).unwrap();
    assert_eq!(
        f.host.sandbox(&f.sandbox).unwrap().unwrap().reservation,
        ReservationState::Held
    );
    observation.sequence = n(5);
    observation.state = MachineState::Destroyed;
    observation.evidence_digest = hash("runtime-and-disks-cleaned");
    let destroyed = f.runtime.observe(observation).unwrap();
    f.host.complete_intent(&destroyed).unwrap();
    let retired = f.host.sandbox(&f.sandbox).unwrap().unwrap();
    assert_eq!(retired.reservation, ReservationState::Released);
    assert!(retired.latest_intent.completion.is_some());
    assert!(f.host.revision(&f.sandbox).is_err());
}

#[test]
fn machine_restart_fences_old_epoch_without_rewinding_history() {
    let mut f = Fixture::new();
    let mut value = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    value.sequence = n(4);
    value.state = MachineState::Stopped;
    f.runtime.observe(value.clone()).unwrap();
    value.sequence = n(5);
    value.state = MachineState::Running;
    assert!(f.runtime.observe(value.clone()).is_err());
    value.state = MachineState::Starting;
    value.epoch = n(2);
    f.runtime.observe(value.clone()).unwrap();
    value.sequence = n(6);
    value.state = MachineState::Running;
    f.runtime.observe(value).unwrap();
    let stale = rebind_mutation(&f.mutation, "stale-after-boot");
    let authorization = f
        .host
        .authorize(stale, Capability::Spawn, &hash("workload"))
        .unwrap();
    assert!(f.runtime.admit(authorization).is_err());
}

#[test]
fn independent_jobs_and_pty_streams_have_separate_reservations() {
    let mut f = Fixture::new();
    let mutation = process_mutation(&f.mutation, "terminal", n(200), StdioMode::Terminal);
    let authorization = f
        .host
        .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
        .unwrap();
    f.runtime.admit(authorization).unwrap();
    let terminal: ProcessId = "terminal".try_into().unwrap();
    f.runtime
        .admit_process(terminal.clone(), &mutation.operation_id, n(200), true)
        .unwrap();
    dispatch(&mut f.runtime, &f.host, &mutation);
    assert!(
        f.runtime
            .append_output(&terminal, n(1), Stream::Stdout, b"wrong stream")
            .is_err()
    );
    f.runtime
        .append_output(&terminal, n(1), Stream::Terminal, b"shell prompt")
        .unwrap();
    f.terminal();
    f.runtime
        .append_output(&terminal, n(2), Stream::Terminal, b"still running")
        .unwrap();
    assert!(f.runtime.receipt(&terminal).unwrap().is_none());
}

// Invoked only by the parent test with its newly allocated private fixture directory.
#[test]
fn abrupt_writer_child() {
    let Some(root) = std::env::var_os("SANDSURF_TEST_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let sandbox: SandboxId = "box".try_into().unwrap();
    let process: ProcessId = "process".try_into().unwrap();
    let mode = std::env::var("SANDSURF_TEST_CRASH_MODE").unwrap();
    let mut runtime = RuntimeJournal::open(&root.join("runtime"), &sandbox).unwrap();
    match mode.as_str() {
        "after-output" => {
            runtime
                .append_output(&process, n(1), Stream::Stdout, b"durable-before-exit")
                .unwrap();
        }
        "after-retirement" => {
            let request: ReleaseRequest =
                serde_json::from_slice(&fs::read(root.join("release-request.json")).unwrap())
                    .unwrap();
            runtime.release(&process, request).unwrap();
        }
        "after-deletion" => {
            let request: ReleaseRequest =
                serde_json::from_slice(&fs::read(root.join("release-request.json")).unwrap())
                    .unwrap();
            runtime.release(&process, request).unwrap();
            // Crash after physical unlink, before committing cleanup completion.
            fs::remove_file(root.join("runtime/process.output")).unwrap();
            fs::File::open(root.join("runtime"))
                .unwrap()
                .sync_all()
                .unwrap();
        }
        _ => panic!("unexpected crash case"),
    }
    // No Rust destructors, journal close, or cooperative shutdown.
    std::process::exit(73);
}

#[test]
fn abrupt_process_exit_preserves_committed_output_and_interrupted_release() {
    for mode in ["after-output", "after-retirement", "after-deletion"] {
        let mut f = Fixture::new();
        let release = if mode == "after-output" {
            None
        } else {
            Some(f.capture_release())
        };
        if let Some(request) = &release {
            fs::write(
                f.root.0.join("release-request.json"),
                serde_json::to_vec(request).unwrap(),
            )
            .unwrap();
        }
        let path = f.root.0.join("runtime");
        drop(f.runtime);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "abrupt_writer_child", "--nocapture"])
            .env("SANDSURF_TEST_CRASH_ROOT", &f.root.0)
            .env("SANDSURF_TEST_CRASH_MODE", mode)
            .output()
            .unwrap();
        assert_eq!(
            status.status.code(),
            Some(73),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let mut runtime = RuntimeJournal::open(&path, &f.sandbox).unwrap();
        if let Some(request) = release {
            let status = runtime.release(&f.process, request).unwrap();
            assert!(status.cleanup_pending);
            runtime
                .cleanup_released(&f.process, &status.request_digest)
                .unwrap();
            assert!(!path.join("process.output").exists());
            assert_eq!(
                fs::read(f.root.0.join("captured.output")).unwrap(),
                b"hello\0\xffstderr"
            );
        } else {
            assert_eq!(
                runtime.read_output(&f.process, n(0), 64).unwrap().chunks[0].bytes,
                b"durable-before-exit"
            );
            assert_eq!(
                runtime
                    .operation(&f.mutation.operation_id)
                    .unwrap()
                    .unwrap()
                    .delivery,
                Delivery::Dispatched
            );
            assert!(runtime.receipt(&f.process).unwrap().is_none());
        }
    }
}

#[test]
fn output_pages_bound_record_count_as_well_as_original_bytes() {
    let mut f = Fixture::new();
    let mutation = process_mutation(&f.mutation, "many-chunks", n(400), StdioMode::Pipes);
    let authorization = f
        .host
        .authorize(mutation.clone(), Capability::Spawn, &hash("workload"))
        .unwrap();
    f.runtime.admit(authorization).unwrap();
    let process: ProcessId = "many-chunks".try_into().unwrap();
    f.runtime
        .admit_process(process.clone(), &mutation.operation_id, n(400), false)
        .unwrap();
    dispatch(&mut f.runtime, &f.host, &mutation);
    for sequence in 1..=300 {
        f.runtime
            .append_output(&process, n(sequence), Stream::Stdout, b"x")
            .unwrap();
    }
    let first = f
        .runtime
        .read_output(&process, n(0), MAX_CONTROL_BYTES)
        .unwrap();
    assert_eq!(first.chunks.len(), 256);
    assert_eq!(first.cursor, n(256));
    let second = f
        .runtime
        .read_output(&process, first.cursor, MAX_CONTROL_BYTES)
        .unwrap();
    assert_eq!(second.chunks.len(), 44);
    assert_eq!(second.cursor, n(300));
}

#[test]
fn malformed_output_index_is_unavailable_without_panicking_or_erasing_receipt() {
    for corruption in [
        "UPDATE chunks SET sequence=0 WHERE sequence=1",
        "UPDATE chunks SET length=0 WHERE sequence=1",
        "UPDATE processes SET boundary=json_set(boundary,'$.finalCursor',999)",
    ] {
        let mut f = Fixture::new();
        let receipt = f.terminal();
        let path = f.root.0.join("runtime");
        drop(f.runtime);
        let database = rusqlite::Connection::open(path.join("authority.sqlite")).unwrap();
        database.execute(corruption, []).unwrap();
        drop(database);
        let runtime = RuntimeJournal::open(&path, &f.sandbox).unwrap();
        assert_eq!(runtime.receipt(&f.process).unwrap(), Some(receipt));
        assert!(runtime.read_output(&f.process, n(0), 64).is_err());
    }
}
