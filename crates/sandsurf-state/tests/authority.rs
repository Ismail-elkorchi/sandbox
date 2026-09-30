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
        managed_executions: n(8),
    }
}
fn catalog_limits() -> CatalogLimits {
    CatalogLimits {
        identities: n(10),
        operations: n(100),
        usage_records: n(100),
        image_bytes: n(400_000),
        resources: Resources {
            vcpus: n(8),
            memory_mib: n(16384),
            disk_bytes: n(400_000),
            output_bytes: n(4000),
            managed_executions: n(32),
        },
    }
}

#[test]
fn incompatible_state_generation_is_rejected_without_rewriting_the_catalog() {
    let root = TempRoot::new();
    let path = root.0.join("incompatible");
    let host =
        HostCatalog::create(&path, "version-test".try_into().unwrap(), catalog_limits()).unwrap();
    drop(host);
    let database = path.join("authority.sqlite");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection.execute_batch("PRAGMA user_version=9;").unwrap();
    drop(connection);
    let original = fs::read(&database).unwrap();
    assert!(matches!(HostCatalog::open(&path), Err(Error::Corrupt(_))));
    assert_eq!(fs::read(&database).unwrap(), original);
}

#[test]
fn machine_execution_defaults_is_host_owned_and_durable() {
    let root = TempRoot::new();
    let path = root.0.join("defaults-configuration-host");
    let machine: MachineId = "configured-box".try_into().unwrap();
    let operation: OperationId = "create-configured-box".try_into().unwrap();
    let image = hash("configured-image");
    let defaults = ExecutionDefaults {
        environment: std::collections::BTreeMap::from([("MODE".into(), "agent".into())]),
        user: Some("agent".into()),
        working_directory: Some("/workspace".into()),
    };
    let lifetime = MachineLifetime {
        expires_at_unix_millis: Some(n(9_000_000_000_000)),
        expiration_action: ExpirationAction::Destroy,
    };
    let request_digest = digest(
        Domain::Machine,
        &(
            &machine,
            &image,
            resources(),
            &defaults,
            &lifetime,
            &operation,
        ),
    )
    .unwrap();
    let mut host = HostCatalog::create(
        &path,
        "configured-host".try_into().unwrap(),
        catalog_limits(),
    )
    .unwrap();
    host.create_machine(
        MachineAdmission {
            id: machine.clone(),
            image,
            resources: resources(),
            defaults: defaults.clone(),
            image_defaults: ExecutionDefaults {
                environment: std::collections::BTreeMap::from([
                    ("MODE".into(), "image".into()),
                    ("IMAGE_ONLY".into(), "retained".into()),
                ]),
                user: Some("root".into()),
                working_directory: Some("/home".into()),
            },
            lifetime: lifetime.clone(),
            operation,
        },
        Approval {
            id: "approve-configured-box".try_into().unwrap(),
            request_digest,
        },
    )
    .unwrap();
    let mut expected = defaults.clone();
    expected
        .environment
        .insert("IMAGE_ONLY".into(), "retained".into());
    let created = host.machine(&machine).unwrap().unwrap();
    assert_eq!(created.execution_defaults, expected);
    assert_eq!(created.lifetime, lifetime);
    let later = created.last_activity_unix_millis.next().unwrap();
    host.observe_activity(&machine, later).unwrap();
    host.observe_activity(&machine, created.last_activity_unix_millis)
        .unwrap();
    drop(host);
    let reopened = HostCatalog::open(&path)
        .unwrap()
        .machine(&machine)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.execution_defaults, expected);
    assert_eq!(reopened.lifetime, lifetime);
    assert_eq!(reopened.last_activity_unix_millis, later);
}

#[test]
fn secret_revocation_is_host_owned_and_gates_redelivery_without_guest_cleanup() {
    let root = TempRoot::new();
    let path = root.0.join("host");
    let mut host =
        HostCatalog::create(&path, "secret-host".try_into().unwrap(), catalog_limits()).unwrap();
    let machine: MachineId = "secret-box".try_into().unwrap();
    let create: OperationId = "create-secret-box".try_into().unwrap();
    let image = hash("secret-image");
    let defaults = ExecutionDefaults::default();
    let create_digest = digest(
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
            id: machine.clone(),
            image,
            resources: resources(),
            defaults,
            image_defaults: ExecutionDefaults::default(),
            lifetime: MachineLifetime::default(),
            operation: create,
        },
        Approval {
            id: "approve-secret-box".try_into().unwrap(),
            request_digest: create_digest,
        },
    )
    .unwrap();
    let secret = SecretVersion {
        id: "credential".try_into().unwrap(),
        version: "opaque-secret-version".try_into().unwrap(),
        bytes: n(12),
    };
    let delivery = SecretDelivery {
        secret: secret.clone(),
        destination: SecretDestination::File {
            path: GuestPath::try_from("/run/credential").unwrap(),
            mode: 0o600,
        },
        lifetime: SecretLifetime::UntilRevoked,
        execution_id: None,
    };
    let delivery_digest = hash("delivery-request");
    let delivery_operation: OperationId = "deliver-credential".try_into().unwrap();
    host.admit_secret_delivery(
        SecretDeliveryRecord {
            operation_id: delivery_operation.clone(),
            machine_id: machine.clone(),
            request_digest: delivery_digest.clone(),
            delivery: delivery.clone(),
            disclosure: SecretDisclosure::NotSent,
            revocation_operation: None,
            revoked: false,
        },
        Counter::ONE,
        Approval {
            id: "approve-delivery".try_into().unwrap(),
            request_digest: delivery_digest.clone(),
        },
    )
    .unwrap();
    host.begin_secret_disclosure(&delivery_operation, &delivery_digest)
        .unwrap();
    host.complete_secret_delivery(&delivery_operation, &delivery_digest)
        .unwrap();
    assert!(!host.secret_version_revoked(&machine, &secret).unwrap());

    let revoke_operation: OperationId = "revoke-credential".try_into().unwrap();
    let revoke_digest = hash("revocation-request");
    let pending = host
        .admit_secret_revocation(
            SecretRevocationAdmission {
                machine_id: machine.clone(),
                operation_id: revoke_operation.clone(),
                expected_revision: Counter::ONE,
                secret: secret.clone(),
                terminate_recipients: true,
                request_digest: revoke_digest.clone(),
            },
            Approval {
                id: "approve-revocation".try_into().unwrap(),
                request_digest: revoke_digest.clone(),
            },
        )
        .unwrap();
    assert_eq!(pending.deliveries, vec![delivery]);
    assert!(pending.guest_cleanup_report.is_none());
    assert!(host.secret_version_revoked(&machine, &secret).unwrap());
    assert!(host.secret_deliveries(&machine).unwrap()[0].revoked);
    assert!(host.machine(&machine).unwrap().unwrap().known_sensitive);
    let evidence = SecretCleanupReport {
        files_removed: Counter::ONE,
        environment_bindings_removed: Counter::ZERO,
        recipients_terminated: Vec::new(),
        recipients_already_stopped: Vec::new(),
        residual_copies_possible: true,
        actions_reported_complete: true,
    };
    let completed = host
        .record_secret_cleanup_report(&revoke_operation, &revoke_digest, evidence.clone())
        .unwrap();
    assert_eq!(completed.guest_cleanup_report, Some(evidence));
    drop(host);

    let host = HostCatalog::open(&path).unwrap();
    assert!(host.secret_version_revoked(&machine, &secret).unwrap());
    assert_eq!(host.secret_revocations(&machine).unwrap(), vec![completed]);
}

#[test]
fn possible_disclosure_is_sticky_across_fork_clean_rollback_and_host_restart() {
    fn capture(
        host: &mut HostCatalog,
        machine: &MachineId,
        revision: Counter,
        id: &str,
    ) -> Snapshot {
        let request = SnapshotRequest {
            id: id.try_into().unwrap(),
            operation_id: format!("capture-{id}").try_into().unwrap(),
            machine_id: machine.clone(),
            expected_generation: Counter::ONE,
            expected_revision: revision,
            kind: SnapshotKind::Disk,
            parent: None,
        };
        let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request)).unwrap();
        let snapshot = host
            .admit_snapshot(
                request,
                Approval {
                    id: format!("approve-{id}").try_into().unwrap(),
                    request_digest: request_digest.clone(),
                },
            )
            .unwrap();
        host.begin_snapshot(&snapshot.request.id, &request_digest)
            .unwrap();
        host.complete_snapshot(
            &snapshot.request.id,
            &request_digest,
            hash(id),
            hash(&format!("manifest-{id}")),
            SnapshotConsistency::Crash,
        )
        .unwrap()
    }
    let mut f = Fixture::new();
    let clean = capture(&mut f.host, &f.machine, n(2), "clean");
    assert!(!clean.sensitive);
    let operation: OperationId = "ambiguous-disclosure".try_into().unwrap();
    let request = hash("ambiguous-secret-request");
    f.host
        .admit_secret_delivery(
            SecretDeliveryRecord {
                operation_id: operation.clone(),
                machine_id: f.machine.clone(),
                request_digest: request.clone(),
                delivery: SecretDelivery {
                    secret: SecretVersion {
                        id: "credential".try_into().unwrap(),
                        version: "opaque-one".try_into().unwrap(),
                        bytes: n(6),
                    },
                    destination: SecretDestination::File {
                        path: "/root/credential".try_into().unwrap(),
                        mode: 0o600,
                    },
                    lifetime: SecretLifetime::UntilRevoked,
                    execution_id: None,
                },
                disclosure: SecretDisclosure::NotSent,
                revocation_operation: None,
                revoked: false,
            },
            n(2),
            Approval {
                id: "approve-ambiguous".try_into().unwrap(),
                request_digest: request.clone(),
            },
        )
        .unwrap();
    assert!(!f.host.machine(&f.machine).unwrap().unwrap().known_sensitive);
    f.host
        .begin_secret_disclosure(&operation, &request)
        .unwrap();
    // No acknowledgement is necessary: a lost reply cannot make copies public.
    assert!(
        f.host
            .begin_secret_disclosure(&operation, &request)
            .is_err()
    );
    let sensitive = capture(&mut f.host, &f.machine, n(2), "sensitive");
    assert!(sensitive.sensitive);
    let fork: MachineId = "sensitive-fork".try_into().unwrap();
    let fork_operation: OperationId = "fork-sensitive".try_into().unwrap();
    let fork_digest = digest(
        Domain::Snapshot,
        &(
            "sandsurf-filesystem-fork-v1",
            &sensitive.request.id,
            &fork,
            resources(),
            &MachineLifetime::default(),
            &fork_operation,
        ),
    )
    .unwrap();
    f.host
        .create_machine_from_snapshot(
            fork.clone(),
            &sensitive.request.id,
            resources(),
            MachineLifetime::default(),
            fork_operation,
            Approval {
                id: "approve-sensitive-fork".try_into().unwrap(),
                request_digest: fork_digest,
            },
        )
        .unwrap();
    assert!(f.host.secret_deliveries(&fork).unwrap().is_empty());
    assert!(capture(&mut f.host, &fork, Counter::ONE, "fork-capture").sensitive);
    let rollback: OperationId = "rollback-clean".try_into().unwrap();
    let rollback_digest = digest(
        Domain::Snapshot,
        &(
            "sandsurf-filesystem-rollback-v1",
            &f.machine,
            &clean.request.id,
            &rollback,
            n(2),
        ),
    )
    .unwrap();
    f.host
        .admit_rollback(
            &f.machine,
            &clean.request.id,
            rollback.clone(),
            n(2),
            Approval {
                id: "approve-clean-rollback".try_into().unwrap(),
                request_digest: rollback_digest.clone(),
            },
        )
        .unwrap();
    f.host
        .complete_rollback(&rollback, &rollback_digest, hash("restored-clean"))
        .unwrap();
    assert!(capture(&mut f.host, &f.machine, n(2), "post-rollback").sensitive);
    drop(f.host);
    let host = HostCatalog::open(&f.root.0.join("host")).unwrap();
    assert!(host.machine(&f.machine).unwrap().unwrap().known_sensitive);
    assert!(host.machine(&fork).unwrap().unwrap().known_sensitive);
}

#[test]
fn new_machine_inherits_sensitive_image_classification() {
    let mut f = Fixture::new();
    let image_operation: OperationId = "publish-sensitive".try_into().unwrap();
    let request = hash("sensitive-image-request");
    f.host
        .admit_image_import(
            image_operation.clone(),
            request.clone(),
            Approval {
                id: "approve-sensitive-image".try_into().unwrap(),
                request_digest: request.clone(),
            },
        )
        .unwrap();
    let mut image = image("sensitive-image", 1000);
    image.sensitive = true;
    f.host
        .complete_image_import(&image_operation, &request, image.clone())
        .unwrap();
    let id: MachineId = "from-sensitive-image".try_into().unwrap();
    let operation: OperationId = "create-from-sensitive-image".try_into().unwrap();
    let defaults = ExecutionDefaults::default();
    let lifetime = MachineLifetime::default();
    let request = digest(
        Domain::Machine,
        &(
            &id,
            &image.digest,
            resources(),
            &defaults,
            &lifetime,
            &operation,
        ),
    )
    .unwrap();
    f.host
        .create_machine(
            MachineAdmission {
                id: id.clone(),
                image: image.digest,
                resources: resources(),
                defaults,
                image_defaults: ExecutionDefaults::default(),
                lifetime,
                operation,
            },
            Approval {
                id: "approve-from-sensitive-image".try_into().unwrap(),
                request_digest: request,
            },
        )
        .unwrap();
    assert!(f.host.machine(&id).unwrap().unwrap().known_sensitive);
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
        storage_bytes: n(2048),
        provenance_digest: hash("conversion"),
        sensitive: false,
    };
    let published = host
        .complete_image_import(&operation, &request, image.clone())
        .unwrap();
    assert_eq!(published.phase, ImageImportPhase::Published);
    assert_eq!(published.image, Some(image.clone()));
    assert_eq!(host.images(None, n(10)).unwrap(), vec![image.clone()]);
    drop(host);
    let mut host = HostCatalog::open(&path).unwrap();
    assert_eq!(host.image(&image.digest).unwrap(), Some(image.clone()));
    assert_eq!(
        host.image_import(&operation).unwrap().unwrap().image,
        Some(image.clone())
    );
    let release_operation: OperationId = "release-image".try_into().unwrap();
    let release_digest = digest(
        Domain::Image,
        &(
            "sandsurf-release-image-v1",
            &release_operation,
            &image.digest,
        ),
    )
    .unwrap();
    let release = host
        .release_image(
            release_operation.clone(),
            image.digest.clone(),
            Approval {
                id: "approve-release-image".try_into().unwrap(),
                request_digest: release_digest.clone(),
            },
        )
        .unwrap();
    assert!(release.cleanup_pending);
    assert!(host.image(&image.digest).unwrap().is_none());
    assert!(host.images(None, n(10)).unwrap().is_empty());
    assert_eq!(host.pending_image_releases().unwrap(), vec![release]);
    assert!(
        !host
            .complete_image_release(&release_operation, &release_digest)
            .unwrap()
            .cleanup_pending
    );
}

#[test]
fn retired_image_storage_remains_reserved_until_cleanup_completion() {
    let root = TempRoot::new();
    let path = root.0.join("host");
    let mut limits = catalog_limits();
    limits.image_bytes = n(3_000);
    let mut host =
        HostCatalog::create(&path, "image-quota-host".try_into().unwrap(), limits).unwrap();
    let first = publish_image(&mut host, "import-first", "first-image", 2_000);
    let release_operation: OperationId = "release-first".try_into().unwrap();
    let release_digest = digest(
        Domain::Image,
        &(
            "sandsurf-release-image-v1",
            &release_operation,
            &first.digest,
        ),
    )
    .unwrap();
    host.release_image(
        release_operation.clone(),
        first.digest,
        Approval {
            id: "approve-release-first".try_into().unwrap(),
            request_digest: release_digest.clone(),
        },
    )
    .unwrap();

    let second_operation: OperationId = "import-second".try_into().unwrap();
    let second_request = hash("second-request");
    host.admit_image_import(
        second_operation.clone(),
        second_request.clone(),
        Approval {
            id: "approve-second".try_into().unwrap(),
            request_digest: second_request.clone(),
        },
    )
    .unwrap();
    let second = image("second-image", 2_000);
    assert!(
        host.complete_image_import(&second_operation, &second_request, second.clone())
            .is_err()
    );

    host.complete_image_release(&release_operation, &release_digest)
        .unwrap();
    assert!(
        host.complete_image_import(&second_operation, &second_request, second)
            .is_ok()
    );
}

fn publish_image(
    host: &mut HostCatalog,
    operation: &str,
    label: &str,
    storage_bytes: u64,
) -> ImageRecord {
    let operation: OperationId = operation.try_into().unwrap();
    let request = hash(&format!("{label}-request"));
    host.admit_image_import(
        operation.clone(),
        request.clone(),
        Approval {
            id: format!("approve-{label}").try_into().unwrap(),
            request_digest: request.clone(),
        },
    )
    .unwrap();
    let image = image(label, storage_bytes);
    host.complete_image_import(&operation, &request, image.clone())
        .unwrap();
    image
}

fn image(label: &str, storage_bytes: u64) -> ImageRecord {
    ImageRecord {
        digest: hash(label),
        source_digest: hash(&format!("{label}-source")),
        platform: "linux".into(),
        architecture: "amd64".into(),
        logical_bytes: n(storage_bytes),
        storage_bytes: n(storage_bytes),
        provenance_digest: hash(&format!("{label}-provenance")),
        sensitive: false,
    }
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
        managed_executions: n(8),
        operations: n(64),
        observations: n(1000),
        events: n(4096),
        chunks: n(1000),
        output_segments: n(64),
        output_bytes: n(1000),
    }
}

struct Fixture {
    runtime: RuntimeJournal,
    host: HostCatalog,
    root: TempRoot,
    machine: MachineId,
    process: ExecutionId,
    command: GuestCommand,
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
                id: machine.clone(),
                image,
                resources: resources(),
                defaults,
                image_defaults: ExecutionDefaults::default(),
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
                generation: n(1),
                sequence: n(1),
                state: MachineState::Creating,
                applied_revision: n(1),
                cause: sandsurf_protocol::ObservationCause::Lifecycle {
                    operation_id: create.clone(),
                },
                evidence_digest: hash("owned"),
            })
            .unwrap();
        let evidence = runtime
            .observe(MachineObservation {
                machine_id: machine.clone(),
                generation: n(1),
                sequence: n(2),
                state: MachineState::Running,
                applied_revision: n(1),
                cause: sandsurf_protocol::ObservationCause::Lifecycle {
                    operation_id: create,
                },
                evidence_digest: hash("booted"),
            })
            .unwrap();
        host.complete_intent(&evidence).unwrap();
        let configuration = host
            .machine(&machine)
            .unwrap()
            .unwrap()
            .runtime_configuration;
        let request_digest = hash("fixture-configuration");
        host.set_runtime_configuration(
            &machine,
            &"configure-fixture".try_into().unwrap(),
            n(1),
            configuration,
            request_digest.clone(),
            Approval {
                id: "approve-configuration".try_into().unwrap(),
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
        let command = GuestCommand::new(
            machine.clone(),
            n(1),
            operation_id.clone(),
            GuestRequest::Spawn {
                request: Box::new(SpawnRequest {
                    machine_id: machine.clone(),
                    generation: n(1),
                    execution_id: "process".try_into().unwrap(),
                    operation_id,
                    argv: vec!["/bin/true".into()],
                    cwd: "/workspace".into(),
                    environment: Default::default(),
                    user: Some("agent".into()),
                    stdio: StdioMode::Pipes,
                    terminal_size: None,
                    active_deadline_millis: None,
                    elapsed_deadline_unix_millis: None,
                    output_bytes: n(100),
                }),
            },
        )
        .unwrap();
        let authorization = command.clone();
        runtime.admit(authorization).unwrap();
        let process: ExecutionId = "process".try_into().unwrap();
        runtime
            .admit_process(process.clone(), &command.operation_id, n(100), false)
            .unwrap();
        dispatch(&mut runtime, &command);
        Self {
            runtime,
            host,
            root,
            machine,
            process,
            command,
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
                ExecutionOutcome::Exit { code: 0 },
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
            operation_id: "release-output".try_into().unwrap(),
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

#[test]
fn runtime_events_are_digest_bound_paginated_and_replayable_after_reopen() {
    let mut fixture = Fixture::new();
    fixture.terminal();
    let mut cursor = Counter::ZERO;
    let mut values = Vec::new();
    loop {
        let page = fixture.runtime.events(cursor, 2).unwrap();
        assert!(page.cursor >= cursor);
        for event in page.events {
            assert_eq!(event.cursor, cursor.next().unwrap());
            cursor = event.cursor;
            values.push(event.value);
        }
        if cursor == page.available {
            break;
        }
    }
    assert!(
        values
            .iter()
            .any(|value| matches!(value, RuntimeEventValue::Machine { .. }))
    );
    assert!(
        values
            .iter()
            .any(|value| matches!(value, RuntimeEventValue::GuestOperation { .. }))
    );
    assert!(
        values
            .iter()
            .any(|value| matches!(value, RuntimeEventValue::Output { .. }))
    );
    assert!(
        values
            .iter()
            .any(|value| matches!(value, RuntimeEventValue::Receipt { .. }))
    );

    let path = fixture.root.0.join("runtime");
    drop(fixture.runtime);
    let reopened = RuntimeJournal::open(&path, &fixture.machine).unwrap();
    let tail = reopened.events(Counter::ZERO, 256).unwrap();
    assert_eq!(tail.cursor, cursor);
    assert_eq!(tail.available, cursor);
}

#[test]
fn journal_pages_are_byte_bounded_before_aggregating_large_execution_metadata() {
    let mut fixture = Fixture::new();
    for index in 0..4 {
        let mut request = fixture.command.request.clone();
        let GuestRequest::Spawn { request: spawn } = &mut request else {
            unreachable!()
        };
        let operation: OperationId = format!("large-{index}").try_into().unwrap();
        spawn.execution_id = format!("large-{index}").try_into().unwrap();
        spawn.operation_id = operation.clone();
        spawn.argv = vec!["/bin/true".into(), "x".repeat(50_000), "y".repeat(50_000)];
        let command =
            GuestCommand::new(fixture.machine.clone(), Counter::ONE, operation, request).unwrap();
        fixture.runtime.admit(command).unwrap();
    }
    let available = fixture.runtime.event_cursor().unwrap();
    let first = fixture.runtime.events(Counter::ZERO, 256).unwrap();
    assert!(
        first.cursor < available,
        "entry count alone must not determine page size"
    );
    let mut cursor = Counter::ZERO;
    while cursor < available {
        let page = fixture.runtime.events(cursor, 256).unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_EVENT_PAGE_BYTES);
        assert!(
            page.cursor > cursor,
            "bounded pages must make progress without skipping entries"
        );
        for event in &page.events {
            assert_eq!(event.cursor, cursor.next().unwrap());
            cursor = event.cursor;
        }
        assert_eq!(cursor, page.cursor);
        assert_eq!(page.available, available);
    }
}

fn dispatch(runtime: &mut RuntimeJournal, command: &GuestCommand) {
    let authorization = command.clone();
    match runtime.begin_dispatch(authorization).unwrap() {
        DispatchDecision::Perform(permit) => permit.perform(|actual| {
            assert_eq!(actual, command);
        }),
        DispatchDecision::Reconcile(_) => panic!("first dispatch unexpectedly reconciled"),
    }
}

#[test]
fn snapshot_fork_and_rollback_keep_authority_and_lineage_host_owned() {
    let mut fixture = Fixture::new();
    let snapshot_id: SnapshotId = "snapshot-one".try_into().unwrap();
    let snapshot_operation: OperationId = "capture-filesystem".try_into().unwrap();
    let request = SnapshotRequest {
        id: snapshot_id.clone(),
        operation_id: snapshot_operation,
        machine_id: fixture.machine.clone(),
        expected_generation: n(1),
        expected_revision: n(2),
        kind: SnapshotKind::Disk,
        parent: None,
    };
    let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request)).unwrap();
    let admitted = fixture
        .host
        .admit_snapshot(
            request,
            Approval {
                id: "approve-snapshot".try_into().unwrap(),
                request_digest: request_digest.clone(),
            },
        )
        .unwrap();
    assert_eq!(admitted.phase, SnapshotPhase::Admitted);
    fixture
        .host
        .begin_snapshot(&snapshot_id, &request_digest)
        .unwrap();
    let ready = fixture
        .host
        .complete_snapshot(
            &snapshot_id,
            &request_digest,
            hash("captured-disk"),
            hash("snapshot-manifest"),
            SnapshotConsistency::Crash,
        )
        .unwrap();
    assert_eq!(ready.phase, SnapshotPhase::Ready);

    let fork_id: MachineId = "forked-box".try_into().unwrap();
    let fork_operation: OperationId = "fork-snapshot".try_into().unwrap();
    let fork_digest = digest(
        Domain::Snapshot,
        &(
            "sandsurf-filesystem-fork-v1",
            &snapshot_id,
            &fork_id,
            resources(),
            &MachineLifetime::default(),
            &fork_operation,
        ),
    )
    .unwrap();
    fixture
        .host
        .create_machine_from_snapshot(
            fork_id.clone(),
            &snapshot_id,
            resources(),
            MachineLifetime::default(),
            fork_operation,
            Approval {
                id: "approve-fork".try_into().unwrap(),
                request_digest: fork_digest,
            },
        )
        .unwrap();
    assert_eq!(
        fixture
            .host
            .machine(&fork_id)
            .unwrap()
            .unwrap()
            .image_digest,
        ready.image_digest
    );
    let fork = fixture.host.machine(&fork_id).unwrap().unwrap();
    assert!(fork.runtime_configuration.network.rules.is_empty());
    assert!(fork.runtime_configuration.exposures.is_empty());

    let rollback_operation: OperationId = "rollback-snapshot".try_into().unwrap();
    let rollback_digest = digest(
        Domain::Snapshot,
        &(
            "sandsurf-filesystem-rollback-v1",
            &fixture.machine,
            &snapshot_id,
            &rollback_operation,
            n(2),
        ),
    )
    .unwrap();
    let rollback = fixture
        .host
        .admit_rollback(
            &fixture.machine,
            &snapshot_id,
            rollback_operation.clone(),
            n(2),
            Approval {
                id: "approve-rollback".try_into().unwrap(),
                request_digest: rollback_digest.clone(),
            },
        )
        .unwrap();
    assert_eq!(rollback.phase, RollbackPhase::Admitted);
    let applied = fixture
        .host
        .complete_rollback(&rollback_operation, &rollback_digest, hash("installed"))
        .unwrap();
    assert_eq!(applied.phase, RollbackPhase::Applied);
    assert_eq!(
        fixture
            .host
            .machine(&fixture.machine)
            .unwrap()
            .unwrap()
            .configuration_revision,
        n(2)
    );
}

#[test]
fn live_usage_stays_monotonic_across_a_new_machine_generation() {
    let mut fixture = Fixture::new();
    let sample = |cpu, network, peak| ResourceUsage {
        cpu_micros: Some(n(cpu)),
        memory_current: Some(n(10)),
        memory_peak: Some(n(peak)),
        disk_logical_bytes: n(100),
        disk_allocated_bytes: n(80),
        io_read_bytes: Some(n(cpu)),
        io_write_bytes: Some(n(cpu * 2)),
        output_retained_bytes: n(5),
        network_rx_bytes: n(network),
        network_tx_bytes: n(network * 2),
        network_connections: n(network),
        executions_current: n(1),
        complete: false,
        source: "guest".into(),
        observed_unix_millis: n(1000 + cpu),
    };
    let first = fixture
        .host
        .observe_usage(&fixture.machine, n(1), sample(10, 20, 30))
        .unwrap();
    assert_eq!(first.cpu_micros, Some(n(10)));
    let same_generation = fixture
        .host
        .observe_usage(&fixture.machine, n(1), sample(15, 24, 40))
        .unwrap();
    assert_eq!(same_generation.cpu_micros, Some(n(15)));
    assert_eq!(same_generation.network_rx_bytes, n(24));
    let next_generation = fixture
        .host
        .observe_usage(&fixture.machine, n(2), sample(3, 25, 12))
        .unwrap();
    assert_eq!(next_generation.cpu_micros, Some(n(18)));
    assert_eq!(next_generation.io_write_bytes, Some(n(36)));
    assert_eq!(next_generation.network_rx_bytes, n(25));
    assert_eq!(next_generation.memory_peak, Some(n(40)));
}

fn rebind_command(value: &GuestCommand, identity: &str) -> GuestCommand {
    let operation_id: OperationId = identity.try_into().unwrap();
    let mut request = value.request.clone();
    if let GuestRequest::Spawn { request } = &mut request {
        request.operation_id = operation_id.clone();
        request.execution_id = identity.try_into().unwrap();
    }
    GuestCommand::new(
        value.machine_id.clone(),
        value.generation,
        operation_id,
        request,
    )
    .unwrap()
}

fn process_command(
    value: &GuestCommand,
    identity: &str,
    output_bytes: Counter,
    stdio: StdioMode,
) -> GuestCommand {
    let rebound = rebind_command(value, identity);
    let mut request = rebound.request.clone();
    let GuestRequest::Spawn { request: spawn } = &mut request else {
        panic!("fixture command is not a spawn");
    };
    spawn.output_bytes = output_bytes;
    spawn.stdio = stdio;
    spawn.terminal_size = (stdio == StdioMode::Terminal).then_some(TerminalSize {
        columns: 80,
        rows: 24,
        pixel_width: 0,
        pixel_height: 0,
    });
    GuestCommand::new(
        rebound.machine_id,
        rebound.generation,
        rebound.operation_id,
        request,
    )
    .unwrap()
}

fn process_command_in_generation(
    value: &GuestCommand,
    identity: &str,
    output_bytes: Counter,
    generation: Counter,
) -> GuestCommand {
    let mut command = process_command(value, identity, output_bytes, StdioMode::Pipes);
    let GuestRequest::Spawn { request } = &mut command.request else {
        unreachable!();
    };
    request.generation = generation;
    GuestCommand::new(
        command.machine_id,
        generation,
        command.operation_id,
        command.request,
    )
    .unwrap()
}

#[test]
fn dispatch_permission_is_single_use_and_reopen_does_not_replay() {
    let mut f = Fixture::new();
    let command = rebind_command(&f.command, "once");
    let authorize = || command.clone();
    f.runtime.admit(authorize()).unwrap();
    let mut effects = 0;
    match f.runtime.begin_dispatch(authorize()).unwrap() {
        DispatchDecision::Perform(permit) => permit.perform(|_| effects += 1),
        DispatchDecision::Reconcile(_) => panic!("first dispatch must be new"),
    }
    assert_eq!(effects, 1);
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut reopened = RuntimeJournal::open(&path, &f.machine).unwrap();
    match reopened.begin_dispatch(authorize()).unwrap() {
        DispatchDecision::Perform(_) => panic!("dispatched operation cannot execute twice"),
        DispatchDecision::Reconcile(old) => assert_eq!(old.delivery, Delivery::Dispatched),
    }
    reopened
        .record_delivery(
            &command.operation_id,
            &command.request_digest,
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
fn ordinary_commands_are_digest_bound_without_grant_envelopes() {
    let mut f = Fixture::new();
    let command = rebind_command(&f.command, "ordinary-command");
    let mut corrupted = command.clone();
    corrupted.request_digest = hash("not-the-command");
    assert!(f.runtime.admit(corrupted).is_err());
    assert_eq!(
        f.runtime.admit(command).unwrap().delivery,
        Delivery::Admitted
    );
}

#[test]
fn dense_binary_admission_retains_commitments_and_never_replays_bytes_after_restart() {
    let mut f = Fixture::new();
    let command = GuestCommand::new(
        f.machine.clone(),
        Counter::ONE,
        "dense-input".try_into().unwrap(),
        GuestRequest::WriteInput {
            execution_id: "execution".try_into().unwrap(),
            terminal_lease_id: None,
            bytes: vec![255; MAX_STREAM_BYTES],
        },
    )
    .unwrap();
    let value = f.runtime.admit(command.clone()).unwrap();
    assert!(serde_json::to_vec(&value).unwrap().len() < 2048);
    assert_eq!(
        value.admission.binary.as_ref().unwrap()[0].length as usize,
        MAX_STREAM_BYTES
    );
    assert!(value.admission.request.validate().is_err());
    match f.runtime.begin_dispatch(command.clone()).unwrap() {
        DispatchDecision::Perform(permit) => permit.perform(|actual| {
            assert_eq!(actual, &command);
        }),
        DispatchDecision::Reconcile(_) => panic!("fresh admission must dispatch"),
    }
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut reopened = RuntimeJournal::open(&path, &f.machine).unwrap();
    assert!(matches!(
        reopened.begin_dispatch(command.clone()).unwrap(),
        DispatchDecision::Reconcile(_)
    ));
    let mut substituted = command;
    let GuestRequest::WriteInput { bytes, .. } = &mut substituted.request else {
        unreachable!()
    };
    bytes[0] = 0;
    let changed = GuestCommand::new(
        substituted.machine_id,
        substituted.generation,
        substituted.operation_id,
        substituted.request,
    )
    .unwrap();
    assert!(reopened.admit(changed).is_err());
}

#[test]
fn dropped_dispatch_permission_preserves_uncertainty_instead_of_retrying() {
    let mut f = Fixture::new();
    let command = rebind_command(&f.command, "interrupted-native-dispatch");
    f.runtime.admit(command.clone()).unwrap();
    // The durable dispatch commit can precede a crash before any native effect.
    drop(f.runtime.begin_dispatch(command.clone()).unwrap());
    assert_eq!(
        f.runtime
            .operation(&command.operation_id)
            .unwrap()
            .unwrap()
            .delivery,
        Delivery::Dispatched
    );
    assert!(matches!(
        f.runtime.begin_dispatch(command).unwrap(),
        DispatchDecision::Reconcile(_)
    ));
}

#[test]
fn admitted_work_does_not_bypass_a_later_machine_barrier() {
    let mut f = Fixture::new();
    let command = rebind_command(&f.command, "queued");
    f.runtime.admit(command.clone()).unwrap();
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
    assert!(f.runtime.begin_dispatch(command.clone()).is_err());
    assert_eq!(
        f.runtime
            .operation(&command.operation_id)
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
    assert!(RuntimeJournal::open(&fixture.root.0.join("runtime"), &fixture.machine).is_err());
    let path = fixture.root.0.join("host");
    drop(fixture.host);
    assert!(RuntimeJournal::open(&path, &fixture.machine).is_err());
    assert_eq!(HostCatalog::open(&path).unwrap().host_id().as_str(), "host");
}

#[test]
fn native_facts_never_install_authority_or_complete_pending_host_intent() {
    let mut f = Fixture::new();
    let operation: OperationId = "stop-with-independent-observation".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&f.machine, &operation, n(2), DesiredState::Stopped),
    )
    .unwrap();
    let intent = f
        .host
        .request_lifecycle(
            &f.machine,
            operation.clone(),
            n(2),
            DesiredState::Stopped,
            Approval {
                id: "approve-independent-stop".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    let authorization = f.host.authorize_lifecycle(&operation).unwrap();
    f.runtime.admit_lifecycle(authorization.clone()).unwrap();
    let LifecycleDecision::Perform(permit) = f.runtime.begin_lifecycle(authorization).unwrap()
    else {
        panic!("new operation");
    };
    permit.perform(|_| ());
    let mut native = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    native.sequence = native.sequence.next().unwrap();
    native.cause = ObservationCause::Native {};
    native.state = MachineState::Stopped;
    native.evidence_digest = hash("independent-native-shutdown");
    let mut invalid = native.clone();
    invalid.applied_revision = intent.revision;
    assert!(
        f.runtime.observe(invalid).is_err(),
        "measurement cannot apply admitted policy"
    );
    let mut invalid = native.clone();
    invalid.generation = invalid.generation.next().unwrap();
    invalid.state = MachineState::Starting;
    assert!(
        f.runtime.observe(invalid).is_err(),
        "measurement cannot assign a new execution lineage"
    );
    let measured = f.runtime.observe(native).unwrap();
    assert!(f.host.complete_intent(&measured).is_err());
    assert!(
        f.runtime
            .record_lifecycle_delivery(
                &operation,
                &intent.request_digest,
                Delivery::Applied,
                Some(hash("not-command-evidence")),
                Some(measured.reference().unwrap())
            )
            .is_err()
    );
    assert_eq!(
        f.runtime
            .lifecycle_operation(&operation)
            .unwrap()
            .unwrap()
            .delivery,
        Delivery::Dispatched
    );
    assert_eq!(
        f.host
            .machine(&f.machine)
            .unwrap()
            .unwrap()
            .latest_intent
            .completion,
        None
    );
}

#[test]
fn stop_intent_is_not_stopped_observation() {
    let mut f = Fixture::new();
    let operation: OperationId = "stop".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&f.machine, &operation, n(2), DesiredState::Stopped),
    )
    .unwrap();
    let intent = f
        .host
        .request_lifecycle(
            &f.machine,
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
    assert!(f.host.require_guest_access(&f.machine).is_err());
    let old = f.runtime.last_observation().unwrap().unwrap();
    assert_eq!(old.value().state, MachineState::Running);
    let mut observation = old.value().clone();
    observation.sequence = n(4);
    observation.applied_revision = n(3);
    observation.cause = ObservationCause::Lifecycle {
        operation_id: operation.clone(),
    };
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
        &(&f.machine, &operation, n(2), DesiredState::Paused),
    )
    .unwrap();
    f.host
        .request_lifecycle(
            &f.machine,
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
fn newer_host_intent_supersedes_unapplied_work_without_replaying_it() {
    let mut f = Fixture::new();
    let pause: OperationId = "pause-before-next-intent".try_into().unwrap();
    let pause_digest = digest(
        Domain::Operation,
        &(&f.machine, &pause, n(2), DesiredState::Paused),
    )
    .unwrap();
    let intent = f
        .host
        .request_lifecycle(
            &f.machine,
            pause.clone(),
            n(2),
            DesiredState::Paused,
            Approval {
                id: "approve-pause-before-next".try_into().unwrap(),
                request_digest: pause_digest,
            },
        )
        .unwrap();

    let authorization = f.host.authorize_lifecycle(&pause).unwrap();
    f.runtime.admit_lifecycle(authorization.clone()).unwrap();
    assert!(matches!(
        f.runtime.begin_lifecycle(authorization.clone()).unwrap(),
        LifecycleDecision::Perform(_)
    ));
    f.runtime
        .record_lifecycle_delivery(
            &pause,
            &intent.request_digest,
            Delivery::NotApplied,
            Some(hash("pause-was-not-applied")),
            None,
        )
        .unwrap();
    assert!(matches!(
        f.runtime.begin_lifecycle(authorization.clone()).unwrap(),
        LifecycleDecision::Perform(_)
    ));
    f.runtime
        .record_lifecycle_delivery(
            &pause,
            &intent.request_digest,
            Delivery::NotApplied,
            Some(hash("pause-still-not-applied")),
            None,
        )
        .unwrap();

    let stop: OperationId = "stop-overtaking-pause".try_into().unwrap();
    let stop_digest = digest(
        Domain::Operation,
        &(&f.machine, &stop, n(3), DesiredState::Stopped),
    )
    .unwrap();
    let stop_intent = f
        .host
        .request_lifecycle(
            &f.machine,
            stop.clone(),
            n(3),
            DesiredState::Stopped,
            Approval {
                id: "approve-overtaking-stop".try_into().unwrap(),
                request_digest: stop_digest,
            },
        )
        .unwrap();
    assert_eq!(stop_intent.revision, n(4));
    assert!(f.host.authorize_lifecycle(&pause).is_err());
    let stop_authorization = f.host.authorize_lifecycle(&stop).unwrap();
    f.runtime
        .admit_lifecycle(stop_authorization.clone())
        .unwrap();
    // Acceptance is durable, even before the newer operation has an effect.
    drop(f.runtime);
    f.runtime = RuntimeJournal::open(&f.root.0.join("runtime"), &f.machine).unwrap();
    assert!(f.runtime.begin_lifecycle(authorization.clone()).is_err());
    assert_eq!(
        f.runtime.admit_lifecycle(authorization).unwrap().delivery,
        Delivery::NotApplied
    );
    assert!(matches!(
        f.runtime.begin_lifecycle(stop_authorization).unwrap(),
        LifecycleDecision::Perform(_)
    ));
    let prior = f.runtime.last_observation().unwrap().unwrap();
    let observed = f
        .runtime
        .observe(MachineObservation {
            machine_id: f.machine.clone(),
            generation: prior.value().generation,
            sequence: prior.value().sequence.next().unwrap(),
            state: MachineState::Stopped,
            applied_revision: n(4),
            cause: sandsurf_protocol::ObservationCause::Lifecycle {
                operation_id: stop.clone(),
            },
            evidence_digest: hash("native-stop"),
        })
        .unwrap();
    f.runtime
        .record_lifecycle_delivery(
            &stop,
            &stop_intent.request_digest,
            Delivery::Applied,
            Some(hash("native-stop")),
            Some(observed.reference().unwrap()),
        )
        .unwrap();
    f.host.complete_intent(&observed).unwrap();
    assert!(f.host.intent(&pause).unwrap().unwrap().completion.is_none());
    assert!(f.host.intent(&stop).unwrap().unwrap().completion.is_some());
}

#[test]
fn newer_configuration_can_skip_failed_revisions_but_old_authority_cannot_retry() {
    let mut f = Fixture::new();
    let configuration = f
        .host
        .machine(&f.machine)
        .unwrap()
        .unwrap()
        .runtime_configuration;
    let mut old = None;
    for expected in 2..=3 {
        let operation: OperationId = format!("configuration-gap-{expected}").try_into().unwrap();
        let request_digest = hash(operation.as_str());
        let admitted = f
            .host
            .set_runtime_configuration(
                &f.machine,
                &operation,
                n(expected),
                configuration.clone(),
                request_digest.clone(),
                Approval {
                    id: format!("approve-configuration-gap-{expected}")
                        .try_into()
                        .unwrap(),
                    request_digest,
                },
            )
            .unwrap();
        let authorized = f
            .host
            .authorize_configuration(&f.machine, admitted.revision)
            .unwrap();
        let guardian = f.runtime.admit_configuration(authorized.clone()).unwrap();
        assert!(matches!(
            f.runtime.begin_configuration(authorized.clone()).unwrap(),
            ConfigurationDecision::Perform(_)
        ));
        f.runtime
            .record_configuration_delivery(
                &guardian.command.operation_id,
                &guardian.command.request_digest,
                Delivery::NotApplied,
                Some(hash("not-applied")),
                None,
            )
            .unwrap();
        if let Some(old) = old.take() {
            assert!(f.runtime.begin_configuration(old).is_err());
        }
        old = Some(authorized);
    }
    assert_eq!(
        f.runtime
            .last_observation()
            .unwrap()
            .unwrap()
            .value()
            .applied_revision,
        n(2)
    );
}

#[test]
fn host_configuration_operations_replay_immutable_results_without_reapplying_old_state() {
    let mut f = Fixture::new();
    let original = f.host.machine(&f.machine).unwrap().unwrap();
    let first_operation: OperationId = "configure-first".try_into().unwrap();
    let first_digest = hash("configure-first-request");
    let mut first_configuration = original.runtime_configuration.clone();
    first_configuration.network.rules = vec![NetworkRule {
        plane: NetworkPlane::DirectTcp,
        destination: NetworkDestination::Ip {
            cidr: "198.51.100.0/24".into(),
        },
        ports: vec![PortRange { from: 443, to: 443 }],
    }];
    let first = f
        .host
        .set_runtime_configuration(
            &f.machine,
            &first_operation,
            n(2),
            first_configuration.clone(),
            first_digest.clone(),
            Approval {
                id: "approve-configure-first".try_into().unwrap(),
                request_digest: first_digest.clone(),
            },
        )
        .unwrap();
    assert_eq!(first.revision, n(3));

    let second_operation: OperationId = "configure-second".try_into().unwrap();
    let second_digest = hash("configure-second-request");
    let mut second_configuration = first_configuration.clone();
    second_configuration.network.rules[0].ports = vec![PortRange { from: 80, to: 80 }];
    let second = f
        .host
        .set_runtime_configuration(
            &f.machine,
            &second_operation,
            n(3),
            second_configuration.clone(),
            second_digest.clone(),
            Approval {
                id: "approve-configure-second".try_into().unwrap(),
                request_digest: second_digest,
            },
        )
        .unwrap();
    assert_eq!(second.revision, n(4));

    assert_eq!(
        f.host
            .set_runtime_configuration(
                &f.machine,
                &first_operation,
                n(2),
                first_configuration,
                first_digest.clone(),
                Approval {
                    id: "ignored-replay-approval".try_into().unwrap(),
                    request_digest: first_digest,
                },
            )
            .unwrap(),
        first
    );
    let current = f.host.machine(&f.machine).unwrap().unwrap();
    assert_eq!(current.configuration_revision, n(4));
    assert_eq!(current.runtime_configuration, second_configuration);
    assert_eq!(
        f.host.operation(&first_operation).unwrap(),
        Some(HostOperationRecord::Configuration(first.clone()))
    );
    assert!(
        f.host
            .set_runtime_configuration(
                &f.machine,
                &first_operation,
                n(2),
                current.runtime_configuration,
                hash("conflicting-request"),
                Approval {
                    id: "conflicting-approval".try_into().unwrap(),
                    request_digest: hash("conflicting-request"),
                },
            )
            .is_err()
    );
    let conflict = digest(
        Domain::Machine,
        &(&f.machine, &first_operation, n(4), DesiredState::Stopped),
    )
    .unwrap();
    assert!(
        f.host
            .request_lifecycle(
                &f.machine,
                first_operation,
                n(4),
                DesiredState::Stopped,
                Approval {
                    id: "approve-conflicting-host-operation".try_into().unwrap(),
                    request_digest: conflict
                },
            )
            .is_err()
    );
}

#[test]
fn guardian_retries_only_configuration_dispatches_proven_not_applied() {
    let mut f = Fixture::new();
    let operation: OperationId = "configure-retry".try_into().unwrap();
    let request_digest = hash("configure-retry-request");
    let mut configuration = f
        .host
        .machine(&f.machine)
        .unwrap()
        .unwrap()
        .runtime_configuration;
    configuration.network.rules = vec![NetworkRule {
        plane: NetworkPlane::DirectTcp,
        destination: NetworkDestination::Ip {
            cidr: "198.51.100.0/24".into(),
        },
        ports: vec![PortRange { from: 443, to: 443 }],
    }];
    f.host
        .set_runtime_configuration(
            &f.machine,
            &operation,
            n(2),
            configuration,
            request_digest.clone(),
            Approval {
                id: "approve-configure-retry".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    let authorization = f.host.authorize_configuration(&f.machine, n(3)).unwrap();
    let command = authorization.statement.command.clone();
    f.runtime
        .admit_configuration(authorization.clone())
        .unwrap();
    assert!(matches!(
        f.runtime
            .begin_configuration(authorization.clone())
            .unwrap(),
        ConfigurationDecision::Perform(_)
    ));
    f.runtime
        .record_configuration_delivery(
            &command.operation_id,
            &command.request_digest,
            Delivery::NotApplied,
            Some(hash("configuration-not-applied")),
            None,
        )
        .unwrap();
    assert!(matches!(
        f.runtime.begin_configuration(authorization).unwrap(),
        ConfigurationDecision::Perform(_)
    ));
}

#[test]
fn host_transfer_operations_reconcile_admission_completion_and_cross_kind_identity() {
    let mut f = Fixture::new();
    let operation: OperationId = "host-transfer-step".try_into().unwrap();
    let request = hash("host-transfer-request");
    let admitted = f
        .host
        .admit_transfer_operation(operation.clone(), f.machine.clone(), request.clone(), None)
        .unwrap();
    assert!(!admitted.applied);
    assert_eq!(
        f.host
            .admit_transfer_operation(operation.clone(), f.machine.clone(), request.clone(), None)
            .unwrap(),
        admitted
    );
    assert!(
        f.host
            .admit_transfer_operation(operation.clone(), f.machine.clone(), hash("changed"), None)
            .is_err()
    );
    let completed = f
        .host
        .complete_transfer_operation(&operation, &request)
        .unwrap();
    assert!(completed.applied);
    assert_eq!(
        f.host.operation(&operation).unwrap(),
        Some(HostOperationRecord::Transfer(completed.clone()))
    );
    assert_eq!(
        f.host
            .complete_transfer_operation(&operation, &request)
            .unwrap(),
        completed
    );

    let lifecycle_digest = digest(
        Domain::Operation,
        &(&f.machine, &operation, n(2), DesiredState::Paused),
    )
    .unwrap();
    assert!(
        f.host
            .request_lifecycle(
                &f.machine,
                operation,
                n(2),
                DesiredState::Paused,
                Approval {
                    id: "approve-transfer-as-lifecycle".try_into().unwrap(),
                    request_digest: lifecycle_digest,
                },
            )
            .is_err()
    );
}

#[test]
fn host_file_authority_approval_binds_the_complete_transfer_and_one_identity() {
    let mut f = Fixture::new();
    let operation: OperationId = "external-files".try_into().unwrap();
    let request = hash("complete-host-path-and-file-scope");
    let approval = Approval {
        id: "approve-external-files".try_into().unwrap(),
        request_digest: request.clone(),
    };
    let admitted = f
        .host
        .admit_transfer_operation(
            operation.clone(),
            f.machine.clone(),
            request.clone(),
            Some(approval.clone()),
        )
        .unwrap();
    assert_eq!(admitted.approval_id, Some(approval.id.clone()));
    assert_eq!(
        f.host
            .admit_transfer_operation(
                operation.clone(),
                f.machine.clone(),
                request.clone(),
                Some(approval.clone())
            )
            .unwrap(),
        admitted
    );
    assert!(
        f.host
            .admit_transfer_operation(operation, f.machine.clone(), request.clone(), None)
            .is_err()
    );
    assert!(
        f.host
            .admit_transfer_operation(
                "reuse-approval".try_into().unwrap(),
                f.machine.clone(),
                request.clone(),
                Some(approval)
            )
            .is_err()
    );
    assert!(
        f.host
            .admit_transfer_operation(
                "wrong-scope".try_into().unwrap(),
                f.machine,
                request,
                Some(Approval {
                    id: "wrong-scope-approval".try_into().unwrap(),
                    request_digest: hash("unrelated")
                })
            )
            .is_err()
    );
}

#[test]
fn host_secret_put_operation_is_durable_and_distinct_from_delivery() {
    let mut f = Fixture::new();
    let operation: OperationId = "put-secret-version".try_into().unwrap();
    let request = hash("put-secret-request");
    let secret = SecretVersion {
        id: "registry-credential".try_into().unwrap(),
        version: "opaque-originals-version".try_into().unwrap(),
        bytes: n(16),
    };
    let admitted = f
        .host
        .admit_secret_put(
            operation.clone(),
            request.clone(),
            secret.clone(),
            Approval {
                id: "approve-put-secret".try_into().unwrap(),
                request_digest: request.clone(),
            },
        )
        .unwrap();
    assert!(!admitted.applied);
    let completed = f
        .host
        .complete_secret_put(&operation, &request, &secret)
        .unwrap();
    assert!(completed.applied);
    assert_eq!(
        f.host.operation(&operation).unwrap(),
        Some(HostOperationRecord::SecretPut(completed.clone()))
    );
    assert_eq!(
        f.host
            .admit_secret_put(
                operation.clone(),
                request.clone(),
                secret.clone(),
                Approval {
                    id: "ignored-put-secret-retry".try_into().unwrap(),
                    request_digest: request,
                },
            )
            .unwrap(),
        completed
    );
    assert!(
        f.host
            .admit_transfer_operation(operation, f.machine, hash("not-a-secret-put"), None)
            .is_err()
    );
}

#[test]
fn unknown_dispatch_is_not_replayed_on_reconnect() {
    let mut f = Fixture::new();
    f.runtime
        .record_delivery(
            &f.command.operation_id,
            &f.command.request_digest,
            Delivery::Unknown,
            None,
        )
        .unwrap();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
    let authorization = f.command.clone();
    assert_eq!(
        runtime.admit(authorization).unwrap().delivery,
        Delivery::Unknown
    );
    assert!(
        runtime
            .record_delivery(
                &f.command.operation_id,
                &f.command.request_digest,
                Delivery::Dispatched,
                None
            )
            .is_err()
    );
    assert!(
        runtime
            .record_delivery(
                &f.command.operation_id,
                &f.command.request_digest,
                Delivery::Applied,
                None
            )
            .is_err()
    );
    runtime
        .record_delivery(
            &f.command.operation_id,
            &f.command.request_digest,
            Delivery::Applied,
            Some(hash("guest-completion")),
        )
        .unwrap();
}

#[test]
fn admission_reservations_are_transactional_and_no_eviction_occurs() {
    let mut f = Fixture::new();
    let machine: MachineId = "over-budget".try_into().unwrap();
    let operation: OperationId = "over-budget".try_into().unwrap();
    let mut resources = resources();
    resources.vcpus = n(8);
    let image = hash("image");
    let defaults = ExecutionDefaults::default();
    let request_digest = digest(
        Domain::Machine,
        &(
            &machine,
            &image,
            &resources,
            &defaults,
            &MachineLifetime::default(),
            &operation,
        ),
    )
    .unwrap();
    assert!(
        f.host
            .create_machine(
                MachineAdmission {
                    id: machine,
                    image,
                    resources,
                    defaults,
                    image_defaults: ExecutionDefaults::default(),
                    lifetime: MachineLifetime::default(),
                    operation: operation.clone(),
                },
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
        .acknowledge_receipt(
            &"acknowledge-receipt".try_into().unwrap(),
            &f.process,
            &identity,
        )
        .unwrap();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
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
fn evidence_command_identities_are_exact_retry_safe_and_globally_fenced() {
    let mut f = Fixture::new();
    let mut release = f.capture_release();
    let receipt_digest = release.receipt_digest.clone();
    let acknowledgement: OperationId = "evidence-operation".try_into().unwrap();
    f.runtime
        .acknowledge_receipt(&acknowledgement, &f.process, &receipt_digest)
        .unwrap();
    assert_eq!(
        f.runtime.runtime_operation(&acknowledgement).unwrap(),
        Some(RuntimeOperationRecord::ReceiptAcknowledgement {
            operation_id: acknowledgement.clone(),
            execution_id: f.process.clone(),
            receipt_digest: receipt_digest.clone(),
        })
    );
    f.runtime
        .acknowledge_receipt(&acknowledgement, &f.process, &receipt_digest)
        .unwrap();
    assert!(
        f.runtime
            .acknowledge_receipt(&acknowledgement, &f.process, &hash("other-receipt"))
            .is_err()
    );
    assert!(
        f.runtime
            .seal_output(
                &acknowledgement,
                &f.process,
                n(1),
                None,
                "cross-kind-pin".try_into().unwrap(),
            )
            .is_err()
    );

    let pin_operation: OperationId = "pin-operation".try_into().unwrap();
    let pin: OutputSegmentId = "retained-output".try_into().unwrap();
    let segment = f
        .runtime
        .seal_output(
            &pin_operation,
            &f.process,
            n(1),
            Some(&release.output),
            pin.clone(),
        )
        .unwrap();
    assert_eq!(
        f.runtime.runtime_operation(&pin_operation).unwrap(),
        Some(RuntimeOperationRecord::OutputSeal {
            operation_id: pin_operation.clone(),
            request_digest: digest(
                Domain::Output,
                &(&f.machine, &f.process, n(1), Some(&release.output), &pin)
            )
            .unwrap(),
            segment,
        })
    );
    f.runtime
        .seal_output(
            &pin_operation,
            &f.process,
            n(1),
            Some(&release.output),
            pin.clone(),
        )
        .unwrap();
    assert_eq!(
        f.runtime
            .read_output_segment(&pin, Counter::ZERO, 64)
            .unwrap()
            .cursor,
        n(13)
    );
    assert!(
        f.runtime
            .seal_output(
                &pin_operation,
                &f.process,
                n(1),
                Some(&release.output),
                "different-pin".try_into().unwrap(),
            )
            .is_err()
    );

    release.operation_id = pin_operation;
    assert!(f.runtime.release(&f.process, release).is_err());
    assert_eq!(
        f.runtime
            .read_output(&f.process, Counter::ZERO, 64)
            .unwrap()
            .cursor,
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
        segment: "url-is-not-retention".try_into().unwrap(),
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
    assert_eq!(
        f.runtime.runtime_operation(&request.operation_id).unwrap(),
        Some(RuntimeOperationRecord::EvidenceRelease {
            execution_id: f.process.clone(),
            request: request.clone(),
            status: status.clone(),
        })
    );
    assert!(
        f.root
            .0
            .join("runtime/output")
            .join(bytes_digest(b"hello\0\xff").as_str())
            .exists()
    );
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let mut runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
    assert_eq!(
        runtime.release(&f.process, request.clone()).unwrap(),
        status
    );
    let cleaned = runtime
        .cleanup_released(&f.process, &status.request_digest)
        .unwrap();
    assert!(!cleaned.cleanup_pending);
    assert!(
        !path
            .join("output")
            .join(bytes_digest(b"hello\0\xff").as_str())
            .exists()
    );
    assert!(
        !path
            .join("output")
            .join(bytes_digest(b"stderr").as_str())
            .exists()
    );
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
    let authorization = f.command.clone();
    assert_eq!(
        runtime.admit(authorization).unwrap().delivery,
        Delivery::Applied
    );
    assert!(
        runtime
            .admit_process(f.process, &f.command.operation_id, n(100), false)
            .is_err()
    );
}

#[test]
fn continuing_retention_keeps_actual_originals_after_source_release() {
    let mut f = Fixture::new();
    let mut request = f.capture_release();
    let pin: OutputSegmentId = "archive-owner".try_into().unwrap();
    f.runtime
        .seal_output(
            &"pin-archive".try_into().unwrap(),
            &f.process,
            n(1),
            Some(&request.output),
            pin.clone(),
        )
        .unwrap();
    request.disposition = ReleaseDisposition::ContinuingRetention {
        segment: pin.clone(),
    };
    let status = f.runtime.release(&f.process, request).unwrap();
    f.runtime
        .cleanup_released(&f.process, &status.request_digest)
        .unwrap();
    assert!(
        f.root
            .0
            .join("runtime/output")
            .join(bytes_digest(b"hello\0\xff").as_str())
            .exists()
    );
    assert!(f.runtime.read_output(&f.process, n(0), 64).is_err());
    assert_eq!(
        f.runtime
            .read_output_segment(&pin, n(0), 64)
            .unwrap()
            .cursor,
        n(13)
    );
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    assert_eq!(
        RuntimeJournal::open(&path, &f.machine)
            .unwrap()
            .read_output_segment(&pin, n(0), 64)
            .unwrap()
            .cursor,
        n(13)
    );
}

#[test]
fn running_output_seals_an_immutable_prefix_without_a_terminal_receipt() {
    let mut f = Fixture::new();
    let first = f
        .runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"first\0\xff")
        .unwrap();
    let operation: OperationId = "seal-running".try_into().unwrap();
    let segment: OutputSegmentId = "running-prefix".try_into().unwrap();
    let sealed = f
        .runtime
        .seal_output(&operation, &f.process, n(1), None, segment.clone())
        .unwrap();
    assert_eq!(sealed.output, first);
    assert!(f.runtime.receipt(&f.process).unwrap().is_none());
    f.runtime
        .append_output(&f.process, n(2), Stream::Stderr, b"second")
        .unwrap();
    assert_eq!(
        f.runtime
            .seal_output(&operation, &f.process, n(1), None, segment.clone())
            .unwrap(),
        sealed
    );
    let page = f.runtime.read_output_segment(&segment, n(0), 64).unwrap();
    assert_eq!(page.available, first.final_cursor);
    assert_eq!(page.chunks[0].bytes, b"first\0\xff");
    assert_eq!(page.chunks.len(), 1);
    assert!(
        f.runtime
            .read_output_segment(&segment, first.final_cursor.next().unwrap(), 64)
            .is_err()
    );
    assert!(
        f.runtime
            .seal_output(&operation, &f.process, n(1), Some(&first), segment.clone())
            .is_err()
    );
    assert!(
        f.runtime
            .seal_output(
                &"extend-same-segment".try_into().unwrap(),
                &f.process,
                n(1),
                None,
                segment.clone()
            )
            .is_err()
    );
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
    assert_eq!(runtime.output_segment(&segment).unwrap(), sealed);
    assert_eq!(
        runtime
            .read_output_segment(&segment, n(0), 2)
            .unwrap()
            .chunks[0]
            .bytes,
        b"fi"
    );
    assert_eq!(runtime.retained_output_bytes().unwrap(), n(13));
}

#[test]
fn partial_segment_cannot_discharge_remaining_originals_but_retains_its_own_bytes() {
    let mut f = Fixture::new();
    let first = f
        .runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"hello\0\xff")
        .unwrap();
    let segment: OutputSegmentId = "protected-prefix".try_into().unwrap();
    f.runtime
        .seal_output(
            &"seal-prefix".try_into().unwrap(),
            &f.process,
            n(1),
            Some(&first),
            segment.clone(),
        )
        .unwrap();
    let request = f.capture_release();
    let mut incomplete = request.clone();
    incomplete.disposition = ReleaseDisposition::ContinuingRetention {
        segment: segment.clone(),
    };
    assert!(f.runtime.release(&f.process, incomplete).is_err());
    assert_eq!(f.runtime.retained_output_bytes().unwrap(), n(13));
    let status = f.runtime.release(&f.process, request).unwrap();
    f.runtime
        .cleanup_released(&f.process, &status.request_digest)
        .unwrap();
    assert_eq!(f.runtime.retained_output_bytes().unwrap(), n(7));
    assert!(f.runtime.read_output(&f.process, n(0), 64).is_err());
    let path = f.root.0.join("runtime");
    assert!(
        !path
            .join("output")
            .join(bytes_digest(b"stderr").as_str())
            .exists()
    );
    drop(f.runtime);
    let runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
    assert_eq!(
        runtime
            .read_output_segment(&segment, n(0), 64)
            .unwrap()
            .chunks[0]
            .bytes,
        b"hello\0\xff"
    );
    assert_eq!(runtime.retained_output_bytes().unwrap(), n(7));
}

#[test]
fn a_segment_reference_with_missing_bytes_does_not_authorize_source_release() {
    let mut f = Fixture::new();
    let mut request = f.capture_release();
    let segment: OutputSegmentId = "missing-originals".try_into().unwrap();
    f.runtime
        .seal_output(
            &"seal-before-corruption".try_into().unwrap(),
            &f.process,
            n(1),
            None,
            segment.clone(),
        )
        .unwrap();
    fs::remove_file(
        f.root
            .0
            .join("runtime/output")
            .join(bytes_digest(b"hello\0\xff").as_str()),
    )
    .unwrap();
    request.disposition = ReleaseDisposition::ContinuingRetention { segment };
    assert!(f.runtime.release(&f.process, request).is_err());
    let db = rusqlite::Connection::open(f.root.0.join("runtime/authority.sqlite")).unwrap();
    let released: bool = db
        .query_row(
            "SELECT release IS NOT NULL FROM processes WHERE id=?1",
            [f.process.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!released);
    assert!(
        f.root
            .0
            .join("runtime/output")
            .join(bytes_digest(b"stderr").as_str())
            .exists()
    );
}

#[test]
fn sealed_prefix_validation_rejects_changed_stream_counts_cursor_hash_and_omissions() {
    let mut f = Fixture::new();
    let boundary = f
        .runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"bytes")
        .unwrap();
    let mut variants = Vec::new();
    let mut changed = boundary.clone();
    changed.stdout_bytes = n(0);
    changed.stderr_bytes = n(5);
    variants.push(changed);
    let mut changed = boundary.clone();
    changed.final_cursor = n(4);
    variants.push(changed);
    let mut changed = boundary.clone();
    changed.final_hash = hash("wrong-prefix");
    variants.push(changed);
    let mut changed = boundary.clone();
    changed.omitted_bytes = n(1);
    variants.push(changed);
    for (index, invalid) in variants.into_iter().enumerate() {
        assert!(
            f.runtime
                .seal_output(
                    &format!("invalid-seal-{index}").try_into().unwrap(),
                    &f.process,
                    n(1),
                    Some(&invalid),
                    format!("invalid-segment-{index}").try_into().unwrap()
                )
                .is_err()
        );
    }
    assert_eq!(
        fs::read_dir(f.root.0.join("runtime/output"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(f.runtime.retained_output_bytes().unwrap(), n(5));
}

#[test]
fn output_seals_bind_the_captured_generation_without_sampling_machine_power() {
    let mut f = Fixture::new();
    f.runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"generation-one")
        .unwrap();
    let operation: OperationId = "wrong-capture-generation".try_into().unwrap();
    let segment: OutputSegmentId = "generation-bound".try_into().unwrap();
    assert!(
        f.runtime
            .seal_output(&operation, &f.process, n(2), None, segment.clone())
            .is_err()
    );
    assert!(
        f.runtime
            .seal_output(&operation, &f.process, n(0), None, segment.clone())
            .is_err()
    );
    assert!(f.runtime.runtime_operation(&operation).unwrap().is_none());
    assert!(f.runtime.output_segment(&segment).is_err());
    let mut observed = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    observed.sequence = observed.sequence.next().unwrap();
    observed.state = MachineState::Stopped;
    observed.cause = ObservationCause::Native {};
    observed.evidence_digest = hash("stopped-independently");
    f.runtime.observe(observed).unwrap();
    assert_eq!(
        f.runtime
            .seal_output(&operation, &f.process, n(1), None, segment.clone())
            .unwrap()
            .generation,
        n(1)
    );
    let db = rusqlite::Connection::open(f.root.0.join("runtime/authority.sqlite")).unwrap();
    for query in [
        "EXPLAIN QUERY PLAN SELECT offset FROM segment_frames WHERE segment=?1 AND offset<=?2 ORDER BY offset DESC LIMIT 1",
        "EXPLAIN QUERY PLAN SELECT sequence,offset,length,stream,bytes_digest,chain_digest FROM segment_frames WHERE segment=?1 AND offset>=?2 AND sequence<=?3 ORDER BY offset LIMIT 256",
    ] {
        let mut statement = db.prepare(query).unwrap();
        let count = statement.parameter_count();
        let values: Vec<rusqlite::types::Value> = if count == 2 {
            vec![segment.as_str().to_owned().into(), 0i64.into()]
        } else {
            vec![segment.as_str().to_owned().into(), 0i64.into(), 1i64.into()]
        };
        let details = statement
            .query_map(rusqlite::params_from_iter(values), |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        assert!(
            details.contains("segment_chunks_by_offset"),
            "unbounded retained-segment read: {details}"
        );
        assert!(
            !details.contains("TEMP B-TREE"),
            "retained-segment pagination must use its ordered index: {details}"
        );
    }
}

#[test]
fn output_segment_index_capacity_fails_atomically_without_bypassing_the_shared_bound() {
    let f = Fixture::new();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let db = rusqlite::Connection::open(path.join("authority.sqlite")).unwrap();
    let mut limits = runtime_limits();
    limits.chunks = n(1);
    db.execute(
        "UPDATE configuration SET limits=?1",
        [serde_json::to_string(&limits).unwrap()],
    )
    .unwrap();
    drop(db);
    let mut runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
    runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"bounded")
        .unwrap();
    let segment: OutputSegmentId = "too-many-references".try_into().unwrap();
    let operation: OperationId = "capacity-seal".try_into().unwrap();
    assert!(
        runtime
            .seal_output(&operation, &f.process, n(1), None, segment.clone())
            .is_err()
    );
    assert!(runtime.output_segment(&segment).is_err());
    assert!(runtime.runtime_operation(&operation).unwrap().is_none());
    assert_eq!(
        runtime.read_output(&f.process, n(0), 64).unwrap().chunks[0].bytes,
        b"bounded"
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
                &f.machine,
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
            &f.machine,
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
fn corrupt_output_does_not_rewrite_terminal_truth_or_support_a_new_segment() {
    let mut f = Fixture::new();
    let receipt = f.terminal();
    fs::write(
        f.root
            .0
            .join("runtime/output")
            .join(bytes_digest(b"hello\0\xff").as_str()),
        b"corrupt bytes",
    )
    .unwrap();
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
            .seal_output(
                &"pin-corrupt".try_into().unwrap(),
                &f.process,
                n(1),
                Some(&receipt.0.output),
                "bad-pin".try_into().unwrap(),
            )
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
    let runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
    assert_eq!(runtime.receipt(&f.process).unwrap(), Some(receipt));
    assert!(runtime.read_output(&f.process, n(0), 64).is_err());
}

#[test]
fn unpublished_output_stage_never_changes_committed_originals() {
    let mut f = Fixture::new();
    f.runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"committed")
        .unwrap();
    let path = f.root.0.join("runtime");
    drop(f.runtime);
    let staged = path
        .join("output")
        .join(format!("{}.staged", bytes_digest(b"next").as_str()));
    fs::write(&staged, b"uncommitted").unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
    let mut runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
    assert_eq!(
        runtime.read_output(&f.process, n(0), 64).unwrap().cursor,
        n(9)
    );
    runtime
        .append_output(&f.process, n(2), Stream::Stderr, b"next")
        .unwrap();
    assert_eq!(
        fs::read(
            path.join("output")
                .join(bytes_digest(b"committed").as_str())
        )
        .unwrap(),
        b"committed"
    );
    assert_eq!(
        fs::read(path.join("output").join(bytes_digest(b"next").as_str())).unwrap(),
        b"next"
    );
    assert!(!staged.exists());
}

#[test]
fn interrupted_capture_recovers_only_the_exact_durable_intent_and_complete_bytes() {
    use std::io::Write;
    for stage in [
        "intent-only",
        "partial-stage",
        "complete-stage",
        "published",
    ] {
        let f = Fixture::new();
        let bytes = b"captured-before-chunk-commit";
        let boundary = f.runtime.process_boundary(&f.process).unwrap();
        let next = extend_output_boundary(&boundary, n(1), Stream::Stdout, bytes).unwrap();
        let root = f.root.0.join("runtime");
        let content = bytes_digest(bytes);
        drop(f.runtime);
        let db = rusqlite::Connection::open(root.join("authority.sqlite")).unwrap();
        db.execute(
            "INSERT INTO capture_writes VALUES (?1,1,0,?2,?3,?4,?5)",
            rusqlite::params![
                f.process.as_str(),
                bytes.len(),
                serde_json::to_string(&Stream::Stdout).unwrap(),
                content.as_str(),
                next.final_hash.as_str()
            ],
        )
        .unwrap();
        drop(db);
        let staged = root
            .join("output")
            .join(format!("{}.staged", content.as_str()));
        if stage != "intent-only" {
            let path = if stage == "published" {
                root.join("output").join(content.as_str())
            } else {
                staged.clone()
            };
            let mut file = sandsurf_native::local::create_private_file(&path).unwrap();
            file.write_all(if stage == "partial-stage" {
                &bytes[..3]
            } else {
                bytes
            })
            .unwrap();
            file.sync_all().unwrap();
            fs::File::open(root.join("output"))
                .unwrap()
                .sync_all()
                .unwrap();
        }
        let mut runtime = RuntimeJournal::open(&root, &f.machine).unwrap();
        let complete = matches!(stage, "complete-stage" | "published");
        assert_eq!(
            runtime.process_boundary(&f.process).unwrap().final_cursor,
            if complete {
                n(bytes.len() as u64)
            } else {
                n(0)
            }
        );
        assert!(!staged.exists());
        runtime
            .append_output(&f.process, n(1), Stream::Stdout, bytes)
            .unwrap();
        assert_eq!(
            runtime.read_output(&f.process, n(0), 64).unwrap().chunks[0].bytes,
            bytes
        );
        assert!(runtime.receipt(&f.process).unwrap().is_none());
        assert_eq!(
            runtime
                .operation(&f.command.operation_id)
                .unwrap()
                .unwrap()
                .delivery,
            Delivery::Dispatched
        );
        assert_eq!(fs::read_dir(root.join("output")).unwrap().count(), 1);
    }
}

#[test]
fn shared_immutable_payload_is_not_deleted_when_another_retention_owner_remains() {
    let mut f = Fixture::new();
    let request = f.capture_release();
    let command = process_command(&f.command, "other-output-owner", n(20), StdioMode::Pipes);
    f.runtime.admit(command.clone()).unwrap();
    let other: ExecutionId = "other-output-owner".try_into().unwrap();
    f.runtime
        .admit_process(other.clone(), &command.operation_id, n(20), false)
        .unwrap();
    dispatch(&mut f.runtime, &command);
    f.runtime
        .append_output(&other, n(1), Stream::Stdout, b"hello\0\xff")
        .unwrap();
    let (receipt, digest) = f
        .runtime
        .publish_receipt(
            &other,
            ExecutionOutcome::Exit { code: 0 },
            hash("cleanup"),
            hash("accounting"),
        )
        .unwrap();
    assert_eq!(
        fs::read_dir(f.root.0.join("runtime/output"))
            .unwrap()
            .count(),
        2
    );
    let pin: OutputSegmentId = "other-retention".try_into().unwrap();
    f.runtime
        .seal_output(
            &"pin-other-output".try_into().unwrap(),
            &other,
            n(1),
            Some(&receipt.output),
            pin.clone(),
        )
        .unwrap();
    let status = f.runtime.release(&f.process, request).unwrap();
    f.runtime
        .cleanup_released(&f.process, &status.request_digest)
        .unwrap();
    assert_eq!(
        fs::read_dir(f.root.0.join("runtime/output"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        f.runtime.read_output(&other, n(0), 64).unwrap().chunks[0].bytes,
        b"hello\0\xff"
    );
    let release = ReleaseRequest {
        operation_id: "release-other-output".try_into().unwrap(),
        receipt_digest: digest,
        output: receipt.output,
        disposition: ReleaseDisposition::ContinuingRetention {
            segment: pin.clone(),
        },
    };
    let status = f.runtime.release(&other, release).unwrap();
    f.runtime
        .cleanup_released(&other, &status.request_digest)
        .unwrap();
    let root = f.root.0.join("runtime");
    drop(f.runtime);
    let runtime = RuntimeJournal::open(&root, &f.machine).unwrap();
    assert_eq!(
        runtime.read_output_segment(&pin, n(0), 64).unwrap().chunks[0].bytes,
        b"hello\0\xff"
    );
}

#[test]
fn malformed_pending_capture_cannot_repair_or_replace_committed_bytes() {
    let mut f = Fixture::new();
    f.runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"original")
        .unwrap();
    let root = f.root.0.join("runtime");
    drop(f.runtime);
    let db = rusqlite::Connection::open(root.join("authority.sqlite")).unwrap();
    db.execute(
        "INSERT INTO capture_writes VALUES (?1,1,0,1,?2,?3,?4)",
        rusqlite::params![
            f.process.as_str(),
            serde_json::to_string(&Stream::Stdout).unwrap(),
            bytes_digest(b"x").as_str(),
            hash("fake-chain").as_str()
        ],
    )
    .unwrap();
    drop(db);
    assert!(RuntimeJournal::open(&root, &f.machine).is_err());
    assert_eq!(
        fs::read(root.join("output").join(bytes_digest(b"original").as_str())).unwrap(),
        b"original"
    );
}

#[test]
fn another_execution_cannot_silently_recreate_missing_retained_originals() {
    let mut f = Fixture::new();
    let receipt = f.terminal();
    let original = f
        .root
        .0
        .join("runtime/output")
        .join(bytes_digest(b"hello\0\xff").as_str());
    fs::remove_file(&original).unwrap();
    let command = process_command(&f.command, "cannot-repair", n(20), StdioMode::Pipes);
    let other: ExecutionId = "cannot-repair".try_into().unwrap();
    f.runtime.admit(command.clone()).unwrap();
    f.runtime
        .admit_process(other.clone(), &command.operation_id, n(20), false)
        .unwrap();
    dispatch(&mut f.runtime, &command);
    assert!(
        f.runtime
            .append_output(&other, n(1), Stream::Stdout, b"hello\0\xff")
            .is_err()
    );
    assert!(!original.exists());
    assert_eq!(f.runtime.receipt(&f.process).unwrap(), Some(receipt));
    assert_eq!(
        f.runtime.process_boundary(&other).unwrap().final_cursor,
        n(0)
    );
}

#[test]
fn usage_is_monotonic_and_duplicate_delivery_does_not_double_charge() {
    let mut f = Fixture::new();
    let id: OperationId = "usage-1".try_into().unwrap();
    f.host.account(&id, &f.machine, n(10), n(20)).unwrap();
    f.host.account(&id, &f.machine, n(10), n(20)).unwrap();
    assert!(f.host.account(&id, &f.machine, n(11), n(20)).is_err());
    assert_eq!(f.host.usage(&f.machine).unwrap(), (n(10), n(20)));
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
    let record = f.host.machine(&f.machine).unwrap().unwrap();
    assert_eq!(record.id, f.machine);
    assert_eq!(record.configuration_revision, n(2));
    assert_eq!(record.reservation, ReservationState::Held);
    assert_eq!(record.latest_intent.desired, DesiredState::Running);
    assert_eq!(f.host.machines(None, n(10)).unwrap(), vec![record]);
    assert!(f.host.machines(None, Counter::ZERO).is_err());
    assert!(f.host.machines(None, n(257)).is_err());

    let operation: OperationId = "destroy-machine".try_into().unwrap();
    let request_digest = digest(
        Domain::Operation,
        &(&f.machine, &operation, n(2), DesiredState::Destroyed),
    )
    .unwrap();
    f.host
        .request_lifecycle(
            &f.machine,
            operation.clone(),
            n(2),
            DesiredState::Destroyed,
            Approval {
                id: "approve-destroy".try_into().unwrap(),
                request_digest,
            },
        )
        .unwrap();
    let pending = f.host.machine(&f.machine).unwrap().unwrap();
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
    observation.cause = ObservationCause::Lifecycle {
        operation_id: operation.clone(),
    };
    observation.evidence_digest = hash("destroying");
    f.runtime.observe(observation.clone()).unwrap();
    assert_eq!(
        f.host.machine(&f.machine).unwrap().unwrap().reservation,
        ReservationState::Held
    );
    observation.sequence = n(5);
    observation.state = MachineState::Destroyed;
    observation.evidence_digest = hash("runtime-and-disks-cleaned");
    let destroyed = f.runtime.observe(observation).unwrap();
    f.host.complete_intent(&destroyed).unwrap();
    assert_eq!(
        f.host.machine(&f.machine).unwrap().unwrap().reservation,
        ReservationState::Held
    );
    assert!(
        f.host.revision(&f.machine).is_err(),
        "retired identity cannot acquire new machine authority during cleanup"
    );
    drop(f.host);
    f.host = HostCatalog::open(&f.root.0.join("host")).unwrap();
    f.host.release_retired_storage(&f.machine).unwrap();
    let retired = f.host.machine(&f.machine).unwrap().unwrap();
    assert_eq!(retired.reservation, ReservationState::Released);
    assert!(retired.latest_intent.completion.is_some());
    assert!(f.host.revision(&f.machine).is_err());
}

#[test]
fn execution_interruption_is_native_history_not_guest_exit_or_output_completion() {
    let mut f = Fixture::new();
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(1));
    assert_eq!(f.runtime.execution_ids().unwrap(), [f.process.clone()]);
    assert_eq!(f.runtime.execution_generation(&f.process).unwrap(), n(1));
    assert!(f.runtime.execution_interruption(n(1)).unwrap().is_none());
    f.runtime
        .append_output(&f.process, n(1), Stream::Stdout, b"captured before crash")
        .unwrap();
    let boundary = f.runtime.process_boundary(&f.process).unwrap();
    let mut observed = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    observed.sequence = n(4);
    observed.state = MachineState::Paused;
    observed.cause = ObservationCause::Native {};
    f.runtime.observe(observed.clone()).unwrap();
    assert!(f.runtime.execution_interruption(n(1)).unwrap().is_none());
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(1));
    observed.sequence = n(5);
    observed.state = MachineState::Running;
    f.runtime.observe(observed.clone()).unwrap();
    observed.sequence = n(6);
    observed.state = MachineState::Stopped;
    f.runtime.observe(observed.clone()).unwrap();
    assert_eq!(
        f.runtime.execution_interruption(n(1)).unwrap(),
        Some(observed.clone())
    );
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(0));
    // Free native execution capacity, not the interrupted capture promise.
    let mut envelope = resources();
    envelope.managed_executions = n(1);
    envelope.output_bytes = n(100);
    f.runtime.validate_resource_envelope(&envelope).unwrap();
    envelope.output_bytes = n(99);
    assert!(f.runtime.validate_resource_envelope(&envelope).is_err());
    // A capture admitted before termination may commit afterward. Its original
    // reservation remains available without resurrecting an execution slot.
    f.runtime
        .append_output(&f.process, n(2), Stream::Stdout, b"committed after stop")
        .unwrap();
    assert!(f.runtime.process_snapshot(&f.process).unwrap().is_none());
    assert!(f.runtime.receipt(&f.process).unwrap().is_none());
    assert_ne!(f.runtime.process_boundary(&f.process).unwrap(), boundary);
    assert_eq!(
        f.runtime
            .read_output(&f.process, Counter::ZERO, 128)
            .unwrap()
            .chunks[0]
            .bytes,
        b"captured before crash"
    );
    let stopped = observed.clone();
    observed.sequence = n(7);
    observed.generation = n(2);
    observed.state = MachineState::Starting;
    observed.cause = ObservationCause::Lifecycle {
        operation_id: "restart".try_into().unwrap(),
    };
    f.runtime.observe(observed.clone()).unwrap();
    observed.sequence = n(8);
    observed.state = MachineState::Running;
    f.runtime.observe(observed).unwrap();
    assert_eq!(
        f.runtime.execution_interruption(n(1)).unwrap(),
        Some(stopped.clone())
    );
    assert!(f.runtime.execution_interruption(n(2)).unwrap().is_none());
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(0));
    let command = process_command_in_generation(&f.command, "after-native-stop", n(900), n(2));
    f.runtime.admit(command.clone()).unwrap();
    f.runtime
        .admit_process(
            "after-native-stop".try_into().unwrap(),
            &command.operation_id,
            n(900),
            false,
        )
        .unwrap();
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(1));
    let overflow = process_command_in_generation(&f.command, "missing-output-headroom", n(1), n(2));
    f.runtime.admit(overflow.clone()).unwrap();
    assert!(
        f.runtime
            .admit_process(
                "missing-output-headroom".try_into().unwrap(),
                &overflow.operation_id,
                n(1),
                false
            )
            .is_err()
    );
    let boundary = f.runtime.process_boundary(&f.process).unwrap();
    let root = f.root.0.join("runtime");
    let machine = f.machine.clone();
    drop(f.runtime);
    let reopened = RuntimeJournal::open(&root, &machine).unwrap();
    assert_eq!(reopened.managed_execution_slots_held().unwrap(), n(1));
    assert_eq!(
        reopened.execution_interruption(n(1)).unwrap(),
        Some(stopped)
    );
    assert!(reopened.receipt(&f.process).unwrap().is_none());
    assert_eq!(reopened.process_boundary(&f.process).unwrap(), boundary);
}

#[test]
fn suspension_is_not_interruption_but_restore_fences_the_old_handle_generation() {
    let mut f = Fixture::new();
    let mut observed = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    observed.sequence = n(4);
    observed.state = MachineState::Suspended;
    observed.cause = ObservationCause::Lifecycle {
        operation_id: "suspend".try_into().unwrap(),
    };
    f.runtime.observe(observed.clone()).unwrap();
    assert!(f.runtime.execution_interruption(n(1)).unwrap().is_none());
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(1));
    observed.sequence = n(5);
    observed.state = MachineState::Restoring;
    observed.generation = n(2);
    f.runtime.observe(observed.clone()).unwrap();
    assert_eq!(
        f.runtime.execution_interruption(n(1)).unwrap(),
        Some(observed)
    );
    assert!(f.runtime.execution_interruption(n(2)).unwrap().is_none());
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(0));
}

#[test]
fn machine_restart_fences_old_generation_without_rewinding_history() {
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
    value.generation = n(2);
    f.runtime.observe(value.clone()).unwrap();
    value.sequence = n(6);
    value.state = MachineState::Running;
    f.runtime.observe(value).unwrap();
    let stale = rebind_command(&f.command, "stale-after-boot");
    let authorization = stale;
    assert!(f.runtime.admit(authorization).is_err());
}

#[test]
fn managed_admission_capacity_survives_management_loss_but_not_native_interruption() {
    let mut f = Fixture::new();
    for index in 0..7 {
        let name = format!("reserved-before-stop-{index}");
        let command = process_command(&f.command, &name, n(10), StdioMode::Pipes);
        f.runtime.admit(command.clone()).unwrap();
        f.runtime
            .admit_process(
                name.try_into().unwrap(),
                &command.operation_id,
                n(10),
                false,
            )
            .unwrap();
    }
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(8));
    assert!(f.runtime.process_snapshots().unwrap().is_empty());
    let command = process_command(&f.command, "one-too-many", n(1), StdioMode::Pipes);
    f.runtime.admit(command.clone()).unwrap();
    assert!(matches!(
        f.runtime.admit_process(
            "one-too-many".try_into().unwrap(),
            &command.operation_id,
            n(1),
            false
        ),
        Err(Error::Capacity("managed execution reservations exhausted"))
    ));
    let mut observed = f
        .runtime
        .last_observation()
        .unwrap()
        .unwrap()
        .value()
        .clone();
    observed.sequence = n(4);
    observed.state = MachineState::Stopped;
    observed.cause = ObservationCause::Native {};
    f.runtime.observe(observed.clone()).unwrap();
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(0));
    observed.sequence = n(5);
    observed.generation = n(2);
    observed.state = MachineState::Starting;
    observed.cause = ObservationCause::Lifecycle {
        operation_id: "cold-boot".try_into().unwrap(),
    };
    f.runtime.observe(observed.clone()).unwrap();
    observed.sequence = n(6);
    observed.state = MachineState::Running;
    f.runtime.observe(observed).unwrap();
    for index in 0..8 {
        let name = format!("reserved-after-stop-{index}");
        let command = process_command_in_generation(&f.command, &name, n(10), n(2));
        f.runtime.admit(command.clone()).unwrap();
        f.runtime
            .admit_process(
                name.try_into().unwrap(),
                &command.operation_id,
                n(10),
                false,
            )
            .unwrap();
    }
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(8));
    let mut envelope = resources();
    envelope.output_bytes = n(249); // Old capture promises: 170; new: 80.
    assert!(f.runtime.validate_resource_envelope(&envelope).is_err());
    envelope.output_bytes = n(250);
    f.runtime.validate_resource_envelope(&envelope).unwrap();
}

#[test]
fn independent_jobs_and_pty_streams_have_separate_reservations() {
    let mut f = Fixture::new();
    let command = process_command(&f.command, "terminal", n(200), StdioMode::Terminal);
    let authorization = command.clone();
    f.runtime.admit(authorization).unwrap();
    let terminal: ExecutionId = "terminal".try_into().unwrap();
    f.runtime
        .admit_process(terminal.clone(), &command.operation_id, n(200), true)
        .unwrap();
    dispatch(&mut f.runtime, &command);
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(2));
    assert!(
        f.runtime
            .append_output(&terminal, n(1), Stream::Stdout, b"wrong stream")
            .is_err()
    );
    f.runtime
        .append_output(&terminal, n(1), Stream::Terminal, b"shell prompt")
        .unwrap();
    f.terminal();
    assert_eq!(f.runtime.managed_execution_slots_held().unwrap(), n(1));
    f.runtime
        .append_output(&terminal, n(2), Stream::Terminal, b"still running")
        .unwrap();
    assert!(f.runtime.receipt(&terminal).unwrap().is_none());
}

#[test]
fn completed_jobs_return_unused_output_headroom_without_releasing_bytes() {
    let mut f = Fixture::new();
    for index in 0..12 {
        let identity = format!("short-job-{index}");
        let command = process_command(&f.command, &identity, n(100), StdioMode::Pipes);
        let authorization = command.clone();
        f.runtime.admit(authorization).unwrap();
        let process: ExecutionId = identity.try_into().unwrap();
        f.runtime
            .admit_process(process.clone(), &command.operation_id, n(100), false)
            .unwrap();
        dispatch(&mut f.runtime, &command);
        f.runtime
            .append_output(&process, n(1), Stream::Stdout, b"x")
            .unwrap();
        f.runtime
            .publish_receipt(
                &process,
                ExecutionOutcome::Exit { code: 0 },
                hash("reaped"),
                hash("accounted"),
            )
            .unwrap();
        assert_eq!(
            f.runtime.read_output(&process, n(0), 16).unwrap().chunks[0].bytes,
            b"x"
        );
    }
    let command = process_command(&f.command, "large-job", n(880), StdioMode::Pipes);
    let authorization = command.clone();
    f.runtime.admit(authorization).unwrap();
    f.runtime
        .admit_process(
            "large-job".try_into().unwrap(),
            &command.operation_id,
            n(880),
            false,
        )
        .unwrap();
    let excessive = process_command(&f.command, "too-large-job", n(10), StdioMode::Pipes);
    let authorization = excessive.clone();
    f.runtime.admit(authorization).unwrap();
    assert!(
        f.runtime
            .admit_process(
                "too-large-job".try_into().unwrap(),
                &excessive.operation_id,
                n(10),
                false,
            )
            .is_err()
    );
}

#[test]
fn confirmed_non_application_returns_output_reservation() {
    let mut f = Fixture::new();
    let failed = process_command(&f.command, "rejected-job", n(850), StdioMode::Pipes);
    let authorization = failed.clone();
    f.runtime.admit(authorization).unwrap();
    f.runtime
        .admit_process(
            "rejected-job".try_into().unwrap(),
            &failed.operation_id,
            n(850),
            false,
        )
        .unwrap();
    f.runtime
        .record_delivery(
            &failed.operation_id,
            &failed.request_digest,
            Delivery::NotApplied,
            Some(hash("rejected")),
        )
        .unwrap();
    let next = process_command(&f.command, "next-job", n(900), StdioMode::Pipes);
    let authorization = next.clone();
    f.runtime.admit(authorization).unwrap();
    f.runtime
        .admit_process(
            "next-job".try_into().unwrap(),
            &next.operation_id,
            n(900),
            false,
        )
        .unwrap();
}

// Invoked only by the parent test with its newly allocated private fixture directory.
#[test]
fn abrupt_writer_child() {
    let Some(root) = std::env::var_os("SANDSURF_TEST_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let machine: MachineId = "box".try_into().unwrap();
    let process: ExecutionId = "process".try_into().unwrap();
    let mode = std::env::var("SANDSURF_TEST_CRASH_MODE").unwrap();
    let mut runtime = RuntimeJournal::open(&root.join("runtime"), &machine).unwrap();
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
            fs::remove_file(
                root.join("runtime/output")
                    .join(bytes_digest(b"hello\0\xff").as_str()),
            )
            .unwrap();
            fs::File::open(root.join("runtime/output"))
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
        let mut runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
        if let Some(request) = release {
            let status = runtime.release(&f.process, request).unwrap();
            assert!(status.cleanup_pending);
            runtime
                .cleanup_released(&f.process, &status.request_digest)
                .unwrap();
            assert!(
                !path
                    .join("output")
                    .join(bytes_digest(b"hello\0\xff").as_str())
                    .exists()
            );
            assert!(
                !path
                    .join("output")
                    .join(bytes_digest(b"stderr").as_str())
                    .exists()
            );
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
                    .operation(&f.command.operation_id)
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
    let command = process_command(&f.command, "many-chunks", n(400), StdioMode::Pipes);
    let authorization = command.clone();
    f.runtime.admit(authorization).unwrap();
    let process: ExecutionId = "many-chunks".try_into().unwrap();
    f.runtime
        .admit_process(process.clone(), &command.operation_id, n(400), false)
        .unwrap();
    dispatch(&mut f.runtime, &command);
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
        let runtime = RuntimeJournal::open(&path, &f.machine).unwrap();
        assert_eq!(runtime.receipt(&f.process).unwrap(), Some(receipt));
        assert!(runtime.read_output(&f.process, n(0), 64).is_err());
    }
}
