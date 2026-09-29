use sandsurf_guest::{ExecutionRegistry, FilesystemService, ManagementService};
use sandsurf_protocol::*;
use sandsurf_protocol::{Counter, GuestPath, MachineId, SpawnRequest, StdioMode, bytes_digest};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let value = std::env::temp_dir().join(format!(
            "sandsurf-management-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&value).unwrap();
        Self(value)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn spawn_request(id: &str, script: &str) -> SpawnRequest {
    SpawnRequest {
        machine_id: MachineId::try_from("box").unwrap(),
        generation: Counter::ONE,
        execution_id: ExecutionId::try_from(id).unwrap(),
        operation_id: OperationId::try_from(format!("spawn-{id}")).unwrap(),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        cwd: "/".into(),
        environment: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        user: None,
        stdio: StdioMode::Pipes,
        terminal_size: None,
        active_deadline_millis: None,
        elapsed_deadline_unix_millis: None,
        output_bytes: Counter::try_from(1024 * 1024).unwrap(),
    }
}

#[test]
fn ordinary_filesystem_queries_do_not_create_a_parallel_capture_session() {
    let root = Temp::new();
    let files = root.0.join("files");
    fs::create_dir(&files).unwrap();
    fs::write(files.join("example"), b"captured").unwrap();
    let processes = ExecutionRegistry::create(
        &root.0.join("spool"),
        MachineId::try_from("box").unwrap(),
        Counter::ONE,
        std::path::Path::new(env!("CARGO_BIN_EXE_sandsurf-guest")),
    )
    .unwrap();
    let service = ManagementService::open(
        processes,
        FilesystemService::new(),
        &root.0.join("operations"),
    )
    .unwrap();
    let path = GuestPath::try_from(files.join("example").to_str().unwrap()).unwrap();
    assert!(matches!(
        service.handle(GuestServiceRequest::FilesystemQuery {
            request: FilesystemRequest::Stat { path: path.clone(), follow: true },
        }),
        GuestServiceResponse::File { response: FilesystemResponse::Stat { value } } if value.size == 8
    ));
    assert!(matches!(
        service.handle(GuestServiceRequest::FilesystemQuery {
            request: FilesystemRequest::Read { path, offset: 0, maximum: 64 },
        }),
        GuestServiceResponse::File { response: FilesystemResponse::Read { range } }
            if range.bytes == b"captured" && range.eof
    ));
    assert!(matches!(
        service.handle(GuestServiceRequest::FilesystemQuery {
            request: FilesystemRequest::Mkdir {
                path: GuestPath::try_from(files.join("forbidden").to_str().unwrap()).unwrap(),
                recursive: false,
            },
        }),
        GuestServiceResponse::Error { code, .. } if code == "request.invalid"
    ));
    assert!(!files.join("forbidden").exists());
}

#[test]
fn filesystem_operations_reconcile_exact_identity_without_reapplying() {
    let root = Temp::new();
    let files = root.0.join("files");
    let spool = root.0.join("spool");
    fs::create_dir(&files).unwrap();
    let processes = ExecutionRegistry::create(
        &spool,
        MachineId::try_from("box").unwrap(),
        Counter::ONE,
        std::path::Path::new(env!("CARGO_BIN_EXE_sandsurf-guest")),
    )
    .unwrap();
    let service = ManagementService::open(
        processes,
        FilesystemService::new(),
        &root.0.join("operations"),
    )
    .unwrap();
    let operation = OperationId::try_from("mkdir").unwrap();
    let request = FilesystemRequest::Mkdir {
        path: GuestPath::try_from(files.join("created").to_str().unwrap()).unwrap(),
        recursive: false,
    };
    let command = GuestCommand::new(
        MachineId::try_from("box").unwrap(),
        Counter::ONE,
        operation.clone(),
        GuestRequest::Filesystem {
            request: Box::new(request),
        },
    )
    .unwrap();
    let first = service.handle(GuestServiceRequest::Dispatch {
        command: command.clone(),
    });
    assert_eq!(
        first,
        service.handle(GuestServiceRequest::Operation {
            operation_id: operation.clone(),
            request_digest: command.request_digest.clone(),
        })
    );
    assert!(files.join("created").is_dir());

    drop(service);
    let reopened = ManagementService::open(
        ExecutionRegistry::create(
            &spool,
            MachineId::try_from("box").unwrap(),
            Counter::ONE,
            std::path::Path::new(env!("CARGO_BIN_EXE_sandsurf-guest")),
        )
        .unwrap(),
        FilesystemService::new(),
        &root.0.join("operations"),
    )
    .unwrap();
    assert_eq!(
        first,
        reopened.handle(GuestServiceRequest::Operation {
            operation_id: operation.clone(),
            request_digest: command.request_digest.clone(),
        })
    );

    let conflict = reopened.handle(GuestServiceRequest::Operation {
        operation_id: operation,
        request_digest: bytes_digest(b"different"),
    });
    assert!(
        matches!(conflict, GuestServiceResponse::Error { code, .. } if code == "operation.conflict")
    );
}

#[test]
fn process_secrets_are_cleaned_and_revocation_terminates_live_recipients() {
    let root = Temp::new();
    let files = root.0.join("files");
    let spool = root.0.join("spool");
    fs::create_dir(&files).unwrap();
    let service = ManagementService::open(
        ExecutionRegistry::create(
            &spool,
            MachineId::try_from("box").unwrap(),
            Counter::ONE,
            std::path::Path::new(env!("CARGO_BIN_EXE_sandsurf-guest")),
        )
        .unwrap(),
        FilesystemService::new(),
        &root.0.join("operations"),
    )
    .unwrap();
    let bytes = b"temporary-secret".to_vec();
    let secret = sandsurf_protocol::SecretVersion {
        id: SecretId::try_from("credential").unwrap(),
        version: "opaque-test-version".try_into().unwrap(),
        bytes: Counter::try_from(bytes.len() as u64).unwrap(),
    };
    let execution_id = ExecutionId::try_from("short-job").unwrap();
    let delivery = sandsurf_protocol::SecretDelivery {
        secret: secret.clone(),
        destination: SecretDestination::File {
            path: GuestPath::try_from(files.join("process-secret").to_str().unwrap()).unwrap(),
            mode: 0o600,
        },
        lifetime: SecretLifetime::Process,
        execution_id: Some(execution_id.clone()),
    };
    assert!(matches!(
        service.handle(GuestServiceRequest::InstallSecret {
            operation_id: OperationId::try_from("deliver-file").unwrap(),
            delivery,
            bytes: bytes.clone(),
        }),
        GuestServiceResponse::SecretInstalled { .. }
    ));
    spawn_managed(&service, spawn_request("short-job", "exit 0"));
    service
        .processes()
        .wait(&execution_id, Some(Duration::from_secs(5)))
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while files.join("process-secret").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!files.join("process-secret").exists());

    let holder = ExecutionId::try_from("secret-holder").unwrap();
    let environment_delivery = sandsurf_protocol::SecretDelivery {
        secret: secret.clone(),
        destination: SecretDestination::Environment {
            name: "TOKEN".into(),
        },
        lifetime: SecretLifetime::Process,
        execution_id: Some(holder.clone()),
    };
    assert!(matches!(
        service.handle(GuestServiceRequest::InstallSecret {
            operation_id: OperationId::try_from("deliver-environment").unwrap(),
            delivery: environment_delivery.clone(),
            bytes,
        }),
        GuestServiceResponse::SecretInstalled { .. }
    ));
    let spawn = spawn_request(
        "secret-holder",
        "test \"$TOKEN\" = temporary-secret; sleep 30",
    );
    spawn_managed(&service, spawn);
    let response = service.handle(GuestServiceRequest::RevokeSecret {
        operation_id: OperationId::try_from("revoke-environment").unwrap(),
        secret_id: secret.id,
        version: secret.version,
        deliveries: vec![environment_delivery],
        terminate_recipients: true,
    });
    let GuestServiceResponse::SecretCleanupReported { report: evidence } = response else {
        panic!("secret revocation failed: {response:?}");
    };
    assert!(evidence.actions_reported_complete);
    assert_eq!(evidence.recipients_terminated, vec![holder]);
    assert!(evidence.residual_copies_possible);
}
fn spawn_managed(service: &ManagementService, request: SpawnRequest) {
    let command = GuestCommand::new(
        request.machine_id.clone(),
        request.generation,
        request.operation_id.clone(),
        GuestRequest::Spawn {
            request: Box::new(request),
        },
    )
    .unwrap();
    assert!(matches!(
        service.handle(GuestServiceRequest::Dispatch { command }),
        GuestServiceResponse::Effect {
            outcome: GuestEffectOutcome::Applied { .. }
        }
    ));
}
