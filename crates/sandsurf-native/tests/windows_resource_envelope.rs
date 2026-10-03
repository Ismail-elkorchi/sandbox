//! Ordinary Windows kernel tests. No WHPX/VM qualification is implied.
#![cfg(windows)]
use sandsurf_native::{owned_windows::OwnedWorker, process_budget::ProcessBudget};
use std::path::PathBuf;
use std::time::{Duration, Instant};
#[path = "support/windows_isolation.rs"]
mod isolation_fixture;

fn fixture() -> Option<PathBuf> {
    std::env::var_os("SANDSURF_WINDOWS_RESOURCE_TEST").map(|_| {
        std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/windows-budget-worker.exe")
    })
}
fn budget() -> ProcessBudget {
    ProcessBudget {
        cpu_quota_micros: 25000,
        memory_bytes: 64 * 1024 * 1024,
        processes: 1,
    }
}

#[test]
fn self_owned_factory_job_retains_limits_until_actual_process_failure_exit() {
    let Some(executable) = fixture() else {
        return;
    };
    let status = std::process::Command::new(executable)
        .arg("self-envelope-error")
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(101),
        "self-owned Job close replaced the real failure status"
    );
}

#[test]
fn scope_recovery_preserves_unknown_bytes_before_reclaiming_any_input() {
    let Some(executable) = fixture() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("ss-rec-{}", std::process::id()));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    let isolation = isolation_fixture::seal(&root, &executable);
    let kernel = isolation.kernel().to_owned();
    let original = std::fs::read(&kernel).unwrap();
    let scope = isolation.namespace().path().parent().unwrap().to_owned();
    let unknown = scope.join("retain.receipt");
    std::fs::write(&unknown, b"not owned by native cleanup").unwrap();
    drop(isolation);
    assert!(sandsurf_native::windows_vmm::reclaim(&root).is_err());
    assert_eq!(std::fs::read(&kernel).unwrap(), original);
    assert_eq!(
        std::fs::read(&unknown).unwrap(),
        b"not owned by native cleanup"
    );
    std::fs::remove_file(unknown).unwrap();
    sandsurf_native::windows_vmm::reclaim(&root).unwrap();
    assert!(!scope.exists());
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn lpac_denies_host_files_native_children_and_ip_but_admits_original_device_scope() {
    let Some(executable) = fixture() else {
        return;
    };
    use std::io::{Read, Write};
    let root = std::env::temp_dir().join(format!("ss-lpc-{}", std::process::id()));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    let host_secret = root.join("host.secret");
    let mut secret = sandsurf_native::local::create_private_file(&host_secret).unwrap();
    secret.write_all(b"host-owned bytes").unwrap();
    drop(secret);
    let host_socket =
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    host_socket
        .bind(&socket2::SockAddr::unix(host_secret.with_extension("sock")).unwrap())
        .unwrap();
    host_socket.listen(1).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let disks = std::array::from_fn(|slot| {
        let path = root.join(format!("disk-{slot}"));
        let file = sandsurf_native::local::create_private_file(&path).unwrap();
        file.set_len(4096).unwrap();
        drop(file);
        sandsurf_native::owned_windows::disk_input(&path, slot == 1).unwrap()
    });
    let lease = sandsurf_native::storage::disk_lease(&root.join("disk.lock")).unwrap();
    let isolation = isolation_fixture::seal(&root, &executable);
    let namespace = isolation.namespace();
    let device = namespace.path().join("console.sock");
    assert!(
        sandsurf_native::local::Directory::open(namespace.path()).is_err(),
        "a VMM scope was admitted as a private host store"
    );
    let arguments = [
        "confinement".into(),
        host_secret.into_os_string(),
        isolation.kernel().as_os_str().to_owned(),
        namespace.path().as_os_str().to_owned(),
        port.to_string().into(),
    ];
    let mut worker = OwnedWorker::launch_vm(
        isolation.executable(),
        &arguments,
        budget(),
        vec![std::sync::Arc::new(lease)],
        disks,
        isolation.clone(),
    )
    .unwrap();
    // Another owner must not reclaim a scope whose original native child lives.
    sandsurf_native::windows_vmm::reclaim(&root).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connection = loop {
        match sandsurf_native::socket_io::SocketConnection::connect_in(
            &namespace,
            &device,
            worker.process_id(),
            Duration::from_secs(1),
        ) {
            Ok(connection) => break connection,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                assert!(
                    Instant::now() < deadline,
                    "scoped fixture device did not become ready"
                );
                assert!(
                    worker.try_wait().unwrap().is_none(),
                    "scoped fixture failed before device readiness"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("native scoped attachment failed: {error}"),
        }
    };
    assert!(sandsurf_native::socket_io::SocketNamespace::private(namespace.path()).is_err());
    connection.write_all(b"scope").unwrap();
    let mut reply = [0u8; 2];
    connection.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"ok");
    assert_eq!(worker.wait_for(Duration::from_secs(5)).unwrap(), Some(0));
    drop(connection);
    drop(worker);
    drop(isolation);
    assert_eq!(
        namespace.check().unwrap_err().kind(),
        std::io::ErrorKind::NotConnected
    );
    assert!(
        !device.parent().unwrap().exists(),
        "ended native scope was retained"
    );
    assert_eq!(
        std::fs::read(root.join("host.secret")).unwrap(),
        b"host-owned bytes"
    );
    drop(host_socket);
    drop(listener);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn original_disk_handles_keep_exact_bytes_and_read_only_access_in_the_native_child() {
    let Some(executable) = fixture() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("ss-dsk-{}", std::process::id()));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    let disks = std::array::from_fn(|slot| {
        let path = root.join(format!("disk-{slot}"));
        let file = sandsurf_native::local::create_private_file(&path).unwrap();
        file.set_len(4096).unwrap();
        drop(file);
        sandsurf_native::owned_windows::disk_input(&path, slot == 1).unwrap()
    });
    let lease = sandsurf_native::storage::disk_lease(&root.join("disk.lock")).unwrap();
    let isolation = isolation_fixture::seal(&root, &executable);
    let namespace = isolation.namespace();
    let mut worker = OwnedWorker::launch_vm(
        isolation.executable(),
        &["disk-access".into()],
        budget(),
        vec![std::sync::Arc::new(lease)],
        disks,
        isolation.clone(),
    )
    .unwrap();
    assert_eq!(worker.wait_for(Duration::from_secs(5)).unwrap(), Some(0));
    assert_eq!(std::fs::read(root.join("disk-0")).unwrap(), [42; 4096]);
    assert_eq!(std::fs::read(root.join("disk-1")).unwrap(), [0; 4096]);
    drop(worker);
    drop(isolation);
    assert_eq!(
        namespace.check().unwrap_err().kind(),
        std::io::ErrorKind::NotConnected
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn kernel_limits_precede_execution_and_native_exit_259_is_not_running() {
    let Some(executable) = fixture() else {
        return;
    };
    let mut worker = OwnedWorker::launch(&executable, &["exit259".into()], budget()).unwrap();
    assert_eq!(worker.wait_for(Duration::from_secs(5)).unwrap(), Some(259));
    assert_eq!(worker.try_wait().unwrap(), Some(259));
    worker.terminate().unwrap();
    drop(worker);

    let start = Instant::now();
    let mut worker = OwnedWorker::launch(&executable, &["spin".into()], budget()).unwrap();
    let live = worker.usage().unwrap();
    assert!(live.current_private_commit.unwrap() > 0);
    assert!(live.process_creation_time.unwrap() > 0);
    assert_eq!(worker.wait_for(Duration::from_secs(15)).unwrap(), Some(0));
    let elapsed = start.elapsed().as_micros() as u64;
    // Native process exit and aggregate Job accounting are distinct kernel
    // observations. Keep querying this original Job until its counter settles.
    let deadline = Instant::now() + Duration::from_secs(5);
    let usage = loop {
        let usage = worker.usage().unwrap();
        if usage.active_processes == 0 {
            break usage;
        }
        assert!(
            Instant::now() < deadline,
            "original Job never observed exit: {usage:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(usage.cpu_micros > 100000, "CPU fixture did not run");
    assert!(
        usage.cpu_micros <= elapsed / 4 + 350000,
        "CPU cap did not throttle: {usage:?}"
    );
    assert_eq!(usage.active_processes, 0);
    assert_eq!(usage.total_processes, 1);
    assert!(usage.current_private_commit.is_none());
    drop(worker);

    let mut worker = OwnedWorker::launch(&executable, &["memory".into()], budget()).unwrap();
    let exit = worker.wait_for(Duration::from_secs(5)).unwrap().unwrap();
    assert_ne!(exit, 0);
    assert_ne!(exit, 99, "native allocation escaped the private commit cap");
    assert!(worker.usage().unwrap().peak_private_commit <= budget().memory_bytes);
    drop(worker);

    let mut worker = OwnedWorker::launch(&executable, &["no-child".into()], budget()).unwrap();
    assert_eq!(worker.wait_for(Duration::from_secs(5)).unwrap(), Some(0));
    assert_eq!(worker.usage().unwrap().total_processes, 1);
}

#[test]
fn native_custody_survives_parent_descriptors_and_job_owner_death_contains_child() {
    let Some(executable) = fixture() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("ss-cst-{}", std::process::id()));
    sandsurf_native::local::ensure_private_directory(&root).unwrap();
    let lock = root.join("disk.lock");
    let parent = sandsurf_native::storage::disk_lease(&lock).unwrap();
    let native = parent.try_clone().unwrap();
    drop(parent);
    assert_eq!(
        sandsurf_native::storage::disk_lease(&lock)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(native);
    drop(sandsurf_native::storage::disk_lease(&lock).unwrap());

    // This is an actual process/Job boundary, not an in-process Drop test. The
    // fixture inherits disk and snapshot objects into its contained native worker.
    let mut owner = std::process::Command::new(executable)
        .arg("owner")
        .arg(&root)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.join("ready").exists() {
        assert!(Instant::now() < deadline, "owned worker never became ready");
        assert!(owner.try_wait().unwrap().is_none(), "worker factory failed");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        sandsurf_native::storage::disk_lease(&lock)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    let snapshot = root.join("snapshot.lock");
    assert_eq!(
        sandsurf_native::storage::disk_lease(&snapshot)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(sandsurf_native::storage::read_lease(&snapshot).unwrap());
    owner.kill().unwrap();
    owner.wait().unwrap();
    loop {
        match sandsurf_native::storage::disk_lease(&lock) {
            Ok(lease) => {
                drop(lease);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "native worker outlived its owned Job"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("native custody recovery failed: {error}"),
        }
    }
    drop(sandsurf_native::storage::disk_lease(&snapshot).unwrap());
    sandsurf_native::windows_vmm::reclaim(&root).unwrap();
    for slot in 0..2 {
        std::fs::remove_file(root.join(format!("io-{slot}"))).unwrap();
    }
    // Only this fixture's exact files; no machine or retained output is erased.
    std::fs::remove_file(root.join("ready")).unwrap();
    std::fs::remove_file(lock).unwrap();
    std::fs::remove_file(snapshot).unwrap();
    std::fs::remove_dir(root).unwrap();
}
