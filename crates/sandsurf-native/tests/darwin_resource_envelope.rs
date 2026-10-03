//! Ordinary Darwin kernel qualification, not VM/hardware qualification. CI
//! installs the example into the operator's fixed worker slot for this test,
//! restores the actual host afterwards, and never packages the fixture.
#![cfg(target_os = "macos")]
use sandsurf_native::process_budget::ProcessBudget;
use sandsurf_native::resource_broker::{
    WorkerExit, WorkerKind,
    macos::{launch, launch_images, launch_vm},
};
use std::fs;
use std::process::Stdio;
use std::time::{Duration, Instant};

#[test]
fn kernel_envelopes_apply_after_exec_and_service_lifetime_is_not_observer_lifetime() {
    if std::env::var_os("SANDSURF_DARWIN_RESOURCE_TEST").is_none() {
        return;
    }
    let root = std::env::temp_dir().join(format!("sandsurf-darwin-budget-{}", std::process::id()));
    sandsurf_native::local::ensure_private_directory(&root).unwrap();
    let budget = ProcessBudget {
        cpu_quota_micros: 25000,
        memory_bytes: 128 * 1024 * 1024,
        processes: 2,
    };
    let path = root.join("cpu.log");
    let output = sandsurf_native::local::create_private_file(&path).unwrap();
    let mut worker = launch(
        WorkerKind::Api,
        budget,
        &["cpu".into()],
        Stdio::null(),
        Stdio::from(output),
        Stdio::inherit(),
    )
    .unwrap();
    let usage = worker.usage().unwrap();
    assert!(usage.owner_start_ticks > 0);
    assert!(usage.worker_start_ticks > 0);
    assert!(usage.memory_current > 0);
    assert_eq!(worker.wait().unwrap(), WorkerExit::Exited(0));
    let cpu: Vec<u64> = fs::read_to_string(&path)
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect();
    assert_eq!(cpu.len(), 3);
    assert_eq!(cpu[2], 15000, "broker allowance was not subtracted");
    assert!(cpu[1] >= 5_000_000);
    assert!(cpu[0] > 100_000, "CPU fixture did not run");
    // One-second ledger interval plus scheduler measurement tolerance. A fully
    // unthrottled five-second spin is far outside this externally applied cap.
    assert!(
        cpu[0] <= cpu[1] * 15 / 100 + 350_000,
        "task CPU ledger did not throttle: {cpu:?}"
    );
    drop(worker);

    let mut worker = launch(
        WorkerKind::Api,
        budget,
        &["memory".into()],
        Stdio::null(),
        Stdio::null(),
        Stdio::inherit(),
    )
    .unwrap();
    assert_eq!(
        worker.wait().unwrap(),
        WorkerExit::Signaled(9),
        "kernel did not kill the owned worker at its fatal physical limit"
    );
    drop(worker);

    let retained = root.join("durable.txt");
    let worker = launch(
        WorkerKind::Api,
        budget,
        &["durable".into(), retained.clone().into_os_string()],
        Stdio::null(),
        Stdio::null(),
        Stdio::inherit(),
    )
    .unwrap();
    drop(worker);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !retained.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        fs::read(&retained).unwrap(),
        b"retained after observer disconnection"
    );

    let custody_path = root.join("disk.lock");
    let custody = sandsurf_native::local::create_private_file(&custody_path).unwrap();
    custody.try_lock().unwrap();
    let snapshot_path = root.join("snapshot.lock");
    let snapshot = sandsurf_native::storage::read_lease(&snapshot_path).unwrap();
    let mut worker = launch_vm(
        budget,
        &["owner-loss".into()],
        vec![std::sync::Arc::new(custody), std::sync::Arc::new(snapshot)],
        Stdio::inherit(),
    )
    .unwrap();
    assert!(worker.try_wait().unwrap().is_none());
    let competing = sandsurf_native::local::open_private_file(
        &custody_path,
        sandsurf_native::PrivateFileAccess::ReadWrite,
    )
    .unwrap();
    assert!(
        matches!(competing.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "observer released storage before native containment"
    );
    let snapshot_competing = sandsurf_native::local::open_private_file(
        &snapshot_path,
        sandsurf_native::PrivateFileAccess::ReadWrite,
    )
    .unwrap();
    assert!(matches!(
        snapshot_competing.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(sandsurf_native::storage::read_lease(&snapshot_path).unwrap());
    let start = Instant::now();
    worker.terminate().unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(worker.wait().unwrap(), WorkerExit::Signaled(9));
    drop(worker);
    competing.try_lock().unwrap();
    snapshot_competing.try_lock().unwrap();
    drop(snapshot_competing);
    drop(competing);
    let image_slot = root.join("image-pool.lock");
    let original = std::sync::Arc::new(sandsurf_native::storage::disk_lease(&image_slot).unwrap());
    assert!(
        launch(
            WorkerKind::Images,
            sandsurf_native::service_pool::ServicePool::Images.process_budget(),
            &[],
            Stdio::null(),
            Stdio::null(),
            Stdio::null()
        )
        .is_err()
    );
    let worker = launch_images(
        &["image-custody".into(), root.clone().into_os_string()],
        original,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !root.join("image-ready").exists() {
        assert!(
            Instant::now() < deadline,
            "image worker never verified inherited custody"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(worker);
    assert_eq!(
        sandsurf_native::storage::disk_lease(&image_slot)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock,
        "observer loss released a live durable image slot"
    );
    drop(sandsurf_native::local::create_private_file(&root.join("image-release")).unwrap());
    loop {
        match sandsurf_native::storage::disk_lease(&image_slot) {
            Ok(lease) => {
                drop(lease);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "image custody outlived native completion"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("image custody recovery failed: {error}"),
        }
    }
    // Only these test-owned small files are deleted; no machine/output data.
    for file in [
        path,
        retained,
        custody_path,
        snapshot_path,
        image_slot,
        root.join("image-ready"),
        root.join("image-release"),
    ] {
        fs::remove_file(file).unwrap();
    }
    fs::remove_dir(&root).unwrap();
}
