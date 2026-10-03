//! Ordinary Windows kernel tests. No WHPX/VM qualification is implied.
#![cfg(windows)]
use sandsurf_native::{owned_windows::OwnedWorker, process_budget::ProcessBudget};
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
fn original_disk_handles_keep_exact_bytes_and_read_only_access_in_the_native_child() {
    let Some(executable) = fixture() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("sandsurf-disk-input-{}", std::process::id()));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    let disks = std::array::from_fn(|slot| {
        let path = root.join(format!("disk-{slot}"));
        let file = sandsurf_native::local::create_private_file(&path).unwrap();
        file.set_len(4096).unwrap();
        drop(file);
        sandsurf_native::owned_windows::disk_input(&path, slot == 1).unwrap()
    });
    let lease = sandsurf_native::storage::disk_lease(&root.join("disk.lock")).unwrap();
    let mut worker = OwnedWorker::launch_vm(
        &executable,
        &["disk-access".into()],
        budget(),
        vec![std::sync::Arc::new(lease)],
        disks,
    )
    .unwrap();
    assert_eq!(worker.wait_for(Duration::from_secs(5)).unwrap(), Some(0));
    assert_eq!(std::fs::read(root.join("disk-0")).unwrap(), [42; 4096]);
    assert_eq!(std::fs::read(root.join("disk-1")).unwrap(), [0; 4096]);
    drop(worker);
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
    let usage = worker.usage().unwrap();
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
    let root =
        std::env::temp_dir().join(format!("sandsurf-windows-custody-{}", std::process::id()));
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
    // Only this test's three tiny files; no machine or retained output is erased.
    std::fs::remove_file(root.join("ready")).unwrap();
    std::fs::remove_file(lock).unwrap();
    std::fs::remove_file(snapshot).unwrap();
    std::fs::remove_dir(root).unwrap();
}
