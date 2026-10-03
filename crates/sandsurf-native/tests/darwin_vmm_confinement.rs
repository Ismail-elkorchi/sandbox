//! The real C entry gate and Darwin kernel policy, without HVF hardware.
#![cfg(target_os = "macos")]
use sandsurf_native::darwin_vmm::Files;
use sandsurf_native::process_budget::ProcessBudget;
use sandsurf_native::resource_broker::{WorkerExit, macos::launch_vm};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn actual_vmm_gate_denies_host_files_and_network_outside_its_footprint() {
    if std::env::var_os("SANDSURF_DARWIN_VMM_TEST").is_none() {
        return;
    }
    let root =
        std::path::Path::new("/private/tmp").join(format!("ssfc-{}-\"(q)\\", std::process::id()));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    let disk = root.join("disk.raw");
    let input = root.join("kernel");
    let hidden = root.join("host-signing-key");
    for path in [&disk, &input, &hidden] {
        let mut file = sandsurf_native::local::create_private_file(path).unwrap();
        file.write_all(b"R").unwrap();
        file.sync_all().unwrap();
    }
    let endpoints = root.join("devices");
    let captures = root.join("captures");
    let operation = captures.join(sandsurf_native::storage::object_name("confinement"));
    for directory in [&endpoints, &captures, &operation] {
        sandsurf_native::local::create_private_directory(directory).unwrap();
    }
    let capture = operation.join("snapshot.vmstate");
    let record = operation.join("capture.json");
    let endpoint = endpoints.join("control.sock");
    let other = root.join("unrelated.sock");
    let unrelated = UnixListener::bind(&other).unwrap();
    let profile = Files {
        read_only: vec![input.clone()],
        disk: disk.clone(),
        endpoints: endpoints.clone(),
        captures: captures.clone(),
    }
    .profile()
    .unwrap();
    let lease_path = root.join("custody.lock");
    let custody = Arc::new(sandsurf_native::storage::disk_lease(&lease_path).unwrap());
    let mut arguments = vec!["--sandsurf-seatbelt".into(), profile.into()];
    arguments.extend(
        [&disk, &input, &hidden, &capture, &record, &endpoint, &other]
            .into_iter()
            .map(|path| path.as_os_str().to_owned()),
    );
    let mut worker = launch_vm(
        ProcessBudget {
            cpu_quota_micros: 100000,
            memory_bytes: 128 * 1024 * 1024,
            processes: 2,
        },
        &arguments,
        vec![custody],
        Stdio::inherit(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connection = loop {
        if let Some(exit) = worker.try_wait().unwrap() {
            panic!("native entry failed before endpoint readiness: {exit:?}");
        }
        match UnixStream::connect(&endpoint) {
            Ok(connection) => break connection,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("private endpoint failed: {error}"),
        }
    };
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    connection.write_all(b"P").unwrap();
    let mut acknowledged = [0];
    connection.read_exact(&mut acknowledged).unwrap();
    assert_eq!(acknowledged, *b"A");
    assert_eq!(worker.wait().unwrap(), WorkerExit::Exited(0));
    assert_eq!(fs::read(&disk).unwrap(), b"D");
    assert_eq!(fs::read(&capture).unwrap(), b"S");
    assert_eq!(fs::read(&input).unwrap(), b"R");
    assert_eq!(fs::read(&hidden).unwrap(), b"R");
    assert!(!record.exists());
    drop(connection);
    drop(worker);
    drop(unrelated);
    // Exact small test-owned objects only; no VM or retained agent data.
    for path in [disk, input, hidden, capture, endpoint, other, lease_path] {
        fs::remove_file(path).unwrap();
    }
    for directory in [operation, captures, endpoints, root] {
        fs::remove_dir(directory).unwrap();
    }
}
