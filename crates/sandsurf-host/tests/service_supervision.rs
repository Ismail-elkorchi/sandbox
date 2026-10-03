//! Real native processes and IPC, without pretending to qualify virtualization.
use sandsurf_host::api::{HostRequest, HostResponse};
use sandsurf_host::service::host_call;
use sandsurf_host::supervision::{Request, call};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn process(mode: &str, directory: &Path) -> Process {
    Process(
        Command::new(env!("CARGO_BIN_EXE_sandsurf-host"))
            .arg(mode)
            .arg("--directory")
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

#[cfg(target_os = "linux")]
fn pool_stopped(root: &Path, pool: sandsurf_native::service_pool::ServicePool) -> bool {
    let unit = pool.unit(root).unwrap();
    !Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", &unit])
        .status()
        .unwrap()
        .success()
}
#[cfg(target_os = "linux")]
fn supervisor_owner(root: &Path) -> u32 {
    let unit = sandsurf_native::service_pool::ServicePool::Supervisor
        .unit(root)
        .unwrap();
    let output = Command::new("systemctl")
        .args(["--user", "show", "--property=MainPID", "--value", &unit])
        .output()
        .unwrap();
    assert!(output.status.success());
    let pid = std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    assert_ne!(pid, 0, "supervisor unit has no running native owner");
    pid
}
#[cfg(not(target_os = "linux"))]
fn supervisor_owner(root: &Path) -> u32 {
    sandsurf_native::local::LocalConnection::connect(
        &root.join("supervision"),
        Duration::from_secs(2),
    )
    .unwrap()
    .peer_process()
    .unwrap()
}
fn ready(mut operation: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !operation() {
        assert!(
            Instant::now() < deadline,
            "native service failed to publish its endpoint"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[cfg_attr(
    windows,
    ignore = "requires an independent Windows service owner, outside the CI runner Job"
)]
fn independently_owned_supervisor_survives_host_api_restart_and_rejects_unadmitted_launches() {
    #[cfg(target_os = "macos")]
    let parent = std::path::PathBuf::from("/tmp");
    #[cfg(not(target_os = "macos"))]
    let parent = std::env::temp_dir();
    let root = parent.join(format!(
        "sandsurf-service-contract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    sandsurf_native::local::create_private_directory(&root).unwrap();
    let mut supervisor = process("supervise", &root);
    let mut host = process("serve", &root);
    ready(|| call(&root, Request::Inspect).is_ok());
    ready(|| {
        host_call(
            &root,
            HostRequest::ListMachines {
                after: None,
                maximum: sandsurf_protocol::Counter::ONE,
            },
        )
        .is_ok()
    });
    let owner = supervisor_owner(&root);
    #[cfg(target_os = "macos")]
    {
        assert!(supervisor.0.wait().unwrap().success());
        assert!(host.0.wait().unwrap().success());
        assert_ne!(
            owner,
            supervisor.0.id(),
            "launcher is not the durable service owner"
        );
    }
    assert!(
        call(
            &root,
            Request::Ensure {
                machine: "not-admitted".try_into().unwrap()
            }
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(root.join("machines")).unwrap().count(), 0);
    let mut duplicate = process("supervise", &root);
    ready(|| duplicate.0.try_wait().unwrap().is_some());
    assert!(
        !duplicate.0.wait().unwrap().success(),
        "a second endpoint owner must not be admitted"
    );
    assert!(matches!(
        host_call(&root, HostRequest::StopService).unwrap(),
        HostResponse::Complete
    ));
    assert!(host.0.wait().unwrap().success());
    #[cfg(target_os = "linux")]
    ready(|| pool_stopped(&root, sandsurf_native::service_pool::ServicePool::Api));
    call(&root, Request::Inspect).unwrap();
    #[cfg(windows)]
    assert!(supervisor.0.try_wait().unwrap().is_none());
    let mut replacement = process("serve", &root);
    ready(|| {
        host_call(
            &root,
            HostRequest::ListMachines {
                after: None,
                maximum: sandsurf_protocol::Counter::ONE,
            },
        )
        .is_ok()
    });
    assert_eq!(supervisor_owner(&root), owner);
    #[cfg(target_os = "macos")]
    assert!(replacement.0.wait().unwrap().success());
    call(&root, Request::Inspect).unwrap();
    host_call(&root, HostRequest::StopService).unwrap();
    assert!(replacement.0.wait().unwrap().success());
    #[cfg(target_os = "linux")]
    ready(|| pool_stopped(&root, sandsurf_native::service_pool::ServicePool::Api));
    call(&root, Request::Shutdown).unwrap();
    assert!(supervisor.0.wait().unwrap().success());
    #[cfg(target_os = "linux")]
    ready(|| {
        pool_stopped(
            &root,
            sandsurf_native::service_pool::ServicePool::Supervisor,
        )
    });
    #[cfg(target_os = "macos")]
    ready(|| {
        sandsurf_native::local::LocalConnection::connect(
            &root.join("supervision"),
            Duration::from_secs(2),
        )
        .is_err()
    });
    drop((supervisor, host, replacement, duplicate));
    // Exact fixture directory only, after every process released its handles.
    fs::remove_dir_all(root).unwrap();
}
