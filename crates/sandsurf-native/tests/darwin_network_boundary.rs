//! Production root factory and PF observation, independent of HVF hardware.
#![cfg(target_os = "macos")]
#[path = "support/network_boundary.rs"]
mod boundary;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Owner(Child);
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires root, installed source-built host and the exclusive PF test profile"]
fn production_factory_observes_policy_and_enforces_socket_custody() {
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let executable = format!("/usr/local/libexec/sandsurf/sandsurf-host-macos-{arch}");
    let mut owner = Owner(
        Command::new(executable)
            .arg("--native-network-sockets")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            owner.0.try_wait().unwrap().is_none(),
            "native socket owner exited"
        );
        if sandsurf_native::network_sockets::probe().is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "production socket owner never admitted the PF boundary"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let observed = sandsurf_native::network_sockets::observe_boundary().unwrap();
    assert_eq!(
        observed,
        sandsurf_native::network_sockets::observe_boundary().unwrap()
    );
    boundary::original_sockets_deny_local_delivery_and_allow_public_tcp();
}
