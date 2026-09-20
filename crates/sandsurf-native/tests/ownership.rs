#![cfg(target_os = "linux")]

use sandsurf_native::linux::*;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct KillOnDrop(File);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = kill_process(&self.0);
    }
}
fn fixture(mode: &str) -> ChildGuard {
    ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_owner_fixture", "--nocapture"])
            .env("SANDSURF_NATIVE_TEST_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}
fn ready(child: &mut Child) -> u32 {
    let output = child.stdout.as_mut().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::new();
    let mut byte = [0u8];
    loop {
        assert!(Instant::now() < deadline, "fixture handshake timed out");
        assert!(bytes.len() < 1024, "fixture handshake exceeded bound");
        let mut event = libc::pollfd {
            fd: output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd names the live child's stdout pipe and the wait is bounded.
        let result = unsafe { libc::poll(&mut event, 1, 100) };
        assert!(result >= 0);
        if result == 0 {
            continue;
        }
        assert_eq!(
            output.read(&mut byte).unwrap(),
            1,
            "fixture ended before readiness"
        );
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            if let Some(value) = String::from_utf8_lossy(&bytes)
                .trim()
                .strip_prefix("SANDSURF_READY=")
            {
                return value.parse().unwrap();
            }
            bytes.clear();
        }
    }
}

#[test]
fn native_owner_fixture() {
    let Ok(mode) = std::env::var("SANDSURF_NATIVE_TEST_MODE") else {
        return;
    };
    if mode == "bound" {
        bind_lifetime_to_parent().unwrap();
        println!("SANDSURF_READY={}", std::process::id());
        std::io::stdout().flush().unwrap();
        // Parent death must terminate this process, not just close an input pipe.
        loop {
            std::thread::park();
        }
    }
    if mode == "owner" {
        let mut child = fixture("bound");
        let pid = ready(&mut child.0);
        println!("SANDSURF_READY={pid}");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        BufReader::new(std::io::stdin())
            .read_line(&mut line)
            .unwrap();
        return;
    }
    if mode == "descriptors" {
        let file = File::open("/dev/null").unwrap();
        // SAFETY: F_DUPFD creates a separate descriptor above the test harness range.
        let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 200) };
        assert!(duplicate >= 200);
        prepare_descriptors_for_exec().unwrap();
        // SAFETY: read flags and close precisely the duplicate created above.
        let flags = unsafe { libc::fcntl(duplicate, libc::F_GETFD) };
        // SAFETY: this test owns the duplicated descriptor and closes it once.
        unsafe { libc::close(duplicate) };
        assert!(flags & libc::FD_CLOEXEC != 0);
        return;
    }
    panic!("unknown native fixture mode");
}

#[test]
fn owner_death_stops_its_bound_child_without_cooperative_io() {
    let mut owner = fixture("owner");
    let pid = ready(&mut owner.0);
    let child = KillOnDrop(open_pidfd(pid).unwrap());
    assert!(!process_exited(&child.0).unwrap());
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    assert!(wait_process_exit(&child.0, Duration::from_secs(5)).unwrap());
    assert!(process_exited(&child.0).unwrap());
}

#[test]
fn retained_process_signaling_does_not_affect_a_sibling() {
    let mut first = fixture("bound");
    let a = KillOnDrop(open_pidfd(ready(&mut first.0)).unwrap());
    let mut sibling = fixture("bound");
    let b = KillOnDrop(open_pidfd(ready(&mut sibling.0)).unwrap());
    assert!(!wait_process_exit(&a.0, Duration::from_millis(10)).unwrap());
    kill_process(&a.0).unwrap();
    assert!(wait_process_exit(&a.0, Duration::from_secs(5)).unwrap());
    first.0.wait().unwrap();
    assert!(!process_exited(&b.0).unwrap());
    kill_process(&a.0).unwrap(); // Idempotent observation of the retired identity.
    assert!(!process_exited(&b.0).unwrap());
}

#[test]
fn ordinary_descriptors_cannot_be_treated_as_process_exit_evidence() {
    let ordinary = File::open("/dev/null").unwrap();
    assert!(process_exited(&ordinary).is_err());
    assert!(kill_process(&ordinary).is_err());
    assert!(wait_process_exit(&ordinary, Duration::from_millis(1)).is_err());
    assert!(bind_to_retained_parent(&ordinary).is_err());
    assert!(open_pidfd(0).is_err());
    assert!(open_pidfd(u32::MAX).is_err());
}

#[test]
fn owned_pipes_and_exec_cleanup_exclude_ambient_descriptors() {
    let (mut reader, mut writer) = pipe_cloexec().unwrap();
    for fd in [reader.as_raw_fd(), writer.as_raw_fd()] {
        // SAFETY: both descriptors are live owned pipe ends; F_GETFD reads flags only.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    writer.write_all(b"\0\xff").unwrap();
    drop(writer);
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, b"\0\xff");
    let mut child = fixture("descriptors");
    assert!(child.0.wait().unwrap().success());
}
