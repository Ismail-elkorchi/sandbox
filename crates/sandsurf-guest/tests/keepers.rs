#![cfg(target_os = "linux")]

use sandsurf_guest::ExecutionRegistry;
use sandsurf_protocol::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "sandsurf-keepers-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn registry(root: &Path) -> ExecutionRegistry {
    ExecutionRegistry::create(
        root,
        "machine".try_into().unwrap(),
        Counter::ONE,
        Path::new(env!("CARGO_BIN_EXE_sandsurf-guest")),
    )
    .unwrap()
}
fn request(id: &str, script: &str, terminal: bool) -> SpawnRequest {
    SpawnRequest {
        machine_id: "machine".try_into().unwrap(),
        generation: Counter::ONE,
        execution_id: id.try_into().unwrap(),
        operation_id: format!("start-{id}").try_into().unwrap(),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        cwd: "/".into(),
        environment: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        user: None,
        stdio: if terminal {
            StdioMode::Terminal
        } else {
            StdioMode::Pipes
        },
        terminal_size: terminal.then_some(TerminalSize {
            columns: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        }),
        active_deadline_millis: None,
        elapsed_deadline_unix_millis: None,
        output_bytes: (1024 * 1024_u64).try_into().unwrap(),
    }
}
fn captured(registry: &ExecutionRegistry, id: &ExecutionId) -> Vec<u8> {
    let mut cursor = Counter::ZERO;
    let mut bytes = Vec::new();
    loop {
        let page = registry.read_output(id, cursor, MAX_STREAM_BYTES).unwrap();
        for chunk in page.chunks {
            cursor = cursor.checked_add(chunk.bytes.len() as u64).unwrap();
            bytes.extend(chunk.bytes);
        }
        if cursor == page.available {
            return bytes;
        }
    }
}

#[test]
fn management_owner_fixture() {
    let Some(root) = std::env::var_os("SANDSURF_KEEPER_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let executions = registry(&root.join("executions"));
    let pipe = request(
        "pipe",
        "printf before; read value; printf 'after:%s' \"$value\"",
        false,
    );
    let terminal = request(
        "terminal",
        "printf terminal-ready; read value; printf 'terminal-after:%s' \"$value\"",
        true,
    );
    executions.spawn(pipe).unwrap();
    executions.spawn(terminal).unwrap();
    executions
        .acquire_terminal_input(
            &"terminal".try_into().unwrap(),
            &"input-owner".try_into().unwrap(),
        )
        .unwrap();
    let children =
        fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id())).unwrap();
    fs::write(root.join("keeper-pids"), children).unwrap();
    fs::write(root.join("ready"), b"ready").unwrap();
    loop {
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn killing_management_preserves_independent_pipes_ptys_and_input_ownership() {
    let root = Temp::new();
    let mut management = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "management_owner_fixture", "--nocapture"])
        .env("SANDSURF_KEEPER_TEST_ROOT", &root.0)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.0.join("ready").exists() {
        assert!(
            management.try_wait().unwrap().is_none(),
            "management fixture failed"
        );
        assert!(
            Instant::now() < deadline,
            "keeper fixture readiness timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    management.kill().unwrap();
    management.wait().unwrap();
    let connected = registry(&root.0.join("executions"));
    let pipe: ExecutionId = "pipe".try_into().unwrap();
    let terminal: ExecutionId = "terminal".try_into().unwrap();
    assert!(matches!(
        connected.get(&pipe).unwrap().state,
        ExecutionState::Running
    ));
    assert!(matches!(
        connected.get(&terminal).unwrap().state,
        ExecutionState::Running
    ));
    assert!(
        connected
            .acquire_terminal_input(&terminal, &"competing-input".try_into().unwrap())
            .is_err()
    );
    connected
        .resize_terminal(
            &terminal,
            TerminalSize {
                columns: 120,
                rows: 40,
                pixel_width: 0,
                pixel_height: 0,
            },
        )
        .unwrap();
    connected
        .write_input(&pipe, None, b"pipe-reconnected\n")
        .unwrap();
    connected
        .write_input(
            &terminal,
            Some(&"input-owner".try_into().unwrap()),
            b"pty-reconnected\n",
        )
        .unwrap();
    connected.wait(&pipe, Some(Duration::from_secs(5))).unwrap();
    connected
        .wait(&terminal, Some(Duration::from_secs(5)))
        .unwrap();
    let pipe_bytes = captured(&connected, &pipe);
    let terminal_bytes = captured(&connected, &terminal);
    assert_eq!(pipe_bytes, b"beforeafter:pipe-reconnected");
    assert!(
        String::from_utf8(terminal_bytes.clone())
            .unwrap()
            .contains("terminal-after:pty-reconnected")
    );
    drop(connected);
    let archive = registry(&root.0.join("executions"));
    assert_eq!(captured(&archive, &pipe), pipe_bytes);
    assert_eq!(captured(&archive, &terminal), terminal_bytes);
}

#[test]
fn leader_exit_does_not_kill_background_descendants_or_claim_output_eof() {
    let root = Temp::new();
    let executions = registry(&root.0.join("executions"));
    let id: ExecutionId = "draining".try_into().unwrap();
    executions
        .spawn(request(
            "draining",
            "(sleep 0.3; printf descendant) & exit 0",
            false,
        ))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match executions.get(&id).unwrap().state {
            ExecutionState::Draining {
                outcome: ExecutionOutcome::Exit { code: 0 },
                ..
            } => break,
            state => {
                assert!(matches!(state, ExecutionState::Running));
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    assert_eq!(captured(&executions, &id), b"");
    executions.wait(&id, Some(Duration::from_secs(5))).unwrap();
    assert_eq!(captured(&executions, &id), b"descendant");
}

#[test]
fn keeper_death_is_capture_uncertainty_not_a_claim_that_linux_processes_stopped() {
    let root = Temp::new();
    let executions = registry(&root.0.join("executions"));
    let id: ExecutionId = "independent".try_into().unwrap();
    let snapshot = executions
        .spawn(request("independent", "exec sleep 30", false))
        .unwrap();
    let directory = root.0.join("executions/independent");
    let lock_inode =
        std::os::unix::fs::MetadataExt::ino(&fs::metadata(directory.join("keeper.lock")).unwrap());
    let locks = fs::read_to_string("/proc/locks").unwrap();
    let pid = locks
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() >= 6
                && fields[1] == "FLOCK"
                && fields[5].rsplit(':').next()?.parse::<u64>().ok()? == lock_inode
            {
                fields[4].parse::<i32>().ok()
            } else {
                None
            }
        })
        .expect("keeper holds its exclusive lock");
    // SAFETY: test obtains this keeper's actual kernel lock owner; no host VM
    // authority or guessed/PID-reused machine handle is involved.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(
            executions.get(&id).unwrap().state,
            ExecutionState::Unknown { .. }
        ) {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(Path::new(&format!("/proc/{}", snapshot.guest_pid)).exists());
    // Explicitly clean the intentionally surviving Linux workload fixture.
    // SAFETY: the PID comes from this fixture's observed live child, which is
    // still verified in /proc immediately before signaling it.
    assert_eq!(
        unsafe { libc::kill(snapshot.guest_pid as i32, libc::SIGKILL) },
        0
    );
}
