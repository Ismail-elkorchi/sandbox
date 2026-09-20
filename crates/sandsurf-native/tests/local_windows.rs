#![cfg(windows)]

use sandsurf_native::local::{LocalConnection, LocalListener, create_private_directory};
use sandsurf_protocol::{AUTHENTICATION_BYTES, Counter, Frame, FrameKind};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(2);
static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ss-ipc-{}-{nonce:x}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn frame() -> Frame {
    Frame {
        kind: FrameKind::Data,
        stream: 7,
        sequence: Counter::ONE,
        authentication: [0; AUTHENTICATION_BYTES],
        payload: vec![0, 255, 0, 10, 128],
    }
}

#[test]
fn private_pipe_authenticates_both_peers_and_preserves_binary_frames() {
    let root = Root::new();
    let listener = LocalListener::bind(&root.0).unwrap();
    let mut client = LocalConnection::connect(&root.0, WAIT).unwrap();
    let mut server = listener.accept(WAIT).unwrap();
    assert_eq!(client.peer().process_id, std::process::id());
    assert_eq!(server.peer().process_id, std::process::id());
    client.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(server.read_frame(WAIT).unwrap(), Some(frame()));
    server.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(client.read_frame(WAIT).unwrap(), Some(frame()));
    listener.close().unwrap();
    client.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(server.read_frame(WAIT).unwrap(), Some(frame()));
}

#[test]
fn endpoint_lease_excludes_duplicate_owner_and_accept_timeout_is_recoverable() {
    let root = Root::new();
    let listener = LocalListener::bind(&root.0).unwrap();
    assert_eq!(
        LocalListener::bind(&root.0).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        listener
            .accept(Duration::from_millis(10))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let _client = LocalConnection::connect(&root.0, WAIT).unwrap();
    let _server = listener.accept(WAIT).unwrap();
}

#[test]
fn pipe_owner_fixture() {
    let Some(root) = std::env::var_os("SANDSURF_PIPE_TEST_ROOT") else {
        return;
    };
    let _listener = LocalListener::bind(&PathBuf::from(root)).unwrap();
    println!("SANDSURF_PIPE_READY");
    io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn crashed_pipe_owner_releases_lease_without_pid_guessing() {
    let root = Root::new();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "pipe_owner_fixture", "--nocapture"])
            .env("SANDSURF_PIPE_TEST_ROOT", &root.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let handshake = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line.unwrap() == "SANDSURF_PIPE_READY" {
                let _ = send.send(());
                return;
            }
        }
    });
    receive.recv_timeout(Duration::from_secs(5)).unwrap();
    handshake.join().unwrap();
    assert_eq!(
        LocalListener::bind(&root.0).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    LocalListener::bind(&root.0).unwrap().close().unwrap();
}
