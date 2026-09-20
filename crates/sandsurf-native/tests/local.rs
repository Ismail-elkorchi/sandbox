#![cfg(any(target_os = "linux", target_os = "macos"))]

use sandsurf_native::local::{LocalConnection, LocalListener};
use sandsurf_protocol::{
    Counter, Frame, FrameKind, HEADER_BYTES, MAX_CONTROL_BYTES, MAX_STREAM_BYTES,
};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(2);
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        // Use a short private test root: macOS TMPDIR often exceeds AF_UNIX's
        // path bound. Exclusive mkdir never adopts an existing directory.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from("/tmp").join(format!(
            "ss-ipc-{}-{nonce:x}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("control.sock")
    }
    fn lease(&self) -> PathBuf {
        self.0.join("control.lock")
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
        payload: vec![0, 255, 0, 10, 128],
    }
}
fn current_uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}

#[test]
fn private_endpoint_authenticates_both_peers_and_preserves_binary_frames() {
    let root = Root::new();
    let listener = LocalListener::bind(&root.0).unwrap();
    assert_eq!(fs::metadata(root.socket()).unwrap().mode() & 0o777, 0o600);
    let mut client = LocalConnection::connect(&root.0, WAIT).unwrap();
    let mut server = listener.accept(WAIT).unwrap();
    assert_eq!(client.peer().uid, current_uid());
    assert_eq!(server.peer().uid, current_uid());
    client.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(server.read_frame(WAIT).unwrap(), Some(frame()));
    server.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(client.read_frame(WAIT).unwrap(), Some(frame()));
    // Listener lifetime is separate from established connections and VM lifetime.
    listener.close().unwrap();
    assert!(!root.socket().exists());
    client.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(server.read_frame(WAIT).unwrap(), Some(frame()));
}

#[test]
fn endpoint_lease_prevents_duplicate_listeners_and_supports_orderly_reopen() {
    let root = Root::new();
    let listener = LocalListener::bind(&root.0).unwrap();
    let socket = fs::symlink_metadata(root.socket()).unwrap().ino();
    let error = LocalListener::bind(&root.0).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(fs::symlink_metadata(root.socket()).unwrap().ino(), socket);
    let _client = LocalConnection::connect(&root.0, WAIT).unwrap();
    let _server = listener.accept(WAIT).unwrap();
    listener.close().unwrap();
    assert!(root.lease().exists()); // Never unlink/recreate a lock file on release.
    LocalListener::bind(&root.0).unwrap().close().unwrap();
}

#[test]
fn ipc_owner_fixture() {
    let Some(root) = std::env::var_os("SANDSURF_IPC_TEST_ROOT") else {
        return;
    };
    let _listener = LocalListener::bind(&PathBuf::from(root)).unwrap();
    println!("SANDSURF_IPC_READY");
    io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn closed_peer_signal_fixture() {
    let Some(root) = std::env::var_os("SANDSURF_IPC_SIGNAL_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let listener = LocalListener::bind(&root).unwrap();
    let mut client = LocalConnection::connect(&root, WAIT).unwrap();
    let server = listener.accept(WAIT).unwrap();
    drop(server);
    // SAFETY: this isolated fixture process owns its signal policy. Restoring
    // SIGPIPE's default disposition tests the transport, not Rust's ignored signal.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    assert!(client.write_frame(&frame(), WAIT).is_err());
}

#[test]
fn closed_peer_is_an_io_error_even_with_default_sigpipe_disposition() {
    let root = Root::new();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "closed_peer_signal_fixture", "--nocapture"])
            .env("SANDSURF_IPC_SIGNAL_TEST_ROOT", &root.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    assert!(child.0.wait().unwrap().success());
}

#[test]
fn crashed_endpoint_owner_is_recovered_without_pid_guessing() {
    let root = Root::new();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ipc_owner_fixture", "--nocapture"])
            .env("SANDSURF_IPC_TEST_ROOT", &root.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let handshake = std::thread::spawn(move || {
        for line in BufReader::new(stdout.take(1024)).lines() {
            if line.unwrap() == "SANDSURF_IPC_READY" {
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
    assert!(root.socket().exists()); // SIGKILL did not run socket cleanup.
    let listener = LocalListener::bind(&root.0).unwrap();
    let mut client = LocalConnection::connect(&root.0, WAIT).unwrap();
    let mut server = listener.accept(WAIT).unwrap();
    client.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(server.read_frame(WAIT).unwrap(), Some(frame()));
}

#[test]
fn insecure_roots_and_root_aliases_are_rejected_without_chmod_or_creation() {
    let root = Root::new();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(LocalListener::bind(&root.0).is_err());
    assert_eq!(fs::metadata(&root.0).unwrap().mode() & 0o777, 0o755);
    assert!(!root.lease().exists());
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let aliases = Root::new();
    symlink(&root.0, aliases.0.join("alias")).unwrap();
    assert!(LocalListener::bind(&aliases.0.join("alias")).is_err());
    assert!(!root.lease().exists());
    // /tmp itself may be a system ancestor alias on macOS; the real final root works.
    LocalListener::bind(&root.0).unwrap().close().unwrap();
}

#[test]
fn private_root_below_a_replaceable_ancestor_is_rejected() {
    let root = Root::new();
    let slot = root.0.join("slot");
    fs::DirBuilder::new().mode(0o700).create(&slot).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(LocalListener::bind(&slot).is_err());
    assert!(!slot.join("control.lock").exists());
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    LocalListener::bind(&slot).unwrap().close().unwrap();
}

#[test]
fn socket_and_lease_aliases_foreign_files_and_hardlinks_are_not_adopted() {
    for target in ["control.sock", "control.lock"] {
        let root = Root::new();
        let outside = Root::new();
        let original = outside.0.join("original");
        fs::write(&original, b"retained").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&original, root.0.join(target)).unwrap();
        assert!(LocalListener::bind(&root.0).is_err());
        assert_eq!(fs::read(&original).unwrap(), b"retained");
        assert!(
            fs::symlink_metadata(root.0.join(target))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    let root = Root::new();
    fs::write(root.socket(), b"not a socket").unwrap();
    assert!(LocalListener::bind(&root.0).is_err());
    assert_eq!(fs::read(root.socket()).unwrap(), b"not a socket");
    let root = Root::new();
    fs::write(root.lease(), b"lease").unwrap();
    fs::set_permissions(root.lease(), fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(root.lease(), root.0.join("alias")).unwrap();
    assert!(LocalListener::bind(&root.0).is_err());
    assert_eq!(fs::read(root.lease()).unwrap(), b"lease");
}

#[test]
fn replaced_socket_or_lease_is_not_removed_by_old_owner_cleanup() {
    for replaced in ["control.sock", "control.lock"] {
        let root = Root::new();
        let listener = LocalListener::bind(&root.0).unwrap();
        fs::rename(root.0.join(replaced), root.0.join("previous")).unwrap();
        fs::write(root.0.join(replaced), b"replacement").unwrap();
        fs::set_permissions(root.0.join(replaced), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(listener.accept(Duration::from_millis(1)).is_err());
        assert!(listener.close().is_err());
        assert_eq!(fs::read(root.0.join(replaced)).unwrap(), b"replacement");
        assert!(root.socket().exists());
    }
}

#[test]
fn replaced_directory_is_not_removed_by_old_owner_cleanup() {
    let root = Root::new();
    let slot = root.0.join("slot");
    fs::DirBuilder::new().mode(0o700).create(&slot).unwrap();
    let listener = LocalListener::bind(&slot).unwrap();
    fs::rename(&slot, root.0.join("previous")).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&slot).unwrap();
    fs::write(slot.join("control.sock"), b"replacement").unwrap();
    assert!(listener.close().is_err());
    assert_eq!(fs::read(slot.join("control.sock")).unwrap(), b"replacement");
    assert!(root.0.join("previous/control.sock").exists());
}

#[test]
fn slow_fragmented_frame_has_one_deadline_and_cannot_resume_after_timeout() {
    let root = Root::new();
    let listener = LocalListener::bind(&root.0).unwrap();
    let mut raw = UnixStream::connect(root.socket()).unwrap();
    raw.set_write_timeout(Some(WAIT)).unwrap();
    let mut server = listener.accept(WAIT).unwrap();
    let mut message = frame();
    message.payload = vec![7; 64];
    let mut bytes = Vec::new();
    message.write(&mut bytes).unwrap();
    let writer = std::thread::spawn(move || {
        for byte in bytes {
            if raw.write_all(&[byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let started = Instant::now();
    let error = server.read_frame(Duration::from_millis(60)).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ));
    assert!(started.elapsed() < WAIT);
    assert_eq!(
        server.read_frame(WAIT).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    writer.join().unwrap();
}

#[test]
fn oversized_and_truncated_headers_poison_the_connection_before_payload_read() {
    let mut header = Vec::new();
    Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ONE,
        payload: vec![],
    }
    .write(&mut header)
    .unwrap();
    assert_eq!(header.len(), HEADER_BYTES);
    header[20..24].copy_from_slice(&((MAX_CONTROL_BYTES + 1) as u32).to_be_bytes());
    for bytes in [header, vec![b'S', b'S']] {
        let root = Root::new();
        let listener = LocalListener::bind(&root.0).unwrap();
        let mut raw = UnixStream::connect(root.socket()).unwrap();
        let mut server = listener.accept(WAIT).unwrap();
        raw.write_all(&bytes).unwrap();
        if bytes.len() < HEADER_BYTES {
            raw.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let expected = if bytes.len() < HEADER_BYTES {
            io::ErrorKind::UnexpectedEof
        } else {
            io::ErrorKind::InvalidData
        };
        assert_eq!(server.read_frame(WAIT).unwrap_err().kind(), expected);
        assert_eq!(
            server.read_frame(WAIT).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }
}

#[test]
fn blocked_output_is_bounded_and_failed_frames_are_not_retried() {
    let root = Root::new();
    let listener = LocalListener::bind(&root.0).unwrap();
    let mut client = LocalConnection::connect(&root.0, WAIT).unwrap();
    let _server = listener.accept(WAIT).unwrap();
    let mut message = frame();
    message.payload = vec![0; MAX_STREAM_BYTES];
    let mut failed = false;
    for _ in 0..128 {
        if let Err(error) = client.write_frame(&message, Duration::from_millis(30)) {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ));
            failed = true;
            break;
        }
    }
    assert!(
        failed,
        "native socket buffering must not absorb unlimited output"
    );
    assert_eq!(
        client.write_frame(&message, WAIT).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
}

#[test]
fn accept_and_frame_waits_require_bounded_deadlines() {
    let root = Root::new();
    let listener = LocalListener::bind(&root.0).unwrap();
    let started = Instant::now();
    assert_eq!(
        listener
            .accept(Duration::from_millis(10))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() < WAIT);
    assert!(LocalConnection::connect(&root.0, Duration::ZERO).is_err());
    let mut client = LocalConnection::connect(&root.0, WAIT).unwrap();
    let mut server = listener.accept(WAIT).unwrap();
    for timeout in [Duration::ZERO, Duration::from_secs(61)] {
        assert_eq!(
            server.read_frame(timeout).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    client.write_frame(&frame(), WAIT).unwrap();
    assert_eq!(server.read_frame(WAIT).unwrap(), Some(frame()));
    drop(client);
    assert_eq!(server.read_frame(WAIT).unwrap(), None);
    assert_eq!(
        server.read_frame(WAIT).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_acl_grants_cannot_hide_behind_private_mode_bits() {
    use sandsurf_native::macos::{require_private_file_acl, require_private_path_acl};
    let root = Root::new();
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow list,search"])
            .arg(&root.0)
            .status()
            .unwrap()
            .success()
    );
    let mode = fs::metadata(&root.0).unwrap().mode() & 0o077;
    let endpoint = LocalListener::bind(&root.0);
    let acl = require_private_path_acl(&root.0);
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(&root.0)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        mode, 0,
        "the ACL broadens access without changing private mode bits"
    );
    assert!(endpoint.is_err());
    assert!(acl.is_err());
    assert!(!root.lease().exists());
    let path = root.0.join("private");
    fs::write(&path, b"retained").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let file = fs::File::open(&path).unwrap();
    require_private_file_acl(&file).unwrap();
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,write"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mode = file.metadata().unwrap().mode() & 0o077;
    let acl = require_private_file_acl(&file);
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(mode, 0);
    assert!(acl.is_err());
    assert_eq!(fs::read(&path).unwrap(), b"retained");
    require_private_file_acl(&file).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn macos_ancestor_acl_cannot_grant_directory_replacement() {
    let root = Root::new();
    let slot = root.0.join("slot");
    fs::DirBuilder::new().mode(0o700).create(&slot).unwrap();
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow delete_child"])
            .arg(&root.0)
            .status()
            .unwrap()
            .success()
    );
    let endpoint = LocalListener::bind(&slot);
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(&root.0)
            .status()
            .unwrap()
            .success()
    );
    assert!(endpoint.is_err());
    assert!(!slot.join("control.lock").exists());
    LocalListener::bind(&slot).unwrap().close().unwrap();
}
