//! Kernel IPC ownership test; no privilege broker or VM hardware is needed.
#![cfg(target_os = "macos")]
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn inherited_pair_identifies_the_retained_sender_after_exec_not_its_creator() {
    const CHILD: &str = "SANDSURF_SOCKETPAIR_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // SAFETY: this test's pre_exec closure transfers exactly this socket to
        // FD 3. Only the explicit child invocation adopts that original slot.
        let mut stream = unsafe { UnixStream::from_raw_fd(3) };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(&std::process::id().to_le_bytes()).unwrap();
        let mut acknowledgement = [0];
        stream.read_exact(&mut acknowledgement).unwrap();
        assert_eq!(acknowledgement, [1]);
        return;
    }
    let (mut stream, peer) = UnixStream::pair().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let socket = socket2::Socket::from(OwnedFd::from(stream.try_clone().unwrap()));
    assert_eq!(
        sandsurf_native::socket_io::peer_process(&socket).unwrap(),
        std::process::id()
    );
    // SAFETY: retained live peer; the returned duplicate is uniquely owned and
    // kept above the fixed inherited slot so dup2 cannot alias its source.
    let fd = unsafe { libc::fcntl(peer.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
    assert!(fd >= 16);
    // SAFETY: successful fcntl above created one new owned descriptor.
    let inherited = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "inherited_pair_identifies_the_retained_sender_after_exec_not_its_creator",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    // SAFETY: after fork only async-signal-safe descriptor operations occur.
    // The closure owns no pointers to guest or authority data.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop((peer, inherited));
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(u32::from_le_bytes(reply), child.id());
    // XNU's LOCAL_PEERPID reports the peer socket's last sender. In contrast,
    // getpeereid retains connection credentials; the root-created entry gate
    // is what proves privileged budget installation, not this caller's pair.
    assert_eq!(
        sandsurf_native::socket_io::peer_process(&socket).unwrap(),
        child.id()
    );
    stream.write_all(&[1]).unwrap();
    assert!(child.wait().unwrap().success());
}
