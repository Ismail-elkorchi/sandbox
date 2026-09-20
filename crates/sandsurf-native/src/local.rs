//! Private local control transport for Linux and macOS.
//!
//! Kernel peer credentials authenticate an OS account, not a grant or a service
//! role. Host/guardian authorization must still bind requests to their admitted
//! identities, revisions and operations. Never accept credentials in frame JSON.
//! A connection's failure says nothing about machine or operation completion.
//! This boundary separates OS accounts, not mutually hostile host processes
//! running as the same account. Workloads must never receive access to this root.
//!
//! This is bounded synchronous transport, not the service scheduler. Each frame
//! has an absolute deadline (including fragmented reads); a partially transferred
//! or invalid frame poisons its connection. Callers must not retry mutations on a
//! replacement connection without reconciling their operation identities.

use sandsurf_protocol::Frame;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SOCKET: &str = "control.sock";
const LEASE: &str = "control.lock";
const MAX_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}
fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn private(metadata: &Metadata) -> io::Result<()> {
    if metadata.uid() != uid() || metadata.mode() & 0o077 != 0 {
        return Err(denied("local endpoint is not private to this account"));
    }
    Ok(())
}

fn protected_ancestors(path: &Path) -> io::Result<()> {
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let metadata = fs::symlink_metadata(ancestor)?;
        // A private final directory is insufficient if another account can
        // rename an ancestor between validation and native socket operations.
        // Root/account-owned sticky directories allow /tmp without permitting
        // another account to replace entries owned by this account or root.
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid())
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(denied("endpoint ancestor permits foreign path replacement"));
        }
        #[cfg(target_os = "macos")]
        crate::macos::require_protected_ancestor_acl(ancestor)?;
    }
    Ok(())
}

struct Directory {
    path: PathBuf,
    held: File,
}
impl Directory {
    fn open(path: &Path) -> io::Result<Self> {
        let original = fs::symlink_metadata(path)?;
        private(&original)?;
        if !original.is_dir() || original.file_type().is_symlink() {
            return Err(denied(
                "endpoint root must be an owned directory, not a link",
            ));
        }
        // Resolve system ancestor aliases (e.g. macOS /var) while rejecting an
        // alias for the supplied final component. Retain and check its identity.
        let path = fs::canonicalize(path)?;
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        if identity(&held.metadata()?) != identity(&original) {
            return Err(denied("endpoint root changed while opening"));
        }
        let root = Self { path, held };
        root.check()?;
        Ok(root)
    }
    fn check(&self) -> io::Result<()> {
        protected_ancestors(&self.path)?;
        #[cfg(target_os = "macos")]
        crate::macos::require_private_file_acl(&self.held)?;
        let actual = fs::symlink_metadata(&self.path)?;
        private(&actual)?;
        if !actual.is_dir() || identity(&actual) != identity(&self.held.metadata()?) {
            return Err(denied("endpoint root identity changed"));
        }
        Ok(())
    }
    fn socket(&self) -> io::Result<Metadata> {
        self.check()?;
        let metadata = fs::symlink_metadata(self.path.join(SOCKET))?;
        private(&metadata)?;
        if !metadata.file_type().is_socket() || metadata.nlink() != 1 {
            return Err(denied(
                "endpoint path is not a singly linked private socket",
            ));
        }
        #[cfg(target_os = "macos")]
        crate::macos::require_private_path_acl(&self.path.join(SOCKET))?;
        Ok(metadata)
    }
}

struct Lease(File);
impl Lease {
    fn acquire(root: &Directory) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(root.path.join(LEASE))?;
        let metadata = file.metadata()?;
        private(&metadata)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(denied("endpoint lease is not a singly linked private file"));
        }
        #[cfg(target_os = "macos")]
        crate::macos::require_private_file_acl(&file)?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => {
                io::Error::new(io::ErrorKind::WouldBlock, "endpoint already has an owner")
            }
            std::fs::TryLockError::Error(error) => error,
        })?;
        let lease = Self(file);
        root.check()?;
        lease.check(root)?;
        Ok(lease)
    }
    fn check(&self, root: &Directory) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        crate::macos::require_private_file_acl(&self.0)?;
        let metadata = fs::symlink_metadata(root.path.join(LEASE))?;
        private(&metadata)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || identity(&metadata) != identity(&self.0.metadata()?)
        {
            return Err(denied("endpoint lease identity changed"));
        }
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        // Orderly owner close must not be held up by a fork/exec child's inherited
        // descriptor. Neither listener nor lease may be used by a fork child.
        let _ = self.0.unlock();
    }
}

struct SocketOwner {
    root: Directory,
    lease: Lease,
    socket_identity: Option<(u64, u64)>,
}
impl SocketOwner {
    fn check(&self) -> io::Result<()> {
        self.lease.check(&self.root)?;
        if Some(identity(&self.root.socket()?)) != self.socket_identity {
            return Err(denied("endpoint socket identity changed"));
        }
        Ok(())
    }
    fn remove(&mut self) -> io::Result<()> {
        if self.socket_identity.is_none() {
            return Ok(());
        }
        self.check()?;
        fs::remove_file(self.root.path.join(SOCKET))?;
        self.socket_identity = None;
        Ok(())
    }
}
impl Drop for SocketOwner {
    fn drop(&mut self) {
        // Cleanup can remove only this owner's socket. A replacement, changed
        // directory, lease, symlink, or foreign file is left untouched.
        let _ = self.remove();
    }
}

/// A private per-account endpoint. The caller provisions its directory with
/// private ownership first; this API neither creates nor chmods an existing root.
/// A separate endpoint lease permits recovery after owner death, but is NOT a
/// guardian journal/VM ownership lease or evidence that a VM has stopped.
pub struct LocalListener {
    // Drop the listener before removing its socket and unlocking its endpoint.
    listener: UnixListener,
    owner: SocketOwner,
}
impl LocalListener {
    pub fn bind(directory: &Path) -> io::Result<Self> {
        let root = Directory::open(directory)?;
        let lease = Lease::acquire(&root)?;
        let path = root.path.join(SOCKET);
        match root.socket() {
            Ok(_) => {
                // Only an exclusive endpoint owner may remove a stale socket.
                // Never scan directories or remove paths by a stale PID guess.
                fs::remove_file(&path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let owner = SocketOwner {
            root,
            lease,
            socket_identity: Some(identity(&metadata)),
        };
        // The parent is already private, including during this chmod.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        owner.check()?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, owner })
    }

    pub fn accept(&self, timeout: Duration) -> io::Result<LocalConnection> {
        let deadline = Deadline::new(timeout)?;
        self.owner.check()?;
        loop {
            deadline.remaining()?;
            match self.listener.accept() {
                Ok((stream, _)) => {
                    self.owner.check()?;
                    return LocalConnection::authenticate(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    deadline.poll(self.listener.as_raw_fd(), libc::POLLIN)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    deadline.remaining()?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Explicit close reports cleanup failure; Drop is best-effort and cannot
    /// remove replacement paths. Established connections have their own lifetime.
    pub fn close(self) -> io::Result<()> {
        let Self {
            listener,
            mut owner,
        } = self;
        drop(listener);
        owner.remove()
    }
}

pub struct LocalConnection {
    stream: UnixStream,
    peer: PeerIdentity,
    usable: bool,
}
impl LocalConnection {
    pub fn connect(directory: &Path, timeout: Duration) -> io::Result<Self> {
        let deadline = Deadline::new(timeout)?;
        let root = Directory::open(directory)?;
        let expected = identity(&root.socket()?);
        let stream = connect_socket(&root.path.join(SOCKET), &deadline)?;
        if identity(&root.socket()?) != expected {
            return Err(denied("endpoint changed while connecting"));
        }
        Self::authenticate(stream)
    }
    fn authenticate(stream: UnixStream) -> io::Result<Self> {
        Self::authenticate_account(stream, uid())
    }
    fn authenticate_account(stream: UnixStream, expected_uid: u32) -> io::Result<Self> {
        let peer = peer_identity(&stream)?;
        if peer.uid != expected_uid {
            return Err(denied("local peer belongs to another account"));
        }
        #[cfg(target_os = "macos")]
        {
            let enabled: libc::c_int = 1;
            // SAFETY: SO_NOSIGPIPE receives one correctly sized initialized int
            // on this owned socket. A peer close must be an I/O error, not SIGPIPE.
            if unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&raw const enabled).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        stream.set_nonblocking(false)?;
        Ok(Self {
            stream,
            peer,
            usable: true,
        })
    }
    pub fn peer(&self) -> PeerIdentity {
        self.peer
    }
    pub fn read_frame(&mut self, timeout: Duration) -> io::Result<Option<Frame>> {
        let deadline = Deadline::new(timeout)?;
        self.check()?;
        let result = Frame::read(&mut DeadlineIo {
            stream: &mut self.stream,
            deadline,
        });
        if !matches!(&result, Ok(Some(_))) {
            self.poison();
        }
        result
    }
    pub fn write_frame(&mut self, frame: &Frame, timeout: Duration) -> io::Result<()> {
        let deadline = Deadline::new(timeout)?;
        self.check()?;
        let result = frame.write(&mut DeadlineIo {
            stream: &mut self.stream,
            deadline,
        });
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn check(&self) -> io::Result<()> {
        if self.usable {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "local connection is closed",
            ))
        }
    }
    fn poison(&mut self) {
        self.usable = false;
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

struct Deadline(Instant);
impl Deadline {
    fn new(timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() || timeout > MAX_DEADLINE {
            return Err(invalid("local transport deadline must be in (0, 60s]"));
        }
        Ok(Self(Instant::now() + timeout))
    }
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.0.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local transport deadline elapsed",
            ))
        } else {
            Ok(remaining)
        }
    }
    fn poll(&self, fd: RawFd, events: libc::c_short) -> io::Result<()> {
        loop {
            let millis = self.remaining()?.as_millis().max(1) as i32;
            let mut event = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: event is one initialized pollfd for the live owned handle.
            let result = unsafe { libc::poll(&mut event, 1, millis) };
            if result > 0 {
                if event.revents & libc::POLLNVAL != 0 {
                    return Err(io::Error::other("local transport handle is invalid"));
                }
                return Ok(()); // HUP/ERR are resolved by accept/read/SO_ERROR.
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}
struct DeadlineIo<'a> {
    stream: &'a mut UnixStream,
    deadline: Deadline,
}
impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(()) // Unix streams have no userspace buffering here.
    }
}

fn connect_socket(path: &Path, deadline: &Deadline) -> io::Result<UnixStream> {
    // SAFETY: sockaddr_un is a plain C struct; zero is valid initial storage.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(invalid(
            "local socket path exceeds native bound or contains NUL",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = length as u8;
    }
    #[cfg(target_os = "linux")]
    let flags = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(target_os = "macos")]
    let flags = libc::SOCK_STREAM;
    // SAFETY: socket takes scalar constants and returns a new owned descriptor.
    let fd = unsafe { libc::socket(libc::AF_UNIX, flags, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is the successful socket call's new descriptor, transferred once.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    #[cfg(target_os = "macos")]
    {
        // SAFETY: F_SETFD marks this owned descriptor close-on-exec. Apple does not
        // provide SOCK_CLOEXEC; launchers must also clear ambient descriptors.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        stream.set_nonblocking(true)?;
    }
    deadline.remaining()?;
    // SAFETY: address is initialized with a bounded, NUL-terminated native path;
    // length is within its allocation, and fd is this live nonblocking socket.
    if unsafe { libc::connect(fd, (&raw const address).cast(), length) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            // In particular, AF_UNIX EAGAIN means backlog admission failed, NOT
            // an established connection. No request has been dispatched.
            return Err(error);
        }
        deadline.poll(fd, libc::POLLOUT)?;
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
    }
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: credentials and size are writable, correctly sized storage for
    // SO_PEERCRED on this live Unix stream; the kernel supplies the identity.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of_val(&credentials) || credentials.pid <= 0 {
        return Err(denied("kernel did not supply valid local peer credentials"));
    }
    Ok(PeerIdentity {
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

#[cfg(target_os = "macos")]
fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let mut peer_uid = 0;
    let mut peer_gid = 0;
    // SAFETY: getpeereid receives initialized writable UID/GID storage and a live
    // Unix stream. These are kernel credentials, not caller-provided bytes.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer_uid, &mut peer_gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerIdentity {
        uid: peer_uid,
        gid: peer_gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_credentials_must_match_the_admitted_account() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let actual = peer_identity(&receiver).unwrap();
        assert_eq!(actual.uid, uid());
        let other_account = actual.uid.checked_add(1).unwrap_or(0);
        let error = LocalConnection::authenticate_account(receiver, other_account)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        drop(sender);
    }
}
