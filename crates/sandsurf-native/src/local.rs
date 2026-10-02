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
//! or invalid frame poisons its connection. Callers must not retry commands on a
//! replacement connection without reconciling their operation identities.

use crate::unix_io::{DeadlineIo, connect_socket, wait_ready};
use sandsurf_protocol::Frame;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SOCKET: &str = "control.sock";
const PENDING_SOCKET: &str = "control.pending.sock";
const LEASE: &str = "control.lock";
const MAX_DEADLINE: Duration = Duration::from_secs(300);

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

/// Retained private directory identity. It is not an endpoint writer lease,
/// machine owner, or authorization decision.
pub struct Directory {
    path: PathBuf,
    held: File,
}

/// Reopen only an owned private directory, or create one below protected ancestry.
pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid("private directory must be absolute"));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            Directory::open(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match create_private_directory(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    Directory::open(path)?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

pub fn canonical_private_directory(path: &Path) -> io::Result<PathBuf> {
    Ok(Directory::open(path)?.path)
}

/// Create a new private directory without adopting an existing identity.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid("private directory must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("private directory requires a parent"))?;
    // Resolve the same system aliases accepted by Directory::open
    // before validating ancestry. Keep the parent identity through
    // creation so /tmp and /var are treated consistently on Darwin.
    let canonical_parent = fs::canonicalize(parent)?;
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical_parent)?;
    let canonical = canonical_parent.join(
        path.file_name()
            .ok_or_else(|| invalid("private directory requires a name"))?,
    );
    crate::filesystem::require_protected_ancestors(&canonical)?;
    if identity(&fs::metadata(parent)?) != identity(&held.metadata()?) {
        return Err(denied("private directory parent changed before creation"));
    }
    fs::DirBuilder::new().mode(0o700).create(&canonical)?;
    Directory::open(&canonical)?;
    if identity(&fs::metadata(parent)?) != identity(&held.metadata()?) {
        return Err(denied("private directory parent changed during creation"));
    }
    Ok(())
}

fn validate_private_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    private(&metadata)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(denied(
            "private object is not a uniquely owned regular file",
        ));
    }
    #[cfg(target_os = "macos")]
    crate::macos::require_private_file_acl(file)?;
    Ok(())
}

pub fn open_private_file(path: &Path, access: crate::PrivateFileAccess) -> io::Result<File> {
    Directory::open(
        path.parent()
            .ok_or_else(|| invalid("private file requires a parent"))?,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .write(access == crate::PrivateFileAccess::ReadWrite)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_private_file(&file)?;
    Ok(file)
}

pub fn create_private_file(path: &Path) -> io::Result<File> {
    Directory::open(
        path.parent()
            .ok_or_else(|| invalid("private file requires a parent"))?,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_private_file(&file)?;
    Ok(file)
}
impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
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
    pub fn check(&self) -> io::Result<()> {
        crate::filesystem::require_protected_ancestors(&self.path)?;
        #[cfg(target_os = "macos")]
        crate::macos::require_private_file_acl(&self.held)?;
        let actual = fs::symlink_metadata(&self.path)?;
        private(&actual)?;
        if !actual.is_dir() || identity(&actual) != identity(&self.held.metadata()?) {
            return Err(denied("endpoint root identity changed"));
        }
        Ok(())
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn socket(&self) -> io::Result<Metadata> {
        self.socket_named(SOCKET)
    }
    fn socket_named(&self, name: &str) -> io::Result<Metadata> {
        self.check()?;
        let metadata = fs::symlink_metadata(self.path.join(name))?;
        private(&metadata)?;
        if !metadata.file_type().is_socket() || metadata.nlink() != 1 {
            return Err(denied(
                "endpoint path is not a singly linked private socket",
            ));
        }
        #[cfg(target_os = "macos")]
        crate::macos::require_private_path_acl(&self.path.join(name))?;
        Ok(metadata)
    }
    fn at_socket<T: Send>(
        &self,
        name: &str,
        operation: impl FnOnce(&Path) -> io::Result<T> + Send,
    ) -> io::Result<T> {
        #[cfg(target_os = "linux")]
        {
            // AF_UNIX has a small pathname field. Resolve the already verified,
            // retained directory descriptor through procfs so an otherwise
            // valid private state root cannot make guardian IPC unreachable.
            operation(&PathBuf::from(format!(
                "/proc/self/fd/{}/{}",
                self.held.as_raw_fd(),
                name
            )))
        }
        #[cfg(target_os = "macos")]
        {
            crate::macos::in_directory(&self.held, || operation(Path::new(name)))
        }
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
    socket_name: &'static str,
}
impl SocketOwner {
    fn check(&self) -> io::Result<()> {
        self.lease.check(&self.root)?;
        if Some(identity(&self.root.socket_named(self.socket_name)?)) != self.socket_identity {
            return Err(denied("endpoint socket identity changed"));
        }
        Ok(())
    }
    fn remove(&mut self) -> io::Result<()> {
        if self.socket_identity.is_none() {
            return Ok(());
        }
        self.check()?;
        fs::remove_file(self.root.path.join(self.socket_name))?;
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
        // The published endpoint must never expose bind's umask-derived mode.
        // A single leased staging name also makes interruption before chmod
        // recoverable without scanning or adopting unrelated filesystem paths.
        let pending = root.path.join(PENDING_SOCKET);
        match fs::symlink_metadata(&pending) {
            Ok(metadata) => {
                root.check()?;
                if metadata.uid() != uid()
                    || !metadata.file_type().is_socket()
                    || metadata.nlink() != 1
                {
                    return Err(denied("pending endpoint is not this account's socket"));
                }
                fs::remove_file(&pending)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = root.at_socket(PENDING_SOCKET, |path| UnixListener::bind(path))?;
        let metadata = fs::symlink_metadata(&pending)?;
        let mut owner = SocketOwner {
            root,
            lease,
            socket_identity: Some(identity(&metadata)),
            socket_name: PENDING_SOCKET,
        };
        // No connection by the public name is possible until privacy and
        // ownership checks have succeeded. No process-global umask mutation.
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o600))?;
        owner.check()?;
        listener.set_nonblocking(true)?;
        crate::storage::publish_name(&pending, &path)?;
        owner.socket_name = SOCKET;
        owner.check()?;
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
        let stream = root.at_socket(SOCKET, |path| connect_socket(path, deadline.0))?;
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
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            peer,
            usable: true,
        })
    }
    pub fn peer(&self) -> PeerIdentity {
        self.peer
    }
    /// Kernel observation of this connection's peer, not permission to adopt
    /// that process. A launcher must compare it with its retained original.
    pub fn peer_process(&self) -> io::Result<u32> {
        self.check()?;
        crate::socket_io::peer_process(&socket2::Socket::from(std::os::fd::OwnedFd::from(
            self.stream.try_clone()?,
        )))
    }
    pub fn read_frame(&mut self, timeout: Duration) -> io::Result<Option<Frame>> {
        let deadline = Deadline::new(timeout)?;
        self.check()?;
        let result = Frame::read(&mut DeadlineIo {
            stream: &mut self.stream,
            deadline: Some(deadline.0),
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
            deadline: Some(deadline.0),
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
            return Err(invalid("local transport deadline must be in (0, 300s]"));
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
        wait_ready(fd, events, Some(self.0))
    }
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
