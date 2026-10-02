//! Linux socket factory for the external packet gateway. The privileged owner
//! only makes ordinary TCP/UDP sockets bearing a fixed restrictive packet mark.
//! It accepts no destination, pathname, PID, executable, or application grant.
//! A separately operator-installed nftables INPUT rule rejects marked packets
//! at actual local delivery, including after address/route/NAT changes. Guest
//! packets never become host raw sockets. Host-owned allow policy remains in
//! sandsurf-network; this module is not a second authorization database.
use crate::unix_io::{DeadlineIo, wait_ready};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

pub const ROOT: &str = "/run/sandsurf-network";
const ENDPOINT: &str = "/run/sandsurf-network/sockets.sock";
pub const MARK: u32 = 0x53534601;
const DEADLINE: Duration = Duration::from_secs(2);
const MAX_CONNECTIONS: usize = 32;

/// Install explicitly, as an operator. The batch replaces only this dedicated
/// table atomically. Do not flush the host ruleset or remove it on broker exit:
/// transferred live sockets must remain restricted after service restart.
pub const NFT_RULES: &str = include_str!("../../../vmm/linux/network-boundary.nft");

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn request(ipv6: bool, udp: bool) -> [u8; 8] {
    [
        b'S',
        b'S',
        b'N',
        b'S',
        1,
        if udp { 17 } else { 6 },
        if ipv6 { 6 } else { 4 },
        0,
    ]
}

fn decode(value: &[u8; 8]) -> io::Result<(bool, bool)> {
    if value[..5] != [b'S', b'S', b'N', b'S', 1]
        || !matches!(value[5], 6 | 17)
        || !matches!(value[6], 4 | 6)
        || value[7] != 0
    {
        return Err(invalid("invalid native socket request"));
    }
    Ok((value[6] == 6, value[5] == 17))
}

/// An in-flight native socket transfer. Poll never waits for the privileged
/// service. Dropping it cancels admission and closes any partial receipt's FD.
pub struct SocketAdmission {
    control: UnixStream,
    receipt: Receipt,
    expected: [u8; 8],
    written: usize,
    deadline: Instant,
    finished: bool,
}
impl SocketAdmission {
    pub fn begin(ipv6: bool, udp: bool) -> io::Result<Self> {
        protected_endpoint()?;
        let connection = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        connection.set_nonblocking(true)?;
        // AF_UNIX backlog saturation is failed admission (EAGAIN), not a
        // connecting Internet socket. Never poll/wait on the packet hot path.
        connection.connect(&socket2::SockAddr::unix(ENDPOINT)?)?;
        let control = UnixStream::from(OwnedFd::from(connection));
        if peer(&control)?.uid != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self {
            control,
            receipt: Receipt::default(),
            expected: request(ipv6, udp),
            written: 0,
            deadline: Instant::now() + DEADLINE,
            finished: false,
        })
    }
    pub fn poll(&mut self) -> io::Result<Option<Socket>> {
        if self.finished {
            return Err(invalid("native socket admission is already finished"));
        }
        if Instant::now() >= self.deadline {
            self.finished = true;
            self.receipt.descriptor.take();
            return Err(io::ErrorKind::TimedOut.into());
        }
        let result = self.poll_inner();
        if !matches!(result, Ok(None)) {
            self.finished = true;
            self.receipt.descriptor.take();
        }
        result
    }
    fn poll_inner(&mut self) -> io::Result<Option<Socket>> {
        if self.written < self.expected.len() {
            // SAFETY: retained socket and bounded remaining receipt bytes.
            let count = unsafe {
                libc::send(
                    self.control.as_raw_fd(),
                    self.expected[self.written..].as_ptr().cast(),
                    self.expected.len() - self.written,
                    libc::MSG_NOSIGNAL,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    return Ok(None);
                }
                return Err(error);
            }
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.written += count as usize;
            if self.written != self.expected.len() {
                return Ok(None);
            }
        }
        let Some((received, fd)) = self.receipt.poll(&self.control)? else {
            return Ok(None);
        };
        if received != self.expected {
            return Err(invalid("native socket receipt differs from request"));
        }
        let socket = Socket::from(fd);
        let (ipv6, udp) = decode(&self.expected)?;
        verify_socket(&socket, ipv6, udp)?;
        socket.set_nonblocking(true)?;
        Ok(Some(socket))
    }
}

/// Probe admission with one shared absolute deadline. This is a control-plane
/// prerequisite check, never a synchronous request for each guest packet.
pub fn probe() -> io::Result<()> {
    let deadline = Instant::now() + DEADLINE;
    let mut pending = [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .map(|(ipv6, udp)| SocketAdmission::begin(ipv6, udp).map(Some))
        .collect::<io::Result<Vec<_>>>()?;
    loop {
        for admission in &mut pending {
            if let Some(value) = admission
                && value.poll()?.is_some()
            {
                *admission = None;
            }
        }
        let Some(next) = pending.iter().flatten().next() else {
            return Ok(());
        };
        wait_ready(
            next.control.as_raw_fd(),
            if next.written < 8 {
                libc::POLLOUT
            } else {
                libc::POLLIN
            },
            Some(deadline),
        )?;
    }
}

fn protected_endpoint() -> io::Result<()> {
    let directory = fs::symlink_metadata(ROOT)?;
    let endpoint = fs::symlink_metadata(ENDPOINT)?;
    if !directory.is_dir()
        || directory.file_type().is_symlink()
        || directory.uid() != 0
        || directory.mode() & 0o022 != 0
        || !endpoint.file_type().is_socket()
        || endpoint.uid() != 0
        || endpoint.nlink() != 1
        || fs::canonicalize(ROOT)? != Path::new(ROOT)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    crate::filesystem::require_protected_ancestors(Path::new(ENDPOINT))
}

fn peer(stream: &UnixStream) -> io::Result<libc::ucred> {
    // SAFETY: initialized credential output and its exact length for this socket.
    let mut value: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: the retained socket, bounded initialized output and length pointers.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut value).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&value)
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

fn scalar(socket: &Socket, option: i32) -> io::Result<i32> {
    let mut value = 0_i32;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: live socket and exact initialized scalar output storage.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&value)
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

fn verify_socket(socket: &Socket, ipv6: bool, udp: bool) -> io::Result<()> {
    if scalar(socket, libc::SO_MARK)? as u32 != MARK
        || scalar(socket, libc::SO_DOMAIN)? != if ipv6 { libc::AF_INET6 } else { libc::AF_INET }
        || scalar(socket, libc::SO_TYPE)?
            != if udp {
                libc::SOCK_DGRAM
            } else {
                libc::SOCK_STREAM
            }
        || scalar(socket, libc::SO_PROTOCOL)?
            != if udp {
                libc::IPPROTO_UDP
            } else {
                libc::IPPROTO_TCP
            }
        || socket.peer_addr().is_ok()
    {
        return Err(invalid("unmarked, connected, or wrong native socket role"));
    }
    Ok(())
}

fn marked_socket(ipv6: bool, udp: bool) -> io::Result<Socket> {
    let mark = MARK;
    let socket = Socket::new(
        if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
        if udp { Type::DGRAM } else { Type::STREAM },
        Some(if udp { Protocol::UDP } else { Protocol::TCP }),
    )?;
    // SAFETY: live socket and a fixed scalar restrictive mark, no caller value.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast(),
            std::mem::size_of_val(&mark) as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    socket.set_nonblocking(true)?;
    verify_socket(&socket, ipv6, udp)?;
    Ok(socket)
}

fn send(stream: &UnixStream, payload: &[u8], fd: &Socket, deadline: Instant) -> io::Result<()> {
    if payload.is_empty() || payload.len() > 8 {
        return Err(invalid("native socket receipt exceeds bound"));
    }
    let mut ancillary = [0_usize; 8];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: zero initialized C message with all pointers assigned below.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    // SAFETY: scalar CMSG_SPACE computes the bounded storage for exactly one FD.
    message.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) } as _;
    // SAFETY: storage is aligned and large enough for this header and FD payload.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd.as_raw_fd());
    }
    loop {
        wait_ready(stream.as_raw_fd(), libc::POLLOUT, Some(deadline))?;
        // SAFETY: retained socket and complete bounded message/ancillary storage.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error);
        }
        // A partial stream send transfers the FD once. Finish only its remaining
        // bytes; never resend SCM_RIGHTS and accidentally duplicate ownership.
        if sent == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let mut cloned = stream.try_clone()?;
        return DeadlineIo {
            stream: &mut cloned,
            deadline: Some(deadline),
        }
        .write_all(&payload[sent as usize..]);
    }
}

#[derive(Default)]
struct Receipt {
    bytes: [u8; 8],
    offset: usize,
    descriptor: Option<OwnedFd>,
}
impl Receipt {
    fn poll(&mut self, stream: &UnixStream) -> io::Result<Option<([u8; 8], OwnedFd)>> {
        if self.offset == self.bytes.len() {
            return Err(invalid("native receipt is already complete"));
        }
        let mut ancillary = [0_usize; 8];
        let mut iov = libc::iovec {
            iov_base: self.bytes[self.offset..].as_mut_ptr().cast(),
            iov_len: self.bytes.len() - self.offset,
        };
        // SAFETY: zero initialized native message with bounded aligned buffers.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&ancillary);
        // SAFETY: retained socket, bounded payload and aligned ancillary storage.
        let read =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Ok(None);
            }
            return Err(error);
        }
        // Own every received handle before checking the closed grammar, so an
        // invalid or truncated receipt cannot leak kernel-delivered descriptors.
        let mut received = Vec::with_capacity(8);
        let mut unknown = false;
        // SAFETY: CMSG traversal stays within the kernel-initialized extent.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let value = &*header;
                if value.cmsg_level == libc::SOL_SOCKET && value.cmsg_type == libc::SCM_RIGHTS {
                    let bytes = value.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                    if !bytes.is_multiple_of(std::mem::size_of::<i32>()) {
                        unknown = true;
                    }
                    for index in 0..bytes / std::mem::size_of::<i32>() {
                        let fd = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<i32>().add(index),
                        );
                        received.push(OwnedFd::from_raw_fd(fd));
                    }
                } else {
                    unknown = true;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if read == 0
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || unknown
            || (self.offset == 0 && received.len() != 1)
            || (self.offset != 0 && !received.is_empty())
        {
            return Err(invalid("invalid native socket handle transfer"));
        }
        if let Some(fd) = received.pop() {
            self.descriptor = Some(fd);
        }
        self.offset += read as usize;
        if self.offset != self.bytes.len() {
            return Ok(None);
        }
        Ok(Some((
            self.bytes,
            self.descriptor
                .take()
                .ok_or_else(|| invalid("missing transferred socket"))?,
        )))
    }
}

#[cfg(test)]
fn receive(stream: &UnixStream, deadline: Instant) -> io::Result<([u8; 8], OwnedFd)> {
    let mut receipt = Receipt::default();
    loop {
        if let Some(value) = receipt.poll(stream)? {
            return Ok(value);
        }
        wait_ready(stream.as_raw_fd(), libc::POLLIN, Some(deadline))?;
    }
}

/// Verify the actual immutable enforcement expression, not merely a table name
/// or a successful policy command. Kernel-assigned handles are observations.
fn verify_rules(bytes: &[u8]) -> io::Result<()> {
    use serde_json::json;
    if bytes.len() > 16384 {
        return Err(invalid("network rule observation exceeds bound"));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    let commands = value
        .get("nftables")
        .and_then(|v| v.as_array())
        .ok_or_else(|| invalid("missing nftables observation"))?;
    let mut observed = Vec::new();
    for entry in commands {
        if entry.get("metainfo").is_some() {
            continue;
        }
        let mut entry = entry.clone();
        if let Some(object) = entry.as_object_mut() {
            for payload in object.values_mut() {
                if let Some(payload) = payload.as_object_mut() {
                    payload.remove("handle");
                }
            }
        }
        observed.push(entry);
    }
    let expected = [
        json!({"table":{"family":"inet","name":"sandsurf_boundary"}}),
        json!({"chain":{"family":"inet","table":"sandsurf_boundary","name":"local_delivery",
            "type":"filter","hook":"input","prio":-300,"policy":"accept"}}),
        json!({"rule":{"family":"inet","table":"sandsurf_boundary","chain":"local_delivery",
            "expr":[{"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":MARK}},{"drop":null}]}}),
    ];
    if observed != expected {
        return Err(invalid("installed local-delivery enforcement differs"));
    }
    Ok(())
}

struct RuleQuery(Child);
impl Drop for RuleQuery {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn inspect_rules() -> io::Result<()> {
    let nft = crate::filesystem::protected_tool(&["/usr/sbin/nft", "/sbin/nft"])?;
    let mut child = RuleQuery(
        Command::new(nft)
            .env_clear()
            .args(["-j", "list", "table", "inet", "sandsurf_boundary"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut output = child
        .0
        .stdout
        .take()
        .ok_or_else(|| invalid("network rule output missing"))?;
    // SAFETY: retained owned output pipe; scalar fcntl sets nonblocking capture.
    if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::with_capacity(4096);
    let mut buffer = [0; 4096];
    loop {
        wait_ready(output.as_raw_fd(), libc::POLLIN, Some(deadline))?;
        match output.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if bytes.len() + count > 16384 {
                    return Err(invalid("network rule output exceeds bound"));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    loop {
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err(invalid("native network rules are not installed"));
            }
            return verify_rules(&bytes);
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn own_endpoint() -> io::Result<(UnixListener, File)> {
    // SAFETY: scalar query of this process's effective credentials.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    match fs::symlink_metadata(ROOT) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o755).create(ROOT)?
        }
        Err(error) => return Err(error),
        Ok(metadata)
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0 =>
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(_) => {}
    }
    if fs::canonicalize(ROOT)? != Path::new(ROOT) {
        return Err(invalid("native network directory is an alias"));
    }
    crate::filesystem::require_protected_ancestors(Path::new(ROOT).join("owner.lock").as_path())?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(ROOT).join("owner.lock"))?;
    let metadata = lease.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    lease.try_lock().map_err(io::Error::other)?;
    // Recover only this dedicated root-owned socket after exclusive ownership.
    match fs::symlink_metadata(ENDPOINT) {
        Ok(metadata)
            if metadata.file_type().is_socket() && metadata.uid() == 0 && metadata.nlink() == 1 =>
        {
            fs::remove_file(ENDPOINT)?
        }
        Ok(_) => return Err(invalid("native network endpoint has foreign identity")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(ENDPOINT)?;
    fs::set_permissions(ENDPOINT, fs::Permissions::from_mode(0o666))?;
    Ok((listener, lease))
}

/// Operator-installed root service. Policy setup is explicit and external; an
/// unavailable/conflicting rule fails before publishing a socket factory.
pub fn serve() -> io::Result<()> {
    crate::filesystem::protected_tool(&["/usr/local/libexec/sandsurf/sandsurf-host"])?;
    if std::env::current_exe()? != Path::new("/usr/local/libexec/sandsurf/sandsurf-host") {
        return Err(invalid("native socket owner must be operator-installed"));
    }
    let (listener, _lease) = own_endpoint()?;
    inspect_rules()?;
    let connections = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut stream = stream?;
        if connections.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            connections.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        struct Admission(Arc<AtomicUsize>);
        impl Drop for Admission {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let admission = Admission(Arc::clone(&connections));
        std::thread::Builder::new()
            .name("network-socket".into())
            .spawn(move || {
                let _admission = admission;
                let _ = (|| -> io::Result<()> {
                    let _credentials = peer(&stream)?; // kernel credentials, no caller claims
                    stream.set_nonblocking(true)?;
                    let deadline = Instant::now() + DEADLINE;
                    let mut value = [0; 8];
                    DeadlineIo {
                        stream: &mut stream,
                        deadline: Some(deadline),
                    }
                    .read_exact(&mut value)?;
                    let (ipv6, udp) = decode(&value)?;
                    let socket = marked_socket(ipv6, udp)?;
                    send(&stream, &value, &socket, deadline)
                })();
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_poll_is_nonblocking_and_partial_receipts_keep_one_absolute_deadline() {
        let (writer, control) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        control.set_nonblocking(true).unwrap();
        let expected = request(false, true);
        let mut admission = SocketAdmission {
            control,
            receipt: Receipt::default(),
            expected,
            written: 8,
            deadline: Instant::now() + Duration::from_millis(250),
            finished: false,
        };
        let start = Instant::now();
        assert!(admission.poll().unwrap().is_none());
        assert!(start.elapsed() < Duration::from_millis(200));
        let original = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        send(
            &writer,
            &expected[..3],
            &original,
            Instant::now() + DEADLINE,
        )
        .unwrap();
        assert!(admission.poll().unwrap().is_none());
        assert_eq!(admission.receipt.offset, 3);
        let fd = admission.receipt.descriptor.as_ref().unwrap().as_raw_fd();
        admission.deadline = Instant::now();
        assert_eq!(
            admission.poll().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(admission.finished);
        assert!(admission.receipt.descriptor.is_none());
        // SAFETY: scalar validity query, not adoption of the already closed FD.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert!(admission.poll().is_err());
    }

    #[test]
    fn receipt_fragments_preserve_the_original_descriptor_without_blocking() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let original = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let expected = request(false, true);
        let mut receipt = Receipt::default();
        send(
            &writer,
            &expected[..1],
            &original,
            Instant::now() + DEADLINE,
        )
        .unwrap();
        assert!(receipt.poll(&reader).unwrap().is_none());
        assert!(receipt.poll(&reader).unwrap().is_none());
        writer.write_all(&expected[1..]).unwrap();
        let (bytes, fd) = receipt.poll(&reader).unwrap().unwrap();
        assert_eq!(bytes, expected);
        let received = Socket::from(fd);
        received
            .bind(
                &"127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .unwrap();
        assert_eq!(
            original.local_addr().unwrap(),
            received.local_addr().unwrap()
        );
        assert!(receipt.poll(&reader).is_err());
    }
    #[test]
    fn installed_rule_asset_and_socket_factory_use_the_same_mark() {
        assert!(NFT_RULES.contains(&format!("meta mark 0x{MARK:08x} drop")));
        assert!(NFT_RULES.contains("hook input priority -300"));
        assert!(!NFT_RULES.contains("flush ruleset"));
    }

    #[test]
    fn missing_handles_and_incomplete_receipts_are_rejected_without_replay() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.write_all(&request(false, false)).unwrap();
        assert!(receive(&reader, Instant::now() + DEADLINE).is_err());
        let (writer, reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let original = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        send(
            &writer,
            &request(false, false),
            &original,
            Instant::now() + DEADLINE,
        )
        .unwrap();
        drop(writer);
        let (_, received) = receive(&reader, Instant::now() + DEADLINE).unwrap();
        assert!(verify_socket(&Socket::from(received), false, false).is_err());
    }

    #[test]
    #[ignore = "requires root in a separately created network namespace; no VM hardware required"]
    fn kernel_local_delivery_denial_survives_route_changes_and_factory_exit() {
        // Never install test rules or change addresses in the initial namespace.
        // CI executes this compiled test binary through sudo unshare --net.
        // SAFETY: scalar credential query without pointer arguments.
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            fs::read_link("/proc/1/ns/net").unwrap()
        );
        let nft = crate::filesystem::protected_tool(&["/usr/sbin/nft", "/sbin/nft"]).unwrap();
        let ip = crate::filesystem::protected_tool(&["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"])
            .unwrap();
        let mut child = RuleQuery(
            Command::new(nft)
                .env_clear()
                .args(["-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        child
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(NFT_RULES.as_bytes())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "nft installation exceeded deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        inspect_rules().unwrap();
        let change = |args: &[&str]| {
            let mut command = Command::new(&ip);
            command.env_clear().args(args);
            crate::resources::run_bounded(command).unwrap();
        };
        change(&["link", "set", "lo", "up"]);
        change(&["route", "add", "198.51.100.0/24", "dev", "lo"]);
        let listener = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        listener
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let target: std::net::SocketAddr =
            format!("198.51.100.37:{}", listener.local_addr().unwrap().port())
                .parse()
                .unwrap();
        let (owner, receiver) = UnixStream::pair().unwrap();
        owner.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let original = marked_socket(false, true).unwrap();
        send(
            &owner,
            &request(false, true),
            &original,
            Instant::now() + DEADLINE,
        )
        .unwrap();
        let (_, fd) = receive(&receiver, Instant::now() + DEADLINE).unwrap();
        let transferred = Socket::from(fd);
        verify_socket(&transferred, false, true).unwrap();
        let udp: std::net::UdpSocket = transferred.into();
        udp.connect(target).unwrap();
        // The destination becomes this host after the flow/socket is established.
        change(&["address", "add", "198.51.100.37/32", "dev", "lo"]);
        drop(original);
        drop(owner); // sole native factory exits, not a PID probe
        udp.send(b"after-route-change").unwrap();
        let mut bytes = [0; 128];
        assert!(matches!(
            listener.recv(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        let reference = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        reference.send_to(b"unmarked-reference", target).unwrap();
        let size = listener.recv(&mut bytes).unwrap();
        assert_eq!(
            &bytes[..size],
            b"unmarked-reference",
            "route change was not exercised"
        );
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let server = std::net::TcpListener::bind(address).unwrap();
            server.set_nonblocking(true).unwrap();
            let target = server.local_addr().unwrap();
            let socket = marked_socket(target.is_ipv6(), false).unwrap();
            assert!(matches!(
                socket.connect(&target.into()).unwrap_err().raw_os_error(),
                Some(libc::EINPROGRESS)
            ));
            let start = Instant::now();
            // Rejecting locally at INPUT does not falsely establish a connection.
            while start.elapsed() < Duration::from_millis(100) {
                assert!(socket.peer_addr().is_err());
                assert_eq!(
                    server.accept().unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let reference =
                std::net::TcpStream::connect_timeout(&target, Duration::from_secs(1)).unwrap();
            drop(server.accept().unwrap());
            drop(reference);
        }
        inspect_rules().unwrap();
    }
    #[test]
    fn requests_are_closed_and_have_no_host_authority_inputs() {
        for ipv6 in [false, true] {
            for udp in [false, true] {
                let value = request(ipv6, udp);
                assert_eq!(decode(&value).unwrap(), (ipv6, udp));
                for index in [0, 1, 2, 3, 4, 7] {
                    let mut bad = value;
                    bad[index] ^= 1;
                    assert!(decode(&bad).is_err());
                }
            }
        }
        for value in [0, 1, 255] {
            let mut bad = request(false, false);
            bad[5] = value;
            assert!(decode(&bad).is_err());
        }
    }
    #[test]
    fn transfer_keeps_original_identity_cloexec_and_finishes_fragmented_receipts() {
        let (writer, reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let original = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let value = request(false, true);
        send(&writer, &value, &original, Instant::now() + DEADLINE).unwrap();
        let (receipt, fd) = receive(&reader, Instant::now() + DEADLINE).unwrap();
        assert_eq!(receipt, value);
        // SAFETY: retained newly transferred descriptor; scalar flag query.
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let received = Socket::from(fd);
        received
            .bind(
                &"127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .unwrap();
        assert_eq!(
            received.local_addr().unwrap(),
            original.local_addr().unwrap()
        );
        assert!(
            verify_socket(&received, false, true).is_err(),
            "unmarked socket was accepted"
        );
    }
    #[test]
    fn rule_verification_rejects_dormant_tables_wrong_hooks_extra_rules_and_changed_mark() {
        let base = serde_json::json!({"nftables":[
            {"metainfo":{"json_schema_version":1}},
            {"table":{"family":"inet","name":"sandsurf_boundary","handle":1}},
            {"chain":{"family":"inet","table":"sandsurf_boundary","name":"local_delivery","handle":2,"type":"filter","hook":"input","prio":-300,"policy":"accept"}},
            {"rule":{"family":"inet","table":"sandsurf_boundary","chain":"local_delivery","handle":3,"expr":[{"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":MARK}},{"drop":null}]}}
        ]});
        verify_rules(&serde_json::to_vec(&base).unwrap()).unwrap();
        for (index, field, value) in [
            (1, "flags", serde_json::json!(["dormant"])),
            (2, "hook", serde_json::json!("output")),
            (2, "prio", serde_json::json!(0)),
        ] {
            let mut bad = base.clone();
            let entry = bad["nftables"][index]
                .as_object_mut()
                .unwrap()
                .values_mut()
                .next()
                .unwrap();
            entry[field] = value;
            assert!(verify_rules(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut bad = base.clone();
        bad["nftables"][3]["rule"]["expr"][0]["match"]["right"] = serde_json::json!(MARK + 1);
        assert!(verify_rules(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = base.clone();
        bad["nftables"]
            .as_array_mut()
            .unwrap()
            .push(base["nftables"][3].clone());
        assert!(verify_rules(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
