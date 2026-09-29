//! Deadline-aware byte transport shared by local IPC and VM guest channels.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Instant;

pub(crate) fn require_time(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|value| value <= Instant::now()) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "transport deadline elapsed",
        ));
    }
    Ok(())
}

/// Establish a native Unix stream without allowing backlog admission to block
/// a host worker indefinitely. Callers resolve the address relative to their
/// retained directory; authentication remains the protocol owner's job.
pub fn connect_socket(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    // SAFETY: sockaddr_un is a plain C struct; zero is valid initial storage.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path exceeds native bound or contains NUL",
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
        // SAFETY: F_SETFD marks this owned descriptor close-on-exec. Apple does
        // not provide SOCK_CLOEXEC; launchers also clear ambient descriptors.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        stream.set_nonblocking(true)?;
    }
    require_time(Some(deadline))?;
    // SAFETY: address is initialized with a bounded, NUL-terminated native path;
    // length is within its allocation, and fd is this live nonblocking socket.
    if unsafe { libc::connect(fd, (&raw const address).cast(), length) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            // AF_UNIX EAGAIN means backlog admission failed, not an established
            // connection. No protocol request has been dispatched.
            return Err(error);
        }
        wait_ready(fd, libc::POLLOUT, Some(deadline))?;
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
    }
    Ok(stream)
}

pub(crate) fn wait_ready(
    fd: RawFd,
    events: libc::c_short,
    deadline: Option<Instant>,
) -> io::Result<()> {
    loop {
        require_time(deadline)?;
        let timeout = deadline.map_or(-1, |value| {
            value
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, i32::MAX as u128) as i32
        });
        let mut event = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: event is one initialized pollfd for the live owned handle.
        let result = unsafe { libc::poll(&mut event, 1, timeout) };
        if result > 0 {
            if event.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::other("transport handle is invalid"));
            }
            return Ok(()); // Read/write resolve HUP/ERR, including buffered data.
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

pub struct DeadlineIo<'a> {
    // Darwin rejects setsockopt after peer shutdown. Nonblocking I/O plus poll
    // preserves buffered responses and EOF without mutating socket options.
    pub stream: &'a mut UnixStream,
    pub deadline: Option<Instant>,
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            require_time(self.deadline)?;
            match self.stream.read(bytes) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(self.stream.as_raw_fd(), libc::POLLIN, self.deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            require_time(self.deadline)?;
            // SAFETY: the slice remains live for send, and the descriptor is
            // owned by this stream. Per-send suppression avoids both SIGPIPE
            // and Darwin socket-option changes after a peer has disconnected.
            let sent = unsafe {
                libc::send(
                    self.stream.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            let result = if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(sent as usize)
            };
            match result {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(self.stream.as_raw_fd(), libc::POLLOUT, self.deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        require_time(self.deadline)
    }
}
