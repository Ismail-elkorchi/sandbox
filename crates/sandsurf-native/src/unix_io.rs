//! Deadline-aware byte transport shared by local IPC and VM guest channels.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
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

pub(crate) struct DeadlineIo<'a> {
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
