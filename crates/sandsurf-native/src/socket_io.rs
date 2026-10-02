//! Deadline-aware private AF_UNIX streams on Unix and Windows. QEMU endpoints
//! live below account-private directories, and kernel peer identity must match
//! the retained child process. A reachable socket is not evidence of VM power.
use crate::GuestConnection;
use socket2::{Domain, SockAddr, Socket, Type};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

pub struct SocketConnection {
    socket: Socket,
    timeout: Cell<Option<Duration>>,
}

impl SocketConnection {
    pub fn connect(path: &Path, process_id: u32, timeout: Duration) -> io::Result<Self> {
        if process_id == 0
            || !path.is_absolute()
            || timeout.is_zero()
            || timeout > Duration::from_secs(300)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid private native socket binding",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("native socket has no owner directory"))?;
        if crate::local::canonical_private_directory(parent)? != parent {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native endpoint directory is an alias",
            ));
        }
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.connect_timeout(&SockAddr::unix(path)?, timeout)?;
        if peer_process(&socket)? != process_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native socket peer is not the owned VM process",
            ));
        }
        Self::new(socket, Some(timeout))
    }

    pub fn new(socket: Socket, timeout: Option<Duration>) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let value = Self {
            socket,
            timeout: Cell::new(None),
        };
        value.set_io_timeout(timeout)?;
        Ok(value)
    }

    pub fn into_socket(self) -> Socket {
        self.socket
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Self::new(self.socket.try_clone()?, self.timeout.get())
    }

    fn deadline(&self) -> Option<Instant> {
        self.timeout.get().map(|timeout| Instant::now() + timeout)
    }
}

impl GuestConnection for SocketConnection {
    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout.is_some_and(|duration| duration.is_zero() || duration > Duration::from_secs(300))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native stream deadline exceeds bound",
            ));
        }
        self.timeout.set(timeout);
        Ok(())
    }
}

impl Read for SocketConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let deadline = self.deadline();
        loop {
            remaining(deadline)?;
            match self.socket.read(bytes) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(&self.socket, false, deadline)?
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

impl Write for SocketConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let deadline = self.deadline();
        loop {
            remaining(deadline)?;
            #[cfg(unix)]
            let flags = libc::MSG_NOSIGNAL;
            #[cfg(windows)]
            let flags = 0;
            match self.socket.send_with_flags(bytes, flags) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(&self.socket, true, deadline)?
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        remaining(self.deadline()).map(|_| ())
    }
}

fn remaining(deadline: Option<Instant>) -> io::Result<i32> {
    match deadline {
        Some(deadline) => {
            let now = Instant::now();
            if deadline <= now {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Ok((deadline - now).as_millis().clamp(1, i32::MAX as u128) as i32)
        }
        None => Ok(-1),
    }
}

fn wait_ready(socket: &Socket, write: bool, deadline: Option<Instant>) -> io::Result<()> {
    loop {
        let timeout = remaining(deadline)?;
        #[cfg(unix)]
        let result = {
            use std::os::fd::AsRawFd;
            let mut event = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: if write { libc::POLLOUT } else { libc::POLLIN },
                revents: 0,
            };
            // SAFETY: event is one initialized pollfd for a live borrowed socket.
            unsafe { libc::poll(&mut event, 1, timeout) }
        };
        #[cfg(windows)]
        let result = {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                POLLRDNORM, POLLWRNORM, WSAPOLLFD, WSAPoll,
            };
            let mut event = WSAPOLLFD {
                fd: socket.as_raw_socket() as _,
                events: if write { POLLWRNORM } else { POLLRDNORM },
                revents: 0,
            };
            // SAFETY: event is one initialized WSAPOLLFD for a live borrowed socket.
            unsafe { WSAPoll(&mut event, 1, timeout) }
        };
        if result > 0 {
            return Ok(());
        }
        if result < 0 {
            let error = native_socket_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(unix)]
fn native_socket_error() -> io::Error {
    io::Error::last_os_error()
}
#[cfg(windows)]
fn native_socket_error() -> io::Error {
    // SAFETY: WSAGetLastError has no pointer or handle preconditions.
    io::Error::from_raw_os_error(unsafe {
        windows_sys::Win32::Networking::WinSock::WSAGetLastError()
    })
}

pub fn peer_process(socket: &Socket) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: ucred is an integer-only C ABI output layout.
        let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&credential) as libc::socklen_t;
        // SAFETY: socket is live and credential/size are writable ABI outputs.
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut credential).cast(),
                &mut size,
            )
        } != 0
            || size as usize != std::mem::size_of_val(&credential)
        {
            return Err(io::Error::last_os_error());
        }
        u32::try_from(credential.pid).map_err(io::Error::other)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut pid: libc::pid_t = 0;
        let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
        // SAFETY: LOCAL_PEERPID returns a pid_t into live writable storage.
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&raw mut pid).cast(),
                &mut size,
            )
        } != 0
            || size as usize != std::mem::size_of_val(&pid)
        {
            return Err(io::Error::last_os_error());
        }
        u32::try_from(pid).map_err(io::Error::other)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{SIO_AF_UNIX_GETPEERPID, WSAIoctl};
        let mut pid = 0u32;
        let mut size = 0u32;
        // SAFETY: owned AF_UNIX socket; output is an initialized DWORD and size
        // slot. This synchronous query has no overlapped operation or callback.
        if unsafe {
            WSAIoctl(
                socket.as_raw_socket() as _,
                SIO_AF_UNIX_GETPEERPID,
                std::ptr::null(),
                0,
                (&raw mut pid).cast(),
                4,
                &mut size,
                std::ptr::null_mut(),
                None,
            )
        } != 0
        {
            return Err(native_socket_error());
        }
        if size != 4 || pid == 0 {
            return Err(io::Error::other("invalid native socket peer identity"));
        }
        Ok(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    #[test]
    fn private_endpoint_verifies_kernel_pid_and_rejects_an_alias_directory() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-peer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        crate::local::create_private_directory(&root).unwrap();
        let root = crate::local::canonical_private_directory(&root).unwrap();
        let path = root.join("peer.sock");
        let server = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        server.bind(&SockAddr::unix(&path).unwrap()).unwrap();
        server.listen(8).unwrap();
        let mut client =
            SocketConnection::connect(&path, std::process::id(), Duration::from_secs(1)).unwrap();
        let (socket, _) = server.accept().unwrap();
        let mut peer = SocketConnection::new(socket, Some(Duration::from_secs(1))).unwrap();
        client.write_all(b"owned").unwrap();
        let mut bytes = [0; 5];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"owned");
        drop(client);
        drop(peer);
        assert_eq!(
            SocketConnection::connect(&path, u32::MAX, Duration::from_secs(1))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let alias = root
            .join("..")
            .join(root.file_name().unwrap())
            .join("peer.sock");
        assert!(
            SocketConnection::connect(&alias, std::process::id(), Duration::from_secs(1)).is_err()
        );
        drop(server);
        std::fs::remove_dir_all(root).unwrap();
    }
    fn pair() -> (SocketConnection, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        (
            SocketConnection::new(stream.into(), Some(Duration::from_millis(50))).unwrap(),
            peer,
        )
    }
    #[test]
    fn idle_peer_times_out_and_closed_peer_preserves_buffered_bytes() {
        let (mut stream, mut peer) = pair();
        assert_eq!(
            stream.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        peer.write_all(b"retained").unwrap();
        drop(peer);
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"retained");
    }
    #[test]
    fn invalid_deadlines_are_rejected_without_changing_the_connection() {
        let (stream, _peer) = pair();
        for timeout in [Duration::ZERO, Duration::from_secs(301)] {
            assert!(stream.set_io_timeout(Some(timeout)).is_err());
        }
        assert_eq!(stream.timeout.get(), Some(Duration::from_millis(50)));
    }
}
