//! Portable guardian-to-guest byte-stream boundary.
//!
//! Native VM drivers provide a stream. Authentication, framing, replay, and
//! workload semantics remain in the shared host/guest protocol.

use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};
use std::time::Duration;

pub trait GuestConnection: Read + Write + Send {
    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

pub trait GuestChannel {
    fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError>;
}

#[derive(Debug)]
pub enum GuestChannelError {
    Io(io::Error),
    Protocol(String),
}

impl Display for GuestChannelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "guest channel I/O error: {error}"),
            Self::Protocol(message) => write!(formatter, "guest channel protocol error: {message}"),
        }
    }
}

impl std::error::Error for GuestChannelError {}

impl From<io::Error> for GuestChannelError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(unix)]
mod unix {
    use super::{GuestChannel, GuestChannelError, GuestConnection};
    #[cfg(target_os = "linux")]
    use std::fs::File;
    use std::io;
    use std::io::{BufRead, BufReader, Write};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;

    impl GuestConnection for UnixStream {
        fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.set_read_timeout(timeout)?;
            self.set_write_timeout(timeout)
        }
    }

    /// A helper-owned Unix relay that carries the raw guest protocol.
    #[derive(Debug, Clone)]
    pub struct DirectUnixChannel {
        pub socket_path: PathBuf,
        pub timeout: Duration,
    }

    impl GuestChannel for DirectUnixChannel {
        fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError> {
            let stream = connect_socket(&self.socket_path)?;
            stream.set_read_timeout(Some(self.timeout))?;
            stream.set_write_timeout(Some(self.timeout))?;
            Ok(Box::new(stream))
        }
    }

    #[derive(Debug, Clone)]
    pub struct UnixVsockChannel {
        pub socket_path: PathBuf,
        pub guest_port: u32,
        pub timeout: Duration,
    }

    impl GuestChannel for UnixVsockChannel {
        fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError> {
            if self.guest_port < 1024 || self.guest_port == u32::MAX {
                return Err(GuestChannelError::Protocol(
                    "invalid guest vsock port".into(),
                ));
            }
            let mut stream = connect_socket(&self.socket_path)?;
            stream.set_read_timeout(Some(self.timeout))?;
            stream.set_write_timeout(Some(self.timeout))?;
            writeln!(stream, "CONNECT {}", self.guest_port)?;
            stream.flush()?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut response = String::new();
            reader.read_line(&mut response)?;
            let assigned_port = response
                .trim()
                .strip_prefix("OK ")
                .and_then(|value| value.parse::<u32>().ok());
            if response.len() > 128 || assigned_port.is_none_or(|port| port < 1024) {
                return Err(GuestChannelError::Protocol(
                    "Firecracker vsock connection acknowledgement is invalid".into(),
                ));
            }
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            Ok(Box::new(stream))
        }
    }

    #[cfg(target_os = "linux")]
    fn connect_socket(path: &Path) -> io::Result<UnixStream> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest socket path must be absolute",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest socket has no parent directory",
            )
        })?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "guest socket has no name")
        })?;
        if name.as_bytes().is_empty() || name.as_bytes().contains(&b'/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest socket name is invalid",
            ));
        }
        let directory = File::open(parent)?;
        let short = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        let stream = UnixStream::connect(short)?;
        drop(directory);
        Ok(stream)
    }

    #[cfg(target_os = "macos")]
    fn connect_socket(path: &std::path::Path) -> io::Result<UnixStream> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest socket path must be absolute",
            ));
        }
        UnixStream::connect(path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn privileged_and_reserved_ports_are_rejected() {
            let mut channel = UnixVsockChannel {
                socket_path: "/nonexistent".into(),
                guest_port: 1,
                timeout: Duration::from_secs(1),
            };
            assert!(matches!(
                channel.connect(),
                Err(GuestChannelError::Protocol(_))
            ));
        }

        #[test]
        fn direct_channel_transports_bytes() {
            use std::fs;
            use std::io::{Read, Write};
            use std::os::unix::net::UnixListener;

            let root = std::env::temp_dir().join(format!("ssdc-{}", std::process::id()));
            fs::create_dir_all(&root).expect("create root");
            let socket = root.join("guest.sock");
            let listener = UnixListener::bind(&socket).expect("bind");
            let server = std::thread::spawn(move || {
                let mut stream = listener.accept().expect("accept").0;
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).expect("read");
                stream.write_all(&byte).expect("write");
            });
            let mut channel = DirectUnixChannel {
                socket_path: socket.clone(),
                timeout: Duration::from_secs(1),
            };
            let mut client = channel.connect().expect("connect");
            client.write_all(b"x").expect("write");
            let mut byte = [0_u8; 1];
            client.read_exact(&mut byte).expect("read");
            assert_eq!(&byte, b"x");
            server.join().expect("server");
            fs::remove_file(socket).expect("remove socket");
            fs::remove_dir(root).expect("remove root");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn descriptor_relative_socket_connect_ignores_long_state_roots() {
            use std::fs;
            use std::os::unix::net::UnixListener;

            let root = std::env::temp_dir().join(format!(
                "sandsurf-vsock-{}-{}",
                std::process::id(),
                "x".repeat(120)
            ));
            fs::create_dir(&root).expect("create long root");
            let socket = root.join("guest.vsock");
            let directory = File::open(&root).expect("open root");
            let listener_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .join("guest.vsock");
            let listener = UnixListener::bind(listener_path).expect("bind short address");
            let client = connect_socket(&socket).expect("connect");
            let _server = listener.accept().expect("accept").0;
            drop(client);
            drop(directory);
            fs::remove_file(&socket).expect("remove socket");
            fs::remove_dir(&root).expect("remove root");
        }
    }
}

#[cfg(unix)]
pub use unix::DirectUnixChannel;
#[cfg(unix)]
pub use unix::UnixVsockChannel;

#[cfg(windows)]
mod windows {
    use super::{GuestChannel, GuestChannelError, GuestConnection};
    use std::io;
    use std::mem::size_of;
    use std::net::TcpStream;
    use std::os::windows::io::{FromRawSocket, RawSocket};
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_sys::Win32::Networking::WinSock::{
        AF_HYPERV, FIONBIO, INVALID_SOCKET, SOCK_STREAM, SOCKADDR, SOCKET_ERROR, SOMAXCONN,
        WSADATA, WSAGetLastError, WSAStartup, accept, bind, closesocket, connect, ioctlsocket,
        listen, socket,
    };
    use windows_sys::Win32::System::Hypervisor::{
        HV_GUID_VSOCK_TEMPLATE, HV_PROTOCOL_RAW, SOCKADDR_HV,
    };
    use windows_sys::core::GUID;

    static WINSOCK: OnceLock<Result<(), i32>> = OnceLock::new();

    impl GuestConnection for TcpStream {
        fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.set_read_timeout(timeout)?;
            self.set_write_timeout(timeout)
        }
    }

    /// Host-initiated Hyper-V socket connection to a Linux AF_VSOCK listener.
    #[derive(Debug, Clone)]
    pub struct HyperVChannel {
        pub vm_id: String,
        pub guest_port: u32,
        pub timeout: Duration,
    }

    /// Host listener for Linux-guest AF_VSOCK connections translated through
    /// Hyper-V sockets. The accepted peer is fenced to one HCS VM identity;
    /// purpose-bound protocol authentication remains mandatory above it.
    pub struct HyperVListener {
        socket: usize,
        vm_id: GUID,
    }

    impl HyperVListener {
        pub fn bind(vm_id: &str, guest_port: u32) -> io::Result<Self> {
            let vm_id = parse_guid(vm_id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid Hyper-V VM identity")
            })?;
            if !(1024..=0x7fff_ffff).contains(&guest_port) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid Hyper-V vsock port",
                ));
            }
            initialize_winsock().map_err(io::Error::other)?;
            // SAFETY: scalar arguments select the documented Hyper-V stream
            // protocol and return a newly owned socket or INVALID_SOCKET.
            let raw = unsafe { socket(AF_HYPERV as i32, SOCK_STREAM, HV_PROTOCOL_RAW as i32) };
            if raw == INVALID_SOCKET {
                return Err(last_socket_error());
            }
            let address = SOCKADDR_HV {
                Family: AF_HYPERV,
                Reserved: 0,
                VmId: GUID::from_u128(0),
                ServiceId: service_id(guest_port),
            };
            // SAFETY: address has the exact SOCKADDR_HV layout and remains live
            // for these synchronous socket calls.
            if unsafe {
                bind(
                    raw,
                    (&raw const address).cast::<SOCKADDR>(),
                    size_of::<SOCKADDR_HV>() as i32,
                )
            } == SOCKET_ERROR
                || unsafe { listen(raw, SOMAXCONN as i32) } == SOCKET_ERROR
            {
                let error = last_socket_error();
                // SAFETY: raw is uniquely owned until successful construction.
                unsafe { closesocket(raw) };
                return Err(error);
            }
            let mut nonblocking = 1_u32;
            // SAFETY: raw is live and nonblocking is a writable u32 as required
            // by FIONBIO.
            if unsafe { ioctlsocket(raw, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
                let error = last_socket_error();
                // SAFETY: raw is uniquely owned until successful construction.
                unsafe { closesocket(raw) };
                return Err(error);
            }
            Ok(Self { socket: raw, vm_id })
        }

        pub fn accept(&self) -> io::Result<TcpStream> {
            let mut address = SOCKADDR_HV::default();
            let mut length = size_of::<SOCKADDR_HV>() as i32;
            // SAFETY: the listener is live and both peer outputs have the exact
            // storage required by AF_HYPERV.
            let accepted = unsafe {
                accept(
                    self.socket,
                    (&raw mut address).cast::<SOCKADDR>(),
                    &mut length,
                )
            };
            if accepted == INVALID_SOCKET {
                return Err(last_socket_error());
            }
            if length != size_of::<SOCKADDR_HV>() as i32
                || address.Family != AF_HYPERV
                || !same_guid(address.VmId, self.vm_id)
            {
                // SAFETY: the rejected accepted socket is uniquely owned here.
                unsafe { closesocket(accepted) };
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Hyper-V socket peer is not the owned Sandbox VM",
                ));
            }
            // SAFETY: ownership of the accepted Winsock socket transfers once.
            Ok(unsafe { TcpStream::from_raw_socket(accepted as RawSocket) })
        }
    }

    impl Drop for HyperVListener {
        fn drop(&mut self) {
            // SAFETY: this listener uniquely owns the socket until drop.
            unsafe { closesocket(self.socket) };
        }
    }

    impl GuestChannel for HyperVChannel {
        fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError> {
            let vm_id = parse_guid(&self.vm_id)
                .ok_or_else(|| GuestChannelError::Protocol("invalid Hyper-V VM identity".into()))?;
            if !(1024..=0x7fff_ffff).contains(&self.guest_port) {
                return Err(GuestChannelError::Protocol(
                    "invalid Hyper-V vsock port".into(),
                ));
            }
            initialize_winsock()?;
            // SAFETY: scalar arguments select the documented Hyper-V stream
            // protocol and return a newly owned socket or INVALID_SOCKET.
            let raw = unsafe { socket(AF_HYPERV as i32, SOCK_STREAM, HV_PROTOCOL_RAW as i32) };
            if raw == INVALID_SOCKET {
                return Err(last_socket_error().into());
            }
            let address = SOCKADDR_HV {
                Family: AF_HYPERV,
                Reserved: 0,
                VmId: vm_id,
                ServiceId: service_id(self.guest_port),
            };
            // SAFETY: address has the exact SOCKADDR_HV layout and remains live
            // for this synchronous connect call.
            if unsafe {
                connect(
                    raw,
                    (&raw const address).cast::<SOCKADDR>(),
                    size_of::<SOCKADDR_HV>() as i32,
                )
            } != 0
            {
                let error = last_socket_error();
                // SAFETY: raw is still uniquely owned after failed connect.
                unsafe { closesocket(raw) };
                return Err(error.into());
            }
            // SAFETY: a connected Winsock SOCKET is representation-compatible
            // with RawSocket and ownership transfers exactly once.
            let stream = unsafe { TcpStream::from_raw_socket(raw as RawSocket) };
            stream.set_read_timeout(Some(self.timeout))?;
            stream.set_write_timeout(Some(self.timeout))?;
            Ok(Box::new(stream))
        }
    }

    fn initialize_winsock() -> Result<(), GuestChannelError> {
        match WINSOCK.get_or_init(|| {
            let mut data = WSADATA::default();
            // SAFETY: data is a valid writable WSADATA and version 2.2 is the
            // platform socket contract used by Hyper-V sockets.
            let result = unsafe { WSAStartup(0x0202, &mut data) };
            if result == 0 { Ok(()) } else { Err(result) }
        }) {
            Ok(()) => Ok(()),
            Err(code) => Err(GuestChannelError::Io(io::Error::from_raw_os_error(*code))),
        }
    }

    fn last_socket_error() -> io::Error {
        // SAFETY: WSAGetLastError has no pointer or ownership preconditions.
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    fn service_id(port: u32) -> GUID {
        GUID {
            data1: port,
            ..HV_GUID_VSOCK_TEMPLATE
        }
    }

    fn same_guid(left: GUID, right: GUID) -> bool {
        left.data1 == right.data1
            && left.data2 == right.data2
            && left.data3 == right.data3
            && left.data4 == right.data4
    }

    fn parse_guid(value: &str) -> Option<GUID> {
        let compact: String = value
            .chars()
            .filter(|character| *character != '-')
            .collect();
        if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let raw = u128::from_str_radix(&compact, 16).ok()?;
        Some(GUID::from_u128(raw))
    }
}

#[cfg(windows)]
pub use windows::{HyperVChannel, HyperVListener};
