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

            let root = std::env::temp_dir().join(format!(
                "sandsurf-direct-channel-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
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
