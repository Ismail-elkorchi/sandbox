use std::fmt::{Display, Formatter};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

pub trait GuestConnection: Read + Write + Send {
    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl GuestConnection for UnixStream {
    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }
}

pub trait GuestChannel {
    fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError>;
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
        let mut stream = UnixStream::connect(&self.socket_path)?;
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
}
