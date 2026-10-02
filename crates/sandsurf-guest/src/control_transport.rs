//! Linux byte transports for the same authenticated management protocol.
//! These devices are guest observations. Their failure says nothing about
//! native VM power, host authority, or the liveness of arbitrary Linux work.
use sandsurf_protocol::{GUEST_SERIAL_CONNECTIONS, GUEST_SERIAL_PREFIX};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct Connection {
    file: File,
    deadline: Option<Instant>,
}

impl Connection {
    pub fn new(file: File) -> io::Result<Self> {
        let fd = file.as_raw_fd();
        // SAFETY: the owned descriptor is live; F_GETFL/F_SETFL take scalars.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            // One absolute authentication deadline, not a renewed allowance
            // per fragment. After authentication the owner controls teardown.
            deadline: Some(Instant::now() + Duration::from_secs(15)),
        })
    }

    pub fn authenticated(&mut self) {
        self.deadline = None;
    }

    pub fn open_port(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.file_type().is_char_device() {
            return Err(io::Error::other(
                "guest control port is not a character device",
            ));
        }
        Self::new(file)
    }

    fn check_deadline(&self) -> io::Result<i32> {
        match self.deadline {
            Some(deadline) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or(io::ErrorKind::TimedOut)?;
                Ok(remaining.as_millis().clamp(1, i32::MAX as u128) as i32)
            }
            None => Ok(-1),
        }
    }

    fn wait(&self, writing: bool) -> io::Result<()> {
        loop {
            let mut event = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: if writing { libc::POLLOUT } else { libc::POLLIN },
                revents: 0,
            };
            // SAFETY: one live borrowed file and one initialized pollfd output.
            let result = unsafe { libc::poll(&mut event, 1, self.check_deadline()?) };
            if result > 0 {
                if event.revents & libc::POLLNVAL != 0 {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                // Read queued bytes before interpreting HUP as EOF. The
                // driver reports disconnect even when the machine stays up.
                return Ok(());
            }
            if result == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Read for Connection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check_deadline()?;
            match self.file.read(bytes) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait(false)?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}
impl Write for Connection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check_deadline()?;
            match self.file.write(bytes) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait(true)?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check_deadline().map(|_| ())
    }
}

/// Discover a complete fixed device set by the virtio device's declared name,
/// not directory order or a distribution-specific /dev symlink convention.
/// Firecracker has no such device; it uses its native vsock attachment.
pub fn serial_ports(sysfs: &Path, devices: &Path) -> io::Result<Option<Vec<PathBuf>>> {
    let entries = match fs::read_dir(sysfs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut ports = vec![None; GUEST_SERIAL_CONNECTIONS];
    for (index, entry) in entries.enumerate() {
        if index >= 256 {
            return Err(io::Error::other(
                "guest virtio port inventory exceeds bound",
            ));
        }
        let entry = entry?;
        let mut name = String::new();
        let name_file = match File::open(entry.path().join("name")) {
            Ok(file) => file,
            // Ordinary unnamed virtio consoles have no name attribute.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        name_file.take(129).read_to_string(&mut name)?;
        if name.len() > 128 {
            return Err(io::Error::other("guest virtio port name exceeds bound"));
        }
        let Some(slot) = name.trim().strip_prefix(GUEST_SERIAL_PREFIX) else {
            continue;
        };
        let slot = slot
            .parse::<usize>()
            .ok()
            .filter(|slot| {
                *slot < GUEST_SERIAL_CONNECTIONS
                    && slot.to_string() == name.trim()[GUEST_SERIAL_PREFIX.len()..]
            })
            .ok_or_else(|| io::Error::other("invalid guest control slot"))?;
        if ports[slot]
            .replace(devices.join(entry.file_name()))
            .is_some()
        {
            return Err(io::Error::other("duplicate guest control slot"));
        }
    }
    if ports.iter().all(Option::is_none) {
        return Ok(None);
    }
    ports
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .map(Some)
        .ok_or_else(|| io::Error::other("guest control device set is incomplete"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn disconnect_preserves_queued_bytes_but_does_not_invent_a_new_session() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut connection = Connection::new(File::from(OwnedFd::from(stream))).unwrap();
        peer.write_all(b"retained").unwrap();
        drop(peer);
        let mut bytes = Vec::new();
        connection.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"retained");
    }
    #[test]
    fn fragmented_authentication_has_one_deadline() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut connection = Connection::new(File::from(OwnedFd::from(stream))).unwrap();
        connection.deadline = Some(Instant::now() + Duration::from_millis(30));
        peer.write_all(b"x").unwrap();
        assert_eq!(connection.read(&mut [0; 1]).unwrap(), 1);
        assert_eq!(
            connection.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        connection.authenticated();
        peer.write_all(b"y").unwrap();
        assert_eq!(connection.read(&mut [0; 1]).unwrap(), 1);
    }
    #[test]
    fn discovery_requires_all_unique_canonically_named_slots() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-guest-ports-{}-{}",
            std::process::id(),
            super::super::hex(&{
                let mut nonce = [0; 16];
                getrandom::getrandom(&mut nonce).unwrap();
                nonce
            })
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("vport0p0")).unwrap();
        assert!(serial_ports(&root, Path::new("/dev")).unwrap().is_none());
        for slot in (0..GUEST_SERIAL_CONNECTIONS).rev() {
            let device = root.join(format!("vport0p{}", slot + 1));
            fs::create_dir(&device).unwrap();
            fs::write(
                device.join("name"),
                format!("{GUEST_SERIAL_PREFIX}{slot}\n"),
            )
            .unwrap();
            if slot > 0 {
                assert!(serial_ports(&root, Path::new("/dev")).is_err());
            }
        }
        let ports = serial_ports(&root, Path::new("/dev")).unwrap().unwrap();
        assert_eq!(ports[0], Path::new("/dev/vport0p1"));
        fs::write(
            root.join("vport0p1/name"),
            format!("{GUEST_SERIAL_PREFIX}01\n"),
        )
        .unwrap();
        assert!(serial_ports(&root, Path::new("/dev")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
