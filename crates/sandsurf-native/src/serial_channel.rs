//! Exclusive connection leases for QEMU's fixed virtio-serial device ports.
//! An owner closes the pool when its child exits; stale channel clones cannot
//! attach to a later owner, even if an operating system reuses the old PID.
use crate::socket_io::SocketConnection;
use crate::{GuestChannel, GuestChannelError, GuestConnection};
use sandsurf_protocol::GUEST_SERIAL_CONNECTIONS;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Slots {
    held: [bool; GUEST_SERIAL_CONNECTIONS],
    closed: bool,
}

struct Pool {
    paths: [PathBuf; GUEST_SERIAL_CONNECTIONS],
    process_id: u32,
    timeout: Duration,
    slots: Mutex<Slots>,
}

/// The VM owner retains this lifetime guard. Connections carry leases but
/// never prolong native power or authorize reopening a dead owner's device.
pub struct SerialOwner {
    pool: Arc<Pool>,
}

#[derive(Clone)]
pub struct SerialChannel {
    pool: Arc<Pool>,
}

impl PartialEq for SerialChannel {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pool, &other.pool)
    }
}
impl Eq for SerialChannel {}

impl SerialOwner {
    pub fn new(directory: &Path, process_id: u32, timeout: Duration) -> io::Result<Self> {
        if process_id == 0 || timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if crate::local::canonical_private_directory(directory)? != directory {
            return Err(io::Error::other("serial endpoint directory is an alias"));
        }
        Ok(Self {
            pool: Arc::new(Pool {
                paths: std::array::from_fn(|slot| directory.join(format!("control-{slot}.sock"))),
                process_id,
                timeout,
                slots: Mutex::new(Slots {
                    held: [false; GUEST_SERIAL_CONNECTIONS],
                    closed: false,
                }),
            }),
        })
    }
    pub fn channel(&self) -> SerialChannel {
        SerialChannel {
            pool: Arc::clone(&self.pool),
        }
    }
    pub fn close(&self) {
        if let Ok(mut slots) = self.pool.slots.lock() {
            slots.closed = true;
        }
    }
}

impl Drop for SerialOwner {
    fn drop(&mut self) {
        self.close();
    }
}

struct Lease {
    pool: Arc<Pool>,
    slot: usize,
}

impl Pool {
    fn acquire(self: &Arc<Self>) -> io::Result<Lease> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| io::Error::other("serial lease lock failed"))?;
        if slots.closed {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let slot = slots
            .held
            .iter()
            .position(|held| !held)
            .ok_or(io::ErrorKind::WouldBlock)?;
        slots.held[slot] = true;
        Ok(Lease {
            pool: Arc::clone(self),
            slot,
        })
    }
}

impl Lease {
    fn check(&self) -> io::Result<()> {
        if self
            .pool
            .slots
            .lock()
            .map_err(|_| io::Error::other("serial lease lock failed"))?
            .closed
        {
            return Err(io::ErrorKind::NotConnected.into());
        }
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.pool.slots.lock() {
            slots.held[self.slot] = false;
        }
    }
}

struct LeasedConnection {
    stream: SocketConnection,
    lease: Lease,
}
impl Read for LeasedConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.lease.check()?;
        self.stream.read(bytes)
    }
}
impl Write for LeasedConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.lease.check()?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.lease.check()?;
        self.stream.flush()
    }
}
impl GuestConnection for LeasedConnection {
    fn set_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.lease.check()?;
        self.stream.set_io_timeout(timeout)
    }
}
impl GuestChannel for SerialChannel {
    fn connect(&mut self) -> Result<Box<dyn GuestConnection>, GuestChannelError> {
        let lease = self.pool.acquire()?;
        let stream = SocketConnection::connect(
            &self.pool.paths[lease.slot],
            self.pool.process_id,
            self.pool.timeout,
        )?;
        lease.check()?;
        Ok(Box::new(LeasedConnection { stream, lease }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pool() -> Arc<Pool> {
        Arc::new(Pool {
            paths: std::array::from_fn(|slot| PathBuf::from(format!("/control-{slot}"))),
            process_id: std::process::id(),
            timeout: Duration::from_secs(1),
            slots: Mutex::new(Slots {
                held: [false; GUEST_SERIAL_CONNECTIONS],
                closed: false,
            }),
        })
    }
    #[test]
    fn slots_are_exclusive_bounded_and_released_on_failed_connect() {
        let pool = pool();
        let mut leases: Vec<_> = (0..GUEST_SERIAL_CONNECTIONS)
            .map(|slot| {
                let lease = pool.acquire().unwrap();
                assert_eq!(lease.slot, slot);
                lease
            })
            .collect();
        assert_eq!(
            pool.acquire().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(leases.remove(3));
        assert_eq!(pool.acquire().unwrap().slot, 3);
        drop(leases);
        let mut channel = SerialChannel {
            pool: Arc::clone(&pool),
        };
        assert!(channel.connect().is_err());
        assert!(pool.slots.lock().unwrap().held.iter().all(|held| !held));
    }
    #[test]
    fn owner_death_fences_previously_cloned_channels_and_active_leases() {
        let pool = pool();
        let owner = SerialOwner {
            pool: Arc::clone(&pool),
        };
        let mut channel = owner.channel();
        let lease = pool.acquire().unwrap();
        drop(owner);
        assert_eq!(
            lease.check().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(channel.connect().is_err());
        drop(lease);
        assert!(pool.slots.lock().unwrap().closed);
    }
}
