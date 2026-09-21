use crate::{GuestChannel, GuestConnection, UnixVsockChannel};
use sandsurf_protocol::Exposure;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const EXPOSURE_MAGIC: &[u8; 8] = b"SSFPORT1";
const GUEST_EXPOSURE_PORT: u32 = 10_790;

pub struct VmPortGateway {
    stop: Arc<AtomicBool>,
    listeners: Vec<JoinHandle<()>>,
    active: Arc<Mutex<HashMap<u64, TcpStream>>>,
}

impl VmPortGateway {
    pub fn start(
        vsock_path: &Path,
        capability: [u8; 32],
        exposures: &[Exposure],
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(Mutex::new(HashMap::new()));
        let next = Arc::new(AtomicU64::new(1));
        let mut listeners = Vec::new();
        for exposure in exposures.iter().filter(|value| value.active) {
            exposure
                .spec
                .validate()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            if exposure.spec.host_port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "host exposure port was not assigned",
                ));
            }
            let listener =
                TcpListener::bind((exposure.spec.host_address.as_str(), exposure.spec.host_port))?;
            listener.set_nonblocking(true)?;
            let guest_port = exposure.spec.guest_port;
            let socket = vsock_path.to_path_buf();
            let thread_stop = Arc::clone(&stop);
            let thread_active = Arc::clone(&active);
            let thread_next = Arc::clone(&next);
            listeners.push(thread::spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            let id = thread_next.fetch_add(1, Ordering::Relaxed);
                            if let Ok(clone) = client.try_clone()
                                && let Ok(mut streams) = thread_active.lock()
                            {
                                streams.insert(id, clone);
                            }
                            let active = Arc::clone(&thread_active);
                            let stop = Arc::clone(&thread_stop);
                            let socket = socket.clone();
                            thread::spawn(move || {
                                let result = connect_guest(&socket, capability, guest_port)
                                    .and_then(|guest| relay(client, guest, &stop));
                                if let Ok(mut streams) = active.lock() {
                                    streams.remove(&id);
                                }
                                let _ = result;
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            }));
        }
        Ok(Self {
            stop,
            listeners,
            active,
        })
    }

    pub fn stop(mut self) -> io::Result<()> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Ok(streams) = self.active.lock() {
            for stream in streams.values() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        let mut failed = false;
        for handle in self.listeners.drain(..) {
            failed |= handle.join().is_err();
        }
        if failed {
            Err(io::Error::other("port exposure listener panicked"))
        } else {
            Ok(())
        }
    }
}

impl Drop for VmPortGateway {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

fn connect_guest(
    socket: &Path,
    capability: [u8; 32],
    port: u16,
) -> io::Result<Box<dyn GuestConnection>> {
    let mut channel = UnixVsockChannel {
        socket_path: socket.to_path_buf(),
        guest_port: GUEST_EXPOSURE_PORT,
        timeout: Duration::from_secs(5),
    };
    let mut guest = channel.connect().map_err(io::Error::other)?;
    guest.write_all(EXPOSURE_MAGIC)?;
    guest.write_all(&capability)?;
    guest.write_all(&port.to_be_bytes())?;
    guest.flush()?;
    Ok(guest)
}

fn relay(
    mut client: TcpStream,
    mut guest: Box<dyn GuestConnection>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let timeout = Some(Duration::from_millis(100));
    client.set_read_timeout(timeout)?;
    client.set_write_timeout(timeout)?;
    guest.set_io_timeout(timeout)?;
    let mut buffer = [0_u8; 64 * 1024];
    while !stop.load(Ordering::Acquire) {
        let mut progressed = false;
        match client.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                guest.write_all(&buffer[..count])?;
                guest.flush()?;
                progressed = true;
            }
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error),
        }
        match guest.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                client.write_all(&buffer[..count])?;
                progressed = true;
            }
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error),
        }
        if !progressed {
            thread::yield_now();
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}
