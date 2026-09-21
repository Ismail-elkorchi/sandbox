use sandbox_network_broker::{
    BrokerHandle, BrokerPolicy, BrokerReport, BrokerSnapshot, NetworkViolation,
};
use sandbox_policy::ManagedNetworkRule;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const AUTH_MAGIC: &[u8; 7] = b"SBXNET1";
const HTTP_VSOCK_PORT: u32 = 12_080;
const SOCKS_VSOCK_PORT: u32 = 12_081;
const DNS_TCP_VSOCK_PORT: u32 = 12_082;
const DNS_UDP_VSOCK_PORT: u32 = 12_083;
const MAX_DNS_MESSAGE: usize = 4096;
const MAX_RECORDED_VIOLATIONS: usize = 1024;

pub struct VmNetworkBridge {
    broker: Option<BrokerHandle>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    listeners: Vec<JoinHandle<()>>,
    socket_paths: Vec<PathBuf>,
    violations: Arc<Mutex<Vec<NetworkViolation>>>,
    active_tunnels: ActiveTunnels,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    stopped: bool,
}

type ActiveTunnels = Arc<Mutex<HashMap<u64, UnixStream>>>;

#[derive(Clone)]
struct TunnelContext {
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    active_tunnels: ActiveTunnels,
    next_tunnel_id: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
}

struct TunnelRegistration {
    id: u64,
    streams: ActiveTunnels,
}

impl TunnelRegistration {
    fn new(id: u64, streams: ActiveTunnels, stream: &UnixStream) -> io::Result<Self> {
        streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, stream.try_clone()?);
        Ok(Self { id, streams })
    }
}

impl Drop for TunnelRegistration {
    fn drop(&mut self) {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

fn shutdown_tunnels(streams: &ActiveTunnels) {
    for stream in streams
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
    {
        let _ = stream.shutdown(Shutdown::Both);
    }
}

impl VmNetworkBridge {
    pub fn start(
        vsock_path: &Path,
        nonce: [u8; 32],
        rules: Vec<ManagedNetworkRule>,
    ) -> io::Result<Self> {
        Self::start_inner(vsock_path, nonce, BrokerRules::Legacy(rules))
    }

    pub fn start_partitioned(
        vsock_path: &Path,
        nonce: [u8; 32],
        policy: BrokerPolicy,
    ) -> io::Result<Self> {
        Self::start_inner(vsock_path, nonce, BrokerRules::Partitioned(policy))
    }

    fn start_inner(vsock_path: &Path, nonce: [u8; 32], rules: BrokerRules) -> io::Result<Self> {
        let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let http_address = http.local_addr()?;
        let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let socks_address = socks.local_addr()?;
        let dns_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let dns_udp_address = dns_udp.local_addr()?;
        let dns_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let dns_tcp_address = dns_tcp.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let active_tunnels = Arc::new(Mutex::new(HashMap::new()));
        let next_tunnel_id = Arc::new(AtomicU64::new(1));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let tx_bytes = Arc::new(AtomicU64::new(0));
        let tunnel_context = TunnelContext {
            stop: Arc::clone(&stop),
            active: Arc::clone(&active),
            active_tunnels: Arc::clone(&active_tunnels),
            next_tunnel_id,
            rx_bytes: Arc::clone(&rx_bytes),
            tx_bytes: Arc::clone(&tx_bytes),
        };
        let specifications = [
            (HTTP_VSOCK_PORT, TunnelTarget::Tcp(http_address)),
            (SOCKS_VSOCK_PORT, TunnelTarget::Tcp(socks_address)),
            (DNS_TCP_VSOCK_PORT, TunnelTarget::Tcp(dns_tcp_address)),
            (DNS_UDP_VSOCK_PORT, TunnelTarget::Udp(dns_udp_address)),
        ];
        let mut bound = Vec::with_capacity(specifications.len());
        for (port, target) in specifications {
            let path = guest_initiated_path(vsock_path, port);
            let listener = match bind_beneath_parent(&path) {
                Ok(listener) => listener,
                Err(error) => {
                    for (_, _, created_path) in &bound {
                        let _ = std::fs::remove_file(created_path);
                    }
                    return Err(error);
                }
            };
            if let Err(error) = listener.set_nonblocking(true) {
                let _ = std::fs::remove_file(&path);
                for (_, _, created_path) in &bound {
                    let _ = std::fs::remove_file(created_path);
                }
                return Err(error);
            }
            bound.push((listener, target, path));
        }
        let violations = Arc::new(Mutex::new(Vec::new()));
        let callback_violations = Arc::clone(&violations);
        let listeners = vec![
            File::from(OwnedFd::from(http)),
            File::from(OwnedFd::from(socks)),
            File::from(OwnedFd::from(dns_udp)),
            File::from(OwnedFd::from(dns_tcp)),
        ];
        let callback = move |violation| {
            if let Ok(mut values) = callback_violations.lock()
                && values.len() < MAX_RECORDED_VIOLATIONS
            {
                values.push(violation);
            }
        };
        let broker_result = match rules {
            BrokerRules::Legacy(rules) => BrokerHandle::start(listeners, rules, callback),
            BrokerRules::Partitioned(policy) => {
                BrokerHandle::start_partitioned(listeners, policy, callback)
            }
        };
        let broker = match broker_result {
            Ok(broker) => broker,
            Err(error) => {
                for (_, _, path) in &bound {
                    let _ = std::fs::remove_file(path);
                }
                return Err(error);
            }
        };
        let mut listeners = Vec::with_capacity(bound.len());
        let mut socket_paths = Vec::with_capacity(bound.len());
        for (listener, target, path) in bound {
            socket_paths.push(path);
            listeners.push(tunnel_accept_loop(
                listener,
                target,
                nonce,
                tunnel_context.clone(),
            ));
        }
        Ok(Self {
            broker: Some(broker),
            stop,
            active,
            listeners,
            socket_paths,
            violations,
            active_tunnels,
            rx_bytes,
            tx_bytes,
            stopped: false,
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> BrokerSnapshot {
        let mut snapshot = self
            .broker
            .as_ref()
            .map_or_else(BrokerSnapshot::default, BrokerHandle::snapshot);
        snapshot.rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        snapshot.tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        snapshot
    }

    pub fn take_violations(&self) -> Vec<NetworkViolation> {
        self.violations
            .lock()
            .map(|mut values| values.drain(..).collect())
            .unwrap_or_default()
    }

    pub fn stop(mut self) -> BrokerReport {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> BrokerReport {
        if self.stopped {
            return BrokerReport::default();
        }
        self.stopped = true;
        self.stop.store(true, Ordering::Release);
        shutdown_tunnels(&self.active_tunnels);
        let mut report = BrokerReport::default();
        for listener in self.listeners.drain(..) {
            if listener.join().is_err() {
                report
                    .cleanup_failures
                    .push("VM network tunnel listener panicked".into());
            }
        }
        shutdown_tunnels(&self.active_tunnels);
        for path in self.socket_paths.drain(..) {
            if let Err(error) = std::fs::remove_file(&path)
                && error.kind() != io::ErrorKind::NotFound
            {
                report.cleanup_failures.push(format!(
                    "VM network tunnel socket {} could not be removed: {error}",
                    path.display()
                ));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.active.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            shutdown_tunnels(&self.active_tunnels);
            thread::sleep(Duration::from_millis(10));
        }
        if self.active.load(Ordering::Acquire) != 0 {
            report
                .cleanup_failures
                .push("VM network tunnels did not drain before cleanup deadline".into());
        }
        if let Some(broker) = self.broker.take() {
            let broker = broker.stop();
            report.connections = broker.connections;
            report.violations = broker.violations;
            report.cleanup_failures.extend(broker.cleanup_failures);
        }
        report.rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        report.tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        report
    }
}

enum BrokerRules {
    Legacy(Vec<ManagedNetworkRule>),
    Partitioned(BrokerPolicy),
}

impl Drop for VmNetworkBridge {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

#[derive(Clone, Copy)]
enum TunnelTarget {
    Tcp(std::net::SocketAddr),
    Udp(std::net::SocketAddr),
}

fn guest_initiated_path(base: &Path, port: u32) -> PathBuf {
    PathBuf::from(format!("{}_{port}", base.to_string_lossy()))
}

/// Bind through an open parent directory so deep durable state roots do not
/// consume the fixed-size `sockaddr_un` pathname. The socket is still created
/// in the exact VM state directory that Firecracker has mounted at `/vm/state`.
fn bind_beneath_parent(path: &Path) -> io::Result<UnixListener> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VM network socket path must be absolute",
        ));
    }
    let _parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VM network socket has no parent directory",
        )
    })?;
    let _name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "VM network socket has no name")
    })?;
    #[cfg(target_os = "linux")]
    {
        let directory = File::open(_parent)?;
        let short = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(_name);
        let listener = UnixListener::bind(short)?;
        drop(directory);
        Ok(listener)
    }
    #[cfg(target_os = "macos")]
    {
        UnixListener::bind(path)
    }
}

fn tunnel_accept_loop(
    listener: UnixListener,
    target: TunnelTarget,
    nonce: [u8; 32],
    context: TunnelContext,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while !context.stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    context.active.fetch_add(1, Ordering::AcqRel);
                    let context = context.clone();
                    let tunnel_id = context.next_tunnel_id.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || {
                        let _ = TunnelRegistration::new(
                            tunnel_id,
                            Arc::clone(&context.active_tunnels),
                            &stream,
                        )
                        .and_then(|_registration| {
                            handle_tunnel(
                                stream,
                                target,
                                &nonce,
                                &context.stop,
                                &context.rx_bytes,
                                &context.tx_bytes,
                            )
                        });
                        context.active.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    })
}

fn handle_tunnel(
    mut guest: UnixStream,
    target: TunnelTarget,
    nonce: &[u8; 32],
    stop: &Arc<AtomicBool>,
    rx_bytes: &Arc<AtomicU64>,
    tx_bytes: &Arc<AtomicU64>,
) -> io::Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "VM network bridge is stopping",
        ));
    }
    guest.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut authentication = [0_u8; AUTH_MAGIC.len() + 32];
    guest.read_exact(&mut authentication)?;
    let matches = authentication[..AUTH_MAGIC.len()] == AUTH_MAGIC[..]
        && authentication[AUTH_MAGIC.len()..]
            .iter()
            .zip(nonce)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0;
    if !matches {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM network tunnel authentication failed",
        ));
    }
    match target {
        TunnelTarget::Tcp(address) => relay_tcp(
            guest,
            TcpStream::connect(address)?,
            stop,
            rx_bytes,
            tx_bytes,
        ),
        TunnelTarget::Udp(address) => relay_udp_query(guest, address, stop, rx_bytes, tx_bytes),
    }
}

fn relay_tcp(
    mut guest: UnixStream,
    mut broker: TcpStream,
    stop: &Arc<AtomicBool>,
    rx_bytes: &Arc<AtomicU64>,
    tx_bytes: &Arc<AtomicU64>,
) -> io::Result<()> {
    guest.set_read_timeout(Some(Duration::from_millis(200)))?;
    guest.set_write_timeout(Some(Duration::from_millis(200)))?;
    broker.set_read_timeout(Some(Duration::from_millis(200)))?;
    broker.set_write_timeout(Some(Duration::from_millis(200)))?;
    let mut guest_reader = guest.try_clone()?;
    let mut broker_writer = broker.try_clone()?;
    let copy_stop = Arc::clone(stop);
    let outbound_bytes = Arc::clone(tx_bytes);
    let outbound = thread::spawn(move || {
        copy_with_stop(
            &mut guest_reader,
            &mut broker_writer,
            &copy_stop,
            &outbound_bytes,
        )
    });
    let inbound = copy_with_stop(&mut broker, &mut guest, stop, rx_bytes);
    let _ = guest.shutdown(Shutdown::Both);
    let _ = broker.shutdown(Shutdown::Both);
    let outbound = outbound
        .join()
        .map_err(|_| io::Error::other("VM tunnel relay panicked"))?;
    inbound.and(outbound)
}

fn copy_with_stop(
    reader: &mut impl Read,
    writer: &mut impl Write,
    stop: &AtomicBool,
    bytes: &AtomicU64,
) -> io::Result<()> {
    let mut buffer = [0_u8; 64 * 1024];
    while !stop.load(Ordering::Acquire) {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                writer.write_all(&buffer[..count])?;
                bytes.fetch_add(count as u64, Ordering::Relaxed);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn relay_udp_query(
    mut guest: UnixStream,
    broker_address: std::net::SocketAddr,
    stop: &AtomicBool,
    rx_bytes: &AtomicU64,
    tx_bytes: &AtomicU64,
) -> io::Result<()> {
    let mut length = [0_u8; 2];
    guest.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_DNS_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tunneled DNS query length",
        ));
    }
    let mut query = vec![0_u8; length];
    guest.read_exact(&mut query)?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.send_to(&query, broker_address)?;
    tx_bytes.fetch_add(query.len() as u64, Ordering::Relaxed);
    let mut response = [0_u8; MAX_DNS_MESSAGE];
    let count = loop {
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "VM network bridge is stopping",
            ));
        }
        match socket.recv(&mut response) {
            Ok(count) => break count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    };
    rx_bytes.fetch_add(count as u64, Ordering::Relaxed);
    guest.write_all(&(count as u16).to_be_bytes())?;
    guest.write_all(&response[..count])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn tunnel_rejects_an_invalid_nonce_before_connecting() {
        let (mut peer, bridge) = UnixStream::pair().expect("pair");
        let stop = Arc::new(AtomicBool::new(false));
        let expected = [7_u8; 32];
        let worker = thread::spawn(move || {
            handle_tunnel(
                bridge,
                TunnelTarget::Tcp("127.0.0.1:1".parse().expect("address")),
                &expected,
                &stop,
                &Arc::new(AtomicU64::new(0)),
                &Arc::new(AtomicU64::new(0)),
            )
        });
        let mut authentication = Vec::from(AUTH_MAGIC);
        authentication.extend_from_slice(&[8_u8; 32]);
        peer.write_all(&authentication).expect("authentication");
        let error = worker
            .join()
            .expect("worker")
            .expect_err("authentication must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn stopping_the_bridge_interrupts_an_unfinished_tunnel() {
        let base = std::env::temp_dir().join(format!(
            "sbx-net-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let bridge = VmNetworkBridge::start(&base, [3_u8; 32], Vec::new()).expect("bridge");
        let mut guest = UnixStream::connect(guest_initiated_path(&base, HTTP_VSOCK_PORT))
            .expect("connect tunnel");
        let deadline = Instant::now() + Duration::from_secs(1);
        while bridge.active.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(bridge.active.load(Ordering::Acquire), 1);
        let started = Instant::now();
        let report = bridge.stop();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(report.cleanup_failures.is_empty(), "{report:?}");
        guest
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        let mut byte = [0_u8; 1];
        assert!(matches!(guest.read(&mut byte), Ok(0) | Err(_)));
    }
}
