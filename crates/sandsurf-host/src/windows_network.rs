//! Guardian-owned Hyper-V socket networking for Windows hosts.

use sandbox_guest::{
    GUEST_EXPOSURE_PORT, NETWORK_AUTH_MAGIC, NETWORK_DNS_TCP_PORT, NETWORK_DNS_UDP_PORT,
    NETWORK_HTTP_PORT, NETWORK_SOCKS_PORT,
};
use sandbox_network_broker::{
    BrokerHandle, BrokerPolicy, BrokerReport, BrokerSnapshot, BrokerSockets, NetworkViolation,
};
use sandsurf_native::{GuestChannel, GuestConnection, HyperVChannel, HyperVListener};
use sandsurf_protocol::Exposure;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_DNS_MESSAGE: usize = 4096;
const MAX_RECORDED_VIOLATIONS: usize = 1024;
const EXPOSURE_MAGIC: &[u8; 8] = b"SSFPORT1";

type ActiveTunnels = Arc<Mutex<HashMap<u64, TcpStream>>>;

#[derive(Clone)]
struct TunnelContext {
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    streams: ActiveTunnels,
    next: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
}

struct TunnelRegistration {
    id: u64,
    streams: ActiveTunnels,
}

impl TunnelRegistration {
    fn new(id: u64, streams: ActiveTunnels, stream: &TcpStream) -> io::Result<Self> {
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

pub struct WindowsNetworkBridge {
    broker: Option<BrokerHandle>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    streams: ActiveTunnels,
    listeners: Vec<JoinHandle<()>>,
    violations: Arc<Mutex<Vec<NetworkViolation>>>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    stopped: bool,
}

impl WindowsNetworkBridge {
    pub fn start(vm_id: &str, capability: [u8; 32], policy: BrokerPolicy) -> io::Result<Self> {
        let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let http_address = http.local_addr()?;
        let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let socks_address = socks.local_addr()?;
        let dns_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let dns_udp_address = dns_udp.local_addr()?;
        let dns_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let dns_tcp_address = dns_tcp.local_addr()?;

        let specifications = [
            (NETWORK_HTTP_PORT, TunnelTarget::Tcp(http_address)),
            (NETWORK_SOCKS_PORT, TunnelTarget::Tcp(socks_address)),
            (NETWORK_DNS_TCP_PORT, TunnelTarget::Tcp(dns_tcp_address)),
            (NETWORK_DNS_UDP_PORT, TunnelTarget::Udp(dns_udp_address)),
        ];
        let mut bound = Vec::with_capacity(specifications.len());
        for (port, target) in specifications {
            bound.push((HyperVListener::bind(vm_id, port)?, target));
        }

        let violations = Arc::new(Mutex::new(Vec::new()));
        let callback_violations = Arc::clone(&violations);
        let broker = BrokerHandle::start_sockets(
            BrokerSockets {
                http,
                socks,
                dns_udp,
                dns_tcp,
            },
            policy,
            move |violation| {
                if let Ok(mut values) = callback_violations.lock()
                    && values.len() < MAX_RECORDED_VIOLATIONS
                {
                    values.push(violation);
                }
            },
        )?;

        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let tx_bytes = Arc::new(AtomicU64::new(0));
        let context = TunnelContext {
            stop: Arc::clone(&stop),
            active: Arc::clone(&active),
            streams: Arc::clone(&streams),
            next: Arc::new(AtomicU64::new(1)),
            rx_bytes: Arc::clone(&rx_bytes),
            tx_bytes: Arc::clone(&tx_bytes),
        };
        let listeners = bound
            .into_iter()
            .map(|(listener, target)| {
                tunnel_accept_loop(listener, target, capability, context.clone())
            })
            .collect();
        Ok(Self {
            broker: Some(broker),
            stop,
            active,
            streams,
            listeners,
            violations,
            rx_bytes,
            tx_bytes,
            stopped: false,
        })
    }

    pub fn snapshot(&self) -> BrokerSnapshot {
        let mut value = self
            .broker
            .as_ref()
            .map_or_else(BrokerSnapshot::default, BrokerHandle::snapshot);
        value.rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        value.tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        value
    }

    #[allow(dead_code)]
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
        shutdown_streams(&self.streams);
        let mut report = BrokerReport::default();
        for listener in self.listeners.drain(..) {
            if listener.join().is_err() {
                report
                    .cleanup_failures
                    .push("Hyper-V network listener panicked".into());
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.active.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            shutdown_streams(&self.streams);
            thread::sleep(Duration::from_millis(10));
        }
        if self.active.load(Ordering::Acquire) != 0 {
            report
                .cleanup_failures
                .push("Hyper-V network tunnels did not drain".into());
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

impl Drop for WindowsNetworkBridge {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

#[derive(Clone, Copy)]
enum TunnelTarget {
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

fn tunnel_accept_loop(
    listener: HyperVListener,
    target: TunnelTarget,
    capability: [u8; 32],
    context: TunnelContext,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while !context.stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok(stream) => {
                    context.active.fetch_add(1, Ordering::AcqRel);
                    let context = context.clone();
                    let id = context.next.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || {
                        let _ = TunnelRegistration::new(id, Arc::clone(&context.streams), &stream)
                            .and_then(|_registration| {
                                handle_tunnel(stream, target, capability, &context)
                            });
                        context.active.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    })
}

fn handle_tunnel(
    mut guest: TcpStream,
    target: TunnelTarget,
    capability: [u8; 32],
    context: &TunnelContext,
) -> io::Result<()> {
    guest.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut authentication = [0_u8; NETWORK_AUTH_MAGIC.len() + 32];
    guest.read_exact(&mut authentication)?;
    if authentication[..NETWORK_AUTH_MAGIC.len()] != *NETWORK_AUTH_MAGIC
        || !constant_time_equal(&authentication[NETWORK_AUTH_MAGIC.len()..], &capability)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hyper-V network authentication failed",
        ));
    }
    match target {
        TunnelTarget::Tcp(address) => relay_tcp(
            guest,
            TcpStream::connect(address)?,
            &context.stop,
            &context.rx_bytes,
            &context.tx_bytes,
        ),
        TunnelTarget::Udp(address) => relay_udp(
            guest,
            address,
            &context.stop,
            &context.rx_bytes,
            &context.tx_bytes,
        ),
    }
}

fn relay_tcp(
    mut guest: TcpStream,
    mut broker: TcpStream,
    stop: &Arc<AtomicBool>,
    rx_bytes: &Arc<AtomicU64>,
    tx_bytes: &Arc<AtomicU64>,
) -> io::Result<()> {
    let timeout = Some(Duration::from_millis(200));
    guest.set_read_timeout(timeout)?;
    guest.set_write_timeout(timeout)?;
    broker.set_read_timeout(timeout)?;
    broker.set_write_timeout(timeout)?;
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
        .map_err(|_| io::Error::other("Hyper-V network relay panicked"))?;
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
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn relay_udp(
    mut guest: TcpStream,
    broker: SocketAddr,
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
    socket.send_to(&query, broker)?;
    tx_bytes.fetch_add(query.len() as u64, Ordering::Relaxed);
    let mut response = [0_u8; MAX_DNS_MESSAGE];
    let count = loop {
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Hyper-V network bridge is stopping",
            ));
        }
        match socket.recv(&mut response) {
            Ok(count) => break count,
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error),
        }
    };
    rx_bytes.fetch_add(count as u64, Ordering::Relaxed);
    guest.write_all(&(count as u16).to_be_bytes())?;
    guest.write_all(&response[..count])
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn shutdown_streams(streams: &ActiveTunnels) {
    for stream in streams
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
    {
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

pub struct WindowsPortGateway {
    stop: Arc<AtomicBool>,
    listeners: Vec<JoinHandle<()>>,
    active: Arc<Mutex<HashMap<u64, TcpStream>>>,
}

impl WindowsPortGateway {
    pub fn start(vm_id: &str, capability: [u8; 32], exposures: &[Exposure]) -> io::Result<Self> {
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
            let vm_id = vm_id.to_owned();
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
                            let vm_id = vm_id.clone();
                            thread::spawn(move || {
                                let result = connect_guest(&vm_id, capability, guest_port)
                                    .and_then(|guest| relay_exposure(client, guest, &stop));
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
        for listener in self.listeners.drain(..) {
            failed |= listener.join().is_err();
        }
        if failed {
            Err(io::Error::other("Hyper-V port exposure listener panicked"))
        } else {
            Ok(())
        }
    }
}

impl Drop for WindowsPortGateway {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

fn connect_guest(
    vm_id: &str,
    capability: [u8; 32],
    port: u16,
) -> io::Result<Box<dyn GuestConnection>> {
    let mut channel = HyperVChannel {
        vm_id: vm_id.to_owned(),
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

fn relay_exposure(
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
