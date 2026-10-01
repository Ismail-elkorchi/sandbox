use crate::packet::{self, FlowKey, Packet};
use crate::policy::{PacketPolicy, host_addresses};
use crate::*;
use sandsurf_protocol::{Exposure, NetworkPlane, NetworkPolicy};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket, SocketBuffer};
use smoltcp::time::{Duration as StackDuration, Instant as StackInstant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const WINDOW: usize = 32 * 1024;
const QUEUE: usize = 64;
const PACKETS_PER_SECOND: usize = 4096;
const BYTES_PER_SECOND: usize = 8 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(120);

/// Already-owned packet endpoint. Linux uses an AF_PACKET socket in the VMM's
/// private namespace; macOS uses the other half of a datagram attachment.
pub enum PacketTransport {
    LinuxPacket(File),
    Datagram(UnixDatagram),
}

impl PacketTransport {
    fn nonblocking(&self) -> io::Result<()> {
        match self {
            Self::Datagram(s) => s.set_nonblocking(true),
            Self::LinuxPacket(s) => {
                // SAFETY: the owned descriptor remains live for both fcntl calls.
                let flags = unsafe { libc::fcntl(s.as_raw_fd(), libc::F_GETFL) };
                if flags < 0
                    || unsafe {
                        libc::fcntl(s.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    } < 0
                {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        }
    }
    fn receive(&mut self) -> io::Result<Vec<Vec<u8>>> {
        match self {
            Self::Datagram(s) => {
                let mut bytes = [0_u8; MAX_FRAME + 1];
                let len = s.recv(&mut bytes)?;
                if len > MAX_FRAME {
                    Ok(Vec::new())
                } else {
                    Ok(vec![bytes[..len].to_vec()])
                }
            }
            Self::LinuxPacket(s) => {
                // One GSO super-packet has an absolute bound. Offload metadata
                // is normalized before strict Ethernet/IP policy admission.
                let mut bytes = [0_u8; 65536 + 14 + 10];
                let mut control = [0_usize; 16]; // aligned cmsghdr / tpacket_auxdata
                let mut iov = libc::iovec {
                    iov_base: bytes.as_mut_ptr().cast(),
                    iov_len: bytes.len(),
                };
                // SAFETY: zeroed msghdr is initialized with writable bounded buffers.
                let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = std::mem::size_of_val(&control) as _;
                // SAFETY: all header, payload, and ancillary buffers remain live.
                let len = unsafe { libc::recvmsg(s.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
                if len < 0 {
                    return Err(io::Error::last_os_error());
                }
                if len as usize > bytes.len()
                    || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                {
                    return Ok(Vec::new());
                }
                // Linux removes VLAN headers before packet taps. AUXDATA is
                // required to reject those packets rather than accidentally
                // authorize their untagged inner IP datagram.
                // SAFETY: CMSG helpers traverse only kernel-initialized storage.
                let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
                let mut has_auxdata = false;
                while !header.is_null() {
                    // SAFETY: non-null CMSG_FIRSTHDR/NXTHDR results lie in control.
                    let h = unsafe { &*header };
                    if h.cmsg_level == 263 && h.cmsg_type == 8 {
                        // SOL_PACKET / PACKET_AUXDATA
                        has_auxdata = true;
                        // SAFETY: CMSG_LEN computes the required native header size.
                        if h.cmsg_len < unsafe { libc::CMSG_LEN(20) } as _ {
                            return Ok(Vec::new());
                        }
                        // SAFETY: AUXDATA contains at least 20 bytes, including
                        // the native-endian status word at its beginning.
                        let status = unsafe {
                            std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<u32>())
                        };
                        if status & (1 << 4) != 0 {
                            return Ok(Vec::new());
                        } // TP_STATUS_VLAN_VALID
                    }
                    // SAFETY: message and current header belong to the same live buffer.
                    header = unsafe { libc::CMSG_NXTHDR(&message, header) };
                }
                if !has_auxdata {
                    return Ok(Vec::new());
                }
                Ok(packet::normalize_offload(&bytes[..len as usize]))
            }
        }
    }
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        let count = match self {
            Self::Datagram(s) => s.send(frame)?,
            Self::LinuxPacket(s) => {
                let mut bytes = Vec::with_capacity(frame.len() + 10);
                bytes.extend_from_slice(&[0; 10]);
                bytes.extend_from_slice(frame);
                let n = s.write(&bytes)?;
                if n != bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial packet write",
                    ));
                }
                return Ok(());
            }
        };
        if count != frame.len() {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial datagram write",
            ))
        } else {
            Ok(())
        }
    }
}

enum Command {
    Apply(
        NetworkPolicy,
        Vec<Exposure>,
        mpsc::SyncSender<io::Result<()>>,
    ),
    Stop(mpsc::SyncSender<()>),
}

/// One bounded worker owns all native flows, TCP windows, packet queues and
/// inbound listeners. A policy revision closes *all* previous flows, including
/// UDP mappings, before opening any new authority and before acknowledgement.
pub struct NativeNetworkGateway {
    control: mpsc::SyncSender<Command>,
    worker: Option<JoinHandle<io::Result<()>>>,
    snapshot: Arc<Mutex<NetworkSnapshot>>,
    violations: Arc<Mutex<Vec<NetworkViolation>>>,
}

impl NativeNetworkGateway {
    pub fn start(transport: PacketTransport, link: LinkIdentity) -> io::Result<Self> {
        transport.nonblocking()?;
        let hosts = host_addresses()?;
        let (control, receiver) = mpsc::sync_channel(1);
        let snapshot = Arc::new(Mutex::new(NetworkSnapshot::default()));
        let violations = Arc::new(Mutex::new(Vec::new()));
        let stats = Arc::clone(&snapshot);
        let denied = Arc::clone(&violations);
        let worker = thread::Builder::new()
            .name("sandsurf-native-network".into())
            .spawn(move || Worker::new(transport, link, hosts, stats, denied).run(receiver))?;
        Ok(Self {
            control,
            worker: Some(worker),
            snapshot,
            violations,
        })
    }

    pub fn configure(&self, policy: &NetworkPolicy, exposures: &[Exposure]) -> io::Result<()> {
        policy
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if exposures.len() > 256 {
            return Err(io::Error::other("too many inbound listeners"));
        }
        let (tx, rx) = mpsc::sync_channel(1);
        self.control
            .try_send(Command::Apply(policy.clone(), exposures.to_vec(), tx))
            .map_err(|_| {
                io::Error::other("network owner unavailable or configuration already pending")
            })?;
        rx.recv_timeout(Duration::from_secs(5)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "network revision was not acknowledged",
            )
        })?
    }

    pub fn snapshot(&self) -> NetworkSnapshot {
        *self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn is_alive(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }
    pub fn take_violations(&self) -> Vec<NetworkViolation> {
        self.violations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect()
    }
    pub fn stop(mut self) -> NetworkReport {
        self.stop_inner()
    }
    fn stop_inner(&mut self) -> NetworkReport {
        let mut failures = Vec::new();
        if let Some(worker) = self.worker.take() {
            let (tx, rx) = mpsc::sync_channel(1);
            if self.control.send(Command::Stop(tx)).is_ok() {
                let _ = rx.recv_timeout(Duration::from_secs(5));
            }
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => failures.push(e.to_string()),
                Err(_) => failures.push("native network worker panicked".into()),
            }
        }
        let s = self.snapshot();
        NetworkReport {
            connections: s.connections,
            violations: s.violations,
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            cleanup_failures: failures,
        }
    }
}
impl Drop for NativeNetworkGateway {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

struct PacketDevice {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
struct Receive(Vec<u8>);
struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for Receive {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        if len <= MAX_FRAME && self.0.len() < QUEUE {
            self.0.push_back(bytes);
        }
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.output.len() >= QUEUE {
            return None;
        }
        self.input
            .pop_front()
            .map(|b| (Receive(b), Transmit(&mut self.output)))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<Self::TxToken<'_>> {
        (self.output.len() < QUEUE).then_some(Transmit(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = MAX_FRAME;
        c.max_burst_size = Some(QUEUE);
        c
    }
}

struct TcpFlow {
    native: TcpStream,
    handle: SocketHandle,
    connecting: bool,
    host_eof: bool,
    guest_eof: bool,
    started: Instant,
    touched: Instant,
    inbound: bool,
}
struct UdpFlow {
    native: UdpSocket,
    touched: Instant,
}
struct Inbound {
    listener: TcpListener,
    target: SocketAddr,
}

struct Worker {
    link: LinkIdentity,
    transport: PacketTransport,
    device: PacketDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: HashMap<FlowKey, TcpFlow>,
    udp: HashMap<FlowKey, UdpFlow>,
    inbound: Vec<Inbound>,
    policy: PacketPolicy,
    authority: NetworkPolicy,
    snapshot: Arc<Mutex<NetworkSnapshot>>,
    violations: Arc<Mutex<Vec<NetworkViolation>>>,
    start: Instant,
    host_refresh: Instant,
    rate_start: Instant,
    packets: usize,
    bytes: usize,
    next_port: u16,
}

impl Worker {
    fn new(
        transport: PacketTransport,
        link: LinkIdentity,
        hosts: Vec<IpAddr>,
        snapshot: Arc<Mutex<NetworkSnapshot>>,
        violations: Arc<Mutex<Vec<NetworkViolation>>>,
    ) -> Self {
        let mut device = PacketDevice {
            input: VecDeque::new(),
            output: VecDeque::new(),
        };
        let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(GATEWAY_MAC)));
        let mut iface = Interface::new(config, &mut device, StackInstant::from_millis(0));
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(GATEWAY_IPV4.into(), 30))
                .expect("IPv4 interface capacity");
            a.push(IpCidr::new(GATEWAY_IPV6.into(), 64))
                .expect("IPv6 interface capacity");
        });
        iface.set_any_ip(true);
        iface
            .routes_mut()
            .add_default_ipv4_route(GATEWAY_IPV4)
            .expect("route capacity");
        iface
            .routes_mut()
            .add_default_ipv6_route(GATEWAY_IPV6)
            .expect("route capacity");
        Self {
            transport,
            link,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            inbound: Vec::new(),
            policy: PacketPolicy::compile(&NetworkPolicy::default(), hosts).expect("empty policy"),
            authority: NetworkPolicy::default(),
            snapshot,
            violations,
            start: Instant::now(),
            host_refresh: Instant::now(),
            rate_start: Instant::now(),
            packets: 0,
            bytes: 0,
            next_port: 32768,
        }
    }
    fn time(&self) -> StackInstant {
        StackInstant::from_millis(self.start.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }
    fn reserve(&mut self, len: usize) -> bool {
        if self.rate_start.elapsed() >= Duration::from_secs(1) {
            self.rate_start = Instant::now();
            self.packets = 0;
            self.bytes = 0;
        }
        if self.packets >= PACKETS_PER_SECOND || self.bytes.saturating_add(len) > BYTES_PER_SECOND {
            return false;
        }
        self.packets += 1;
        self.bytes += len;
        true
    }
    fn deny(&mut self, key: Option<FlowKey>, reason: &str) {
        let mut s = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.violations = s.violations.saturating_add(1);
        let mut v = self
            .violations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if v.len() < 256 {
            v.push(NetworkViolation {
                destination: key.map_or_else(|| "packet".into(), |k| k.remote.ip().to_string()),
                port: key.map_or(0, |k| k.remote.port()),
                rule_reason: reason.into(),
            });
        }
    }
    fn close_flows(&mut self) {
        for (_, f) in self.tcp.drain() {
            let _ = f.native.shutdown(Shutdown::Both);
            self.sockets.get_mut::<Socket>(f.handle).abort();
            self.sockets.remove(f.handle);
        }
        self.udp.clear();
        self.inbound.clear();
        self.device.input.clear();
        self.device.output.clear();
        self.policy = PacketPolicy::default();
        self.authority = NetworkPolicy::default();
    }
    fn apply(&mut self, policy: NetworkPolicy, exposures: Vec<Exposure>) -> io::Result<()> {
        // Install deny and close native sockets before validation/bind. Failure
        // remains deny with no listeners, never successful partial revocation.
        self.close_flows();
        let compiled = PacketPolicy::compile(&policy, host_addresses()?)?;
        let mut listeners = Vec::new();
        for exposure in exposures.iter().filter(|e| e.active) {
            exposure
                .spec
                .validate()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let ip: IpAddr = exposure
                .spec
                .guest_address
                .parse()
                .map_err(|_| io::Error::other("inbound target must be a NIC IP"))?;
            if exposure.spec.host_port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "inbound host port must be assigned by the host authority",
                ));
            }
            if ip != IpAddr::V4(GUEST_IPV4) && ip != IpAddr::V6(GUEST_IPV6) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "inbound target must be this machine's NIC, not guest loopback",
                ));
            }
            let host: IpAddr = exposure
                .spec
                .host_address
                .parse()
                .map_err(|_| io::Error::other("inbound host address must be an IP"))?;
            let listener = native_listener(SocketAddr::new(host, exposure.spec.host_port))?;
            listeners.push(Inbound {
                listener,
                target: SocketAddr::new(ip, exposure.spec.guest_port),
            });
        }
        self.inbound = listeners;
        self.policy = compiled;
        self.authority = policy;
        Ok(())
    }
    fn run(mut self, commands: mpsc::Receiver<Command>) -> io::Result<()> {
        let result = self.run_inner(commands);
        self.close_flows();
        result
    }
    fn run_inner(&mut self, commands: mpsc::Receiver<Command>) -> io::Result<()> {
        loop {
            match commands.try_recv() {
                Ok(Command::Apply(p, e, tx)) => {
                    let _ = tx.send(self.apply(p, e));
                }
                Ok(Command::Stop(tx)) => {
                    self.close_flows();
                    let _ = tx.send(());
                    return Ok(());
                }
                Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // Host interface changes must not turn an existing remote socket
            // into access to a newly assigned host management address.
            if self.host_refresh.elapsed() >= Duration::from_secs(1) {
                self.host_refresh = Instant::now();
                let refreshed = PacketPolicy::compile(&self.authority, host_addresses()?)?;
                let affected = self
                    .tcp
                    .keys()
                    .filter(|k| {
                        !self.tcp[*k].inbound && !refreshed.allows(NetworkPlane::Tcp, k.remote)
                    })
                    .copied()
                    .collect::<Vec<_>>();
                for k in affected {
                    self.remove_tcp(&k);
                }
                self.udp
                    .retain(|k, _| refreshed.allows(NetworkPlane::Udp, k.remote));
                self.policy = refreshed;
            }
            for _ in 0..64 {
                match self.transport.receive() {
                    Ok(frames) => {
                        if frames.is_empty() {
                            break;
                        }
                        for frame in frames {
                            if !self.reserve(frame.len()) {
                                self.deny(None, "traffic rate limit");
                                continue;
                            }
                            self.snapshot
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .tx_bytes += frame.len() as u64;
                            self.ingress(frame)?;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            self.accept_inbound();
            self.pump_tcp();
            self.pump_udp();
            let time = self.time();
            self.iface.poll(time, &mut self.device, &mut self.sockets);
            while let Some(frame) = self.device.output.pop_front() {
                if !self.reserve(frame.len()) {
                    continue;
                }
                match self.transport.send(&frame) {
                    Ok(()) => {
                        self.snapshot
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .rx_bytes += frame.len() as u64
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {} // TCP retransmits; datagrams explicitly have no delivery guarantee.
                    Err(e) => return Err(e),
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn ingress(&mut self, frame: Vec<u8>) -> io::Result<()> {
        if self.device.input.len() >= QUEUE {
            self.deny(None, "packet queue limit");
            return Ok(());
        }
        let Some(packet) = packet::parse(&frame, &self.link) else {
            self.deny(None, "malformed, fragmented, spoofed or unsupported packet");
            return Ok(());
        };
        match packet {
            Packet::Control => self.device.input.push_back(frame),
            Packet::Dhcp { payload } => {
                let end = 14 + usize::from(u16::from_be_bytes([frame[16], frame[17]]));
                if let Some(reply) = packet::dhcp_reply(&frame[payload..end], &self.link) {
                    self.enqueue(reply);
                }
            }
            Packet::Tcp { key, syn } => {
                let inbound = self.tcp.get(&key).is_some_and(|f| f.inbound);
                if !inbound && !self.policy.allows(NetworkPlane::Tcp, key.remote) {
                    self.deny(Some(key), "TCP destination denied");
                    return Ok(());
                }
                if !self.tcp.contains_key(&key) {
                    if !syn
                        || self.tcp.len() + self.udp.len() >= MAX_FLOWS
                        || !self.device.input.is_empty()
                        || self.device.output.len() >= QUEUE
                    {
                        return Ok(());
                    }
                    if host_addresses()?.contains(&key.remote.ip()) {
                        self.deny(Some(key), "host address denied");
                        return Ok(());
                    }
                    let Ok(native) = connect_nonblocking(key.remote) else {
                        return Ok(());
                    };
                    let mut socket = tcp_socket();
                    socket.listen(key.remote).map_err(io::Error::other)?;
                    let handle = self.sockets.add(socket);
                    self.tcp.insert(
                        key,
                        TcpFlow {
                            native,
                            handle,
                            connecting: true,
                            host_eof: false,
                            guest_eof: false,
                            started: Instant::now(),
                            touched: Instant::now(),
                            inbound: false,
                        },
                    );
                    self.connection();
                }
                if let Some(f) = self.tcp.get_mut(&key) {
                    f.touched = Instant::now();
                }
                self.device.input.push_back(frame);
            }
            Packet::Udp { key, payload } => {
                if !self.policy.allows(NetworkPlane::Udp, key.remote) {
                    self.deny(Some(key), "UDP destination denied");
                    return Ok(());
                }
                if !self.udp.contains_key(&key) {
                    if self.tcp.len() + self.udp.len() >= MAX_FLOWS {
                        return Ok(());
                    }
                    if host_addresses()?.contains(&key.remote.ip()) {
                        self.deny(Some(key), "host address denied");
                        return Ok(());
                    }
                    let Ok(socket) = connect_udp(key.remote) else {
                        self.deny(Some(key), "native UDP endpoint unavailable");
                        return Ok(());
                    };
                    self.udp.insert(
                        key,
                        UdpFlow {
                            native: socket,
                            touched: Instant::now(),
                        },
                    );
                    self.connection();
                }
                let end = if key.guest.is_ipv4() {
                    14 + usize::from(u16::from_be_bytes([frame[16], frame[17]]))
                } else {
                    54 + usize::from(u16::from_be_bytes([frame[18], frame[19]]))
                };
                let flow = self.udp.get_mut(&key).expect("inserted UDP flow");
                let _ = flow.native.send(&frame[payload..end]);
                flow.touched = Instant::now();
            }
        }
        // Admit one TCP SYN at a time, so each listen socket binds the exact
        // remote tuple before another SYN to the same destination is processed.
        let time = self.time();
        self.iface.poll(time, &mut self.device, &mut self.sockets);
        Ok(())
    }
    fn connection(&self) {
        self.snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connections += 1;
    }
    fn enqueue(&mut self, frame: Vec<u8>) {
        if self.device.output.len() < QUEUE {
            self.device.output.push_back(frame);
        }
    }
    fn accept_inbound(&mut self) {
        for i in 0..self.inbound.len() {
            if self.tcp.len() + self.udp.len() >= MAX_FLOWS {
                break;
            }
            let Ok((native, _)) = self.inbound[i].listener.accept() else {
                continue;
            };
            if native.set_nonblocking(true).is_err() {
                continue;
            }
            if bound_socket_buffers(native.as_raw_fd()).is_err() {
                continue;
            }
            let guest = self.inbound[i].target;
            let remote_ip = if guest.is_ipv4() {
                IpAddr::V4(GATEWAY_IPV4)
            } else {
                IpAddr::V6(GATEWAY_IPV6)
            };
            let mut key = FlowKey {
                guest,
                remote: SocketAddr::new(remote_ip, self.next_port),
            };
            let mut attempts = 0;
            while self.tcp.contains_key(&key) && attempts < MAX_FLOWS {
                self.next_port = if self.next_port == 65535 {
                    32768
                } else {
                    self.next_port + 1
                };
                key.remote.set_port(self.next_port);
                attempts += 1;
            }
            self.next_port = if self.next_port == 65535 {
                32768
            } else {
                self.next_port + 1
            };
            if attempts == MAX_FLOWS {
                continue;
            }
            let mut socket = tcp_socket();
            if socket
                .connect(self.iface.context(), guest, key.remote)
                .is_err()
            {
                continue;
            }
            let handle = self.sockets.add(socket);
            self.tcp.insert(
                key,
                TcpFlow {
                    native,
                    handle,
                    connecting: false,
                    host_eof: false,
                    guest_eof: false,
                    started: Instant::now(),
                    touched: Instant::now(),
                    inbound: true,
                },
            );
            self.connection();
        }
    }
    fn remove_tcp(&mut self, key: &FlowKey) {
        if let Some(f) = self.tcp.remove(key) {
            let _ = f.native.shutdown(Shutdown::Both);
            self.sockets.get_mut::<Socket>(f.handle).abort();
            self.sockets.remove(f.handle);
        }
    }
    fn pump_tcp(&mut self) {
        let mut remove = Vec::new();
        for (key, flow) in &mut self.tcp {
            let socket = self.sockets.get_mut::<Socket>(flow.handle);
            if flow.touched.elapsed() > IDLE || !socket.is_open() {
                remove.push(*key);
                continue;
            }
            if flow.connecting {
                if flow.started.elapsed() > Duration::from_secs(15) {
                    remove.push(*key);
                    continue;
                }
                match connected(&flow.native) {
                    Ok(false) => continue,
                    Ok(true) => flow.connecting = false,
                    Err(_) => {
                        remove.push(*key);
                        continue;
                    }
                }
            }
            let mut failed = false;
            if socket.can_recv() {
                let _ = socket.recv(|bytes| {
                    let n = match flow.native.write(bytes) {
                        Ok(0) => {
                            failed = true;
                            0
                        }
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                        Err(_) => {
                            failed = true;
                            0
                        }
                    };
                    if n > 0 {
                        flow.touched = Instant::now();
                    }
                    (n, ())
                });
            }
            if !flow.guest_eof
                && !socket.may_recv()
                && !matches!(
                    socket.state(),
                    smoltcp::socket::tcp::State::Listen
                        | smoltcp::socket::tcp::State::SynSent
                        | smoltcp::socket::tcp::State::SynReceived
                )
            {
                let _ = flow.native.shutdown(Shutdown::Write);
                flow.guest_eof = true;
            }
            if socket.can_send() && !flow.host_eof {
                let _ = socket.send(|bytes| {
                    let n = match flow.native.read(bytes) {
                        Ok(0) => {
                            flow.host_eof = true;
                            0
                        }
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                        Err(_) => {
                            failed = true;
                            0
                        }
                    };
                    if n > 0 {
                        flow.touched = Instant::now();
                    }
                    (n, ())
                });
                if flow.host_eof {
                    socket.close();
                }
            }
            if failed {
                remove.push(*key);
            }
        }
        for key in remove {
            self.remove_tcp(&key);
        }
    }
    fn pump_udp(&mut self) {
        let mut replies = Vec::new();
        self.udp
            .retain(|_, f| f.touched.elapsed() < Duration::from_secs(30));
        for (key, flow) in &mut self.udp {
            let mut bytes = [0_u8; MTU + 1];
            match flow.native.recv(&mut bytes) {
                Ok(len) => {
                    if let Some(reply) =
                        packet::udp_reply(key.remote, key.guest, &bytes[..len], false, &self.link)
                    {
                        replies.push(reply);
                    }
                    flow.touched = Instant::now();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
            if replies.len() >= QUEUE {
                break;
            }
        }
        for reply in replies {
            self.enqueue(reply);
        }
    }
}
fn tcp_socket() -> Socket<'static> {
    let mut socket = Socket::new(
        SocketBuffer::new(vec![0; WINDOW]),
        SocketBuffer::new(vec![0; WINDOW]),
    );
    socket.set_timeout(Some(StackDuration::from_secs(120)));
    socket.set_ack_delay(None);
    socket
}
fn connect_nonblocking(address: SocketAddr) -> io::Result<TcpStream> {
    let socket = new_tcp_socket(address)?;
    let result = socket_address_call(socket.as_raw_fd(), address, true);
    if result < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(TcpStream::from(OwnedFd::from(socket)))
}
fn native_listener(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = new_tcp_socket(address)?;
    let fd = socket.as_raw_fd();
    let reuse = 1_i32;
    // SAFETY: initialized option for a live owned socket. SO_REUSEPORT is never
    // enabled; another process cannot share this listener's authority.
    if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, (&reuse as *const i32).cast(), std::mem::size_of_val(&reuse) as _) } < 0
        || socket_address_call(fd, address, false) < 0
        // SAFETY: fd is a successfully bound TCP socket with bounded buffers.
        || unsafe { libc::listen(fd, 1) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(OwnedFd::from(socket)))
}
fn new_tcp_socket(address: SocketAddr) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    let socket_kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(not(target_os = "linux"))]
    let socket_kind = libc::SOCK_STREAM;
    // SAFETY: socket creates a new descriptor; ownership transfers once below.
    let fd = unsafe {
        libc::socket(
            if address.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            },
            socket_kind,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a new successful socket allocation.
    let socket = unsafe { File::from_raw_fd(fd) };
    // SAFETY: owned descriptor stays live for all flag operations. Set CLOEXEC
    // before publishing the socket to any other thread or native owner.
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    // SAFETY: socket owns fd throughout this native status-flag query.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if descriptor_flags < 0
        || flags < 0
        // SAFETY: successful flag queries and the held socket keep fd live;
        // these scalar updates retain existing flags and add only confinement.
        || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    bound_socket_buffers(fd)?;
    Ok(socket)
}
fn socket_address_call(fd: libc::c_int, address: SocketAddr, connect: bool) -> libc::c_int {
    // SAFETY: each initialized native sockaddr remains live for bind/connect and
    // has the exact length for its family. No guest pathname is interpreted.
    unsafe {
        match address {
            SocketAddr::V4(v) => {
                let mut a: libc::sockaddr_in = std::mem::zeroed();
                #[cfg(target_os = "macos")]
                {
                    a.sin_len = std::mem::size_of_val(&a) as _;
                }
                a.sin_family = libc::AF_INET as _;
                a.sin_port = v.port().to_be();
                a.sin_addr.s_addr = u32::from_ne_bytes(v.ip().octets());
                let pointer = (&a as *const libc::sockaddr_in).cast();
                let size = std::mem::size_of_val(&a) as _;
                if connect {
                    libc::connect(fd, pointer, size)
                } else {
                    libc::bind(fd, pointer, size)
                }
            }
            SocketAddr::V6(v) => {
                let mut a: libc::sockaddr_in6 = std::mem::zeroed();
                #[cfg(target_os = "macos")]
                {
                    a.sin6_len = std::mem::size_of_val(&a) as _;
                }
                a.sin6_family = libc::AF_INET6 as _;
                a.sin6_port = v.port().to_be();
                a.sin6_addr.s6_addr = v.ip().octets();
                a.sin6_scope_id = v.scope_id();
                let pointer = (&a as *const libc::sockaddr_in6).cast();
                let size = std::mem::size_of_val(&a) as _;
                if connect {
                    libc::connect(fd, pointer, size)
                } else {
                    libc::bind(fd, pointer, size)
                }
            }
        }
    }
}
fn connected(stream: &TcpStream) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: p is writable storage for exactly one live descriptor; timeout zero.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Ok(false);
    }
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    Ok(true)
}

fn connect_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    bound_socket_buffers(socket.as_raw_fd())?;
    socket.set_nonblocking(true)?;
    socket.connect(address)?;
    Ok(socket)
}

fn bound_socket_buffers(fd: libc::c_int) -> io::Result<()> {
    let size = WINDOW as libc::c_int;
    for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        // SAFETY: caller owns fd and size is initialized c_int storage.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
