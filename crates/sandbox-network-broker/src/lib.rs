#![deny(unsafe_code)]

use sandbox_policy::{
    ManagedNetworkDestination, ManagedNetworkPort, ManagedNetworkRule, normalize_dns_name,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_PROXY_HEADER: usize = 64 * 1024;
const MAX_DNS_MESSAGE: usize = 4096;
const MAX_RESOLVED_ADDRESSES: usize = 128;

#[derive(Debug, Clone)]
pub struct NetworkViolation {
    pub destination: String,
    pub port: u16,
    pub rule_reason: String,
}

#[derive(Debug, Default)]
pub struct BrokerReport {
    pub connections: u64,
    pub violations: u64,
    pub cleanup_failures: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BrokerSnapshot {
    pub connections: u64,
    pub violations: u64,
}

pub struct BrokerHandle {
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    connections: Arc<AtomicU64>,
    violations: Arc<AtomicU64>,
    active_streams: ActiveStreams,
    threads: Vec<JoinHandle<()>>,
    stopped: bool,
}

type ViolationCallback = Arc<dyn Fn(NetworkViolation) + Send + Sync>;
type ActiveStreams = Arc<Mutex<HashMap<u64, Vec<TcpStream>>>>;

struct ConnectionRegistration {
    id: u64,
    streams: ActiveStreams,
}

struct ConnectContext<'a> {
    rules: &'a [ManagedNetworkRule],
    connections: &'a AtomicU64,
    violations: &'a AtomicU64,
    callback: &'a ViolationCallback,
    stop: &'a AtomicBool,
    registration: &'a ConnectionRegistration,
}

impl ConnectionRegistration {
    fn new(id: u64, streams: ActiveStreams, client: &TcpStream) -> io::Result<Self> {
        streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, vec![client.try_clone()?]);
        Ok(Self { id, streams })
    }

    fn add(&self, stream: &TcpStream) -> io::Result<()> {
        let duplicate = stream.try_clone()?;
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = streams.get_mut(&self.id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Interrupted, "network broker is stopping")
        })?;
        entry.push(duplicate);
        Ok(())
    }
}

impl Drop for ConnectionRegistration {
    fn drop(&mut self) {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

fn shutdown_active_streams(streams: &ActiveStreams) {
    let streams = streams
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for connection in streams.values() {
        for stream in connection {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

impl BrokerHandle {
    pub fn start(
        listeners: Vec<File>,
        rules: Vec<ManagedNetworkRule>,
        callback: impl Fn(NetworkViolation) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        if listeners.len() != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "broker requires HTTP, SOCKS5, DNS/UDP and DNS/TCP listeners",
            ));
        }
        let mut listeners = listeners.into_iter();
        let http = TcpListener::from(OwnedFd::from(listeners.next().expect("length checked")));
        let socks = TcpListener::from(OwnedFd::from(listeners.next().expect("length checked")));
        let dns_udp = UdpSocket::from(OwnedFd::from(listeners.next().expect("length checked")));
        let dns_tcp = TcpListener::from(OwnedFd::from(listeners.next().expect("length checked")));
        http.set_nonblocking(true)?;
        socks.set_nonblocking(true)?;
        dns_udp.set_nonblocking(true)?;
        dns_tcp.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicU64::new(0));
        let violations = Arc::new(AtomicU64::new(0));
        let active_streams = Arc::new(Mutex::new(HashMap::new()));
        let next_connection_id = Arc::new(AtomicU64::new(1));
        let rules = Arc::new(rules);
        let callback: ViolationCallback = Arc::new(callback);
        let threads = vec![
            tcp_accept_loop(
                http,
                Arc::clone(&stop),
                Arc::clone(&active),
                Arc::clone(&connections),
                Arc::clone(&violations),
                Arc::clone(&rules),
                Arc::clone(&callback),
                Arc::clone(&active_streams),
                Arc::clone(&next_connection_id),
                ProxyKind::Http,
            ),
            tcp_accept_loop(
                socks,
                Arc::clone(&stop),
                Arc::clone(&active),
                Arc::clone(&connections),
                Arc::clone(&violations),
                Arc::clone(&rules),
                Arc::clone(&callback),
                Arc::clone(&active_streams),
                Arc::clone(&next_connection_id),
                ProxyKind::Socks5,
            ),
            dns_udp_loop(
                dns_udp,
                Arc::clone(&stop),
                Arc::clone(&violations),
                Arc::clone(&rules),
                Arc::clone(&callback),
            ),
            dns_tcp_loop(
                dns_tcp,
                Arc::clone(&stop),
                Arc::clone(&active),
                Arc::clone(&violations),
                Arc::clone(&rules),
                Arc::clone(&callback),
            ),
        ];
        Ok(Self {
            stop,
            active,
            connections,
            violations,
            active_streams,
            threads,
            stopped: false,
        })
    }

    pub fn stop(mut self) -> BrokerReport {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> BrokerReport {
        if self.stopped {
            return BrokerReport {
                connections: self.connections.load(Ordering::Relaxed),
                violations: self.violations.load(Ordering::Relaxed),
                cleanup_failures: Vec::new(),
            };
        }
        self.stopped = true;
        self.stop.store(true, Ordering::Release);
        shutdown_active_streams(&self.active_streams);
        let mut report = BrokerReport::default();
        for handle in self.threads.drain(..) {
            if handle.join().is_err() {
                report
                    .cleanup_failures
                    .push("managed-network listener thread panicked".into());
            }
        }
        // Close connections accepted immediately before the listener observed the stop flag.
        shutdown_active_streams(&self.active_streams);
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.active.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            shutdown_active_streams(&self.active_streams);
            thread::sleep(Duration::from_millis(10));
        }
        if self.active.load(Ordering::Acquire) != 0 {
            report
                .cleanup_failures
                .push("managed-network connections did not drain before cleanup deadline".into());
        }
        report.connections = self.connections.load(Ordering::Relaxed);
        report.violations = self.violations.load(Ordering::Relaxed);
        report
    }

    #[must_use]
    pub fn snapshot(&self) -> BrokerSnapshot {
        BrokerSnapshot {
            connections: self.connections.load(Ordering::Relaxed),
            violations: self.violations.load(Ordering::Relaxed),
        }
    }
}

impl Drop for BrokerHandle {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

#[derive(Clone, Copy)]
enum ProxyKind {
    Http,
    Socks5,
}

#[allow(clippy::too_many_arguments)]
fn tcp_accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    connections: Arc<AtomicU64>,
    violations: Arc<AtomicU64>,
    rules: Arc<Vec<ManagedNetworkRule>>,
    callback: ViolationCallback,
    active_streams: ActiveStreams,
    next_connection_id: Arc<AtomicU64>,
    kind: ProxyKind,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    active.fetch_add(1, Ordering::AcqRel);
                    let active = Arc::clone(&active);
                    let connections = Arc::clone(&connections);
                    let violations = Arc::clone(&violations);
                    let rules = Arc::clone(&rules);
                    let callback = Arc::clone(&callback);
                    let stop = Arc::clone(&stop);
                    let active_streams = Arc::clone(&active_streams);
                    let connection_id = next_connection_id.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || {
                        let result =
                            ConnectionRegistration::new(connection_id, active_streams, &stream)
                                .and_then(|registration| match kind {
                                    ProxyKind::Http => handle_http(
                                        stream,
                                        &rules,
                                        &connections,
                                        &violations,
                                        &callback,
                                        &stop,
                                        &registration,
                                    ),
                                    ProxyKind::Socks5 => handle_socks5(
                                        stream,
                                        &rules,
                                        &connections,
                                        &violations,
                                        &callback,
                                        &stop,
                                        &registration,
                                    ),
                                });
                        let _ = result;
                        active.fetch_sub(1, Ordering::AcqRel);
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

fn handle_http(
    mut client: TcpStream,
    rules: &[ManagedNetworkRule],
    connections: &AtomicU64,
    violations: &AtomicU64,
    callback: &ViolationCallback,
    stop: &AtomicBool,
    registration: &ConnectionRegistration,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(15)))?;
    client.set_write_timeout(Some(Duration::from_secs(15)))?;
    let header = read_header(&mut client)?;
    let text = std::str::from_utf8(&header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy header is not UTF-8"))?;
    let first = text.lines().next().unwrap_or_default();
    let mut fields = first.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    let context = ConnectContext {
        rules,
        connections,
        violations,
        callback,
        stop,
        registration,
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_http_connect_request(&header)?;
        let mut upstream = connect_authorized(&host, port, &context)?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        relay(&mut client, &mut upstream)
    } else {
        let (host, port, path) = parse_absolute_http_uri(target)?;
        let mut upstream = connect_authorized(&host, port, &context)?;
        let rewritten = rewrite_http_request(&header, method, &path)?;
        upstream.write_all(&rewritten)?;
        relay(&mut client, &mut upstream)
    }
}

fn handle_socks5(
    mut client: TcpStream,
    rules: &[ManagedNetworkRule],
    connections: &AtomicU64,
    violations: &AtomicU64,
    callback: &ViolationCallback,
    stop: &AtomicBool,
    registration: &ConnectionRegistration,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(15)))?;
    client.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting)?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 greeting",
        ));
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        return Ok(());
    }
    client.write_all(&[5, 0])?;
    let mut request = [0_u8; 4];
    client.read_exact(&mut request)?;
    let mut encoded = request.to_vec();
    match request[3] {
        1 => {
            let mut bytes = [0_u8; 4];
            client.read_exact(&mut bytes)?;
            encoded.extend_from_slice(&bytes);
        }
        4 => {
            let mut bytes = [0_u8; 16];
            client.read_exact(&mut bytes)?;
            encoded.extend_from_slice(&bytes);
        }
        3 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length)?;
            encoded.push(length[0]);
            let mut bytes = vec![0_u8; length[0] as usize];
            client.read_exact(&mut bytes)?;
            encoded.extend_from_slice(&bytes);
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 address type",
            ));
        }
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port)?;
    encoded.extend_from_slice(&port);
    let (host, port) = parse_socks5_request(&encoded)?;
    let context = ConnectContext {
        rules,
        connections,
        violations,
        callback,
        stop,
        registration,
    };
    match connect_authorized(&host, port, &context) {
        Ok(mut upstream) => {
            client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
            relay(&mut client, &mut upstream)
        }
        Err(error) => {
            let _ = client.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
            Err(error)
        }
    }
}

fn connect_authorized(
    host: &str,
    port: u16,
    context: &ConnectContext<'_>,
) -> io::Result<TcpStream> {
    if context.stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "network broker is stopping",
        ));
    }
    let decision = authorize(host, port, context.rules);
    let addresses = match decision {
        Ok(addresses) => addresses,
        Err(reason) => {
            context.violations.fetch_add(1, Ordering::Relaxed);
            (context.callback)(NetworkViolation {
                destination: host.into(),
                port,
                rule_reason: reason.clone(),
            });
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
        }
    };
    let mut last = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    for address in addresses {
        if context.stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "network broker is stopping",
            ));
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let attempt_timeout = remaining.min(Duration::from_millis(250));
        match TcpStream::connect_timeout(&address, attempt_timeout) {
            Ok(stream) => {
                context.registration.add(&stream)?;
                if context.stop.load(Ordering::Acquire) {
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "network broker is stopping",
                    ));
                }
                context.connections.fetch_add(1, Ordering::Relaxed);
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no destination address")))
}

fn authorize(
    host: &str,
    port: u16,
    rules: &[ManagedNetworkRule],
) -> Result<Vec<SocketAddr>, String> {
    authorize_with_resolver(host, port, rules, |name, port| {
        (name, port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .map_err(|error| format!("broker DNS resolution failed: {error}"))
    })
}

fn authorize_with_resolver(
    host: &str,
    port: u16,
    rules: &[ManagedNetworkRule],
    resolver: impl FnOnce(&str, u16) -> Result<Vec<SocketAddr>, String>,
) -> Result<Vec<SocketAddr>, String> {
    let parsed_ip = host.trim_matches(['[', ']']).parse::<IpAddr>().ok();
    if let Some(ip) = parsed_ip {
        if !rules.iter().any(|rule| rule_matches_ip(rule, ip, port)) {
            return Err("IP destination is not allowlisted".into());
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host = normalize_host(host).ok_or_else(|| "DNS name is invalid".to_string())?;
    let matching: Vec<_> = rules
        .iter()
        .filter_map(|rule| match &rule.destination {
            ManagedNetworkDestination::Dns {
                name,
                include_subdomains,
                allow_private_addresses,
            } if port_allowed(rule, port)
                && (host == *name
                    || *include_subdomains
                        && host
                            .strip_suffix(name)
                            .is_some_and(|prefix| prefix.ends_with('.'))) =>
            {
                Some(*allow_private_addresses)
            }
            _ => None,
        })
        .collect();
    if matching.is_empty() {
        return Err("DNS destination and port are not allowlisted".into());
    }
    let addresses = resolver(&host, port)?;
    if addresses.is_empty() {
        return Err("broker DNS resolution returned no addresses".into());
    }
    if addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err("broker DNS resolution returned too many addresses".into());
    }
    let private_allowed = matching.into_iter().any(|value| value);
    if !private_allowed
        && addresses
            .iter()
            .any(|address| prohibited_address(address.ip()))
    {
        return Err("DNS resolution included a private or non-routable address".into());
    }
    Ok(addresses)
}

fn rule_matches_ip(rule: &ManagedNetworkRule, address: IpAddr, port: u16) -> bool {
    let ManagedNetworkDestination::Ip { cidr } = &rule.destination else {
        return false;
    };
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(network) = network.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    port_allowed(rule, port) && cidr_contains(network, prefix, address)
}

fn port_allowed(rule: &ManagedNetworkRule, port: u16) -> bool {
    rule.ports.iter().any(|entry| match entry {
        ManagedNetworkPort::Single(value) => *value == port,
        ManagedNetworkPort::Range { from, to } => *from <= port && port <= *to,
    })
}

fn cidr_contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn prohibited_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => prohibited_ipv4(value),
        IpAddr::V6(value) => prohibited_ipv6(value),
    }
}

fn prohibited_ipv4(value: Ipv4Addr) -> bool {
    let octets = value.octets();
    value.is_private()
        || value.is_loopback()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_unspecified()
        || octets == [255, 255, 255, 255]
        || octets[0] == 0
        || octets[0] >= 224
        || octets[0] == 100 && (64..=127).contains(&octets[1])
        || octets[0] == 192 && octets[1] == 0 && octets[2] <= 2
        || octets[0] == 192 && octets[1] == 88 && octets[2] == 99
        || octets[0] == 198 && matches!(octets[1], 18 | 19 | 51)
        || octets[0] == 203 && octets[1] == 0 && octets[2] == 113
}

fn prohibited_ipv6(value: Ipv6Addr) -> bool {
    let segments = value.segments();
    if let Some(mapped) = value.to_ipv4_mapped() {
        return prohibited_ipv4(mapped);
    }
    // Permit only current global-unicast space, then remove special-purpose blocks within it.
    if segments[0] & 0xe000 != 0x2000 {
        return true;
    }
    // IETF special-purpose, documentation, ORCHID, and benchmarking assignments.
    if segments[0] == 0x2001
        && (segments[1] < 0x0200
            || segments[1] == 0x0db8
            || (0x0010..=0x001f).contains(&segments[1])
            || (0x0020..=0x002f).contains(&segments[1]))
    {
        return true;
    }
    // 6to4 embeds an IPv4 address; reject private/special embedded destinations.
    if segments[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        );
        return prohibited_ipv4(embedded);
    }
    // 3fff::/20 is reserved for documentation.
    segments[0] == 0x3fff && segments[1] & 0xf000 == 0
}

fn dns_udp_loop(
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    violations: Arc<AtomicU64>,
    rules: Arc<Vec<ManagedNetworkRule>>,
    callback: ViolationCallback,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; MAX_DNS_MESSAGE];
        while !stop.load(Ordering::Acquire) {
            match socket.recv_from(&mut buffer) {
                Ok((count, peer)) => {
                    if let Ok(response) =
                        answer_dns(&buffer[..count], &rules, &violations, &callback)
                    {
                        let _ = socket.send_to(&response, peer);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    })
}

fn dns_tcp_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    violations: Arc<AtomicU64>,
    rules: Arc<Vec<ManagedNetworkRule>>,
    callback: ViolationCallback,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    active.fetch_add(1, Ordering::AcqRel);
                    let active = Arc::clone(&active);
                    let violations = Arc::clone(&violations);
                    let rules = Arc::clone(&rules);
                    let callback = Arc::clone(&callback);
                    thread::spawn(move || {
                        let result = (|| -> io::Result<()> {
                            let mut length = [0_u8; 2];
                            stream.read_exact(&mut length)?;
                            let length = u16::from_be_bytes(length) as usize;
                            if length > MAX_DNS_MESSAGE {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "DNS message too large",
                                ));
                            }
                            let mut query = vec![0_u8; length];
                            stream.read_exact(&mut query)?;
                            let response = answer_dns(&query, &rules, &violations, &callback)?;
                            stream.write_all(&(response.len() as u16).to_be_bytes())?;
                            stream.write_all(&response)
                        })();
                        let _ = result;
                        active.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    })
}

fn answer_dns(
    query: &[u8],
    rules: &[ManagedNetworkRule],
    violations: &AtomicU64,
    callback: &ViolationCallback,
) -> io::Result<Vec<u8>> {
    let (name, question_end, query_type) = parse_dns_question(query)?;
    let rule = rules.iter().find_map(|rule| match &rule.destination {
        ManagedNetworkDestination::Dns {
            name: allowed,
            include_subdomains,
            allow_private_addresses,
        } if name == *allowed
            || *include_subdomains
                && name
                    .strip_suffix(allowed)
                    .is_some_and(|prefix| prefix.ends_with('.')) =>
        {
            Some(*allow_private_addresses)
        }
        _ => None,
    });
    let Some(private_allowed) = rule else {
        violations.fetch_add(1, Ordering::Relaxed);
        callback(NetworkViolation {
            destination: name,
            port: 53,
            rule_reason: "DNS name is not allowlisted".into(),
        });
        return Ok(dns_error_response(query, question_end, 5));
    };
    let mut addresses: Vec<IpAddr> = (name.as_str(), 0)
        .to_socket_addrs()?
        .map(|address| address.ip())
        .filter(|address| {
            matches!(
                (query_type, address),
                (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))
            )
        })
        .collect();
    addresses.sort();
    addresses.dedup();
    if addresses.len() > MAX_RESOLVED_ADDRESSES {
        violations.fetch_add(1, Ordering::Relaxed);
        callback(NetworkViolation {
            destination: name,
            port: 53,
            rule_reason: "DNS resolution returned too many addresses".into(),
        });
        return Ok(dns_error_response(query, question_end, 5));
    }
    if !private_allowed && addresses.iter().any(|address| prohibited_address(*address)) {
        violations.fetch_add(1, Ordering::Relaxed);
        callback(NetworkViolation {
            destination: name,
            port: 53,
            rule_reason: "DNS resolution included a private or non-routable address".into(),
        });
        return Ok(dns_error_response(query, question_end, 5));
    }
    dns_success_response(query, question_end, query_type, &addresses)
}

pub fn parse_dns_question(query: &[u8]) -> io::Result<(String, usize, u16)> {
    if query.len() < 17 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS query must contain one question",
        ));
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < query.len() {
        let length = query[offset] as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + length > query.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS question name",
            ));
        }
        labels.push(
            std::str::from_utf8(&query[offset..offset + length]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS question is not ASCII")
            })?,
        );
        offset += length;
    }
    if offset + 4 > query.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated DNS question",
        ));
    }
    let query_type = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let query_class = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);
    if !matches!(query_type, 1 | 28) || query_class != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only DNS A and AAAA are supported",
        ));
    }
    let name = normalize_host(&labels.join("."))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid DNS name"))?;
    Ok((name, offset + 4, query_type))
}

fn dns_error_response(query: &[u8], question_end: usize, code: u8) -> Vec<u8> {
    let mut response = query[..question_end].to_vec();
    response[2] = 0x81;
    response[3] = 0x80 | (code & 0x0f);
    response[6..12].fill(0);
    response
}

fn dns_success_response(
    query: &[u8],
    question_end: usize,
    query_type: u16,
    addresses: &[IpAddr],
) -> io::Result<Vec<u8>> {
    let mut response = query[..question_end].to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    let count = u16::try_from(addresses.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many DNS answers"))?;
    response[6..8].copy_from_slice(&count.to_be_bytes());
    response[8..12].fill(0);
    for address in addresses {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&query_type.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&30_u32.to_be_bytes());
        match address {
            IpAddr::V4(value) => {
                response.extend_from_slice(&4_u16.to_be_bytes());
                response.extend_from_slice(&value.octets());
            }
            IpAddr::V6(value) => {
                response.extend_from_slice(&16_u16.to_be_bytes());
                response.extend_from_slice(&value.octets());
            }
        }
        if response.len() > MAX_DNS_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response exceeds broker message limit",
            ));
        }
    }
    Ok(response)
}

fn read_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut value = Vec::new();
    let mut byte = [0_u8; 1];
    while value.len() < MAX_PROXY_HEADER {
        stream.read_exact(&mut byte)?;
        value.push(byte[0]);
        if value.ends_with(b"\r\n\r\n") {
            return Ok(value);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "proxy header exceeds limit",
    ))
}

pub fn split_authority(value: &str, default_port: u16) -> io::Result<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 authority"))?;
        let port = port
            .strip_prefix(':')
            .map_or(Ok(default_port), |value| value.parse())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid authority port"))?;
        return Ok((host.into(), port));
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
    {
        return Ok((
            host.into(),
            port.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid authority port")
            })?,
        ));
    }
    Ok((value.into(), default_port))
}

pub fn parse_absolute_http_uri(value: &str) -> io::Result<(String, u16, String)> {
    let rest = value.strip_prefix("http://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "only absolute HTTP proxy URIs are supported",
        )
    })?;
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".into()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    let (host, port) = split_authority(authority, 80)?;
    Ok((host, port, path))
}

/// Parse a complete SOCKS5 CONNECT request, beginning with VER/CMD/RSV/ATYP.
pub fn parse_socks5_request(request: &[u8]) -> io::Result<(String, u16)> {
    if request.len() < 6 || request[..3] != [5, 1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS5 request",
        ));
    }
    let (host, port_offset) = match request[3] {
        1 => {
            if request.len() != 10 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 IPv4 request length",
                ));
            }
            (
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&request[4..8]).expect("length checked"),
                ))
                .to_string(),
                8,
            )
        }
        4 => {
            if request.len() != 22 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 IPv6 request length",
                ));
            }
            (
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&request[4..20]).expect("length checked"),
                ))
                .to_string(),
                20,
            )
        }
        3 => {
            let length = request[4] as usize;
            if length == 0 || request.len() != 7 + length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 domain request length",
                ));
            }
            let host = std::str::from_utf8(&request[5..5 + length])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 host"))?;
            (host.to_owned(), 5 + length)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 address type",
            ));
        }
    };
    let port = u16::from_be_bytes([request[port_offset], request[port_offset + 1]]);
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 destination port zero is invalid",
        ));
    }
    Ok((host, port))
}

/// Parse and validate the first request line of an HTTP CONNECT header.
pub fn parse_http_connect_request(header: &[u8]) -> io::Result<(String, u16)> {
    if header.len() > MAX_PROXY_HEADER || !header.ends_with(b"\r\n\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete or oversized HTTP CONNECT header",
        ));
    }
    let text = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy header is not UTF-8"))?;
    let mut fields = text.lines().next().unwrap_or_default().split_whitespace();
    let method = fields.next().unwrap_or_default();
    let authority = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT")
        || authority.is_empty()
        || !version.starts_with("HTTP/")
        || fields.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP CONNECT request line",
        ));
    }
    split_authority(authority, 443)
}

fn rewrite_http_request(header: &[u8], method: &str, path: &str) -> io::Result<Vec<u8>> {
    let text = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP header is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let version = first.split_whitespace().nth(2).unwrap_or("HTTP/1.1");
    let mut result = format!("{method} {path} {version}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if !line.to_ascii_lowercase().starts_with("proxy-connection:") {
            result.extend_from_slice(line.as_bytes());
            result.extend_from_slice(b"\r\n");
        }
    }
    result.extend_from_slice(b"\r\n");
    Ok(result)
}

fn relay(left: &mut TcpStream, right: &mut TcpStream) -> io::Result<()> {
    left.set_read_timeout(None)?;
    left.set_write_timeout(None)?;
    right.set_read_timeout(None)?;
    right.set_write_timeout(None)?;
    let mut left_read = left.try_clone()?;
    let mut right_write = right.try_clone()?;
    let forward = thread::spawn(move || {
        let result = io::copy(&mut left_read, &mut right_write);
        let _ = right_write.shutdown(Shutdown::Write);
        result
    });
    let backward = io::copy(right, left);
    let _ = left.shutdown(Shutdown::Write);
    let forward = forward
        .join()
        .map_err(|_| io::Error::other("proxy relay thread panicked"))?;
    forward?;
    backward?;
    Ok(())
}

fn normalize_host(value: &str) -> Option<String> {
    normalize_dns_name(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_rule(
        name: &str,
        include_subdomains: bool,
        allow_private_addresses: bool,
        port: u16,
    ) -> ManagedNetworkRule {
        ManagedNetworkRule {
            transport: "tcp".into(),
            destination: ManagedNetworkDestination::Dns {
                name: normalize_dns_name(name).unwrap(),
                include_subdomains,
                allow_private_addresses,
            },
            ports: vec![ManagedNetworkPort::Single(port)],
        }
    }

    fn resolved(addresses: &[&str], port: u16) -> Vec<SocketAddr> {
        addresses
            .iter()
            .map(|address| SocketAddr::new(address.parse().unwrap(), port))
            .collect()
    }

    #[test]
    fn cidr_matching_respects_prefixes() {
        assert!(cidr_contains(
            "10.0.0.0".parse().unwrap(),
            8,
            "10.2.3.4".parse().unwrap()
        ));
        assert!(!cidr_contains(
            "10.0.0.0".parse().unwrap(),
            8,
            "11.2.3.4".parse().unwrap()
        ));
    }

    #[test]
    fn private_addresses_are_classified() {
        for address in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            assert!(prohibited_address(address.parse().unwrap()), "{address}");
        }
        assert!(!prohibited_address("1.1.1.1".parse().unwrap()));
        assert!(!prohibited_address("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn domain_rules_are_exact_normalized_and_port_bound() {
        let rules = vec![dns_rule("bücher.example", true, false, 443)];
        let public = resolved(&["1.1.1.1"], 443);
        for host in [
            "xn--bcher-kva.example",
            "BÜCHER.EXAMPLE.",
            "api.xn--bcher-kva.example",
        ] {
            let result = authorize_with_resolver(host, 443, &rules, |_, _| Ok(public.clone()));
            assert_eq!(result.unwrap(), public, "{host}");
        }
        assert!(
            authorize_with_resolver("sibling.example", 443, &rules, |_, _| Ok(public.clone()))
                .is_err()
        );
        assert!(
            authorize_with_resolver("xn--bcher-kva.example", 80, &rules, |_, _| {
                Ok(public.clone())
            })
            .is_err()
        );
    }

    #[test]
    fn every_final_dns_answer_is_validated_before_connect() {
        let rules = vec![dns_rule("alias.example", false, false, 443)];
        let mixed = resolved(&["1.1.1.1", "127.0.0.1"], 443);
        let error =
            authorize_with_resolver("alias.example", 443, &rules, |_, _| Ok(mixed)).unwrap_err();
        assert!(error.contains("private or non-routable"));

        let public = resolved(&["1.1.1.1", "8.8.8.8"], 443);
        assert_eq!(
            authorize_with_resolver("alias.example", 443, &rules, |_, _| Ok(public.clone()))
                .unwrap(),
            public
        );
    }

    #[test]
    fn explicit_private_dns_and_ip_prefix_rules_are_unambiguous() {
        let private_rule = dns_rule("internal.example", false, true, 8443);
        assert!(
            authorize_with_resolver("internal.example", 8443, &[private_rule], |_, _| {
                Ok(resolved(&["127.0.0.1", "fd00::1"], 8443))
            })
            .is_ok()
        );
        let ip_rule = ManagedNetworkRule {
            transport: "tcp".into(),
            destination: ManagedNetworkDestination::Ip {
                cidr: "10.0.0.0/8".into(),
            },
            ports: vec![ManagedNetworkPort::Single(443)],
        };
        assert!(authorize("10.4.5.6", 443, std::slice::from_ref(&ip_rule)).is_ok());
        assert!(authorize("11.4.5.6", 443, &[ip_rule]).is_err());
    }

    #[test]
    fn active_connection_shutdown_is_forced_during_broker_cleanup() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let registration = ConnectionRegistration::new(1, Arc::clone(&streams), &client).unwrap();
        shutdown_active_streams(&streams);
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
        drop(registration);
        assert!(streams.lock().unwrap().is_empty());
    }

    #[test]
    fn socks5_requests_are_length_checked() {
        assert_eq!(
            parse_socks5_request(&[5, 1, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]).unwrap(),
            ("127.0.0.1".into(), 8080)
        );
        assert_eq!(
            parse_socks5_request(&[
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                0, 80,
            ])
            .unwrap(),
            ("example.com".into(), 80)
        );
        assert!(parse_socks5_request(&[5, 1, 0, 1, 127]).is_err());
        assert!(parse_socks5_request(&[5, 1, 0, 9, 0, 80]).is_err());
    }

    #[test]
    fn connect_parser_requires_a_complete_exact_request_line() {
        assert_eq!(
            parse_http_connect_request(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            .unwrap(),
            ("example.com".into(), 443)
        );
        assert!(parse_http_connect_request(b"CONNECT example.com:443\r\n\r\n").is_err());
        assert!(parse_http_connect_request(b"GET example.com:443 HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn dns_parser_rejects_compression_and_truncation() {
        let query = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        assert_eq!(parse_dns_question(&query).unwrap().0, "example.com");
        assert!(parse_dns_question(&query[..query.len() - 1]).is_err());
        let mut compressed = query;
        compressed[12] = 0xc0;
        assert!(parse_dns_question(&compressed).is_err());
    }
}
