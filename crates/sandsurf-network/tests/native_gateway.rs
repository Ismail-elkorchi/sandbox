#![cfg(unix)]
use sandsurf_network::{
    GATEWAY_IPV4, GUEST_IPV4, LinkIdentity, MAX_FRAME, NativeNetworkGateway, PacketTransport,
};
use sandsurf_protocol::{Counter, Exposure, ExposureSpec, NetworkPolicy};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket, SocketBuffer};
use smoltcp::time::Instant as StackTime;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixDatagram;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct Nic(UnixDatagram);
struct Rx(Vec<u8>);
struct Tx<'a>(&'a UnixDatagram);
impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0; len];
        let value = f(&mut frame);
        let _ = self.0.send(&frame);
        value
    }
}
impl Device for Nic {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: StackTime) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut frame = [0; MAX_FRAME];
        let n = self.0.recv(&mut frame).ok()?;
        Some((Rx(frame[..n].to_vec()), Tx(&self.0)))
    }
    fn transmit(&mut self, _: StackTime) -> Option<Self::TxToken<'_>> {
        Some(Tx(&self.0))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = MAX_FRAME;
        c
    }
}

fn exposure() -> Exposure {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    Exposure {
        id: "port-fixture".try_into().unwrap(),
        machine_id: "machine-fixture".try_into().unwrap(),
        revision: Counter::ONE,
        spec: ExposureSpec {
            guest_address: GUEST_IPV4.to_string(),
            guest_port: 8080,
            host_address: "127.0.0.1".into(),
            host_port: port,
            public: false,
        },
        active: true,
        bound_port: Some(port),
    }
}
fn echo_guest(socket: UnixDatagram, stop: Arc<AtomicBool>, link: LinkIdentity) {
    socket.set_nonblocking(true).unwrap();
    let mut nic = Nic(socket);
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ethernet(EthernetAddress(link.guest_mac))),
        &mut nic,
        StackTime::from_millis(0),
    );
    interface.update_ip_addrs(|a| {
        a.push(IpCidr::new(GUEST_IPV4.into(), 30)).unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(GATEWAY_IPV4)
        .unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp = Socket::new(
        SocketBuffer::new(vec![0; 4096]),
        SocketBuffer::new(vec![0; 4096]),
    );
    tcp.listen(8080).unwrap();
    let handle = sockets.add(tcp);
    let start = Instant::now();
    while !stop.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(10) {
        interface.poll(
            StackTime::from_millis(start.elapsed().as_millis() as i64),
            &mut nic,
            &mut sockets,
        );
        let tcp = sockets.get_mut::<Socket>(handle);
        if tcp.can_recv() && tcp.can_send() {
            let mut bytes = [0; 1024];
            let n = tcp.recv_slice(&mut bytes).unwrap();
            tcp.send_slice(&bytes[..n]).unwrap();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn inbound_targets_native_nic_and_revocation_closes_existing_client_before_success() {
    let (host, guest) = UnixDatagram::pair().unwrap();
    let link = LinkIdentity::for_machine(&"machine-fixture".try_into().unwrap());
    let gateway = NativeNetworkGateway::start(PacketTransport::Datagram(host), link).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let guest_stop = Arc::clone(&stop);
    let worker = std::thread::spawn(move || echo_guest(guest, guest_stop, link));
    let exposure = exposure();
    gateway
        .configure(&NetworkPolicy::default(), std::slice::from_ref(&exposure))
        .unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", exposure.spec.host_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client.write_all(b"native NIC echo").unwrap();
    let mut response = [0; 15];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"native NIC echo");
    assert_eq!(gateway.snapshot().connections, 1);
    gateway.configure(&NetworkPolicy::default(), &[]).unwrap();
    match client.read(&mut response) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("existing native flow survived acknowledged revocation: {other:?}"),
    }
    assert!(TcpStream::connect(("127.0.0.1", exposure.spec.host_port)).is_err());
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
    assert!(gateway.stop().cleanup_failures.is_empty());
}

#[test]
fn failed_installation_leaves_deny_and_closes_previous_inbound_authority() {
    let (host, _guest) = UnixDatagram::pair().unwrap();
    let gateway = NativeNetworkGateway::start(PacketTransport::Datagram(host), TEST_LINK).unwrap();
    let good = exposure();
    gateway
        .configure(&NetworkPolicy::default(), std::slice::from_ref(&good))
        .unwrap();
    let mut bad = good.clone();
    bad.spec.guest_address = "127.0.0.1".into();
    assert!(
        gateway
            .configure(&NetworkPolicy::default(), &[bad])
            .is_err()
    );
    assert!(TcpStream::connect(("127.0.0.1", good.spec.host_port)).is_err());
    assert!(gateway.stop().cleanup_failures.is_empty());
}

#[test]
fn malformed_flood_cannot_grow_violation_retention_or_block_revocation() {
    let (host, guest) = UnixDatagram::pair().unwrap();
    let gateway = NativeNetworkGateway::start(PacketTransport::Datagram(host), TEST_LINK).unwrap();
    guest.set_nonblocking(true).unwrap();
    for _ in 0..2048 {
        let _ = guest.send(&[255; MAX_FRAME]);
    }
    std::thread::sleep(Duration::from_millis(100));
    gateway.configure(&NetworkPolicy::default(), &[]).unwrap();
    assert!(gateway.take_violations().len() <= 256);
    assert_eq!(gateway.snapshot().connections, 0);
    assert!(gateway.stop().cleanup_failures.is_empty());
}

const TEST_LINK: LinkIdentity = LinkIdentity {
    guest_mac: [2, 0, 0, 0, 0, 2],
};
