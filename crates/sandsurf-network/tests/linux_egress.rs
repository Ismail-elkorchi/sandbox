//! Ignored real TAP test with remote TCP/UDP servers in a second private netns.
//! No host interface, firewall, NAT, sudo, or Internet dependency is involved.
#![cfg(target_os = "linux")]
use sandsurf_network::{
    GATEWAY_IPV4, GATEWAY_IPV6, GATEWAY_MAC, GUEST_IPV4, GUEST_IPV6, LinkIdentity, MAX_FRAME,
    NativeNetworkGateway, PacketTransport,
};
use sandsurf_protocol::{NetworkDestination, NetworkPlane, NetworkPolicy, NetworkRule, PortRange};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket, SocketBuffer};
use smoltcp::time::Instant as StackTime;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const REMOTE_V4: &str = "198.51.100.2";
const REMOTE_V6: &str = "2001:db8:1234::2";
const PAYLOAD: &[u8] = b"ordinary native packets";

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn ip(args: &[&str]) {
    assert!(
        Command::new("ip").args(args).status().unwrap().success(),
        "private test link setup: {args:?}"
    );
}
fn wait_file(root: &Path, name: &str) {
    let start = Instant::now();
    while !root.join(name).exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "private peer did not signal {name}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn servers(root: &Path) {
    std::fs::write(root.join("namespace-ready"), b"ready").unwrap();
    wait_file(root, "link-moved");
    ip(&["link", "set", "nsremote", "up"]);
    ip(&["addr", "add", "198.51.100.2/30", "dev", "nsremote"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:1234::2/64",
        "dev",
        "nsremote",
        "nodad",
    ]);
    let mut workers = Vec::new();
    for (index, address) in [REMOTE_V4, REMOTE_V6].iter().enumerate() {
        let ip: IpAddr = address.parse().unwrap();
        let tcp = TcpListener::bind(SocketAddr::new(ip, 8888)).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let closed = root.join(format!("tcp-closed-{index}"));
        workers.push(std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(20) {
                match tcp.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(10)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(10)))
                            .unwrap();
                        let mut bytes = [0; 1024];
                        loop {
                            match stream.read(&mut bytes) {
                                Ok(0) => {
                                    std::fs::write(&closed, b"closed").unwrap();
                                    return;
                                }
                                Ok(n) => {
                                    stream.write_all(&bytes[..n]).unwrap();
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                                    std::fs::write(&closed, b"reset").unwrap();
                                    return;
                                }
                                Err(e) => panic!("external TCP echo failed: {e}"),
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("external TCP listener failed: {e}"),
                }
            }
            panic!("external TCP connection was never established");
        }));
        let udp = UdpSocket::bind(SocketAddr::new(ip, 8889)).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let denied_vlan = root.join(format!("vlan-denied-{index}"));
        workers.push(std::thread::spawn(move || {
            let mut bytes = [0; 1500];
            let (n, peer) = udp.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..n], PAYLOAD);
            udp.send_to(&bytes[..n], peer).unwrap();
            udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let error = udp
                .recv_from(&mut bytes)
                .expect_err("stripped VLAN traffic bypassed native admission");
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            std::fs::write(denied_vlan, b"denied").unwrap();
        }));
    }
    std::fs::write(root.join("servers-ready"), b"ready").unwrap();
    for worker in workers {
        worker.join().unwrap();
    }
}

struct Nic(File);
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut File);
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
        let mut bytes = vec![0; 10 + len];
        let result = f(&mut bytes[10..]);
        match self.0.write(&bytes) {
            Ok(n) => assert_eq!(n, bytes.len()),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
        }
        result
    }
}
impl Device for Nic {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: StackTime) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut bytes = [0; MAX_FRAME + 10];
        let n = self.0.read(&mut bytes).ok()?;
        if n < 10 {
            return None;
        }
        Some((Rx(bytes[10..n].to_vec()), Tx(&mut self.0)))
    }
    fn transmit(&mut self, _: StackTime) -> Option<Self::TxToken<'_>> {
        Some(Tx(&mut self.0))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = MAX_FRAME;
        c
    }
}
fn open_nic() -> Nic {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .unwrap();
    // SAFETY: zeroed native ifreq is initialized before the standard ioctl.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (a, b) in req.ifr_name.iter_mut().zip(b"sandsurf0") {
        *a = *b as _;
    }
    req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as _;
    // SAFETY: live owned TUN fd and initialized request.
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &req) },
        0
    );
    Nic(file)
}
fn tcp_echo(nic: &mut Nic, gateway: &NativeNetworkGateway) {
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ethernet(EthernetAddress(GUEST_MAC))),
        nic,
        StackTime::from_millis(0),
    );
    interface.update_ip_addrs(|a| {
        a.push(IpCidr::new(GUEST_IPV4.into(), 30)).unwrap();
        a.push(IpCidr::new(GUEST_IPV6.into(), 64)).unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(GATEWAY_IPV4)
        .unwrap();
    interface
        .routes_mut()
        .add_default_ipv6_route(GATEWAY_IPV6)
        .unwrap();
    let mut sockets = SocketSet::new(Vec::new());
    let mut handles = Vec::new();
    for (index, (guest, remote)) in [
        (IpAddr::V4(GUEST_IPV4), REMOTE_V4),
        (IpAddr::V6(GUEST_IPV6), REMOTE_V6),
    ]
    .iter()
    .enumerate()
    {
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; 4096]),
            SocketBuffer::new(vec![0; 4096]),
        );
        socket
            .connect(
                interface.context(),
                SocketAddr::new(remote.parse().unwrap(), 8888),
                SocketAddr::new(*guest, 50000 + index as u16),
            )
            .unwrap();
        handles.push(sockets.add(socket));
    }
    let mut sent = [false; 2];
    let mut responses = [Vec::new(), Vec::new()];
    let start = Instant::now();
    while responses.iter().any(|r| r.len() < PAYLOAD.len()) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "native TCP/v4/v6 failed: {:?}",
            gateway.take_violations()
        );
        interface.poll(
            StackTime::from_millis(start.elapsed().as_millis() as i64),
            nic,
            &mut sockets,
        );
        for (index, handle) in handles.iter().enumerate() {
            let socket = sockets.get_mut::<Socket>(*handle);
            if socket.can_send() && !sent[index] {
                assert_eq!(socket.send_slice(PAYLOAD).unwrap(), PAYLOAD.len());
                sent[index] = true;
            }
            if socket.can_recv() {
                socket
                    .recv(|b| {
                        responses[index].extend_from_slice(b);
                        (b.len(), ())
                    })
                    .unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    for response in responses {
        assert_eq!(response, PAYLOAD);
    }
    // Drop only the simulated stack. No FIN/RST is emitted: native sockets
    // must remain established until the guardian's policy revision closes them.
}
fn udp_echo(nic: &mut Nic, guest: IpAddr, remote: IpAddr) {
    let source = SocketAddr::new(guest, 51000);
    let destination = SocketAddr::new(remote, 8889);
    let mut frame =
        sandsurf_network::packet::udp_reply(source, destination, PAYLOAD, false, &TEST_LINK)
            .unwrap();
    frame[..6].copy_from_slice(&GATEWAY_MAC);
    frame[6..12].copy_from_slice(&GUEST_MAC);
    let mut bytes = vec![0; 10];
    bytes.extend_from_slice(&frame);
    assert_eq!(nic.0.write(&bytes).unwrap(), bytes.len());
    let expected =
        sandsurf_network::packet::udp_reply(destination, source, PAYLOAD, false, &TEST_LINK)
            .unwrap();
    let start = Instant::now();
    let mut bytes = [0; MAX_FRAME + 10];
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "native UDP/v4/v6 echo missing"
        );
        if let Ok(n) = nic.0.read(&mut bytes)
            && n >= 10
            && bytes[10..n] == expected
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
#[ignore = "requires iproute2, /dev/net/tun, bubblewrap, and user/network namespaces"]
fn native_tcp_udp_ipv4_ipv6_and_established_flow_revocation() {
    if let Some(root) = std::env::var_os("SANDSURF_EGRESS_PEER") {
        servers(Path::new(&root));
        return;
    }
    if std::env::var_os("SANDSURF_EGRESS_NAMESPACE").is_none() {
        let result = Command::new("/usr/bin/bwrap")
            .args([
                "--unshare-user",
                "--unshare-net",
                "--uid",
                "0",
                "--gid",
                "0",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CAP_NET_ADMIN",
                "--cap-add",
                "CAP_NET_RAW",
                "--ro-bind",
                "/",
                "/",
                "--bind",
                "/tmp",
                "/tmp",
                "--dev-bind",
                "/dev",
                "/dev",
                "--proc",
                "/proc",
                "--setenv",
                "SANDSURF_EGRESS_NAMESPACE",
                "1",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "native_tcp_udp_ipv4_ipv6_and_established_flow_revocation",
                "--nocapture",
            ])
            .status()
            .unwrap();
        assert!(result.success());
        return;
    }
    let root = std::env::temp_dir().join(format!("sandsurf-native-egress-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut peer = Command::new(std::env::current_exe().unwrap());
    peer.env("SANDSURF_EGRESS_PEER", &root).args([
        "--ignored",
        "--exact",
        "native_tcp_udp_ipv4_ipv6_and_established_flow_revocation",
        "--nocapture",
    ]);
    // SAFETY: the child executes only the namespace syscall before exec. Its
    // CAP_NET_ADMIN is scoped to the bubblewrap-created user namespace.
    unsafe {
        peer.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWNET) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut peer = Peer(peer.spawn().unwrap());
    wait_file(&root, "namespace-ready");
    ip(&[
        "link",
        "add",
        "nsgateway",
        "type",
        "veth",
        "peer",
        "name",
        "nsremote",
    ]);
    ip(&["link", "set", "nsremote", "netns", &peer.0.id().to_string()]);
    ip(&["link", "set", "nsgateway", "up"]);
    ip(&["addr", "add", "198.51.100.1/30", "dev", "nsgateway"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:1234::1/64",
        "dev",
        "nsgateway",
        "nodad",
    ]);
    std::fs::write(root.join("link-moved"), b"ready").unwrap();
    wait_file(&root, "servers-ready");
    let transport = sandsurf_network::linux::create_isolated_packet_socket().unwrap();
    let gateway =
        NativeNetworkGateway::start(PacketTransport::LinuxPacket(transport), TEST_LINK).unwrap();
    let mut nic = open_nic();
    let policy = NetworkPolicy {
        rules: [NetworkPlane::Tcp, NetworkPlane::Udp]
            .iter()
            .flat_map(|plane| {
                [(REMOTE_V4, 32), (REMOTE_V6, 128)].map(|(ip, prefix)| NetworkRule {
                    plane: *plane,
                    destination: NetworkDestination::Ip {
                        cidr: format!("{ip}/{prefix}"),
                        allow_private_addresses: false,
                    },
                    ports: vec![PortRange {
                        from: if *plane == NetworkPlane::Tcp {
                            8888
                        } else {
                            8889
                        },
                        to: if *plane == NetworkPlane::Tcp {
                            8888
                        } else {
                            8889
                        },
                    }],
                })
            })
            .collect(),
    };
    gateway.configure(&policy, &[]).unwrap();
    tcp_echo(&mut nic, &gateway);
    udp_echo(&mut nic, GUEST_IPV4.into(), REMOTE_V4.parse().unwrap());
    udp_echo(&mut nic, GUEST_IPV6.into(), REMOTE_V6.parse().unwrap());
    for (guest, remote) in [
        (IpAddr::V4(GUEST_IPV4), REMOTE_V4),
        (IpAddr::V6(GUEST_IPV6), REMOTE_V6),
    ] {
        let mut frame = sandsurf_network::packet::udp_reply(
            SocketAddr::new(guest, 51000),
            SocketAddr::new(remote.parse().unwrap(), 8889),
            PAYLOAD,
            false,
            &TEST_LINK,
        )
        .unwrap();
        frame[..6].copy_from_slice(&GATEWAY_MAC);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        // Valid allowed inner IP/UDP, tagged at L2. Linux strips this header
        // before packet delivery: the gateway must inspect PACKET_AUXDATA.
        let mut tagged = vec![0; 10];
        tagged.extend_from_slice(&frame[..12]);
        tagged.extend_from_slice(&[0x81, 0, 0, 1]);
        tagged.extend_from_slice(&frame[12..]);
        assert_eq!(nic.0.write(&tagged).unwrap(), tagged.len());
    }
    wait_file(&root, "vlan-denied-0");
    wait_file(&root, "vlan-denied-1");
    assert_eq!(gateway.snapshot().connections, 4);
    gateway.configure(&NetworkPolicy::default(), &[]).unwrap();
    wait_file(&root, "tcp-closed-0");
    wait_file(&root, "tcp-closed-1");
    assert!(peer.0.wait().unwrap().success());
    // Even if a kernel address/listener were added to this private TAP, guest
    // packets must be seen only by AF_PACKET, then dropped before kernel UDP.
    ip(&["addr", "add", "100.64.0.1/30", "dev", "sandsurf0"]);
    let kernel = UdpSocket::bind((GATEWAY_IPV4, 8890)).unwrap();
    kernel.set_nonblocking(true).unwrap();
    let mut kernel_frame = sandsurf_network::packet::udp_reply(
        SocketAddr::new(GUEST_IPV4.into(), 51001),
        SocketAddr::new(GATEWAY_IPV4.into(), 8890),
        PAYLOAD,
        false,
        &TEST_LINK,
    )
    .unwrap();
    let kernel_mac = std::fs::read_to_string("/sys/class/net/sandsurf0/address")
        .unwrap()
        .trim()
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).unwrap())
        .collect::<Vec<_>>();
    kernel_frame[..6].copy_from_slice(&kernel_mac);
    kernel_frame[6..12].copy_from_slice(&GUEST_MAC);
    let mut kernel_bytes = vec![0; 10];
    kernel_bytes.extend_from_slice(&kernel_frame);
    nic.0.write_all(&kernel_bytes).unwrap();
    for (guest, remote) in [
        (IpAddr::V4(GUEST_IPV4), REMOTE_V4),
        (IpAddr::V6(GUEST_IPV6), REMOTE_V6),
    ] {
        let mut frame = sandsurf_network::packet::udp_reply(
            SocketAddr::new(guest, 51000),
            SocketAddr::new(remote.parse().unwrap(), 8889),
            PAYLOAD,
            false,
            &TEST_LINK,
        )
        .unwrap();
        frame[..6].copy_from_slice(&GATEWAY_MAC);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        let mut bytes = vec![0; 10];
        bytes.extend_from_slice(&frame);
        nic.0.write_all(&bytes).unwrap();
    }
    let start = Instant::now();
    while gateway.snapshot().violations < 3 && start.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(gateway.snapshot().violations >= 3);
    assert_eq!(gateway.snapshot().connections, 4);
    assert_eq!(
        kernel.recv(&mut [0; 1024]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(gateway.stop().cleanup_failures.is_empty());
    std::fs::remove_dir_all(&root).unwrap();
}

const TEST_LINK: LinkIdentity = LinkIdentity {
    guest_mac: [2, 0, 0, 0, 0, 2],
};
const GUEST_MAC: [u8; 6] = TEST_LINK.guest_mac;
