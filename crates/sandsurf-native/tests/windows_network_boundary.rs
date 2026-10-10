//! Actual production socket admission, independent of WHPX availability.
#![cfg(windows)]
use sandsurf_native::network_sockets::{SocketAdmission, probe};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

#[test]
#[ignore = "requires running native firewall services and public Internet access"]
fn original_sockets_deny_local_delivery_and_allow_public_tcp() {
    probe().unwrap();
    for ip in ["127.0.0.1", "::1"] {
        let tcp = TcpListener::bind((ip, 0)).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let address = tcp.local_addr().unwrap();
        let mut ordinary = TcpStream::connect(address).unwrap();
        ordinary.write_all(b"control").unwrap();
        let (mut accepted, _) = tcp.accept().unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0; 7];
        accepted.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"control");
        let mut admission = SocketAdmission::begin(address.is_ipv6(), false).unwrap();
        let restricted = admission.poll().unwrap().unwrap();
        assert_eq!(
            admission.poll().unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert!(
            restricted
                .connect_timeout(&address.into(), Duration::from_secs(1))
                .is_err()
        );
        assert_eq!(tcp.accept().unwrap_err().kind(), ErrorKind::WouldBlock);

        let udp = UdpSocket::bind((ip, 0)).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let address = udp.local_addr().unwrap();
        let ordinary = UdpSocket::bind((ip, 0)).unwrap();
        ordinary.send_to(b"control", address).unwrap();
        assert_eq!(udp.recv(&mut bytes).unwrap(), bytes.len());
        let restricted: UdpSocket = SocketAdmission::begin(address.is_ipv6(), true)
            .unwrap()
            .poll()
            .unwrap()
            .unwrap()
            .into();
        let _ = restricted.send_to(b"denied", address);
        let error = udp.recv(&mut bytes).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
    }
    // Denying all traffic is not sufficient. Use the production identity to
    // establish an actual external connection after socket creation reverts.
    let mut connected = false;
    for address in ("github.com", 443)
        .to_socket_addrs()
        .unwrap()
        .filter(|v| v.is_ipv4())
        .take(4)
    {
        let socket = SocketAdmission::begin(false, false)
            .unwrap()
            .poll()
            .unwrap()
            .unwrap();
        if socket
            .connect_timeout(&address.into(), Duration::from_secs(3))
            .is_ok()
        {
            connected = true;
            break;
        }
    }
    assert!(
        connected,
        "production network identity could not reach public TCP"
    );
}
