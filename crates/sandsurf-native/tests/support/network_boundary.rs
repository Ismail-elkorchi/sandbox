use sandsurf_native::network_sockets::{SocketAdmission, probe};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub fn original_sockets_deny_local_delivery_and_allow_public_tcp() {
    probe().unwrap();
    for ip in ["127.0.0.1", "::1"] {
        let tcp = TcpListener::bind((ip, 0)).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let address = tcp.local_addr().unwrap();
        let mut ordinary = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        ordinary.write_all(b"control").unwrap();
        let (mut accepted, _) = tcp.accept().unwrap();
        // Darwin inherits O_NONBLOCK from the listener; SO_RCVTIMEO alone
        // does not turn a nonblocking accepted socket into a bounded read.
        accepted.set_nonblocking(false).unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0; 7];
        accepted.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"control");
        let restricted = admit(address.is_ipv6(), false);
        let attempt = restricted.connect(&address.into());
        eprintln!(
            "restricted {address}: connect={attempt:?}, peer={:?}",
            restricted.peer_addr()
        );
        let mut restricted: TcpStream = restricted.into();
        let _ = restricted.write(b"denied");
        // Packet denial is actual non-delivery, not a library's interpretation
        // of connect/poll completion. Keep the positive control above intact.
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            assert_eq!(
                tcp.accept().unwrap_err().kind(),
                ErrorKind::WouldBlock,
                "restricted TCP reached the local listener"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let udp = UdpSocket::bind((ip, 0)).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let address = udp.local_addr().unwrap();
        let ordinary = UdpSocket::bind((ip, 0)).unwrap();
        ordinary.send_to(b"control", address).unwrap();
        assert_eq!(udp.recv(&mut bytes).unwrap(), bytes.len());
        let restricted: UdpSocket = admit(address.is_ipv6(), true).into();
        let _ = restricted.send_to(b"denied", address);
        let error = udp.recv(&mut bytes).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
    }
    // Denial alone is insufficient: the same native identity must carry real
    // external traffic after the allocation credential has been restored.
    let mut connected = false;
    for address in ("github.com", 80)
        .to_socket_addrs()
        .unwrap()
        .filter(|v| v.is_ipv4())
        .take(4)
    {
        let ordinary = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        ordinary.set_nonblocking(true).unwrap();
        let ordinary = connect(ordinary, address).and_then(http);
        eprintln!("public {address}: ordinary={ordinary:?}");
        if ordinary.is_err() {
            continue;
        }
        let restricted = connect(admit(false, false), address).and_then(http);
        eprintln!("public {address}: restricted={restricted:?}");
        if restricted.is_ok() {
            connected = true;
            break;
        }
    }
    assert!(
        connected,
        "production network identity could not exchange bytes over public TCP"
    );
}

fn connect(socket: socket2::Socket, address: SocketAddr) -> std::io::Result<TcpStream> {
    describe(&socket, "before connect");
    if let Err(error) = socket.connect(&address.into()) {
        #[cfg(unix)]
        let pending = error.raw_os_error() == Some(libc::EINPROGRESS);
        #[cfg(windows)]
        let pending = error.kind() == ErrorKind::WouldBlock;
        if !pending {
            return Err(error);
        }
    }
    let stream: TcpStream = socket.into();
    // Exercise the same nonblocking readiness contract as the packet gateway.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if sandsurf_native::socket_io::tcp_connected(&stream)? {
            stream.set_nonblocking(false)?;
            describe(&socket2::SockRef::from(&stream), "connected");
            return Ok(stream);
        }
        if std::time::Instant::now() >= deadline {
            return Err(ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn http(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"HEAD / HTTP/1.0\r\nHost: github.com\r\n\r\n")?;
    describe(&socket2::SockRef::from(&stream), "before read");
    let mut response = [0; 5];
    let result = stream.read_exact(&mut response);
    describe(&socket2::SockRef::from(&stream), "after read");
    result?;
    if &response != b"HTTP/" {
        return Err(ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn admit(ipv6: bool, udp: bool) -> socket2::Socket {
    let mut admission = SocketAdmission::begin(ipv6, udp).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(socket) = admission.poll().unwrap() {
            describe(&socket, "admitted");
            assert!(
                admission.poll().is_err(),
                "completed admission replayed its handle"
            );
            return socket;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "native admission did not complete"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn describe(socket: &socket2::Socket, stage: &str) {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: exact initialized native stat output for a borrowed socket.
        let mut state: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: retained socket and writable native stat output.
        assert_eq!(unsafe { libc::fstat(socket.as_raw_fd(), &mut state) }, 0);
        eprintln!(
            "{stage}: fd={} mode={:o} uid={} recv_buffer={:?}",
            socket.as_raw_fd(),
            state.st_mode,
            state.st_uid,
            socket.recv_buffer_size()
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (socket, stage);
}
