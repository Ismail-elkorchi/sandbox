//! Transparent TCP for workload programs that do not speak an application proxy.
//!
//! The guest kernel routes ordinary IP connects into a private TUN interface.
//! A bounded user-space TCP stack converts those packets into streams and sends
//! each stream to the local authenticated SOCKS relay. The relay crosses vsock
//! to the host network broker, which remains the sole policy and egress
//! authority. No guest interface has direct access to a host or physical NIC.

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::zeroed;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

const INTERFACE: &str = "sandsurf0";
const TUN_PATH: &str = "/dev/net/tun";
const MTU: usize = 1500;
const MAX_DIRECT_CONNECTIONS: usize = 256;
const PACKET_QUEUE: usize = 256;
const TCP_QUEUE: usize = 256;
const TCP_WINDOW: u32 = 64 * 1024;
const SOCKS_PORT: u16 = 1080;

/// Create the fail-closed interface synchronously, then start its isolated
/// runtime. Startup is acknowledged only after the stack owns the TUN device.
pub fn start() -> io::Result<()> {
    let tun = create_tun()?;
    configure_interface()?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("sandsurf-direct-network".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build();
            let result = runtime.and_then(|runtime| runtime.block_on(run(tun, ready_tx)));
            if let Err(error) = result {
                eprintln!("sandsurf direct network failed: {error}");
                // A dead gateway with a live default route would create an
                // unobservable partial machine. Terminate PID 1 so the host
                // records machine failure instead.
                std::process::exit(1);
            }
        })?;
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "direct network startup timed out"))?
}

async fn run(tun: File, ready: mpsc::SyncSender<io::Result<()>>) -> io::Result<()> {
    let (stack, runner, _, listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(false)
        .enable_icmp(false)
        .stack_buffer_size(PACKET_QUEUE)
        .tcp_buffer_size(TCP_QUEUE)
        .tcp_recv_buffer_size(TCP_WINDOW)
        .tcp_send_buffer_size(TCP_WINDOW)
        .mtu(MTU)
        .build()?;
    let runner = runner.ok_or_else(|| io::Error::other("TCP stack runner is absent"))?;
    let mut listener = listener.ok_or_else(|| io::Error::other("TCP listener is absent"))?;
    let tun = Arc::new(AsyncFd::new(tun)?);
    let (mut ingress, mut egress) = stack.split();
    let read_tun = Arc::clone(&tun);
    let write_tun = Arc::clone(&tun);
    let permits = Arc::new(Semaphore::new(MAX_DIRECT_CONNECTIONS));
    ready
        .send(Ok(()))
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "startup waiter closed"))?;

    let packets_to_stack = async move {
        let mut packet = vec![0_u8; MTU + 64];
        loop {
            let length = read_packet(&read_tun, &mut packet).await?;
            if length == 0 || length > MTU {
                continue;
            }
            ingress.send(packet[..length].to_vec()).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let packets_to_kernel = async move {
        while let Some(packet) = egress.next().await {
            let packet = packet?;
            if packet.is_empty() || packet.len() > MTU {
                continue;
            }
            write_packet(&write_tun, &packet).await?;
        }
        Err::<(), io::Error>(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "direct network packet stream closed",
        ))
    };
    let connections = async move {
        while let Some((stream, _, destination)) = listener.next().await {
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                drop(stream);
                continue;
            };
            tokio::spawn(async move {
                let _permit = permit;
                let _ = forward(stream, destination).await;
            });
        }
        Err::<(), io::Error>(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "direct network TCP listener closed",
        ))
    };
    tokio::try_join!(runner, packets_to_stack, packets_to_kernel, connections)?;
    Ok(())
}

async fn forward(
    mut workload: netstack_smoltcp::TcpStream,
    destination: SocketAddr,
) -> io::Result<()> {
    let mut relay = tokio::time::timeout(Duration::from_secs(15), async {
        let mut relay = TcpStream::connect((Ipv4Addr::LOCALHOST, SOCKS_PORT)).await?;
        relay.write_all(&[5, 1, 0]).await?;
        let mut greeting = [0_u8; 2];
        relay.read_exact(&mut greeting).await?;
        if greeting != [5, 0] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local SOCKS relay rejected authentication",
            ));
        }
        relay
            .write_all(&socks_request(destination.ip(), destination.port()))
            .await?;
        read_socks_reply(&mut relay).await?;
        Ok::<TcpStream, io::Error>(relay)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS relay timed out"))??;
    tokio::io::copy_bidirectional(&mut workload, &mut relay).await?;
    Ok(())
}

fn socks_request(address: IpAddr, port: u16) -> Vec<u8> {
    let mut request = vec![5, 1, 0];
    match address {
        IpAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    request
}

async fn read_socks_reply(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local SOCKS relay returned a malformed reply",
        ));
    }
    if header[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "host network policy rejected direct TCP",
        ));
    }
    let address_bytes = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            if length[0] == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "local SOCKS relay returned an empty address",
                ));
            }
            usize::from(length[0])
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local SOCKS relay returned an invalid address type",
            ));
        }
    };
    let mut remainder = vec![0_u8; address_bytes + 2];
    stream.read_exact(&mut remainder).await?;
    Ok(())
}

async fn read_packet(tun: &AsyncFd<File>, bytes: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = tun.readable().await?;
        match ready.try_io(|inner| {
            // SAFETY: the AsyncFd owns one live nonblocking TUN descriptor and
            // bytes points to writable storage of the supplied length.
            let result = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn write_packet(tun: &AsyncFd<File>, bytes: &[u8]) -> io::Result<()> {
    loop {
        let mut ready = tun.writable().await?;
        match ready.try_io(|inner| {
            // SAFETY: the AsyncFd owns one live nonblocking TUN descriptor and
            // bytes points to initialized storage of the supplied length.
            let result = unsafe {
                libc::write(
                    inner.get_ref().as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else if result as usize != bytes.len() {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial TUN packet write",
                ))
            } else {
                Ok(())
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

fn create_tun() -> io::Result<File> {
    ensure_tun_device()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(TUN_PATH)?;
    // SAFETY: zero is a valid initial representation for ifreq. The selected
    // union member is initialized before the kernel reads it.
    let mut request: libc::ifreq = unsafe { zeroed() };
    set_interface_name(&mut request)?;
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: TUNSETIFF receives one live TUN descriptor and a correctly sized,
    // initialized ifreq that remains valid for the duration of the call.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &mut request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn ensure_tun_device() -> io::Result<()> {
    fs::create_dir_all("/dev/net")?;
    match fs::symlink_metadata(TUN_PATH) {
        Ok(metadata)
            if metadata.file_type().is_char_device()
                && metadata.rdev() == libc::makedev(10, 200) =>
        {
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TUN device path has an unexpected type or device number",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let path = CString::new(TUN_PATH).expect("constant has no NUL");
            // SAFETY: path is a valid NUL-terminated pathname and makedev uses
            // the Linux misc/TUN device numbers documented by the kernel ABI.
            if unsafe {
                libc::mknod(
                    path.as_ptr(),
                    libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
                    libc::makedev(10, 200),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn configure_interface() -> io::Result<()> {
    // SAFETY: arguments request a standard close-on-exec IPv4 control socket.
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket creation transfers sole ownership here.
    let socket = unsafe { File::from_raw_fd(descriptor) };
    configure_ipv4(socket.as_raw_fd())?;
    bring_up(socket.as_raw_fd())?;
    add_ipv4_default_route(socket.as_raw_fd())?;
    configure_ipv6()?;
    Ok(())
}

fn configure_ipv4(socket: libc::c_int) -> io::Result<()> {
    // SAFETY: each zeroed ifreq has its selected address union member and name
    // initialized before its corresponding ioctl reads it.
    let mut address: libc::ifreq = unsafe { zeroed() };
    set_interface_name(&mut address)?;
    address.ifr_ifru.ifru_addr = sockaddr_v4(Ipv4Addr::new(100, 64, 0, 2));
    // SAFETY: SIOCSIFADDR reads one initialized ifreq for a live control socket.
    if unsafe { libc::ioctl(socket, libc::SIOCSIFADDR as _, &address) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see the address request above.
    let mut netmask: libc::ifreq = unsafe { zeroed() };
    set_interface_name(&mut netmask)?;
    netmask.ifr_ifru.ifru_netmask = sockaddr_v4(Ipv4Addr::new(255, 255, 255, 255));
    // SAFETY: SIOCSIFNETMASK reads one initialized ifreq.
    if unsafe { libc::ioctl(socket, libc::SIOCSIFNETMASK as _, &netmask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bring_up(socket: libc::c_int) -> io::Result<()> {
    // SAFETY: zero is a valid initial representation and the name is filled
    // before either flags ioctl reads the request.
    let mut request: libc::ifreq = unsafe { zeroed() };
    set_interface_name(&mut request)?;
    // SAFETY: SIOCGIFFLAGS writes the selected flags union member.
    if unsafe { libc::ioctl(socket, libc::SIOCGIFFLAGS as _, &mut request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the preceding ioctl initialized the selected flags member.
    let flags = unsafe { request.ifr_ifru.ifru_flags }
        | libc::IFF_UP as libc::c_short
        | libc::IFF_RUNNING as libc::c_short;
    request.ifr_ifru.ifru_flags = flags;
    // SAFETY: SIOCSIFFLAGS reads the initialized name and flags member.
    if unsafe { libc::ioctl(socket, libc::SIOCSIFFLAGS as _, &request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn add_ipv4_default_route(socket: libc::c_int) -> io::Result<()> {
    // SAFETY: zero initializes all unused route fields to their required
    // default. The destination, mask, flags, and device are set below.
    let mut route: libc::rtentry = unsafe { zeroed() };
    route.rt_dst = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
    route.rt_genmask = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
    route.rt_gateway = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
    route.rt_flags = libc::RTF_UP;
    let interface = CString::new(INTERFACE).expect("constant has no NUL");
    route.rt_dev = interface.as_ptr().cast_mut();
    // SAFETY: SIOCADDRT reads the complete route during this call while the
    // device-name CString and route storage remain live.
    if unsafe { libc::ioctl(socket, libc::SIOCADDRT as _, &route) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct In6IfReq {
    address: libc::in6_addr,
    prefix_length: u32,
    interface_index: libc::c_int,
}

#[repr(C)]
struct In6Route {
    destination: libc::in6_addr,
    source: libc::in6_addr,
    gateway: libc::in6_addr,
    route_type: u32,
    destination_length: u16,
    source_length: u16,
    metric: u32,
    info: libc::c_ulong,
    flags: u32,
    interface_index: libc::c_int,
}

fn configure_ipv6() -> io::Result<()> {
    let interface = CString::new(INTERFACE).expect("constant has no NUL");
    // SAFETY: the constant interface name is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: arguments request a standard close-on-exec IPv6 control socket.
    let descriptor =
        unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket creation transfers sole ownership here.
    let socket = unsafe { File::from_raw_fd(descriptor) };
    let request = In6IfReq {
        address: in6_addr(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        prefix_length: 128,
        interface_index: index as libc::c_int,
    };
    // SAFETY: Linux SIOCSIFADDR on an AF_INET6 control socket reads the stable
    // in6_ifreq ABI represented by In6IfReq.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFADDR as _, &request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let route = In6Route {
        destination: in6_addr(Ipv6Addr::UNSPECIFIED),
        source: in6_addr(Ipv6Addr::UNSPECIFIED),
        gateway: in6_addr(Ipv6Addr::UNSPECIFIED),
        route_type: 0,
        destination_length: 0,
        source_length: 0,
        metric: 1,
        info: 0,
        flags: u32::from(libc::RTF_UP),
        interface_index: index as libc::c_int,
    };
    // SAFETY: Linux SIOCADDRT on an AF_INET6 socket reads the stable in6_rtmsg
    // ABI represented by In6Route for the duration of this call.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCADDRT as _, &route) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_interface_name(request: &mut libc::ifreq) -> io::Result<()> {
    let bytes = INTERFACE.as_bytes();
    if bytes.len() >= request.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "direct network interface name is too long",
        ));
    }
    for (destination, source) in request.ifr_name.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    Ok(())
}

fn sockaddr_v4(address: Ipv4Addr) -> libc::sockaddr {
    let mut value = libc::sockaddr {
        sa_family: libc::AF_INET as libc::sa_family_t,
        sa_data: [0; 14],
    };
    for (destination, source) in value.sa_data[2..6].iter_mut().zip(address.octets()) {
        *destination = source as libc::c_char;
    }
    value
}

fn in6_addr(address: Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: address.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_requests_preserve_exact_ip_and_port() {
        assert_eq!(
            socks_request(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443),
            [5, 1, 0, 1, 203, 0, 113, 9, 1, 187]
        );
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let request = socks_request(IpAddr::V6(ipv6), 8443);
        assert_eq!(&request[..4], &[5, 1, 0, 4]);
        assert_eq!(&request[4..20], &ipv6.octets());
        assert_eq!(&request[20..], &8443_u16.to_be_bytes());
    }

    #[test]
    fn kernel_abi_structures_match_linux_layouts() {
        assert_eq!(std::mem::size_of::<In6IfReq>(), 24);
        assert_eq!(
            std::mem::size_of::<In6Route>(),
            std::mem::size_of::<libc::in6_rtmsg>()
        );
    }
}
