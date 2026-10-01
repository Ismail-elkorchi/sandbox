//! Setup executes inside a new user/network namespace, never the host network.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;

pub const TAP_NAME: &str = "sandsurf0";

pub fn create_isolated_packet_socket() -> io::Result<File> {
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/net/tun")?;
    // SAFETY: zero initializes ifreq; the selected flags and name are filled.
    let mut request: libc::ifreq = unsafe { zeroed() };
    for (a, b) in request.ifr_name.iter_mut().zip(TAP_NAME.bytes()) {
        *a = b as _;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as _;
    // SAFETY: live TUN descriptor, initialized ifreq, standard Linux ioctl ABI.
    if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF as _, &request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: scalar UID/persistence options apply only to this isolated TAP.
    // Ownership lets Firecracker attach after setup capabilities are dropped.
    if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETOWNER as _, libc::geteuid()) } < 0
        || unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETPERSIST as _, 1) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: interface name is a constant NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(c"sandsurf0".as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    isolate_kernel_ingress(index)?;
    // SAFETY: creates a standard interface-control socket.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sole ownership transfers from socket creation.
    let control = unsafe { File::from_raw_fd(fd) };
    request.ifr_ifru.ifru_flags = libc::IFF_UP as _;
    // SAFETY: initialized name/flags request for a live control socket.
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // No host-side route, physical interface or bridge. All external
    // communication must cross the userspace gateway's native sockets.
    // SAFETY: CAP_NET_RAW is scoped to the fresh user/network namespace.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            i32::from(3_u16.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sole ownership transfers from successful socket creation.
    let packet = unsafe { File::from_raw_fd(fd) };
    // SAFETY: zero initializes unused sockaddr_ll fields.
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family = libc::AF_PACKET as _;
    address.sll_protocol = 3_u16.to_be();
    address.sll_ifindex = index as _;
    // SAFETY: exact native sockaddr_ll layout and length.
    if unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    for (level, option, value) in [
        (libc::SOL_PACKET, 15, 1_i32), // PACKET_VNET_HDR
        (libc::SOL_PACKET, 23, 1_i32), // PACKET_IGNORE_OUTGOING
        (libc::SOL_PACKET, 8, 1_i32),  // PACKET_AUXDATA: reject stripped VLAN tags
        (libc::SOL_SOCKET, libc::SO_RCVBUF, 256 * 1024),
        (libc::SOL_SOCKET, libc::SO_SNDBUF, 256 * 1024),
    ] {
        // SAFETY: pointer to one initialized c_int for a live socket.
        if unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                (&value as *const i32).cast(),
                std::mem::size_of_val(&value) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    drop(tun); // Firecracker owns the TAP queue; gateway owns AF_PACKET.
    Ok(packet)
}

/// ETH_P_ALL packet taps run before TC ingress. Deliver their bounded packet
/// copy to the gateway, then drop the original before kernel ARP/IP/NDP input.
/// This also prevents a malicious guest RA from configuring the TAP's kernel
/// IPv6 stack. Only this fresh private TAP is changed; no global policy exists.
fn isolate_kernel_ingress(index: u32) -> io::Result<()> {
    let mut qdisc = tc_message(index, 0xffff_0000, 0xffff_fff1, 0);
    attribute(&mut qdisc, 1, b"ingress\0"); // TCA_KIND
    netlink_ack(36, &qdisc)?; // RTM_NEWQDISC

    let mut filter = tc_message(index, 1, 0xffff_0000, (1 << 16) | u32::from(3_u16.to_be()));
    attribute(&mut filter, 1, b"matchall\0"); // TCA_KIND
    let mut parameters = vec![0; 20]; // struct tc_gact / tc_gen
    parameters[8..12].copy_from_slice(&2_i32.to_ne_bytes()); // TC_ACT_SHOT
    let mut gact = Vec::new();
    attribute(&mut gact, 2, &parameters); // TCA_GACT_PARMS
    let mut action = Vec::new();
    attribute(&mut action, 1, b"gact\0");
    attribute(&mut action, 2 | 0x8000, &gact); // TCA_ACT_OPTIONS
    let mut actions = Vec::new();
    attribute(&mut actions, 1 | 0x8000, &action);
    let mut options = Vec::new();
    attribute(&mut options, 2 | 0x8000, &actions); // TCA_MATCHALL_ACT
    attribute(&mut filter, 2 | 0x8000, &options); // TCA_OPTIONS
    netlink_ack(44, &filter) // RTM_NEWTFILTER; failure forbids launching the VMM
}
fn tc_message(index: u32, handle: u32, parent: u32, info: u32) -> Vec<u8> {
    let mut body = vec![0; 20]; // struct tcmsg, AF_UNSPEC, native-endian UAPI
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    body[8..12].copy_from_slice(&handle.to_ne_bytes());
    body[12..16].copy_from_slice(&parent.to_ne_bytes());
    body[16..20].copy_from_slice(&info.to_ne_bytes());
    body
}
fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    bytes.extend_from_slice(&(len as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}
fn netlink_ack(kind: u16, body: &[u8]) -> io::Result<()> {
    // SAFETY: creates one private route-control socket in this network namespace.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket allocation transfers ownership once.
    let mut socket = unsafe { File::from_raw_fd(fd) };
    // SAFETY: initialize all native address fields before connect.
    let mut address: libc::sockaddr_nl = unsafe { zeroed() };
    address.nl_family = libc::AF_NETLINK as _;
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: valid initialized sockaddr/timeval storage and exact native sizes.
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as _,
        )
    } < 0
        // SAFETY: socket retains fd and timeout is initialized live timeval
        // storage with its exact native size; this installs a receive deadline.
        || unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&timeout) as _,
            )
        } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut message = vec![0; 16]; // nlmsghdr
    message[..4].copy_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    message[4..6].copy_from_slice(&kind.to_ne_bytes());
    message[6..8].copy_from_slice(&0x605_u16.to_ne_bytes()); // REQUEST|ACK|CREATE|EXCL
    message[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    message.extend_from_slice(body);
    if socket.write(&message)? != message.len() {
        return Err(io::Error::other("partial private TAP isolation request"));
    }
    let mut ack = [0; 4096];
    let n = socket.read(&mut ack)?;
    if n < 20
        || u16::from_ne_bytes(ack[4..6].try_into().expect("bounded")) != 2
        || u32::from_ne_bytes(ack[8..12].try_into().expect("bounded")) != 1
    {
        return Err(io::Error::other(
            "private TAP isolation was not acknowledged",
        ));
    }
    let status = i32::from_ne_bytes(ack[16..20].try_into().expect("bounded"));
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "private TAP requires ingress/matchall/gact kernel support: {}",
            io::Error::from_raw_os_error(status.saturating_neg())
        )))
    }
}
