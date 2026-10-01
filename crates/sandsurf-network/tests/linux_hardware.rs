//! Real kernel TAP/AF_PACKET test, intentionally ignored in ordinary unit runs.
//! Runs inside bubblewrap as the caller, without sudo or host network changes.
#![cfg(target_os = "linux")]
use sandsurf_network::{
    GATEWAY_MAC, GUEST_IPV4, LinkIdentity, NativeNetworkGateway, PacketTransport,
};
use sandsurf_protocol::NetworkPolicy;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires /dev/net/tun, bubblewrap, and unprivileged user/network namespaces"]
fn isolated_tap_hardware_contract() {
    if std::env::var_os("SANDSURF_NETNS_TEST_INTERNAL").is_none() {
        let binary = std::env::current_exe().unwrap();
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
                "--dev-bind",
                "/dev",
                "/dev",
                "--proc",
                "/proc",
                "--setenv",
                "SANDSURF_NETNS_TEST_INTERNAL",
                "1",
                "--",
            ])
            .arg(binary)
            .args([
                "--ignored",
                "--exact",
                "isolated_tap_hardware_contract",
                "--nocapture",
            ])
            .status()
            .unwrap();
        assert!(
            result.success(),
            "native namespace/TAP prerequisite or enforcement failed"
        );
        return;
    }
    let packets = sandsurf_network::linux::create_isolated_packet_socket().unwrap();
    let names = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect::<Vec<_>>();
    assert!(names.iter().all(|name| name == "lo" || name == "sandsurf0"));
    let gateway =
        NativeNetworkGateway::start(PacketTransport::LinuxPacket(packets), TEST_LINK).unwrap();
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset receives the Linux v3 ABI with two initialized data words.
    // This test intentionally proves Firecracker can reopen the owned TAP
    // after all namespace setup capabilities have been discarded.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) },
        0
    );
    let mut nic = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .unwrap();
    // SAFETY: fully initialized standard ifreq passed to a live TUN descriptor.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (a, b) in request.ifr_name.iter_mut().zip(b"sandsurf0") {
        *a = *b as _;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as _;
    // SAFETY: the live device and initialized request remain valid during ioctl.
    assert_eq!(
        unsafe { libc::ioctl(nic.as_raw_fd(), libc::TUNSETIFF as _, &request) },
        0
    );
    let mut frame = sandsurf_network::packet::udp_reply(
        (GUEST_IPV4, 50000).into(),
        ("1.1.1.1".parse::<std::net::Ipv4Addr>().unwrap(), 53).into(),
        b"denied",
        false,
        &TEST_LINK,
    )
    .unwrap();
    frame[..6].copy_from_slice(&GATEWAY_MAC);
    frame[6..12].copy_from_slice(&GUEST_MAC);
    let mut offload = vec![0; 10];
    offload.extend_from_slice(&frame);
    nic.write_all(&offload).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while gateway.snapshot().violations == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(gateway.snapshot().violations > 0);
    assert_eq!(gateway.snapshot().connections, 0);
    gateway.configure(&NetworkPolicy::default(), &[]).unwrap();
    assert!(gateway.stop().cleanup_failures.is_empty());
}

const TEST_LINK: LinkIdentity = LinkIdentity {
    guest_mac: [2, 0, 0, 0, 0, 2],
};
const GUEST_MAC: [u8; 6] = TEST_LINK.guest_mac;
