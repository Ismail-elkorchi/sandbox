//! Strict admission before any allocation in the TCP stack. VLANs, IPv4
//! options/fragments, IPv6 extensions/fragments, external ICMP, and unknown
//! EtherTypes/protocols are dropped. Only ARP, DHCP, and on-link NDP are local
//! control traffic; none can reach an external socket.
use crate::{
    GATEWAY_IPV4, GATEWAY_IPV6, GATEWAY_MAC, GUEST_IPV4, GUEST_IPV6, LinkIdentity, MAX_FRAME,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub guest: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packet {
    Control,
    Dhcp { payload: usize },
    Tcp { key: FlowKey, syn: bool },
    Udp { key: FlowKey, payload: usize },
}

fn word(b: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([b[offset], b[offset + 1]])
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let sum = bytes.chunks(2).fold(0_u32, |s, b| {
        s + u32::from(u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]))
    });
    finish(sum)
}
fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn transport_checksum(src: IpAddr, dst: IpAddr, protocol: u8, bytes: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40);
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&[0, protocol]);
            pseudo.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        }
        _ => return 1,
    }
    // Both pseudo-header layouts are even in length.
    let sum = pseudo
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| word.as_slice())
        .chain(bytes.chunks(2))
        .fold(0_u32, |s, b| {
            s + u32::from(u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]))
        });
    finish(sum)
}

/// Normalize virtio checksum/TSO metadata; this is not IP reassembly.
/// UDP GSO and unknown offloads are unsupported. Segment count is bounded.
pub fn normalize_offload(bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.len() < 24 || bytes.len() > 65536 + 24 || bytes[0] & !3 != 0 {
        return Vec::new();
    }
    let frame = &bytes[10..];
    let gso = bytes[1] & !0x80;
    if gso == 0 && bytes[0] & 1 == 0 {
        return if frame.len() <= MAX_FRAME {
            vec![frame.to_vec()]
        } else {
            Vec::new()
        };
    }
    let (src, dst, protocol, offset, end) = match word(frame, 12) {
        0x0800 => {
            if frame.len() < 34
                || frame[14] != 0x45
                || checksum(&frame[14..34]) != 0
                || word(frame, 20) & 0xbfff != 0
            {
                return Vec::new();
            }
            let end = 14 + usize::from(word(frame, 16));
            if end > frame.len() || end < 34 {
                return Vec::new();
            }
            (
                IpAddr::V4(Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29])),
                IpAddr::V4(Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33])),
                frame[23],
                34,
                end,
            )
        }
        0x86dd => {
            if frame.len() < 54 || frame[14] >> 4 != 6 {
                return Vec::new();
            }
            let end = 54 + usize::from(word(frame, 18));
            if end > frame.len() {
                return Vec::new();
            }
            (
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[22..38]).expect("bounded"),
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[38..54]).expect("bounded"),
                )),
                frame[20],
                54,
                end,
            )
        }
        _ => return Vec::new(),
    };
    let checksum_at = match protocol {
        6 => 16,
        17 => 6,
        _ => return Vec::new(),
    };
    let start = usize::from(u16::from_le_bytes([bytes[6], bytes[7]]));
    let at = usize::from(u16::from_le_bytes([bytes[8], bytes[9]]));
    if bytes[0] & 1 != 0 && (start != offset || at != checksum_at) {
        return Vec::new();
    }
    if offset + checksum_at + 2 > end {
        return Vec::new();
    }
    if gso == 0 {
        if frame.len() > MAX_FRAME {
            return Vec::new();
        }
        let mut packet = frame.to_vec();
        packet[offset + checksum_at..offset + checksum_at + 2].fill(0);
        let check = transport_checksum(src, dst, protocol, &packet[offset..end]);
        packet[offset + checksum_at..offset + checksum_at + 2].copy_from_slice(
            &if protocol == 17 && check == 0 {
                65535
            } else {
                check
            }
            .to_be_bytes(),
        );
        return vec![packet];
    }
    if protocol != 6
        || (src.is_ipv4() && gso != 1)
        || (src.is_ipv6() && gso != 4)
        || offset + 20 > end
    {
        return Vec::new();
    }
    let tcp_header = usize::from(frame[offset + 12] >> 4) * 4;
    let header = offset + tcp_header;
    let size = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    if tcp_header < 20
        || header > end
        || size == 0
        || header + size > MAX_FRAME
        || usize::from(u16::from_le_bytes([bytes[2], bytes[3]])) != header
        || (end - header).div_ceil(size) > 64
        || frame[offset + 13] & (2 | 4 | 32) != 0
    {
        return Vec::new();
    }
    let sequence = u32::from_be_bytes(frame[offset + 4..offset + 8].try_into().expect("bounded"));
    let mut segments = Vec::new();
    for (index, payload) in frame[header..end].chunks(size).enumerate() {
        let mut packet = frame[..header].to_vec();
        packet.extend_from_slice(payload);
        let n = packet.len();
        packet[offset + 4..offset + 8]
            .copy_from_slice(&sequence.wrapping_add((index * size) as u32).to_be_bytes());
        if header + index * size + payload.len() < end {
            packet[offset + 13] &= !(1 | 8);
        }
        if index > 0 {
            packet[offset + 13] &= !128;
        }
        if src.is_ipv4() {
            packet[16..18].copy_from_slice(&((n - 14) as u16).to_be_bytes());
            let id = word(frame, 18).wrapping_add(index as u16);
            packet[18..20].copy_from_slice(&id.to_be_bytes());
            packet[24..26].fill(0);
            let check = checksum(&packet[14..34]);
            packet[24..26].copy_from_slice(&check.to_be_bytes());
        } else {
            packet[18..20].copy_from_slice(&((n - 54) as u16).to_be_bytes());
        }
        packet[offset + 16..offset + 18].fill(0);
        let check = transport_checksum(src, dst, 6, &packet[offset..]);
        packet[offset + 16..offset + 18].copy_from_slice(&check.to_be_bytes());
        segments.push(packet);
    }
    segments
}

pub fn parse(frame: &[u8], link: &LinkIdentity) -> Option<Packet> {
    if frame.len() < 14 || frame.len() > MAX_FRAME || frame[6..12] != link.guest_mac {
        return None;
    }
    let kind = word(frame, 12);
    if kind == 0x0806 {
        if frame.len() < 42
            || word(frame, 14) != 1
            || word(frame, 16) != 0x0800
            || frame[18..20] != [6, 4]
            || !matches!(word(frame, 20), 1 | 2)
            || frame[22..28] != link.guest_mac
            || frame[38..42] != GATEWAY_IPV4.octets()
            || (frame[28..32] != GUEST_IPV4.octets() && frame[28..32] != [0; 4])
            || (frame[..6] != GATEWAY_MAC && frame[..6] != [255; 6])
        {
            return None;
        }
        if word(frame, 20) == 2
            && (frame[28..32] != GUEST_IPV4.octets()
                || frame[32..38] != GATEWAY_MAC
                || frame[..6] != GATEWAY_MAC)
        {
            return None;
        }
        return Some(Packet::Control);
    }
    let (src, dst, protocol, offset, end, hop) = match kind {
        0x0800 => {
            if frame.len() < 34 || frame[14] != 0x45 {
                return None;
            }
            let len = usize::from(word(frame, 16));
            // Ethernet minimum-frame padding may follow the IP datagram.
            if len < 20
                || len + 14 > frame.len()
                || word(frame, 20) & 0xbfff != 0
                || checksum(&frame[14..34]) != 0
                || frame[22] == 0
            {
                return None;
            }
            let src = Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
            let dst = Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);
            (
                IpAddr::V4(src),
                IpAddr::V4(dst),
                frame[23],
                34,
                14 + len,
                frame[22],
            )
        }
        0x86dd => {
            if frame.len() < 54 || frame[14] >> 4 != 6 {
                return None;
            }
            let end = 54 + usize::from(word(frame, 18));
            if end > frame.len() || frame[21] == 0 {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[22..38]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[38..54]).ok()?);
            (
                IpAddr::V6(src),
                IpAddr::V6(dst),
                frame[20],
                54,
                end,
                frame[21],
            )
        }
        _ => return None,
    };
    let bytes = &frame[offset..end];
    if protocol == 58 {
        // Local NDP only, with the RFC 4861 hop-limit and pseudo-header checksum.
        if bytes.len() < 24
            || !matches!(bytes[0], 135 | 136)
            || bytes[1] != 0
            || hop != 255
            || transport_checksum(src, dst, protocol, bytes) != 0
        {
            return None;
        }
        let IpAddr::V6(source) = src else {
            return None;
        };
        if source != GUEST_IPV6
            && source.segments()[0] & 0xffc0 != 0xfe80
            && !source.is_unspecified()
        {
            return None;
        }
        let target = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?);
        if (bytes[0] == 135 && target != GATEWAY_IPV6 && target != GUEST_IPV6)
            || (bytes[0] == 136 && target != GUEST_IPV6)
        {
            return None;
        }
        // Every supplied link-layer option must agree with the NIC identity.
        let mut at = 24;
        while at < bytes.len() {
            if at + 2 > bytes.len() || bytes[at + 1] == 0 {
                return None;
            }
            let size = usize::from(bytes[at + 1]) * 8;
            if at + size > bytes.len() {
                return None;
            }
            if matches!(bytes[at], 1 | 2) && (size != 8 || bytes[at + 2..at + 8] != link.guest_mac)
            {
                return None;
            }
            at += size;
        }
        return Some(Packet::Control);
    }
    if bytes.len() < 8 || !matches!(protocol, 6 | 17) {
        return None;
    }
    let src_port = word(bytes, 0);
    let dst_port = word(bytes, 2);
    if src_port == 0 || dst_port == 0 {
        return None;
    }
    if protocol == 17 {
        if usize::from(word(bytes, 4)) != bytes.len() {
            return None;
        }
        // IPv4 UDP may legally omit its checksum. IPv6 UDP may not.
        if src.is_ipv6() && word(bytes, 6) == 0 {
            return None;
        }
        if !(src.is_ipv4() && word(bytes, 6) == 0) && transport_checksum(src, dst, 17, bytes) != 0 {
            return None;
        }
        if src_port == 68
            && dst_port == 67
            && src.is_ipv4()
            && (src == IpAddr::V4(Ipv4Addr::UNSPECIFIED) || src == IpAddr::V4(GUEST_IPV4))
            && (dst == IpAddr::V4(Ipv4Addr::BROADCAST) || dst == IpAddr::V4(GATEWAY_IPV4))
        {
            return Some(Packet::Dhcp {
                payload: offset + 8,
            });
        }
    } else if bytes.len() < 20
        || bytes[12] & 0x0e != 0
        || (bytes[13] & 2 != 0 && bytes[13] & (1 | 4) != 0)
        || usize::from(bytes[12] >> 4) * 4 < 20
        || usize::from(bytes[12] >> 4) * 4 > bytes.len()
        || transport_checksum(src, dst, 6, bytes) != 0
    {
        return None;
    }
    if (src != IpAddr::V4(GUEST_IPV4) && src != IpAddr::V6(GUEST_IPV6)) || frame[..6] != GATEWAY_MAC
    {
        return None;
    }
    let key = FlowKey {
        guest: SocketAddr::new(src, src_port),
        remote: SocketAddr::new(dst, dst_port),
    };
    if protocol == 6 {
        Some(Packet::Tcp {
            key,
            syn: bytes[13] & 0x12 == 2,
        })
    } else {
        Some(Packet::Udp {
            key,
            payload: offset + 8,
        })
    }
}

/// A response is synthesized only from an already-authorized connected UDP
/// socket. Never reflect arbitrary guest-supplied IP headers or Ethernet data.
pub fn udp_reply(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    broadcast: bool,
    link: &LinkIdentity,
) -> Option<Vec<u8>> {
    let header = if source.is_ipv4() && destination.is_ipv4() {
        20
    } else if source.is_ipv6() && destination.is_ipv6() {
        40
    } else {
        return None;
    };
    if header + 8 + payload.len() > crate::MTU {
        return None;
    }
    let mut frame = vec![0; 14 + header + 8 + payload.len()];
    frame[..6].copy_from_slice(if broadcast {
        &[255; 6]
    } else {
        &link.guest_mac
    });
    frame[6..12].copy_from_slice(&GATEWAY_MAC);
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&((header + 8 + payload.len()) as u16).to_be_bytes());
            frame[22] = 64;
            frame[23] = 17;
            frame[26..30].copy_from_slice(&src.octets());
            frame[30..34].copy_from_slice(&dst.octets());
            let check = checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&check.to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
            frame[14] = 0x60;
            frame[18..20].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            frame[20] = 17;
            frame[21] = 64;
            frame[22..38].copy_from_slice(&src.octets());
            frame[38..54].copy_from_slice(&dst.octets());
        }
        _ => return None,
    }
    let at = 14 + header;
    frame[at..at + 2].copy_from_slice(&source.port().to_be_bytes());
    frame[at + 2..at + 4].copy_from_slice(&destination.port().to_be_bytes());
    frame[at + 4..at + 6].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    frame[at + 8..].copy_from_slice(payload);
    let check = transport_checksum(source.ip(), destination.ip(), 17, &frame[at..]);
    frame[at + 6..at + 8].copy_from_slice(&if check == 0 { 65535 } else { check }.to_be_bytes());
    Some(frame)
}

/// One fixed machine lease. DHCP changes no external network authority.
pub fn dhcp_reply(query: &[u8], link: &LinkIdentity) -> Option<Vec<u8>> {
    if query.len() < 240
        || query.len() > 1024
        || query[..3] != [1, 1, 6]
        || query[28..34] != link.guest_mac
        || query[236..240] != [99, 130, 83, 99]
    {
        return None;
    }
    let mut message = None;
    let mut at = 240;
    while at < query.len() {
        let code = query[at];
        at += 1;
        if code == 255 {
            break;
        }
        if code == 0 {
            continue;
        }
        if at >= query.len() {
            return None;
        }
        let len = usize::from(query[at]);
        at += 1;
        if at + len > query.len() {
            return None;
        }
        if code == 53 {
            if len != 1 || message.is_some() {
                return None;
            }
            message = Some(query[at]);
        }
        if code == 54 && (len != 4 || query[at..at + len] != GATEWAY_IPV4.octets()) {
            return None;
        }
        if code == 50 && (len != 4 || query[at..at + len] != GUEST_IPV4.octets()) {
            return None;
        }
        at += len;
    }
    let response = match message? {
        1 => 2,
        3 => 5,
        _ => return None,
    };
    let mut bytes = vec![0; 240];
    bytes[..3].copy_from_slice(&[2, 1, 6]);
    bytes[4..8].copy_from_slice(&query[4..8]);
    bytes[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
    bytes[16..20].copy_from_slice(&GUEST_IPV4.octets());
    bytes[20..24].copy_from_slice(&GATEWAY_IPV4.octets());
    bytes[28..34].copy_from_slice(&link.guest_mac);
    bytes[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bytes.extend_from_slice(&[53, 1, response, 54, 4]);
    bytes.extend_from_slice(&GATEWAY_IPV4.octets());
    bytes.extend_from_slice(&[1, 4, 255, 255, 255, 252, 3, 4]);
    bytes.extend_from_slice(&GATEWAY_IPV4.octets());
    bytes.extend_from_slice(&[51, 4, 0, 0, 14, 16, 26, 2, 5, 220, 255]);
    // Resolver selection is ordinary guest OS state. UDP/TCP to a selected
    // external resolver must be explicitly allowed, like every other service.
    udp_reply(
        SocketAddr::new(GATEWAY_IPV4.into(), 67),
        SocketAddr::new(Ipv4Addr::BROADCAST.into(), 68),
        &bytes,
        true,
        link,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_LINK: LinkIdentity = LinkIdentity {
        guest_mac: [2, 0, 0, 0, 0, 2],
    };
    const GUEST_MAC: [u8; 6] = TEST_LINK.guest_mac;
    #[test]
    fn host_selected_mac_is_used_for_replies_and_spoof_fencing() {
        let link = LinkIdentity::for_machine(&"fork-machine".try_into().unwrap());
        let mut frame = udp_reply(
            SocketAddr::new(GUEST_IPV4.into(), 50000),
            "1.1.1.1:53".parse().unwrap(),
            b"query",
            false,
            &link,
        )
        .unwrap();
        assert_eq!(&frame[..6], &link.guest_mac);
        frame[..6].copy_from_slice(&GATEWAY_MAC);
        frame[6..12].copy_from_slice(&link.guest_mac);
        assert!(matches!(parse(&frame, &link), Some(Packet::Udp { .. })));
        assert!(parse(&frame, &TEST_LINK).is_none());
    }
    #[test]
    fn bounded_arbitrary_frames_never_panic() {
        let mut state = 31_u32;
        for len in 0..=MAX_FRAME + 1 {
            let mut bytes = vec![0; len];
            for b in &mut bytes {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                *b = (state >> 24) as u8;
            }
            let _ = parse(&bytes, &TEST_LINK);
        }
    }
    #[test]
    fn fragments_vlan_and_spoofing_are_rejected() {
        let mut frame = udp_reply(
            "1.1.1.1:53".parse().unwrap(),
            SocketAddr::new(GUEST_IPV4.into(), 50000),
            b"query",
            false,
            &TEST_LINK,
        )
        .unwrap();
        frame[..6].copy_from_slice(&GATEWAY_MAC);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        assert!(parse(&frame, &TEST_LINK).is_none()); // Source IP is forged.
        let mut frame = udp_reply(
            SocketAddr::new(GUEST_IPV4.into(), 50000),
            "1.1.1.1:53".parse().unwrap(),
            b"query",
            false,
            &TEST_LINK,
        )
        .unwrap();
        frame[..6].copy_from_slice(&GATEWAY_MAC);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        assert!(matches!(
            parse(&frame, &TEST_LINK),
            Some(Packet::Udp { .. })
        ));
        frame[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        assert!(parse(&frame, &TEST_LINK).is_none());
        for flags in [0x2000_u16, 1, 0x8000, 0x4000] {
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[20..22].copy_from_slice(&flags.to_be_bytes());
            frame[24..26].fill(0);
            let check = checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&check.to_be_bytes());
            assert_eq!(parse(&frame, &TEST_LINK).is_some(), flags == 0x4000);
        }
    }
    #[test]
    fn udp_v4_and_v6_checksums_validate_and_corruption_drops() {
        for (guest, remote) in [
            (GUEST_IPV4.to_string(), "1.1.1.1".to_owned()),
            (GUEST_IPV6.to_string(), "2606:4700:4700::1111".to_owned()),
        ] {
            let a = SocketAddr::new(guest.parse().unwrap(), 50000);
            let b = SocketAddr::new(remote.parse().unwrap(), 53);
            let mut frame = udp_reply(a, b, b"datagram", false, &TEST_LINK).unwrap();
            frame[..6].copy_from_slice(&GATEWAY_MAC);
            frame[6..12].copy_from_slice(&GUEST_MAC);
            assert!(matches!(
                parse(&frame, &TEST_LINK),
                Some(Packet::Udp { .. })
            ));
            *frame.last_mut().unwrap() ^= 1;
            assert!(parse(&frame, &TEST_LINK).is_none());
        }
    }

    #[test]
    fn arp_reply_supports_native_inbound_neighbor_discovery_without_spoofing() {
        let mut frame = vec![0; 42];
        frame[..6].copy_from_slice(&GATEWAY_MAC);
        frame[6..12].copy_from_slice(&GUEST_MAC);
        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[18..20].copy_from_slice(&[6, 4]);
        frame[20..22].copy_from_slice(&2_u16.to_be_bytes());
        frame[22..28].copy_from_slice(&GUEST_MAC);
        frame[28..32].copy_from_slice(&GUEST_IPV4.octets());
        frame[32..38].copy_from_slice(&GATEWAY_MAC);
        frame[38..42].copy_from_slice(&GATEWAY_IPV4.octets());
        assert_eq!(parse(&frame, &TEST_LINK), Some(Packet::Control));
        frame[31] ^= 1;
        assert_eq!(parse(&frame, &TEST_LINK), None);
    }

    #[test]
    fn virtio_partial_checksum_is_normalized_and_bad_metadata_drops() {
        for (guest, remote, offset) in [
            (IpAddr::V4(GUEST_IPV4), "1.1.1.1".parse().unwrap(), 34),
            (
                IpAddr::V6(GUEST_IPV6),
                "2606:4700:4700::1111".parse().unwrap(),
                54,
            ),
        ] {
            let mut frame = udp_reply(
                SocketAddr::new(guest, 50000),
                SocketAddr::new(remote, 53),
                b"checksum",
                false,
                &TEST_LINK,
            )
            .unwrap();
            frame[..6].copy_from_slice(&GATEWAY_MAC);
            frame[6..12].copy_from_slice(&GUEST_MAC);
            frame[offset + 6..offset + 8].fill(0);
            let mut bytes = vec![0; 10];
            bytes[0] = 1;
            bytes[6..8].copy_from_slice(&(offset as u16).to_le_bytes());
            bytes[8..10].copy_from_slice(&6_u16.to_le_bytes());
            bytes.extend_from_slice(&frame);
            let normalized = normalize_offload(&bytes);
            assert_eq!(normalized.len(), 1);
            assert!(matches!(
                parse(&normalized[0], &TEST_LINK),
                Some(Packet::Udp { .. })
            ));
            bytes[8] = 5;
            assert!(normalize_offload(&bytes).is_empty());
            if guest.is_ipv6() {
                assert!(parse(&frame, &TEST_LINK).is_none());
            }
        }
    }

    #[test]
    fn tcp_gso_reconstructs_bounded_checksummed_segments_for_both_families() {
        for (guest, remote, offset, gso) in [
            (IpAddr::V4(GUEST_IPV4), "1.1.1.1".parse().unwrap(), 34, 1),
            (
                IpAddr::V6(GUEST_IPV6),
                "2606:4700:4700::1111".parse().unwrap(),
                54,
                4,
            ),
        ] {
            let header = offset + 20;
            let mut frame = udp_reply(
                SocketAddr::new(guest, 50000),
                SocketAddr::new(remote, 443),
                &[],
                false,
                &TEST_LINK,
            )
            .unwrap();
            frame[..6].copy_from_slice(&GATEWAY_MAC);
            frame[6..12].copy_from_slice(&GUEST_MAC);
            frame.resize(header + 4096, 0x5a);
            frame[offset..header].fill(0);
            frame[offset..offset + 2].copy_from_slice(&50000_u16.to_be_bytes());
            frame[offset + 2..offset + 4].copy_from_slice(&443_u16.to_be_bytes());
            frame[offset + 4..offset + 8].copy_from_slice(&0xffff_ff00_u32.to_be_bytes());
            frame[offset + 12] = 0x50;
            frame[offset + 13] = 0x99; // ACK, CWR, PSH, FIN
            frame[offset + 14..offset + 16].copy_from_slice(&32768_u16.to_be_bytes());
            let length = frame.len();
            if guest.is_ipv4() {
                frame[16..18].copy_from_slice(&((length - 14) as u16).to_be_bytes());
                frame[23] = 6;
                frame[24..26].fill(0);
                let check = checksum(&frame[14..34]);
                frame[24..26].copy_from_slice(&check.to_be_bytes());
            } else {
                frame[18..20].copy_from_slice(&((length - 54) as u16).to_be_bytes());
                frame[20] = 6;
            }
            let mut bytes = vec![1, gso, 0, 0, 0, 0, 0, 0, 0, 0];
            bytes[2..4].copy_from_slice(&(header as u16).to_le_bytes());
            bytes[4..6].copy_from_slice(&1000_u16.to_le_bytes());
            bytes[6..8].copy_from_slice(&(offset as u16).to_le_bytes());
            bytes[8..10].copy_from_slice(&16_u16.to_le_bytes());
            bytes.extend_from_slice(&frame);
            let segments = normalize_offload(&bytes);
            assert_eq!(segments.len(), 5);
            for (index, segment) in segments.iter().enumerate() {
                assert!(segment.len() <= MAX_FRAME);
                assert!(matches!(
                    parse(segment, &TEST_LINK),
                    Some(Packet::Tcp { .. })
                ));
                assert_eq!(
                    u32::from_be_bytes(segment[offset + 4..offset + 8].try_into().unwrap()),
                    0xffff_ff00_u32.wrapping_add((index * 1000) as u32)
                );
                assert_eq!(segment[offset + 13] & 9, if index == 4 { 9 } else { 0 });
                assert_eq!(segment[offset + 13] & 128, if index == 0 { 128 } else { 0 });
            }
            assert_eq!(
                segments.iter().map(|p| p.len() - header).sum::<usize>(),
                4096
            );
            bytes[1] = 3; // UDP GSO is never an unrestricted fallback.
            assert!(normalize_offload(&bytes).is_empty());
            bytes[1] = gso;
            bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
            assert!(normalize_offload(&bytes).is_empty()); // bounded segment count
        }
    }
}
