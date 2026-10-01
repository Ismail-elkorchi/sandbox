use sandsurf_protocol::{NetworkDestination, NetworkPlane, NetworkPolicy};
use std::io;
use std::net::{IpAddr, SocketAddr};

/// Compiled authority. DNS resolution never creates authority for IP traffic.
#[derive(Clone, Default)]
pub struct PacketPolicy {
    rules: Vec<Rule>,
    host_addresses: Vec<IpAddr>,
}

#[derive(Clone)]
struct Rule {
    plane: NetworkPlane,
    address: IpAddr,
    prefix: u8,
    private: bool,
    ports: Vec<sandsurf_protocol::PortRange>,
}

impl PacketPolicy {
    pub fn compile(policy: &NetworkPolicy, host_addresses: Vec<IpAddr>) -> io::Result<Self> {
        let policy = policy
            .normalized()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut rules = Vec::with_capacity(policy.rules.len());
        for rule in &policy.rules {
            let NetworkDestination::Ip {
                cidr,
                allow_private_addresses,
            } = &rule.destination;
            let (ip, bits) = cidr
                .split_once('/')
                .ok_or_else(|| io::Error::other("invalid CIDR"))?;
            rules.push(Rule {
                plane: rule.plane,
                address: ip
                    .parse()
                    .map_err(|_| io::Error::other("invalid CIDR address"))?,
                prefix: bits
                    .parse()
                    .map_err(|_| io::Error::other("invalid CIDR prefix"))?,
                private: *allow_private_addresses,
                ports: rule.ports.clone(),
            });
        }
        Ok(Self {
            rules,
            host_addresses,
        })
    }

    pub fn allows(&self, plane: NetworkPlane, destination: SocketAddr) -> bool {
        let ip = destination.ip();
        if forbidden(ip) || self.host_addresses.contains(&ip) || destination.port() == 0 {
            return false;
        }
        self.rules.iter().any(|rule| {
            rule.plane == plane
                && (!private(ip) || rule.private)
                && contains(rule.address, rule.prefix, ip)
                && rule
                    .ports
                    .iter()
                    .any(|p| p.from <= destination.port() && destination.port() <= p.to)
        })
    }
}

fn contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) if prefix <= 32 => {
            prefix == 0 || (u32::from(a) ^ u32::from(b)) >> (32 - prefix) == 0
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if prefix <= 128 => {
            prefix == 0 || (u128::from(a) ^ u128::from(b)) >> (128 - prefix) == 0
        }
        _ => false,
    }
}

/// Always denied, even by a broad/private allow: host loopback, metadata,
/// multicast, translation aliases, reserved space, and every machine link.
fn forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            a == 0
                || a == 127
                || a >= 224
                || (a == 169 && b == 254)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || v.octets() == [168, 63, 129, 16]
                || v.octets()[..3] == [192, 0, 0]
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_unspecified() || v.is_loopback() || v.is_multicast()
                || (s[0] & 0xffc0 == 0xfe80) || s[0] == 0xfd00
                || (s[0] == 0xfd20 && s[1] == 0x00ce)
                || v.to_ipv4_mapped().is_some()
                || s[0] & 0xe000 != 0x2000 && s[0] & 0xfe00 != 0xfc00
                // Disallow transition mechanisms which may hide an IPv4 target.
                || s[0] == 0x2002 || (s[0] == 0x2001 && s[1] == 0)
        }
    }
}

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private(),
        IpAddr::V6(v) => v.segments()[0] & 0xfe00 == 0xfc00,
    }
}

#[cfg(unix)]
pub fn host_addresses() -> io::Result<Vec<IpAddr>> {
    let mut first = std::ptr::null_mut();
    // SAFETY: getifaddrs writes an owned list through a valid out pointer.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut result = Vec::new();
    let mut cursor = first;
    while !cursor.is_null() {
        // SAFETY: cursor belongs to the live getifaddrs list until freeifaddrs.
        let entry = unsafe { &*cursor };
        if !entry.ifa_addr.is_null() {
            // SAFETY: each non-null address has the family-specific native layout.
            unsafe {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let a = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                        result.push(IpAddr::V4(std::net::Ipv4Addr::from(
                            a.sin_addr.s_addr.to_ne_bytes(),
                        )));
                    }
                    libc::AF_INET6 => {
                        let a = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                        result.push(IpAddr::V6(std::net::Ipv6Addr::from(a.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: first is the exact allocation returned by successful getifaddrs.
    unsafe { libc::freeifaddrs(first) };
    result.sort();
    result.dedup();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::{NetworkRule, PortRange};
    #[test]
    fn deny_is_intrinsic_and_private_is_explicit() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                plane: NetworkPlane::Tcp,
                destination: NetworkDestination::Ip {
                    cidr: "0.0.0.0/0".into(),
                    allow_private_addresses: false,
                },
                ports: vec![PortRange { from: 443, to: 443 }],
            }],
        };
        let p = PacketPolicy::compile(&policy, vec!["8.8.8.8".parse().unwrap()]).unwrap();
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.3",
            "10.0.0.1",
            "8.8.8.8",
            "224.0.0.1",
        ] {
            assert!(!p.allows(NetworkPlane::Tcp, format!("{ip}:443").parse().unwrap()));
        }
        assert!(p.allows(NetworkPlane::Tcp, "1.1.1.1:443".parse().unwrap()));
        assert!(!p.allows(NetworkPlane::Udp, "1.1.1.1:443".parse().unwrap()));
        assert!(!p.allows(NetworkPlane::Tcp, "1.1.1.1:80".parse().unwrap()));
    }
    #[test]
    fn cidr_canonicalization_is_idempotent_for_every_prefix() {
        for (ip, width) in [("192.168.27.99", 32), ("2001:db8:1:2:3:4:5:6", 128)] {
            for prefix in 0..=width {
                let policy = NetworkPolicy {
                    rules: vec![NetworkRule {
                        plane: NetworkPlane::Tcp,
                        destination: NetworkDestination::Ip {
                            cidr: format!("{ip}/{prefix}"),
                            allow_private_addresses: false,
                        },
                        ports: vec![PortRange { from: 1, to: 65535 }],
                    }],
                };
                let normalized = policy.normalized().unwrap();
                assert_eq!(normalized.normalized().unwrap(), normalized);
            }
        }
    }
    #[test]
    fn ipv6_translation_and_machine_aliases_are_denied() {
        for ip in [
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
            "2001::1",
            "fd00::2",
            "fe80::1",
            "::1",
        ] {
            assert!(forbidden(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn explicit_private_authority_never_grants_host_or_machine_links() {
        let policy = NetworkPolicy {
            rules: ["0.0.0.0/0", "::/0"]
                .map(|cidr| NetworkRule {
                    plane: NetworkPlane::Udp,
                    destination: NetworkDestination::Ip {
                        cidr: cidr.into(),
                        allow_private_addresses: true,
                    },
                    ports: vec![PortRange { from: 53, to: 53 }],
                })
                .into(),
        };
        let p = PacketPolicy::compile(
            &policy,
            vec!["10.0.0.2".parse().unwrap(), "fc01::2".parse().unwrap()],
        )
        .unwrap();
        for ip in ["10.0.0.1", "fc01::1"] {
            assert!(p.allows(NetworkPlane::Udp, SocketAddr::new(ip.parse().unwrap(), 53)));
        }
        for ip in [
            "10.0.0.2",
            "fc01::2",
            "fd00::2",
            "fd20:ce::254",
            "168.63.129.16",
            "100.100.100.200",
            "127.0.0.1",
        ] {
            assert!(
                !p.allows(NetworkPlane::Udp, SocketAddr::new(ip.parse().unwrap(), 53)),
                "{ip}"
            );
        }
    }

    #[test]
    fn normalization_preserves_port_membership_and_deduplicates_equivalent_cidrs() {
        let ports = vec![
            PortRange { from: 82, to: 82 },
            PortRange { from: 80, to: 81 },
            PortRange { from: 443, to: 443 },
        ];
        let policy = NetworkPolicy {
            rules: ["10.1.2.3/8", "10.9.8.7/8"]
                .map(|cidr| NetworkRule {
                    plane: NetworkPlane::Tcp,
                    destination: NetworkDestination::Ip {
                        cidr: cidr.into(),
                        allow_private_addresses: true,
                    },
                    ports: ports.clone(),
                })
                .into(),
        };
        let normalized = policy.normalized().unwrap();
        assert_eq!(normalized.rules.len(), 1);
        let p = PacketPolicy::compile(&normalized, Vec::new()).unwrap();
        for port in 1..=65535 {
            assert_eq!(
                p.allows(
                    NetworkPlane::Tcp,
                    SocketAddr::new("10.10.20.30".parse().unwrap(), port)
                ),
                ports
                    .iter()
                    .any(|range| range.from <= port && port <= range.to)
            );
        }
    }
}
