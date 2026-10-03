//! Native Ethernet attachment and bounded, default-deny external enforcement.
//! There is no host bridge, kernel forwarding, NAT, or guest management relay.
#![deny(unsafe_op_in_unsafe_fn)]

mod gateway;
pub mod packet;
pub mod policy;
pub use gateway::{NativeNetworkGateway, PacketTransport};
mod stream;
pub use stream::PacketStream;
#[cfg(target_os = "linux")]
pub mod linux;

/// Enforcement implementation/installation, independently of VM qualification.
/// Address enumeration alone cannot establish a kernel local-delivery boundary.
pub fn egress_capability() -> sandsurf_protocol::Capability {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match sandsurf_native::network_sockets::probe() {
        Ok(()) => sandsurf_protocol::Capability::Supported {
            qualification: sandsurf_protocol::Qualification::Unqualified {
                reasons: vec!["the installed socket factory, routing/filter configuration, and real NIC require configuration-specific qualification".into()],
            },
        },
        Err(error) => sandsurf_protocol::Capability::Unsupported {
            reasons: vec![format!("native kernel socket boundary unavailable: {error}")],
        },
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    sandsurf_protocol::Capability::Unsupported {
        reasons: vec!["native kernel local-delivery enforcement is not implemented for this host; host-address observations alone are insufficient".into()],
    }
}

/// The host machine identity selects a stable locally administered NIC address.
/// Addresses are link identifiers, never substitutes for host authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkIdentity {
    pub guest_mac: [u8; 6],
}

impl LinkIdentity {
    pub fn for_machine(machine: &sandsurf_protocol::MachineId) -> Self {
        let digest = sandsurf_protocol::bytes_digest(machine.as_str().as_bytes());
        let mut guest_mac = [0; 6];
        for (index, byte) in guest_mac.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest.as_str()[index * 2..index * 2 + 2], 16)
                .expect("digest hex");
        }
        guest_mac[0] = (guest_mac[0] & 0xfc) | 2;
        Self { guest_mac }
    }
    pub fn mac_address(&self) -> String {
        self.guest_mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}
pub const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const GUEST_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 2);
pub const GATEWAY_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 1);
pub const GUEST_IPV6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
pub const GATEWAY_IPV6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
pub const MTU: usize = 1500;
pub const MAX_FLOWS: usize = 128;
pub const MAX_FRAME: usize = MTU + 14;

#[derive(Debug, Clone)]
pub struct NetworkViolation {
    pub destination: String,
    pub port: u16,
    pub rule_reason: String,
}

#[derive(Debug, Default)]
pub struct NetworkReport {
    pub connections: u64,
    pub violations: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub cleanup_failures: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkSnapshot {
    pub connections: u64,
    pub violations: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn machine_nic_is_stable_across_generations_and_distinct_for_forks() {
        let source: sandsurf_protocol::MachineId = "source-machine".try_into().unwrap();
        let fork: sandsurf_protocol::MachineId = "fork-machine".try_into().unwrap();
        let link = LinkIdentity::for_machine(&source);
        assert_eq!(link, LinkIdentity::for_machine(&source));
        assert_ne!(link, LinkIdentity::for_machine(&fork));
        assert_eq!(link.guest_mac[0] & 3, 2, "locally administered unicast");
    }
}
