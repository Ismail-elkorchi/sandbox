#![deny(unsafe_code)]

//! Host-enforced network policy values shared by the Sandsurf gateways.
//!
//! This crate deliberately contains no prepared-process, backend-selection, or
//! host-filesystem policy. A Sandbox configuration is the authority boundary;
//! these values are only the normalized destination rules installed by its
//! guardian.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

const MAX_RULES: usize = 4096;
const MAX_PORTS_PER_RULE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedNetworkRule {
    pub transport: String,
    pub destination: ManagedNetworkDestination,
    pub ports: Vec<ManagedNetworkPort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ManagedNetworkDestination {
    Dns {
        name: String,
        #[serde(default)]
        include_subdomains: bool,
        #[serde(default)]
        allow_private_addresses: bool,
    },
    Ip {
        cidr: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManagedNetworkPort {
    Single(u16),
    Range { from: u16, to: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicyError(&'static str);

impl Display for NetworkPolicyError {
    fn fmt(&self, output: &mut Formatter<'_>) -> std::fmt::Result {
        output.write_str(self.0)
    }
}

impl std::error::Error for NetworkPolicyError {}

/// Validate and canonicalize a complete gateway rule set before installation.
pub fn normalize_managed_network_rules(
    rules: &[ManagedNetworkRule],
) -> Result<Vec<ManagedNetworkRule>, NetworkPolicyError> {
    if rules.len() > MAX_RULES {
        return Err(NetworkPolicyError("network policy exceeds its rule bound"));
    }
    let mut normalized = Vec::with_capacity(rules.len());
    for rule in rules {
        if rule.transport != "tcp" || rule.ports.is_empty() || rule.ports.len() > MAX_PORTS_PER_RULE
        {
            return Err(NetworkPolicyError(
                "network rule transport or port set is invalid",
            ));
        }
        let ports = rule
            .ports
            .iter()
            .map(|port| match port {
                ManagedNetworkPort::Single(0) => {
                    Err(NetworkPolicyError("network port zero is invalid"))
                }
                ManagedNetworkPort::Single(value) => Ok(ManagedNetworkPort::Single(*value)),
                ManagedNetworkPort::Range { from, to } if *from == 0 || from > to => {
                    Err(NetworkPolicyError("network port range is invalid"))
                }
                ManagedNetworkPort::Range { from, to } => Ok(ManagedNetworkPort::Range {
                    from: *from,
                    to: *to,
                }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let destination = match &rule.destination {
            ManagedNetworkDestination::Dns {
                name,
                include_subdomains,
                allow_private_addresses,
            } => ManagedNetworkDestination::Dns {
                name: normalize_dns_name(name)?,
                include_subdomains: *include_subdomains,
                allow_private_addresses: *allow_private_addresses,
            },
            ManagedNetworkDestination::Ip { cidr } => ManagedNetworkDestination::Ip {
                cidr: normalize_cidr(cidr)?,
            },
        };
        normalized.push(ManagedNetworkRule {
            transport: "tcp".into(),
            destination,
            ports,
        });
    }
    normalized.sort_by(|left, right| {
        serde_json::to_vec(left)
            .unwrap_or_default()
            .cmp(&serde_json::to_vec(right).unwrap_or_default())
    });
    normalized.dedup();
    Ok(normalized)
}

pub fn normalize_dns_name(value: &str) -> Result<String, NetworkPolicyError> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.contains('*') {
        return Err(NetworkPolicyError(
            "DNS name must be an explicit name without wildcards",
        ));
    }
    let value = idna::domain_to_ascii_strict(value)
        .map_err(|_| NetworkPolicyError("DNS name is not valid IDNA"))?
        .to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 {
        return Err(NetworkPolicyError("normalized DNS name exceeds its limit"));
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(NetworkPolicyError("DNS name contains an invalid label"));
    }
    Ok(value)
}

fn normalize_cidr(value: &str) -> Result<String, NetworkPolicyError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or(NetworkPolicyError("network CIDR is malformed"))?;
    if prefix.contains('/') {
        return Err(NetworkPolicyError("network CIDR is malformed"));
    }
    let address: IpAddr = address
        .parse()
        .map_err(|_| NetworkPolicyError("network CIDR address is invalid"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| NetworkPolicyError("network CIDR prefix is invalid"))?;
    if prefix > if address.is_ipv4() { 32 } else { 128 } {
        return Err(NetworkPolicyError("network CIDR prefix exceeds its width"));
    }
    Ok(format!("{address}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_dns_names_have_one_canonical_idna_form() {
        assert_eq!(normalize_dns_name("Example.COM.").unwrap(), "example.com");
        assert_eq!(
            normalize_dns_name("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        for invalid in [
            "*.example.com",
            ".example.com",
            "example.com..",
            "-bad.example",
        ] {
            assert!(normalize_dns_name(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn rules_are_bounded_normalized_and_deduplicated() {
        let rule = ManagedNetworkRule {
            transport: "tcp".into(),
            destination: ManagedNetworkDestination::Dns {
                name: "Example.COM.".into(),
                include_subdomains: true,
                allow_private_addresses: false,
            },
            ports: vec![ManagedNetworkPort::Range { from: 80, to: 443 }],
        };
        let normalized = normalize_managed_network_rules(&[rule.clone(), rule]).unwrap();
        assert_eq!(normalized.len(), 1);
        assert!(matches!(
            &normalized[0].destination,
            ManagedNetworkDestination::Dns { name, .. } if name == "example.com"
        ));
    }

    #[test]
    fn managed_dns_wire_fields_use_camel_case() {
        let destination: ManagedNetworkDestination = serde_json::from_value(serde_json::json!({
            "kind": "dns",
            "name": "localhost",
            "includeSubdomains": true,
            "allowPrivateAddresses": true
        }))
        .unwrap();
        let encoded = serde_json::to_value(destination).unwrap();
        assert_eq!(encoded["includeSubdomains"], true);
        assert_eq!(encoded["allowPrivateAddresses"], true);
    }
}
