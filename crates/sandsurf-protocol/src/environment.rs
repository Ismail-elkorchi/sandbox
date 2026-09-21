use crate::{Counter, Digest, ExposureId, GrantId, Invalid, ProcessId, SandboxId, SecretId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPlane {
    NamedProxy,
    DirectTcp,
    Dns,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NetworkDestination {
    Dns {
        name: String,
        include_subdomains: bool,
        allow_private_addresses: bool,
    },
    Ip {
        cidr: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkRule {
    pub plane: NetworkPlane,
    pub destination: NetworkDestination,
    pub ports: Vec<PortRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPolicy {
    pub rules: Vec<NetworkRule>,
}

impl NetworkPolicy {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.rules.len() > 4096 {
            return Err(Invalid("network policy exceeds 4096 rules"));
        }
        for rule in &self.rules {
            if rule.ports.is_empty() || rule.ports.len() > 4096 {
                return Err(Invalid("network rule port set is empty or oversized"));
            }
            if rule
                .ports
                .iter()
                .any(|range| range.from == 0 || range.from > range.to)
            {
                return Err(Invalid("network rule has an invalid port range"));
            }
            match (&rule.plane, &rule.destination) {
                (NetworkPlane::Dns, NetworkDestination::Dns { .. })
                | (NetworkPlane::NamedProxy, NetworkDestination::Dns { .. })
                | (NetworkPlane::DirectTcp, NetworkDestination::Ip { .. }) => {}
                _ => return Err(Invalid("network plane and destination do not match")),
            }
            match &rule.destination {
                NetworkDestination::Dns { name, .. } => {
                    if name.is_empty()
                        || name.len() > 253
                        || name.contains(['*', '\0'])
                        || name.starts_with('.')
                        || name.ends_with('.')
                    {
                        return Err(Invalid("network DNS destination is malformed"));
                    }
                }
                NetworkDestination::Ip { cidr } => {
                    let (address, prefix) = cidr
                        .split_once('/')
                        .ok_or(Invalid("network IP destination requires CIDR notation"))?;
                    let address: std::net::IpAddr = address
                        .parse()
                        .map_err(|_| Invalid("network CIDR address is malformed"))?;
                    let prefix: u8 = prefix
                        .parse()
                        .map_err(|_| Invalid("network CIDR prefix is malformed"))?;
                    if prefix > if address.is_ipv4() { 32 } else { 128 } {
                        return Err(Invalid("network CIDR prefix is out of range"));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExposureSpec {
    pub guest_address: String,
    pub guest_port: u16,
    pub host_address: String,
    pub host_port: u16,
    pub public: bool,
}

impl ExposureSpec {
    pub fn validate(&self) -> Result<(), Invalid> {
        let guest: std::net::IpAddr = self
            .guest_address
            .parse()
            .map_err(|_| Invalid("guest exposure address is malformed"))?;
        let host: std::net::IpAddr = self
            .host_address
            .parse()
            .map_err(|_| Invalid("host exposure address is malformed"))?;
        if self.guest_port == 0
            || !guest.is_loopback()
            || (!self.public && !host.is_loopback())
            || host.is_unspecified()
        {
            return Err(Invalid("exposure endpoint is outside its authorized scope"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Exposure {
    pub id: ExposureId,
    pub sandbox_id: SandboxId,
    pub grant_id: GrantId,
    pub revision: Counter,
    pub spec: ExposureSpec,
    pub active: bool,
    pub bound_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretLifetime {
    Process,
    Sandbox,
    UntilRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SecretDestination {
    File { path: crate::GuestPath, mode: u32 },
    Environment { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretVersion {
    pub id: SecretId,
    pub version: Digest,
    pub bytes: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretDelivery {
    pub secret: SecretVersion,
    pub destination: SecretDestination,
    pub lifetime: SecretLifetime,
    pub process_id: Option<crate::ProcessId>,
}

/// Exact guest-side enforcement established for one host-owned revocation.
/// Removing an installed binding is distinct from proving that no workload
/// copied the bytes while it held them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretRevocationEvidence {
    pub files_removed: Counter,
    pub environment_bindings_removed: Counter,
    pub recipients_terminated: Vec<ProcessId>,
    pub recipients_already_stopped: Vec<ProcessId>,
    pub residual_copies_possible: bool,
    pub enforcement_complete: bool,
}

impl SecretDelivery {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.secret.bytes == Counter::ZERO || self.secret.bytes.get() > 1024 * 1024 {
            return Err(Invalid("secret size is outside the delivery bound"));
        }
        match &self.destination {
            SecretDestination::File { mode, .. } if mode & !0o777 != 0 || mode & 0o077 != 0 => {
                Err(Invalid("secret file mode must be private"))
            }
            SecretDestination::Environment { name }
                if name.is_empty()
                    || name.len() > 4096
                    || name.contains(['=', '\0'])
                    || !name
                        .bytes()
                        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) =>
            {
                Err(Invalid("secret environment name is malformed"))
            }
            SecretDestination::Environment { .. } if self.process_id.is_none() => Err(Invalid(
                "environment secret delivery requires a process identity",
            )),
            _ if matches!(self.lifetime, SecretLifetime::Process) && self.process_id.is_none() => {
                Err(Invalid(
                    "process secret lifetime requires a process identity",
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveResourceLimits {
    pub workload_memory_bytes: Counter,
    pub workload_processes: Counter,
    /// CPU quota and period in microseconds; `None` means the boot envelope.
    pub cpu_max: Option<(Counter, Counter)>,
}

impl LiveResourceLimits {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.workload_memory_bytes == Counter::ZERO || self.workload_processes == Counter::ZERO {
            return Err(Invalid("live workload quotas must be positive"));
        }
        if self.cpu_max.is_some_and(|(quota, period)| {
            quota == Counter::ZERO || !(1_000..=1_000_000).contains(&period.get())
        }) {
            return Err(Invalid("live CPU quota is malformed"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfiguration {
    pub network: NetworkPolicy,
    pub exposures: Vec<Exposure>,
    pub resources: LiveResourceLimits,
}

impl Default for RuntimeConfiguration {
    fn default() -> Self {
        Self {
            network: NetworkPolicy { rules: Vec::new() },
            exposures: Vec::new(),
            resources: LiveResourceLimits {
                workload_memory_bytes: Counter::ONE,
                workload_processes: Counter::ONE,
                cpu_max: None,
            },
        }
    }
}

impl RuntimeConfiguration {
    pub fn validate(&self) -> Result<(), Invalid> {
        self.network.validate()?;
        self.resources.validate()?;
        if self.exposures.len() > 256 {
            return Err(Invalid("exposure count exceeds 256"));
        }
        for exposure in &self.exposures {
            exposure.spec.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceUsage {
    pub cpu_micros: Counter,
    pub memory_current: Counter,
    pub memory_peak: Counter,
    pub disk_logical_bytes: Counter,
    pub disk_allocated_bytes: Counter,
    pub io_read_bytes: Counter,
    pub io_write_bytes: Counter,
    pub output_retained_bytes: Counter,
    pub network_rx_bytes: Counter,
    pub network_tx_bytes: Counter,
    pub network_connections: Counter,
    pub processes_current: Counter,
    pub complete: bool,
    pub source: String,
    pub observed_unix_millis: Counter,
}
