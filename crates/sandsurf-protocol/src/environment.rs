use crate::{
    Counter, ExecutionId, ExposureId, Invalid, MachineId, Resources, SecretId, SecretVersionId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Linux execution preferences. Creation accepts overrides of immutable image
/// defaults; the host catalog stores the resulting complete machine preferences.
/// Guest defaults are OS preferences, not a compartment or host authority.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionDefaults {
    pub environment: BTreeMap<String, String>,
    pub user: Option<String>,
    pub working_directory: Option<String>,
}

/// Explicit host-owned absolute expiration. An empty SDK execution inventory
/// says nothing about arbitrary Linux services and never implies idleness.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineLifetime {
    pub expires_at_unix_millis: Option<Counter>,
    pub expiration_action: ExpirationAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpirationAction {
    #[default]
    Stop,
    Destroy,
}

impl MachineLifetime {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self
            .expires_at_unix_millis
            .is_some_and(|value| value == Counter::ZERO)
        {
            return Err(Invalid("absolute Machine expiration must be positive"));
        }
        Ok(())
    }
}

impl ExecutionDefaults {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.environment.len() > 4096 {
            return Err(Invalid("workload environment exceeds 4096 entries"));
        }
        if self.environment.iter().any(|(name, value)| {
            name.is_empty()
                || name.len() > 512
                || name.contains(['\0', '='])
                || value.len() > 64 * 1024
                || value.contains('\0')
        }) {
            return Err(Invalid("workload environment is malformed"));
        }
        if self
            .user
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 256 || value.contains('\0'))
        {
            return Err(Invalid("workload user is malformed"));
        }
        if self.working_directory.as_ref().is_some_and(|value| {
            value.len() > 4096 || !value.starts_with('/') || value.contains('\0')
        }) {
            return Err(Invalid("workload working directory is malformed"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPlane {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NetworkDestination {
    Ip {
        cidr: String,
        allow_private_addresses: bool,
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
    /// Canonicalize CIDRs, merge port ranges, and remove duplicate rules.
    /// Native traffic is authorized by address, never by a DNS observation.
    pub fn normalized(&self) -> Result<Self, Invalid> {
        self.validate()?;
        let mut result = self.clone();
        for rule in &mut result.rules {
            let NetworkDestination::Ip { cidr, .. } = &mut rule.destination;
            let (address, prefix) = cidr.split_once('/').ok_or(Invalid("CIDR prefix missing"))?;
            let address: std::net::IpAddr = address
                .parse()
                .map_err(|_| Invalid("invalid CIDR address"))?;
            let prefix: u8 = prefix.parse().map_err(|_| Invalid("invalid CIDR prefix"))?;
            *cidr = match address {
                std::net::IpAddr::V4(ip) => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    };
                    format!(
                        "{}/{prefix}",
                        std::net::Ipv4Addr::from(u32::from(ip) & mask)
                    )
                }
                std::net::IpAddr::V6(ip) => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    format!(
                        "{}/{prefix}",
                        std::net::Ipv6Addr::from(u128::from(ip) & mask)
                    )
                }
            };
            rule.ports.sort_by_key(|p| (p.from, p.to));
            let mut merged: Vec<PortRange> = Vec::new();
            for port in &rule.ports {
                if let Some(last) = merged.last_mut()
                    && u32::from(port.from) <= u32::from(last.to) + 1
                {
                    last.to = last.to.max(port.to);
                } else {
                    merged.push(*port);
                }
            }
            rule.ports = merged;
        }
        result.rules.sort_by_cached_key(|rule| {
            serde_json::to_vec(rule).expect("network rule serialization")
        });
        result.rules.dedup();
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), Invalid> {
        if self.rules.len() > 4096 {
            return Err(Invalid("network policy exceeds 4096 rules"));
        }
        if self.rules.iter().map(|r| r.ports.len()).sum::<usize>() > 16384 {
            return Err(Invalid("network policy exceeds 16384 total port ranges"));
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
            match &rule.destination {
                NetworkDestination::Ip { cidr, .. } => {
                    let (address, prefix) = cidr
                        .split_once('/')
                        .ok_or(Invalid("network IP destination requires CIDR notation"))?;
                    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Invalid("network CIDR prefix is malformed"));
                    }
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
            || (guest
                != "100.64.0.2"
                    .parse::<std::net::IpAddr>()
                    .expect("constant NIC IP")
                && guest
                    != "fd00::2"
                        .parse::<std::net::IpAddr>()
                        .expect("constant NIC IP"))
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
    pub machine_id: MachineId,
    pub revision: Counter,
    pub spec: ExposureSpec,
    pub active: bool,
    pub bound_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretLifetime {
    Process,
    Machine,
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
    /// Opaque identity; neither a plaintext digest nor an erasure guarantee.
    pub version: SecretVersionId,
    pub bytes: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretDelivery {
    pub secret: SecretVersion,
    pub destination: SecretDestination,
    pub lifetime: SecretLifetime,
    pub execution_id: Option<crate::ExecutionId>,
}

/// Host-owned transport disclosure state, independent of any guest erasure report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretDisclosure {
    NotSent,
    Possible,
    GuestReportedReceived,
}

/// Cooperative guest observations; root can forge them and retain secret copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretCleanupReport {
    pub files_removed: Counter,
    pub environment_bindings_removed: Counter,
    pub recipients_terminated: Vec<ExecutionId>,
    pub recipients_already_stopped: Vec<ExecutionId>,
    pub residual_copies_possible: bool,
    pub actions_reported_complete: bool,
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
            SecretDestination::Environment { .. } if self.execution_id.is_none() => Err(Invalid(
                "environment secret delivery requires a process identity",
            )),
            _ if matches!(self.lifetime, SecretLifetime::Process)
                && self.execution_id.is_none() =>
            {
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
pub struct RuntimeConfiguration {
    pub network: NetworkPolicy,
    pub exposures: Vec<Exposure>,
    pub resources: Resources,
}

impl Default for RuntimeConfiguration {
    fn default() -> Self {
        Self {
            network: NetworkPolicy { rules: Vec::new() },
            exposures: Vec::new(),
            resources: Resources::from_geometry(
                Counter::ONE,
                Counter::try_from(128).expect("static memory bound"),
                Counter::try_from(64 * 1024 * 1024).expect("static disk bound"),
                Counter::ONE,
                Counter::ONE,
            )
            .expect("static resource envelope"),
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
    pub provenance: ResourceProvenance,
    /// Host process-unit lifetime, independent of guest reboot/generation.
    pub host_counter_epoch: Option<crate::Digest>,
    pub channels_current: Option<Counter>,
    pub inflight_requests_current: Option<Counter>,
    /// A complete externally observed aggregate only where the native
    /// mechanism establishes one. Separate ledgers below are not its sum.
    pub cpu_micros: Option<Counter>,
    pub cpu_ledgers: Option<CpuLedgers>,
    pub memory_current: Option<Counter>,
    pub memory_peak: Option<Counter>,
    /// Regular-file lengths in the host-owned machine tree, not guest free
    /// space or the virtual capacity of a dynamic disk.
    pub disk_logical_bytes: Counter,
    /// Native filesystem allocation attributed to files and directories.
    /// Shared/reflink extents may be attributed to more than one object; this
    /// observation is not an exclusive physical-space reservation.
    pub disk_allocated_bytes: Counter,
    pub io_read_bytes: Option<Counter>,
    pub io_write_bytes: Option<Counter>,
    pub output_retained_bytes: Counter,
    pub network_rx_bytes: Counter,
    pub network_tx_bytes: Counter,
    pub network_connections: Counter,
    /// Host-owned managed admission slots held, including admissions without
    /// a guest report. Native interruption frees slots, never retained bytes
    /// or unsettled capture headroom. Not the root-controlled Linux PID count.
    pub executions_current: Counter,
    pub complete: bool,
    pub source: String,
    pub observed_unix_millis: Counter,
}

impl ResourceUsage {
    /// Unsupported native measurements are absent, never manufactured zeroes.
    pub fn host_observation(source: &str, observed_unix_millis: Counter) -> Self {
        Self {
            provenance: ResourceProvenance::default(),
            host_counter_epoch: None,
            channels_current: None,
            inflight_requests_current: None,
            cpu_micros: None,
            cpu_ledgers: None,
            memory_current: None,
            memory_peak: None,
            io_read_bytes: None,
            io_write_bytes: None,
            disk_logical_bytes: Counter::ZERO,
            disk_allocated_bytes: Counter::ZERO,
            output_retained_bytes: Counter::ZERO,
            network_rx_bytes: Counter::ZERO,
            network_tx_bytes: Counter::ZERO,
            network_connections: Counter::ZERO,
            executions_current: Counter::ZERO,
            complete: false,
            source: source.to_owned(),
            observed_unix_millis,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MeasurementSource {
    #[default]
    Unavailable,
    HostCgroup,
    HostDarwinTask,
    HostJob,
    HostPartition,
    HostFilesystem,
    HostRetention,
    HostAdmission,
    HostNetwork,
    GuestReported,
}

/// Worker-lifetime observations fenced by host_counter_epoch, not cumulative
/// machine-lifetime totals. WHP reports total VP runtime and hypervisor runtime
/// separately; overlap with Job CPU has not been established. Neither ledger
/// is guest-reported, and adding them cannot prove unique total CPU.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CpuLedgers {
    pub native_micros: Option<Counter>,
    pub native_source: MeasurementSource,
    pub partition_micros: Option<Counter>,
    pub partition_hypervisor_micros: Option<Counter>,
    pub partition_source: MeasurementSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceProvenance {
    pub cpu: MeasurementSource,
    pub memory: MeasurementSource,
    pub io: MeasurementSource,
    pub storage: MeasurementSource,
    pub output: MeasurementSource,
    pub executions: MeasurementSource,
    pub channels: MeasurementSource,
    pub network: MeasurementSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceChangeMode {
    Live,
    RequiresReboot,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceChangeAssessment {
    pub mode: ResourceChangeMode,
    pub reasons: Vec<String>,
}
