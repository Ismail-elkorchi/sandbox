#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::path::{Component, Path};

#[cfg(target_os = "linux")]
pub const BACKEND_ID: &str = "linux-namespace-v1";
#[cfg(target_os = "windows")]
pub const BACKEND_ID: &str = "windows-appcontainer-v1";
#[cfg(target_os = "macos")]
pub const BACKEND_ID: &str = "darwin-seatbelt-v1";
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub const BACKEND_ID: &str = "unsupported-process-v1";
pub const BACKEND_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CONFORMANCE_MANIFEST_ID: &str = "linux-namespace-v1-conformance-1";
pub const BUILD_ID: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
pub const MAX_PREPARED_TTL_MS: u64 = 1_800_000;
pub const DEFAULT_PREPARED_TTL_MS: u64 = 300_000;

pub const GUARANTEES: &[&str] = &[
    "runtime.setup-before-exec",
    "runtime.no-ambient-environment",
    "runtime.no-ambient-handles",
    "runtime.executable-identity-bound",
    "filesystem.grant-roots-identity-bound",
    "filesystem.read-confined",
    "filesystem.content-write-confined",
    "filesystem.namespace-mutation-confined",
    "filesystem.metadata-mutation-confined",
    "filesystem.execution-confined",
    "filesystem.host-user-data-hidden",
    "network.no-external-connect",
    "network.no-external-listen",
    "network.no-host-loopback",
    "network.egress-brokered",
    "network.private-addresses-denied",
    "process.host-enumeration-denied",
    "process.host-control-denied",
    "process.complete-tree-termination",
    "ipc.host-endpoints-hidden-outside-grants",
    "ipc.host-shared-memory-hidden",
    "resource.wall-time-hard",
    "resource.output-hard",
    "resource.memory-hard",
    "resource.cpu-time-hard",
    "resource.process-count-hard",
    "resource.open-files-hard",
    "resource.single-file-size-hard",
    "vm.boot-artifacts-verified",
    "vm.guest-control-authenticated",
    "vm.control-plane-hidden-from-target",
    "vm.host-filesystem-absent-outside-imports",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareRunMessage {
    pub request_id: String,
    pub options: RunOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareSessionMessage {
    pub request_id: String,
    pub options: SessionOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareProcessMessage {
    pub request_id: String,
    pub session_id: String,
    pub process: ProcessOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRunMessage {
    pub request_id: String,
    pub id: String,
    pub policy_digest: String,
    pub execution_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivateSessionMessage {
    pub request_id: String,
    pub id: String,
    pub policy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartProcessMessage {
    pub request_id: String,
    pub id: String,
    pub policy_digest: String,
    pub execution_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdMessage {
    pub request_id: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminateMessage {
    pub request_id: String,
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunOptions {
    pub isolation: Isolation,
    pub policy: Policy,
    pub requirements: Requirements,
    #[serde(default)]
    pub resources: PartialResourceLimits,
    pub prepared_ttl_ms: Option<u64>,
    pub process: ProcessOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionOptions {
    pub isolation: Isolation,
    pub policy: Policy,
    pub requirements: Requirements,
    #[serde(default)]
    pub resources: PartialResourceLimits,
    pub prepared_ttl_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Isolation {
    Process,
    HardwareVm {
        image: ImageReference,
        #[serde(rename = "filesystemTransport")]
        filesystem_transport: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageReference {
    pub manifest_path: String,
    pub trust: String,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub process: ProcessPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemPolicy {
    pub runtime: RuntimeView,
    pub grants: Vec<FilesystemGrant>,
    #[serde(default)]
    pub masks: Vec<FilesystemMask>,
    pub private_home: Option<PrivateDirectoryPolicy>,
    pub temporary: Option<TemporaryDirectoryPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeView {
    System,
    Empty,
}

impl RuntimeView {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Empty => "empty",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemGrant {
    pub host_path: String,
    pub target_path: String,
    pub access: String,
    pub execution: Option<String>,
    pub root_resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemMask {
    pub target_path: String,
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateDirectoryPolicy {
    pub enabled: Option<bool>,
    pub size_bytes: Option<u64>,
    pub executable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemporaryDirectoryPolicy {
    pub size_bytes: Option<u64>,
    pub executable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NetworkPolicy {
    None,
    Managed { allow: Vec<ManagedNetworkRule> },
    Unrestricted { acknowledgement: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedNetworkRule {
    pub transport: String,
    pub destination: ManagedNetworkDestination,
    pub ports: Vec<ManagedNetworkPort>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManagedNetworkPort {
    Single(u16),
    Range { from: u16, to: u16 },
}

impl NetworkPolicy {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Managed { .. } => "managed",
            Self::Unrestricted { .. } => "unrestricted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessPolicy {
    pub host_processes: String,
    pub host_ipc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Requirements {
    pub boundary: String,
    pub required: Vec<String>,
    #[serde(default)]
    pub allow_experimental_backend: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartialResourceLimits {
    pub wall_time_ms: Option<u64>,
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u64>,
    pub max_open_files_per_process: Option<u64>,
    pub max_single_file_bytes: Option<u64>,
    pub max_output_bytes: Option<u64>,
    pub termination_grace_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceLimits {
    pub wall_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: u64,
    pub max_processes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_open_files_per_process: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_single_file_bytes: Option<u64>,
    pub max_output_bytes: u64,
    pub termination_grace_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessOptions {
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: String,
    pub environment: Option<Environment>,
    pub stdin: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub artifacts: Option<ArtifactRequest>,
    pub change_set: Option<WorkspaceChangeRequest>,
    #[serde(default)]
    pub resources: PartialResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRequest {
    pub paths: Vec<String>,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceChangeRequest {
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Environment {
    pub base: Option<String>,
    #[serde(default)]
    pub inherit: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, EnvironmentValue>,
    #[serde(default)]
    pub unset: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EnvironmentValue {
    Plain(String),
    Sensitive { value: String, sensitive: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedPolicy {
    pub isolation: Isolation,
    pub runtime_view: String,
    pub grants: Vec<NormalizedGrant>,
    pub masks: Vec<NormalizedMask>,
    pub private_home: NormalizedPrivateDirectory,
    pub temporary: NormalizedTemporaryDirectory,
    pub network: String,
    pub managed_network_rules: Vec<ManagedNetworkRule>,
    pub process: ProcessPolicy,
    pub resources: ResourceLimits,
    pub prepared_ttl_ms: u64,
    pub requirements: Requirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedGrant {
    pub requested_host_path: String,
    pub target_path: String,
    pub access: String,
    pub execution: String,
    pub root_resolution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedMask {
    pub target_path: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedPrivateDirectory {
    pub enabled: bool,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedTemporaryDirectory {
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedExecution {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub environment: BTreeMap<String, CapturedEnvironmentValue>,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<ArtifactRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_set: Option<WorkspaceChangeRequest>,
    pub resources: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedEnvironmentValue {
    pub value: String,
    pub sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeFact {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub enforced_by: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mechanism: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementCaveat {
    pub code: String,
    pub message: String,
    pub affected_guarantees: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementReport {
    pub boundary: EnforcementBoundary,
    pub host: EnforcementHost,
    pub target: EnforcementTarget,
    pub guarantees: Vec<GuaranteeFact>,
    pub runtime_view: EnforcementRuntimeView,
    pub caveats: Vec<EnforcementCaveat>,
    pub conformance: EnforcementConformance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementBoundary {
    pub kind: String,
    pub backend_id: String,
    pub backend_version: String,
    pub stability: String,
    pub mechanism: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementHost {
    pub platform: String,
    pub architecture: String,
    pub path_style: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementTarget {
    pub operating_system: String,
    pub path_style: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementRuntimeView {
    pub kind: String,
    pub manifest_digest: String,
    pub visible_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementConformance {
    pub manifest_id: String,
    pub build_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorData {
    pub code: String,
    pub message: String,
    pub phase: String,
    pub target_executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<EnforcementReport>,
}

impl ErrorData {
    #[must_use]
    pub fn new(code: &str, message: impl Into<String>, phase: &str) -> Self {
        Self {
            code: code.into(),
            message: sanitize_message(&message.into()),
            phase: phase.into(),
            target_executed: false,
            backend: Some(BACKEND_ID.into()),
            platform: Some(std::env::consts::OS.into()),
            cause_code: None,
            enforcement: None,
        }
    }
}

#[derive(Debug)]
pub struct PolicyError(pub Box<ErrorData>);

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.message)
    }
}

impl std::error::Error for PolicyError {}

pub fn normalize_session(
    options: SessionOptions,
    host_physical_memory: u64,
) -> Result<NormalizedPolicy, PolicyError> {
    let expected_boundary = match &options.isolation {
        Isolation::Process => "os-process",
        Isolation::HardwareVm {
            image,
            filesystem_transport,
        } => {
            if filesystem_transport != "ephemeral" && filesystem_transport != "import" {
                return Err(policy_error(
                    "policy.vm_filesystem_transport",
                    "hardware VM filesystem transport must be ephemeral or import",
                ));
            }
            if image.manifest_path.is_empty()
                || !Path::new(&image.manifest_path).is_absolute()
                || (image.trust != "bundled" && image.trust != "explicit-local")
                || image.digest.as_ref().is_some_and(|digest| {
                    digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                })
            {
                return Err(policy_error(
                    "policy.vm_image",
                    "hardware VM image reference is invalid",
                ));
            }
            "hardware-virtualized"
        }
    };
    if options.requirements.boundary != expected_boundary {
        return Err(policy_error(
            "requirement.boundary",
            format!("the requested boundary must be {expected_boundary}"),
        ));
    }
    validate_requirements(&options.requirements)?;
    if options.policy.process.host_processes != "deny" || options.policy.process.host_ipc != "deny"
    {
        return Err(policy_error(
            "policy.process",
            "host process and IPC policy must be deny",
        ));
    }
    let managed_network_rules = match &options.policy.network {
        NetworkPolicy::None => Vec::new(),
        NetworkPolicy::Managed { allow } => normalize_managed_rules(allow)?,
        NetworkPolicy::Unrestricted { acknowledgement } => {
            if acknowledgement != "network-is-not-restricted" {
                return Err(policy_error(
                    "policy.network",
                    "unrestricted networking requires the exact acknowledgement",
                ));
            }
            Vec::new()
        }
    };

    let resources = resolve_resources(&options.resources, host_physical_memory)?;
    let prepared_ttl_ms = options.prepared_ttl_ms.unwrap_or(DEFAULT_PREPARED_TTL_MS);
    if prepared_ttl_ms == 0 || prepared_ttl_ms > MAX_PREPARED_TTL_MS {
        return Err(policy_error(
            "policy.prepared_ttl",
            "preparedTtlMs must be between 1 and 1800000",
        ));
    }
    let private = options
        .policy
        .filesystem
        .private_home
        .unwrap_or(PrivateDirectoryPolicy {
            enabled: None,
            size_bytes: None,
            executable: None,
        });
    let private_home = NormalizedPrivateDirectory {
        enabled: private.enabled.unwrap_or(true),
        size_bytes: private.size_bytes.unwrap_or(268_435_456),
        executable: private.executable.unwrap_or(false),
    };
    let temporary = options
        .policy
        .filesystem
        .temporary
        .unwrap_or(TemporaryDirectoryPolicy {
            size_bytes: None,
            executable: None,
        });
    let temporary = NormalizedTemporaryDirectory {
        size_bytes: temporary.size_bytes.unwrap_or(536_870_912),
        executable: temporary.executable.unwrap_or(false),
    };
    if private_home.enabled && private_home.size_bytes == 0 || temporary.size_bytes == 0 {
        return Err(policy_error(
            "policy.private_directory",
            "private directory sizes must be positive",
        ));
    }

    let mut grants = Vec::with_capacity(options.policy.filesystem.grants.len());
    let mut target_paths = BTreeSet::new();
    for grant in options.policy.filesystem.grants {
        validate_absolute_host_path(&grant.host_path)?;
        let target_path = normalize_target_path(&grant.target_path)?;
        if reserved_target_conflict(&target_path) {
            return Err(policy_error(
                "policy.grant_reserved_target",
                format!("grant target {target_path} conflicts with a runtime-owned path"),
            ));
        }
        if !target_paths.insert(target_path.clone()) {
            return Err(policy_error(
                "policy.grant_conflict",
                "multiple grants map to the same target path",
            ));
        }
        if grant.access != "read" && grant.access != "read-write" {
            return Err(policy_error(
                "policy.grant_access",
                "grant access must be read or read-write",
            ));
        }
        let execution = grant.execution.unwrap_or_else(|| "deny".into());
        if execution != "deny" && execution != "allow" {
            return Err(policy_error(
                "policy.grant_execution",
                "grant execution must be deny or allow",
            ));
        }
        let root_resolution = grant
            .root_resolution
            .unwrap_or_else(|| "resolve-once".into());
        if root_resolution != "resolve-once" && root_resolution != "reject-if-link" {
            return Err(policy_error(
                "policy.grant_resolution",
                "unsupported grant root resolution",
            ));
        }
        grants.push(NormalizedGrant {
            requested_host_path: grant.host_path,
            target_path,
            access: grant.access,
            execution,
            root_resolution,
        });
    }
    grants.sort_by(|left, right| {
        left.target_path
            .as_bytes()
            .cmp(right.target_path.as_bytes())
    });
    for (index, parent) in grants.iter().enumerate() {
        if grants[index + 1..]
            .iter()
            .any(|child| paths_overlap(&parent.target_path, &child.target_path))
        {
            return Err(policy_error(
                "policy.grant_overlap",
                "grant targets must not contain one another",
            ));
        }
    }

    let mut masks = Vec::with_capacity(options.policy.filesystem.masks.len());
    let mut mask_paths = BTreeSet::new();
    for mask in options.policy.filesystem.masks {
        let target_path = normalize_target_path(&mask.target_path)?;
        if target_path == "/" || !mask_paths.insert(target_path.clone()) {
            return Err(policy_error(
                "policy.mask_conflict",
                "invalid or duplicate mask target",
            ));
        }
        let replacement = mask.replacement.unwrap_or_else(|| "inaccessible".into());
        if !matches!(
            replacement.as_str(),
            "inaccessible" | "empty-file" | "empty-directory"
        ) {
            return Err(policy_error(
                "policy.mask_replacement",
                "unsupported mask replacement",
            ));
        }
        masks.push(NormalizedMask {
            target_path,
            replacement,
        });
    }
    masks.sort_by(|left, right| {
        left.target_path
            .as_bytes()
            .cmp(right.target_path.as_bytes())
    });

    Ok(NormalizedPolicy {
        isolation: options.isolation,
        runtime_view: options.policy.filesystem.runtime.name().into(),
        grants,
        masks,
        private_home,
        temporary,
        network: options.policy.network.name().into(),
        managed_network_rules,
        process: options.policy.process,
        resources,
        prepared_ttl_ms,
        requirements: options.requirements,
    })
}

fn normalize_managed_rules(
    rules: &[ManagedNetworkRule],
) -> Result<Vec<ManagedNetworkRule>, PolicyError> {
    if rules.len() > 4096 {
        return Err(policy_error(
            "policy.network_rules",
            "managed network policy exceeds 4096 rules",
        ));
    }
    let mut normalized = Vec::with_capacity(rules.len());
    for rule in rules {
        if rule.transport != "tcp" || rule.ports.is_empty() || rule.ports.len() > 4096 {
            return Err(policy_error(
                "policy.network_rule",
                "managed rules require TCP and one to 4096 port entries",
            ));
        }
        for port in &rule.ports {
            match port {
                ManagedNetworkPort::Single(0) => {
                    return Err(policy_error("policy.network_port", "port zero is invalid"));
                }
                ManagedNetworkPort::Range { from, to } if *from == 0 || from > to => {
                    return Err(policy_error("policy.network_port", "port range is invalid"));
                }
                _ => {}
            }
        }
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
            ManagedNetworkDestination::Ip { cidr } => {
                let (address, prefix) = cidr.split_once('/').ok_or_else(|| {
                    policy_error("policy.network_cidr", "IP rules require CIDR notation")
                })?;
                let address: std::net::IpAddr = address
                    .parse()
                    .map_err(|_| policy_error("policy.network_cidr", "CIDR address is invalid"))?;
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| policy_error("policy.network_cidr", "CIDR prefix is invalid"))?;
                let maximum = if address.is_ipv4() { 32 } else { 128 };
                if prefix > maximum {
                    return Err(policy_error(
                        "policy.network_cidr",
                        "CIDR prefix exceeds its address width",
                    ));
                }
                ManagedNetworkDestination::Ip {
                    cidr: format!("{address}/{prefix}"),
                }
            }
        };
        normalized.push(ManagedNetworkRule {
            transport: "tcp".into(),
            destination,
            ports: rule.ports.clone(),
        });
    }
    normalized.sort_by_key(|rule| serde_json::to_vec(rule).unwrap_or_default());
    normalized
        .dedup_by(|left, right| serde_json::to_vec(left).ok() == serde_json::to_vec(right).ok());
    Ok(normalized)
}

pub fn normalize_dns_name(value: &str) -> Result<String, PolicyError> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.contains('*') {
        return Err(policy_error(
            "policy.network_dns",
            "DNS name must be an explicit name without wildcards",
        ));
    }
    let value = idna::domain_to_ascii_strict(value)
        .map_err(|_| policy_error("policy.network_dns", "DNS name is not valid IDNA"))?
        .to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 {
        return Err(policy_error(
            "policy.network_dns",
            "normalized DNS name exceeds the DNS length limit",
        ));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(policy_error(
                "policy.network_dns",
                "DNS name contains an invalid label",
            ));
        }
    }
    Ok(value)
}

pub fn normalize_run(
    options: RunOptions,
    host_physical_memory: u64,
) -> Result<(NormalizedPolicy, NormalizedExecution), PolicyError> {
    let process = options.process;
    let session = SessionOptions {
        isolation: options.isolation,
        policy: options.policy,
        requirements: options.requirements,
        resources: options.resources,
        prepared_ttl_ms: options.prepared_ttl_ms,
    };
    let policy = normalize_session(session, host_physical_memory)?;
    let execution = normalize_process(process, &policy.resources)?;
    Ok((policy, execution))
}

pub fn normalize_process(
    process: ProcessOptions,
    session_limits: &ResourceLimits,
) -> Result<NormalizedExecution, PolicyError> {
    let executable = normalize_target_path(&process.executable)?;
    if executable == "/" {
        return Err(policy_error(
            "policy.executable",
            "executable cannot be the target root",
        ));
    }
    let cwd = normalize_target_path(&process.cwd)?;
    for value in std::iter::once(&process.executable)
        .chain(std::iter::once(&process.cwd))
        .chain(process.args.iter())
    {
        if value.contains('\0') {
            return Err(policy_error(
                "policy.nul",
                "process strings cannot contain NUL",
            ));
        }
    }
    let resources = narrow_resources(session_limits, &process.resources)?;
    let environment = capture_environment(process.environment)?;
    let stdin = validate_mode(
        process.stdin.as_deref().unwrap_or("closed"),
        &["pipe", "closed"],
        "stdin",
    )?;
    let stdout = validate_mode(
        process.stdout.as_deref().unwrap_or("capture"),
        &["pipe", "capture", "discard"],
        "stdout",
    )?;
    let stderr = validate_mode(
        process.stderr.as_deref().unwrap_or("capture"),
        &["pipe", "capture", "discard"],
        "stderr",
    )?;
    let artifacts = process
        .artifacts
        .map(normalize_artifact_request)
        .transpose()?;
    let change_set = process
        .change_set
        .map(normalize_workspace_change_request)
        .transpose()?;
    Ok(NormalizedExecution {
        executable,
        args: process.args,
        cwd,
        environment,
        stdin,
        stdout,
        stderr,
        artifacts,
        change_set,
        resources,
    })
}

fn normalize_workspace_change_request(
    request: WorkspaceChangeRequest,
) -> Result<WorkspaceChangeRequest, PolicyError> {
    if request.max_bytes == 0 || request.max_bytes > 64 * 1024 * 1024 {
        return Err(policy_error(
            "policy.change_set",
            "workspace change-set export requires a byte limit no larger than 64 MiB",
        ));
    }
    Ok(request)
}

fn normalize_artifact_request(request: ArtifactRequest) -> Result<ArtifactRequest, PolicyError> {
    if request.paths.is_empty()
        || request.paths.len() > 65_536
        || request.max_bytes == 0
        || request.max_bytes > 64 * 1024 * 1024
    {
        return Err(policy_error(
            "policy.artifacts",
            "artifact export requires one to 65536 paths and a byte limit no larger than 64 MiB",
        ));
    }
    let mut paths = BTreeSet::new();
    for value in request.paths {
        if value.contains('\0') {
            return Err(policy_error(
                "policy.artifact_path",
                "artifact path contains NUL",
            ));
        }
        let path = Path::new(&value);
        let normalized = if path.is_absolute() {
            normalize_target_path(&value)?
                .strip_prefix('/')
                .unwrap_or("")
                .to_owned()
        } else {
            if value.is_empty()
                || path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(policy_error(
                    "policy.artifact_path",
                    "artifact paths must be normalized target paths",
                ));
            }
            value
        };
        if normalized.is_empty() || !paths.insert(normalized) {
            return Err(policy_error(
                "policy.artifact_path",
                "artifact paths must be unique and non-root",
            ));
        }
    }
    Ok(ArtifactRequest {
        paths: paths.into_iter().collect(),
        max_bytes: request.max_bytes,
    })
}

fn validate_mode(value: &str, accepted: &[&str], name: &str) -> Result<String, PolicyError> {
    if accepted.contains(&value) {
        Ok(value.into())
    } else {
        Err(policy_error(
            "policy.stream",
            format!("invalid {name} mode"),
        ))
    }
}

fn capture_environment(
    environment: Option<Environment>,
) -> Result<BTreeMap<String, CapturedEnvironmentValue>, PolicyError> {
    let environment = environment.unwrap_or(Environment {
        base: None,
        inherit: Vec::new(),
        set: BTreeMap::new(),
        unset: Vec::new(),
    });
    let base = environment.base.as_deref().unwrap_or("minimal");
    if base != "minimal" && base != "empty" {
        return Err(policy_error(
            "policy.environment_base",
            "environment base must be minimal or empty",
        ));
    }
    let mut result = BTreeMap::new();
    if base == "minimal" {
        for (name, value) in [
            ("HOME", "/home/sandbox"),
            ("PATH", "/usr/bin:/bin"),
            ("TMPDIR", "/tmp"),
            ("TMP", "/tmp"),
            ("TEMP", "/tmp"),
        ] {
            result.insert(
                name.into(),
                CapturedEnvironmentValue {
                    value: value.into(),
                    sensitive: false,
                },
            );
        }
    }
    let mut seen = BTreeSet::new();
    for name in environment.inherit {
        validate_environment_name(&name)?;
        if !seen.insert(name.clone()) {
            return Err(policy_error(
                "policy.environment_duplicate",
                "duplicate inherited environment name",
            ));
        }
        if let Some(value) = std::env::var_os(&name) {
            let value = value.into_string().map_err(|_| {
                policy_error(
                    "policy.environment_encoding",
                    "inherited environment value is not UTF-8",
                )
            })?;
            result.insert(
                name,
                CapturedEnvironmentValue {
                    value,
                    sensitive: false,
                },
            );
        }
    }
    for (name, value) in environment.set {
        validate_environment_name(&name)?;
        let (value, sensitive) = match value {
            EnvironmentValue::Plain(value) => (value, false),
            EnvironmentValue::Sensitive { value, sensitive } => {
                if !sensitive {
                    return Err(policy_error(
                        "policy.environment_sensitive",
                        "sensitive marker must be true",
                    ));
                }
                (value, true)
            }
        };
        if value.contains('\0') {
            return Err(policy_error(
                "policy.environment_nul",
                "environment values cannot contain NUL",
            ));
        }
        result.insert(name, CapturedEnvironmentValue { value, sensitive });
    }
    for name in environment.unset {
        validate_environment_name(&name)?;
        result.remove(&name);
    }
    Ok(result)
}

fn validate_environment_name(name: &str) -> Result<(), PolicyError> {
    let mut bytes = name.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic());
    if !valid_first || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        return Err(policy_error(
            "policy.environment_name",
            "invalid environment variable name",
        ));
    }
    Ok(())
}

fn validate_requirements(requirements: &Requirements) -> Result<(), PolicyError> {
    let mut seen = BTreeSet::new();
    for guarantee in &requirements.required {
        if !GUARANTEES.contains(&guarantee.as_str()) {
            return Err(policy_error(
                "requirement.unknown",
                format!("unknown guarantee: {guarantee}"),
            ));
        }
        if !seen.insert(guarantee) {
            return Err(policy_error(
                "requirement.duplicate",
                format!("duplicate guarantee: {guarantee}"),
            ));
        }
    }
    Ok(())
}

pub fn resolve_resources(
    partial: &PartialResourceLimits,
    host_memory: u64,
) -> Result<ResourceLimits, PolicyError> {
    let calculated_memory = 4_294_967_296_u64.min(host_memory / 2);
    let memory_bytes = match partial.memory_bytes {
        Some(value) => value,
        None if calculated_memory < 536_870_912 => {
            return Err(policy_error(
                "policy.memory_default",
                "host memory is too low for the default envelope; provide memoryBytes explicitly",
            ));
        }
        None => calculated_memory,
    };
    let limits = ResourceLimits {
        wall_time_ms: partial.wall_time_ms.unwrap_or(600_000),
        cpu_time_ms: partial.cpu_time_ms,
        memory_bytes,
        max_processes: partial.max_processes.unwrap_or(256),
        max_open_files_per_process: Some(partial.max_open_files_per_process.unwrap_or(1024)),
        max_single_file_bytes: Some(partial.max_single_file_bytes.unwrap_or(1_073_741_824)),
        max_output_bytes: partial.max_output_bytes.unwrap_or(33_554_432),
        termination_grace_ms: partial.termination_grace_ms.unwrap_or(2_000),
    };
    validate_limits(&limits)?;
    Ok(limits)
}

fn validate_limits(limits: &ResourceLimits) -> Result<(), PolicyError> {
    if limits.wall_time_ms == 0
        || limits.memory_bytes == 0
        || limits.max_processes == 0
        || limits.max_output_bytes == 0
        || limits.max_open_files_per_process == Some(0)
        || limits.max_single_file_bytes == Some(0)
        || limits.cpu_time_ms == Some(0)
    {
        return Err(policy_error(
            "policy.resource",
            "resource limits must be positive",
        ));
    }
    if limits.termination_grace_ms > 10_000 {
        return Err(policy_error(
            "policy.termination_grace",
            "terminationGraceMs must be between 0 and 10000",
        ));
    }
    Ok(())
}

fn narrow_resources(
    session: &ResourceLimits,
    partial: &PartialResourceLimits,
) -> Result<ResourceLimits, PolicyError> {
    let narrowed = ResourceLimits {
        wall_time_ms: partial.wall_time_ms.unwrap_or(session.wall_time_ms),
        cpu_time_ms: partial.cpu_time_ms.or(session.cpu_time_ms),
        memory_bytes: partial.memory_bytes.unwrap_or(session.memory_bytes),
        max_processes: partial.max_processes.unwrap_or(session.max_processes),
        max_open_files_per_process: partial
            .max_open_files_per_process
            .or(session.max_open_files_per_process),
        max_single_file_bytes: partial
            .max_single_file_bytes
            .or(session.max_single_file_bytes),
        max_output_bytes: partial.max_output_bytes.unwrap_or(session.max_output_bytes),
        termination_grace_ms: partial
            .termination_grace_ms
            .unwrap_or(session.termination_grace_ms),
    };
    validate_limits(&narrowed)?;
    let widened = narrowed.wall_time_ms > session.wall_time_ms
        || narrowed.memory_bytes > session.memory_bytes
        || narrowed.max_processes > session.max_processes
        || narrowed.max_output_bytes > session.max_output_bytes
        || option_widens(narrowed.cpu_time_ms, session.cpu_time_ms)
        || option_widens(
            narrowed.max_open_files_per_process,
            session.max_open_files_per_process,
        )
        || option_widens(
            narrowed.max_single_file_bytes,
            session.max_single_file_bytes,
        )
        || narrowed.termination_grace_ms > session.termination_grace_ms;
    if widened {
        return Err(policy_error(
            "policy.resource_widening",
            "process limits may not widen session limits",
        ));
    }
    Ok(narrowed)
}

const fn option_widens(child: Option<u64>, parent: Option<u64>) -> bool {
    match (child, parent) {
        (Some(child), Some(parent)) => child > parent,
        (None, Some(_)) => true,
        _ => false,
    }
}

pub fn normalize_target_path(value: &str) -> Result<String, PolicyError> {
    #[cfg(target_os = "windows")]
    {
        normalize_windows_target_path(value)
    }
    #[cfg(not(target_os = "windows"))]
    {
        normalize_posix_target_path(value)
    }
}

#[cfg(not(target_os = "windows"))]
fn normalize_posix_target_path(value: &str) -> Result<String, PolicyError> {
    if value.is_empty() || value.contains('\0') || !value.starts_with('/') {
        return Err(policy_error(
            "policy.target_path",
            "target paths must be absolute POSIX paths",
        ));
    }
    let path = Path::new(value);
    let mut normalized = String::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push('/'),
            Component::Normal(part) => {
                if normalized.len() > 1 {
                    normalized.push('/');
                }
                let part = part.to_str().ok_or_else(|| {
                    policy_error("policy.target_path_encoding", "target path is not UTF-8")
                })?;
                normalized.push_str(part);
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(policy_error(
                    "policy.target_path_traversal",
                    "target paths cannot contain traversal components",
                ));
            }
        }
    }
    if normalized.is_empty() {
        normalized.push('/');
    }
    if normalized != value && value != format!("{normalized}/") {
        return Err(policy_error(
            "policy.target_path_normalization",
            "target paths must already be normalized",
        ));
    }
    Ok(normalized)
}

#[cfg(target_os = "windows")]
fn normalize_windows_target_path(value: &str) -> Result<String, PolicyError> {
    use std::path::Prefix;

    if value.is_empty() || value.contains('\0') || !Path::new(value).is_absolute() {
        return Err(policy_error(
            "policy.target_path",
            "target paths must be absolute Windows paths",
        ));
    }
    let mut components = Path::new(value).components();
    match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_)
            | Prefix::VerbatimDisk(_)
            | Prefix::UNC(_, _)
            | Prefix::VerbatimUNC(_, _) => {}
            _ => {
                return Err(policy_error(
                    "policy.target_path",
                    "device and relative Windows prefixes are prohibited",
                ));
            }
        },
        _ => {
            return Err(policy_error(
                "policy.target_path",
                "target paths require an explicit Windows volume",
            ));
        }
    }
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(policy_error(
            "policy.target_path",
            "target path is not rooted",
        ));
    }
    for component in components {
        let Component::Normal(name) = component else {
            return Err(policy_error(
                "policy.target_path_traversal",
                "target paths cannot contain traversal components",
            ));
        };
        let name = name.to_string_lossy();
        let trimmed = name.trim_end_matches([' ', '.']);
        let stem = trimmed
            .split_once('.')
            .map_or(trimmed, |(stem, _)| stem)
            .to_ascii_uppercase();
        let reserved_device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || stem
                .strip_prefix("COM")
                .or_else(|| stem.strip_prefix("LPT"))
                .is_some_and(|suffix| {
                    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
                });
        if trimmed != name || name.contains(':') || reserved_device {
            return Err(policy_error(
                "policy.target_path_ambiguous",
                "target paths cannot contain device names, alternate streams, or trailing dots/spaces",
            ));
        }
    }
    let normalized = Path::new(value).to_string_lossy().into_owned();
    if normalized != value.trim_end_matches(['\\', '/']) && Path::new(value).parent().is_some() {
        return Err(policy_error(
            "policy.target_path_normalization",
            "target paths must already be normalized",
        ));
    }
    Ok(normalized)
}

#[cfg(target_os = "linux")]
const RUNTIME_OWNED_TARGETS: &[&str] = &[
    "/dev",
    "/proc",
    "/tmp",
    "/home/sandbox",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/resolv.conf",
];

#[cfg(target_os = "linux")]
fn reserved_target_conflict(target: &str) -> bool {
    target == "/"
        || target
            .strip_prefix('/')
            .and_then(|relative| relative.split('/').next())
            .is_some_and(|component| component.starts_with(".sandbox-"))
        || RUNTIME_OWNED_TARGETS
            .iter()
            .any(|reserved| paths_overlap(target, reserved))
}

#[cfg(not(target_os = "linux"))]
fn reserved_target_conflict(target: &str) -> bool {
    Path::new(target).parent().is_none()
}

fn paths_overlap(left: &str, right: &str) -> bool {
    path_contains(left, right) || path_contains(right, left)
}

fn path_contains(parent: &str, child: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        let parent = windows_path_key(parent);
        let child = windows_path_key(child);
        child == parent
            || child
                .strip_prefix(&parent)
                .is_some_and(|remainder| remainder.starts_with('\\'))
    }
    #[cfg(not(target_os = "windows"))]
    {
        parent == child
            || parent == "/"
            || child
                .strip_prefix(parent)
                .is_some_and(|remainder| remainder.starts_with('/'))
    }
}

#[cfg(target_os = "windows")]
fn windows_path_key(value: &str) -> String {
    let replaced = value.replace('/', "\\");
    let ordinary = replaced
        .strip_prefix(r"\\?\UNC\")
        .map(|suffix| format!(r"\\{suffix}"))
        .or_else(|| replaced.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or(replaced);
    ordinary.to_uppercase()
}

fn validate_absolute_host_path(value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.contains('\0') || !Path::new(value).is_absolute() {
        return Err(policy_error(
            "policy.host_path",
            "host grant paths must be absolute and contain no NUL",
        ));
    }
    Ok(())
}

pub fn policy_error(code: &str, message: impl Into<String>) -> PolicyError {
    PolicyError(Box::new(ErrorData::new(code, message, "validate")))
}

fn sanitize_message(message: &str) -> String {
    message
        .chars()
        .take(4096)
        .filter(|character| !character.is_control() || *character == ' ')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn target_paths_are_strict() {
        assert_eq!(
            normalize_target_path("/work/src").expect("path"),
            "/work/src"
        );
        assert!(normalize_target_path("work").is_err());
        assert!(normalize_target_path("/work/../secret").is_err());
        assert!(normalize_target_path("/work//src").is_err());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn target_paths_are_strict() {
        assert_eq!(
            normalize_target_path(r"C:\work\src").expect("path"),
            r"C:\work\src"
        );
        assert!(normalize_target_path(r"work\src").is_err());
        assert!(normalize_target_path(r"C:\work\..\secret").is_err());
        assert!(normalize_target_path(r"\\.\PhysicalDrive0").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn runtime_owned_grant_targets_are_reserved() {
        for path in [
            "/",
            "/.sandbox-masks",
            "/.sandbox-runtime/executable",
            "/tmp/work",
            "/home",
            "/etc",
            "/dev/null",
            "/proc/self",
        ] {
            assert!(reserved_target_conflict(path), "{path} must be reserved");
        }
        for path in ["/workspace", "/home/other", "/etc-custom", "/devtools"] {
            assert!(!reserved_target_conflict(path), "{path} must remain usable");
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn only_the_target_root_is_generically_reserved() {
        assert!(reserved_target_conflict("/"));
        assert!(!reserved_target_conflict("/workspace"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn only_a_target_volume_root_is_generically_reserved() {
        assert!(reserved_target_conflict(r"C:\"));
        assert!(!reserved_target_conflict(r"C:\workspace"));
    }

    #[test]
    fn defaults_are_resolved() {
        let limits = resolve_resources(&PartialResourceLimits::default(), 16 * 1024 * 1024 * 1024)
            .expect("limits");
        assert_eq!(limits.memory_bytes, 4_294_967_296);
        assert_eq!(limits.wall_time_ms, 600_000);
        assert_eq!(limits.max_output_bytes, 33_554_432);
    }

    #[test]
    fn process_limits_cannot_widen() {
        let session = resolve_resources(&PartialResourceLimits::default(), 8 * 1024 * 1024 * 1024)
            .expect("limits");
        let wider = PartialResourceLimits {
            wall_time_ms: Some(session.wall_time_ms + 1),
            ..Default::default()
        };
        assert!(narrow_resources(&session, &wider).is_err());
    }

    #[test]
    fn environment_values_are_captured_but_not_part_of_names() {
        let environment = Environment {
            base: Some("empty".into()),
            inherit: Vec::new(),
            set: BTreeMap::from([(
                "TOKEN".into(),
                EnvironmentValue::Sensitive {
                    value: "secret".into(),
                    sensitive: true,
                },
            )]),
            unset: Vec::new(),
        };
        let values = capture_environment(Some(environment)).expect("environment");
        assert!(values["TOKEN"].sensitive);
    }

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
    fn managed_dns_wire_fields_use_the_public_camel_case_contract() {
        let destination: ManagedNetworkDestination = serde_json::from_value(serde_json::json!({
            "kind": "dns",
            "name": "localhost",
            "includeSubdomains": true,
            "allowPrivateAddresses": true
        }))
        .expect("public managed-network destination");
        assert!(matches!(
            destination,
            ManagedNetworkDestination::Dns {
                include_subdomains: true,
                allow_private_addresses: true,
                ..
            }
        ));
        let encoded = serde_json::to_value(destination).expect("destination serialization");
        assert_eq!(encoded["includeSubdomains"], true);
        assert_eq!(encoded["allowPrivateAddresses"], true);
        assert!(encoded.get("include_subdomains").is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_targets_reject_device_and_case_ambiguity() {
        for path in [
            r"C:\workspace\NUL",
            r"C:\workspace\con.txt",
            r"C:\workspace\stream:secret",
            r"C:\workspace\trailing.",
            r"C:\workspace\trailing ",
        ] {
            assert!(normalize_target_path(path).is_err(), "{path}");
        }
        assert!(paths_overlap(r"C:\Workspace", r"c:/workspace/child"));
        assert!(paths_overlap(r"\\?\C:\Workspace", r"c:\WORKSPACE"));
    }
}
