#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::path::{Component, Path};

pub const MAX_PREPARED_TTL_MS: u64 = 1_800_000;
pub const DEFAULT_PREPARED_TTL_MS: u64 = 300_000;

pub const GUARANTEES: &[&str] = &[
    "runtime.setup-before-exec",
    "runtime.no-ambient-environment",
    "runtime.no-ambient-handles",
    "runtime.executable-identity-bound",
    "filesystem.resource-identities-bound",
    "filesystem.content-read-confined",
    "filesystem.content-write-confined",
    "filesystem.directory-entry-mutation-confined",
    "filesystem.metadata-mutation-confined",
    "filesystem.execution-confined",
    "filesystem.name-visibility-confined",
    "filesystem.isolated-layout",
    "network.no-external-connect",
    "network.no-external-listen",
    "network.no-host-loopback",
    "network.egress-brokered",
    "network.private-addresses-denied",
    "process.host-visibility-denied",
    "process.host-control-denied",
    "process.descendant-tree-termination",
    "process.group-termination",
    "ipc.host-endpoints-hidden",
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
    pub ipc: IpcPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FilesystemPolicy {
    Host {
        resources: Vec<HostFilesystemResource>,
    },
    Isolated {
        resources: Vec<IsolatedFilesystemResource>,
        #[serde(default)]
        masks: Vec<FilesystemMask>,
        #[serde(rename = "privateHome")]
        private_home: Option<SyntheticDirectoryPolicy>,
        temporary: Option<SyntheticDirectoryPolicy>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostFilesystemResource {
    pub id: String,
    pub path: CoordinatePath,
    pub access: FilesystemAccess,
    pub purposes: Vec<String>,
    pub root_resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolatedFilesystemResource {
    pub id: String,
    pub source: CoordinatePath,
    pub target: CoordinatePath,
    pub access: FilesystemAccess,
    pub purposes: Vec<String>,
    pub root_resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemAccess {
    pub content: String,
    pub directory_entries: String,
    pub metadata: String,
    pub execution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemMask {
    pub path: CoordinatePath,
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyntheticDirectoryPolicy {
    pub path: CoordinatePath,
    pub size_bytes: u64,
    pub executable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "space", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CoordinatePath {
    Host { path: String },
    Isolated { path: String },
}

impl CoordinatePath {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Host { path } | Self::Isolated { path } => path,
        }
    }

    #[must_use]
    pub const fn space(&self) -> &'static str {
        match self {
            Self::Host { .. } => "host",
            Self::Isolated { .. } => "isolated",
        }
    }
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
    pub visibility: String,
    pub control: String,
    pub termination: TerminationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminationPolicy {
    pub scope: String,
    pub grace_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcPolicy {
    pub visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Requirements {
    #[serde(default)]
    pub additional: Vec<String>,
    #[serde(default)]
    pub allow_experimental_implementations: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartialResourceLimits {
    pub wall_time: Option<HardLimit>,
    pub cpu_time: Option<HardLimit>,
    pub memory: Option<HardLimit>,
    pub process_count: Option<HardLimit>,
    pub open_files: Option<HardLimit>,
    pub single_file_size: Option<HardLimit>,
    pub output: Option<HardLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceLimits {
    pub wall_time: HardLimit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_time: Option<HardLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<HardLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_count: Option<HardLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_files: Option<HardLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_file_size: Option<HardLimit>,
    pub output: HardLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardLimit {
    pub enforcement: String,
    pub scope: String,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessOptions {
    pub executable: CoordinatePath,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: CoordinatePath,
    pub environment: Option<Environment>,
    pub stdin: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub artifacts: Option<ArtifactRequest>,
    pub change_set: Option<WorkspaceChangeRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRequest {
    pub paths: Vec<CoordinatePath>,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceChangeRequest {
    pub root: CoordinatePath,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Environment {
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
    pub filesystem_kind: String,
    pub resources: Vec<NormalizedResource>,
    pub masks: Vec<NormalizedMask>,
    pub private_home: Option<NormalizedSyntheticDirectory>,
    pub temporary: Option<NormalizedSyntheticDirectory>,
    pub network: String,
    pub managed_network_rules: Vec<ManagedNetworkRule>,
    pub process: ProcessPolicy,
    pub ipc: IpcPolicy,
    pub limits: ResourceLimits,
    pub prepared_ttl_ms: u64,
    pub obligations: Vec<String>,
    pub requirements: Requirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedResource {
    pub id: String,
    pub requested_host_path: String,
    pub target_path: String,
    pub access: FilesystemAccess,
    pub purposes: Vec<String>,
    pub root_resolution: String,
}

impl NormalizedResource {
    #[must_use]
    pub fn read_only(&self) -> bool {
        self.access.content == "read"
            && self.access.directory_entries == "read"
            && self.access.metadata == "read"
    }

    #[must_use]
    pub fn executable(&self) -> bool {
        self.access.execution == "allow"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedMask {
    pub target_path: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedSyntheticDirectory {
    pub target_path: String,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedExecution {
    pub executable: CoordinatePath,
    pub args: Vec<String>,
    pub cwd: CoordinatePath,
    pub environment: BTreeMap<String, CapturedEnvironmentValue>,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<ArtifactRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_set: Option<WorkspaceChangeRequest>,
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
    pub implementation: EnforcementImplementation,
    pub host: EnforcementHost,
    pub target: EnforcementTarget,
    pub guarantees: Vec<GuaranteeFact>,
    pub filesystem: EnforcementFilesystem,
    pub caveats: Vec<EnforcementCaveat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementBoundary {
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcementImplementation {
    pub id: String,
    pub version: String,
    pub build_id: String,
    pub conformance_manifest_id: String,
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
pub struct EnforcementFilesystem {
    pub kind: String,
    pub resource_manifest_digest: String,
    pub visible_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorData {
    pub code: String,
    pub message: String,
    pub phase: String,
    pub target_executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation: Option<String>,
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
            implementation: None,
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

pub fn normalize_session(options: SessionOptions) -> Result<NormalizedPolicy, PolicyError> {
    match &options.isolation {
        Isolation::Process => "os-process",
        Isolation::HardwareVm {
            image,
            filesystem_transport,
        } => {
            if filesystem_transport != "import" {
                return Err(policy_error(
                    "policy.vm_filesystem_transport",
                    "hardware VM filesystem transport must be import",
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
    validate_requirements(&options.requirements)?;
    let Policy {
        filesystem,
        network,
        process,
        ipc,
    } = options.policy;
    if !matches!(process.visibility.as_str(), "session" | "host")
        || !matches!(process.control.as_str(), "session" | "host")
        || !matches!(
            process.termination.scope.as_str(),
            "descendant-tree" | "process-group"
        )
        || process.termination.grace_ms > 10_000
    {
        return Err(policy_error(
            "policy.process",
            "process visibility, control, or termination policy is invalid",
        ));
    }
    if !matches!(ipc.visibility.as_str(), "session" | "host") {
        return Err(policy_error(
            "policy.ipc",
            "IPC visibility policy is invalid",
        ));
    }
    let managed_network_rules = match &network {
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

    let resolved_limits = resolve_resources(&options.resources)?;
    let prepared_ttl_ms = options.prepared_ttl_ms.unwrap_or(DEFAULT_PREPARED_TTL_MS);
    if prepared_ttl_ms == 0 || prepared_ttl_ms > MAX_PREPARED_TTL_MS {
        return Err(policy_error(
            "policy.prepared_ttl",
            "preparedTtlMs must be between 1 and 1800000",
        ));
    }
    let (filesystem_kind, raw_resources, raw_masks, private_home, temporary) = match filesystem {
        FilesystemPolicy::Host { resources } => {
            if matches!(options.isolation, Isolation::HardwareVm { .. }) {
                return Err(policy_error(
                    "policy.filesystem_layout",
                    "hardware VM isolation requires an isolated filesystem layout",
                ));
            }
            let resources = resources
                .into_iter()
                .map(|resource| {
                    let CoordinatePath::Host { path } = resource.path else {
                        return Err(policy_error(
                            "policy.path_space",
                            "host-layout resources require host paths",
                        ));
                    };
                    Ok((
                        resource.id,
                        path.clone(),
                        path,
                        resource.access,
                        resource.purposes,
                        resource.root_resolution,
                    ))
                })
                .collect::<Result<Vec<_>, PolicyError>>()?;
            ("host", resources, Vec::new(), None, None)
        }
        FilesystemPolicy::Isolated {
            resources,
            masks,
            private_home,
            temporary,
        } => {
            let resources = resources
                .into_iter()
                .map(|resource| {
                    let CoordinatePath::Host { path: source } = resource.source else {
                        return Err(policy_error(
                            "policy.path_space",
                            "isolated resource sources require host paths",
                        ));
                    };
                    let CoordinatePath::Isolated { path: target } = resource.target else {
                        return Err(policy_error(
                            "policy.path_space",
                            "isolated resource targets require isolated paths",
                        ));
                    };
                    Ok((
                        resource.id,
                        source,
                        target,
                        resource.access,
                        resource.purposes,
                        resource.root_resolution,
                    ))
                })
                .collect::<Result<Vec<_>, PolicyError>>()?;
            (
                "isolated",
                resources,
                masks,
                normalize_synthetic_directory(private_home, "privateHome")?,
                normalize_synthetic_directory(temporary, "temporary")?,
            )
        }
    };

    let mut normalized_resources = Vec::with_capacity(raw_resources.len());
    let mut target_paths = BTreeSet::new();
    let mut resource_ids = BTreeSet::new();
    for (id, host_path, raw_target, access, purposes, root_resolution) in raw_resources {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !resource_ids.insert(id.clone())
        {
            return Err(policy_error(
                "policy.resource_id",
                "filesystem resource IDs must be unique portable identifiers",
            ));
        }
        validate_absolute_host_path(&host_path)?;
        validate_filesystem_access(&access)?;
        let purposes = normalize_resource_purposes(purposes)?;
        let target_path = if filesystem_kind == "host" {
            validate_absolute_host_path(&raw_target)?;
            raw_target
        } else {
            normalize_target_path(&raw_target)?
        };
        if !target_paths.insert(target_path.clone()) {
            return Err(policy_error(
                "policy.resource_conflict",
                "multiple resources map to the same target path",
            ));
        }
        let root_resolution = root_resolution.unwrap_or_else(|| "resolve-once".into());
        if root_resolution != "resolve-once" && root_resolution != "reject-if-link" {
            return Err(policy_error(
                "policy.resource_resolution",
                "unsupported resource root resolution",
            ));
        }
        normalized_resources.push(NormalizedResource {
            id,
            requested_host_path: host_path,
            target_path,
            access,
            purposes,
            root_resolution,
        });
    }
    normalized_resources.sort_by(|left, right| {
        left.target_path
            .as_bytes()
            .cmp(right.target_path.as_bytes())
    });
    for (index, parent) in normalized_resources.iter().enumerate() {
        if normalized_resources[index + 1..]
            .iter()
            .any(|child| paths_overlap(&parent.target_path, &child.target_path))
        {
            return Err(policy_error(
                "policy.resource_overlap",
                "resource targets must not contain one another",
            ));
        }
    }

    for directory in private_home.iter().chain(temporary.iter()) {
        if normalized_resources
            .iter()
            .any(|resource| paths_overlap(&resource.target_path, &directory.target_path))
        {
            return Err(policy_error(
                "policy.synthetic_directory_conflict",
                "synthetic directory paths conflict with an owned or authorized resource",
            ));
        }
    }
    if private_home
        .as_ref()
        .zip(temporary.as_ref())
        .is_some_and(|(left, right)| paths_overlap(&left.target_path, &right.target_path))
    {
        return Err(policy_error(
            "policy.synthetic_directory_conflict",
            "synthetic directory paths overlap",
        ));
    }

    let mut masks = Vec::with_capacity(raw_masks.len());
    let mut mask_paths = BTreeSet::new();
    for mask in raw_masks {
        let CoordinatePath::Isolated { path } = mask.path else {
            return Err(policy_error(
                "policy.path_space",
                "mask paths require isolated coordinates",
            ));
        };
        let target_path = normalize_target_path(&path)?;
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

    let mut normalized = NormalizedPolicy {
        isolation: options.isolation,
        filesystem_kind: filesystem_kind.into(),
        resources: normalized_resources,
        masks,
        private_home,
        temporary,
        network: network.name().into(),
        managed_network_rules,
        process,
        ipc,
        limits: resolved_limits,
        prepared_ttl_ms,
        obligations: Vec::new(),
        requirements: options.requirements,
    };
    normalized.obligations = derive_obligations(&normalized);
    Ok(normalized)
}

fn normalize_synthetic_directory(
    directory: Option<SyntheticDirectoryPolicy>,
    label: &str,
) -> Result<Option<NormalizedSyntheticDirectory>, PolicyError> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    let CoordinatePath::Isolated { path } = directory.path else {
        return Err(policy_error(
            "policy.path_space",
            format!("{label} requires an isolated path"),
        ));
    };
    if directory.size_bytes == 0 {
        return Err(policy_error(
            "policy.synthetic_directory_size",
            format!("{label} size must be positive"),
        ));
    }
    Ok(Some(NormalizedSyntheticDirectory {
        target_path: normalize_target_path(&path)?,
        size_bytes: directory.size_bytes,
        executable: directory.executable.unwrap_or(false),
    }))
}

fn validate_filesystem_access(access: &FilesystemAccess) -> Result<(), PolicyError> {
    if !matches!(access.content.as_str(), "read" | "read-write")
        || !matches!(access.directory_entries.as_str(), "read" | "read-write")
        || !matches!(access.metadata.as_str(), "read" | "read-write")
        || !matches!(access.execution.as_str(), "deny" | "allow")
    {
        return Err(policy_error(
            "policy.resource_access",
            "filesystem access dimensions are invalid",
        ));
    }
    Ok(())
}

fn normalize_resource_purposes(mut purposes: Vec<String>) -> Result<Vec<String>, PolicyError> {
    purposes.sort();
    purposes.dedup();
    if purposes.is_empty()
        || purposes.iter().any(|purpose| {
            !matches!(
                purpose.as_str(),
                "executable" | "interpreter" | "loader" | "library" | "cache" | "data"
            )
        })
    {
        return Err(policy_error(
            "policy.resource_purpose",
            "filesystem resources require one or more known purposes",
        ));
    }
    Ok(purposes)
}

fn derive_obligations(policy: &NormalizedPolicy) -> Vec<String> {
    let mut obligations = BTreeSet::from([
        "runtime.setup-before-exec".to_owned(),
        "runtime.no-ambient-environment".to_owned(),
        "runtime.no-ambient-handles".to_owned(),
        "filesystem.content-read-confined".to_owned(),
        "filesystem.content-write-confined".to_owned(),
        "filesystem.directory-entry-mutation-confined".to_owned(),
        "filesystem.metadata-mutation-confined".to_owned(),
        "filesystem.execution-confined".to_owned(),
        "resource.wall-time-hard".to_owned(),
        "resource.output-hard".to_owned(),
    ]);
    if policy.filesystem_kind == "isolated" {
        obligations.insert("runtime.executable-identity-bound".into());
        obligations.insert("filesystem.resource-identities-bound".into());
        obligations.insert("filesystem.name-visibility-confined".into());
        obligations.insert("filesystem.isolated-layout".into());
    }
    match policy.network.as_str() {
        "none" => {
            obligations.insert("network.no-external-connect".into());
            obligations.insert("network.no-external-listen".into());
            obligations.insert("network.no-host-loopback".into());
        }
        "managed" => {
            obligations.insert("network.egress-brokered".into());
            obligations.insert("network.private-addresses-denied".into());
            obligations.insert("network.no-external-listen".into());
            obligations.insert("network.no-host-loopback".into());
        }
        _ => {}
    }
    if policy.process.visibility == "session" {
        obligations.insert("process.host-visibility-denied".into());
    }
    if policy.process.control == "session" {
        obligations.insert("process.host-control-denied".into());
    }
    obligations.insert(
        if policy.process.termination.scope == "descendant-tree" {
            "process.descendant-tree-termination"
        } else {
            "process.group-termination"
        }
        .into(),
    );
    if policy.ipc.visibility == "session" {
        obligations.insert("ipc.host-endpoints-hidden".into());
        obligations.insert("ipc.host-shared-memory-hidden".into());
    }
    if policy.limits.memory.is_some() {
        obligations.insert("resource.memory-hard".into());
    }
    if policy.limits.process_count.is_some() {
        obligations.insert("resource.process-count-hard".into());
    }
    if policy.limits.cpu_time.is_some() {
        obligations.insert("resource.cpu-time-hard".into());
    }
    if policy.limits.open_files.is_some() {
        obligations.insert("resource.open-files-hard".into());
    }
    if policy.limits.single_file_size.is_some() {
        obligations.insert("resource.single-file-size-hard".into());
    }
    if matches!(policy.isolation, Isolation::HardwareVm { .. }) {
        obligations.extend([
            "vm.boot-artifacts-verified".into(),
            "vm.guest-control-authenticated".into(),
            "vm.control-plane-hidden-from-target".into(),
            "vm.host-filesystem-absent-outside-imports".into(),
        ]);
    }
    obligations.into_iter().collect()
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
) -> Result<(NormalizedPolicy, NormalizedExecution), PolicyError> {
    let process = options.process;
    let session = SessionOptions {
        isolation: options.isolation,
        policy: options.policy,
        requirements: options.requirements,
        resources: options.resources,
        prepared_ttl_ms: options.prepared_ttl_ms,
    };
    let policy = normalize_session(session)?;
    let execution = normalize_process(process, &policy)?;
    Ok((policy, execution))
}

pub fn normalize_process(
    process: ProcessOptions,
    policy: &NormalizedPolicy,
) -> Result<NormalizedExecution, PolicyError> {
    let executable = normalize_execution_path(process.executable, &policy.filesystem_kind)?;
    if executable.path() == "/" {
        return Err(policy_error(
            "policy.executable",
            "executable cannot be the target root",
        ));
    }
    let cwd = normalize_execution_path(process.cwd, &policy.filesystem_kind)?;
    for value in std::iter::once(executable.path())
        .chain(std::iter::once(cwd.path()))
        .chain(process.args.iter().map(String::as_str))
    {
        if value.contains('\0') {
            return Err(policy_error(
                "policy.nul",
                "process strings cannot contain NUL",
            ));
        }
    }
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
        .map(|request| normalize_artifact_request(request, &policy.filesystem_kind))
        .transpose()?;
    let change_set = process
        .change_set
        .map(|request| normalize_workspace_change_request(request, &policy.filesystem_kind))
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
    })
}

fn normalize_workspace_change_request(
    mut request: WorkspaceChangeRequest,
    filesystem_kind: &str,
) -> Result<WorkspaceChangeRequest, PolicyError> {
    if request.max_bytes == 0 || request.max_bytes > 64 * 1024 * 1024 {
        return Err(policy_error(
            "policy.change_set",
            "workspace change-set export requires a byte limit no larger than 64 MiB",
        ));
    }
    request.root = normalize_execution_path(request.root, filesystem_kind)?;
    Ok(request)
}

fn normalize_artifact_request(
    request: ArtifactRequest,
    filesystem_kind: &str,
) -> Result<ArtifactRequest, PolicyError> {
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
    let mut paths = BTreeMap::new();
    for value in request.paths {
        let normalized = normalize_execution_path(value, filesystem_kind)?;
        if normalized.path() == "/"
            || paths
                .insert(normalized.path().to_owned(), normalized)
                .is_some()
        {
            return Err(policy_error(
                "policy.artifact_path",
                "artifact paths must be unique and non-root",
            ));
        }
    }
    Ok(ArtifactRequest {
        paths: paths.into_values().collect(),
        max_bytes: request.max_bytes,
    })
}

fn normalize_execution_path(
    path: CoordinatePath,
    filesystem_kind: &str,
) -> Result<CoordinatePath, PolicyError> {
    match (filesystem_kind, path) {
        ("host", CoordinatePath::Host { path }) => {
            validate_absolute_host_path(&path)?;
            Ok(CoordinatePath::Host { path })
        }
        ("isolated", CoordinatePath::Isolated { path }) => Ok(CoordinatePath::Isolated {
            path: normalize_target_path(&path)?,
        }),
        ("host", CoordinatePath::Isolated { .. }) | ("isolated", CoordinatePath::Host { .. }) => {
            Err(policy_error(
                "policy.path_space",
                "execution paths must use the filesystem layout coordinate space",
            ))
        }
        _ => Err(policy_error(
            "policy.filesystem_layout",
            "unknown filesystem layout",
        )),
    }
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
        inherit: Vec::new(),
        set: BTreeMap::new(),
        unset: Vec::new(),
    });
    let mut result = BTreeMap::new();
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
    for guarantee in &requirements.additional {
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

pub fn resolve_resources(partial: &PartialResourceLimits) -> Result<ResourceLimits, PolicyError> {
    let limits = ResourceLimits {
        wall_time: partial
            .wall_time
            .clone()
            .unwrap_or_else(|| hard_limit("process", 600_000)),
        cpu_time: partial.cpu_time.clone(),
        memory: partial.memory.clone(),
        process_count: partial.process_count.clone(),
        open_files: partial.open_files.clone(),
        single_file_size: partial.single_file_size.clone(),
        output: partial
            .output
            .clone()
            .unwrap_or_else(|| hard_limit("process", 33_554_432)),
    };
    validate_limits(&limits)?;
    Ok(limits)
}

fn validate_limits(limits: &ResourceLimits) -> Result<(), PolicyError> {
    let valid = validate_limit(&limits.wall_time, &["process", "session"])
        && limits
            .cpu_time
            .as_ref()
            .is_none_or(|limit| validate_limit(limit, &["descendant-tree", "session"]))
        && limits
            .memory
            .as_ref()
            .is_none_or(|limit| validate_limit(limit, &["descendant-tree", "session"]))
        && limits
            .process_count
            .as_ref()
            .is_none_or(|limit| validate_limit(limit, &["descendant-tree", "session"]))
        && limits
            .open_files
            .as_ref()
            .is_none_or(|limit| validate_limit(limit, &["process"]))
        && limits
            .single_file_size
            .as_ref()
            .is_none_or(|limit| validate_limit(limit, &["process"]))
        && validate_limit(&limits.output, &["process", "session"]);
    if !valid {
        return Err(policy_error(
            "policy.resource",
            "resource limits must be positive hard limits with a valid scope",
        ));
    }
    Ok(())
}

fn hard_limit(scope: &str, value: u64) -> HardLimit {
    HardLimit {
        enforcement: "hard".into(),
        scope: scope.into(),
        value,
    }
}

fn validate_limit(limit: &HardLimit, scopes: &[&str]) -> bool {
    limit.enforcement == "hard" && limit.value > 0 && scopes.contains(&limit.scope.as_str())
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
    fn defaults_are_resolved() {
        let limits = resolve_resources(&PartialResourceLimits::default()).expect("limits");
        assert!(limits.memory.is_none());
        assert!(limits.process_count.is_none());
        assert_eq!(limits.wall_time.value, 600_000);
        assert_eq!(limits.output.value, 33_554_432);
    }

    #[test]
    fn resource_scopes_are_validated() {
        let invalid = PartialResourceLimits {
            wall_time: Some(hard_limit("descendant-tree", 1000)),
            ..Default::default()
        };
        assert!(resolve_resources(&invalid).is_err());
    }

    #[test]
    fn environment_values_are_captured_but_not_part_of_names() {
        let environment = Environment {
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
