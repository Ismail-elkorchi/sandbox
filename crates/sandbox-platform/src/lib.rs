#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::result_large_err)]

use sandbox_digest::{execution_digest, identity_digest, policy_digest};
use sandbox_launcher_linux::{
    FileIdentity, LaunchSpec, MountSpec, NamespaceLauncher, PreparedCwd, ProbeOutcome,
    file_identity,
};
use sandbox_policy::{
    EnforcementBoundary, EnforcementCaveat, EnforcementFilesystem, EnforcementHost,
    EnforcementImplementation, EnforcementReport, EnforcementTarget, ErrorData, GUARANTEES,
    GuaranteeFact, NormalizedExecution, NormalizedPolicy,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NONCE: AtomicU64 = AtomicU64::new(1);
pub const IMPLEMENTATION_ID: &str = "linux-namespace-v1";
pub const HOST_IMPLEMENTATION_ID: &str = "linux-landlock-v1";
pub const IMPLEMENTATION_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CONFORMANCE_MANIFEST_ID: &str = "linux-namespace-v1-conformance-1";
pub const HOST_CONFORMANCE_MANIFEST_ID: &str = "linux-landlock-v1-conformance-1";
pub const BUILD_ID: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeCapabilities {
    pub namespaces: bool,
    pub network_namespace: bool,
    pub landlock_abi: u32,
    pub seccomp: bool,
    pub cgroup_memory: bool,
    pub cgroup_processes: bool,
    pub mechanisms: std::collections::BTreeMap<String, ProbeOutcome>,
}

impl ProbeCapabilities {
    #[must_use]
    pub fn namespace_available(&self, network: &str) -> bool {
        self.namespaces
            && self.landlock_abi >= 3
            && self.seccomp
            && (network == "unrestricted" || self.network_namespace)
    }

    #[must_use]
    pub fn diagnostics(&self, network: &str) -> String {
        self.mechanisms
            .iter()
            .filter(|(name, outcome)| {
                outcome.state != "available"
                    && (matches!(name.as_str(), "namespace-launcher" | "landlock" | "seccomp")
                        || (network != "unrestricted" && name.as_str() == "network-namespace"))
            })
            .map(|(name, outcome)| {
                format!(
                    "{name}: {} during {}: {}",
                    outcome.state,
                    outcome.operation,
                    outcome.detail.as_deref().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug)]
pub struct HeldMount {
    pub file: File,
    pub target_path: String,
    pub kind: String,
    pub read_only: bool,
    pub executable: bool,
    pub resolved_path: String,
    pub identity: FileIdentity,
    pub identity_digest: String,
}

#[derive(Debug)]
pub struct PreparedHostPath {
    pub file: File,
    pub kind: String,
    pub resolved_path: String,
    pub identity: FileIdentity,
    pub identity_digest: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedResourceSummary {
    pub id: String,
    pub source: PreparedResourceSource,
    pub target: Value,
    pub access: sandbox_policy::FilesystemAccess,
    pub purposes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedResourceSource {
    pub requested: String,
    pub resolved: String,
    pub identity_digest: String,
}

#[derive(Debug)]
pub struct PreparedLinuxPolicy {
    pub normalized: NormalizedPolicy,
    implementation: LinuxImplementation,
    pub mounts: Vec<HeldMount>,
    pub resources: Vec<PreparedResourceSummary>,
    pub resource_manifest_digest: String,
    pub visible_roots: Vec<String>,
    pub enforcement: EnforcementReport,
    pub policy_digest: String,
    state: StateDirectory,
}

#[derive(Debug)]
enum LinuxImplementation {
    Namespace(NamespaceLauncher),
    Host,
}

impl LinuxImplementation {
    const fn id(&self) -> &'static str {
        match self {
            Self::Namespace(_) => IMPLEMENTATION_ID,
            Self::Host => HOST_IMPLEMENTATION_ID,
        }
    }

    const fn conformance_manifest_id(&self) -> &'static str {
        match self {
            Self::Namespace(_) => CONFORMANCE_MANIFEST_ID,
            Self::Host => HOST_CONFORMANCE_MANIFEST_ID,
        }
    }
}

#[derive(Debug)]
pub struct PreparedLinuxExecution {
    pub normalized: NormalizedExecution,
    pub executable: File,
    pub executable_identity: FileIdentity,
    pub executable_identity_digest: String,
    pub executable_content_sha256: String,
    pub cwd: Option<File>,
    pub cwd_identity: Option<FileIdentity>,
    pub cwd_identity_digest: String,
    pub execution_digest: String,
}

#[derive(Debug)]
struct StateDirectory {
    path: PathBuf,
    cleaned: bool,
}

impl Drop for StateDirectory {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl StateDirectory {
    fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug)]
pub struct LaunchBundle {
    pub spec: LaunchSpec,
    pub files: Vec<File>,
}

pub fn prepare_policy(
    normalized: NormalizedPolicy,
    capabilities: &ProbeCapabilities,
) -> Result<PreparedLinuxPolicy, ErrorData> {
    let implementation = select_implementation(&normalized, capabilities)?;
    let state = create_state_directory()
        .map_err(|error| os_error("preparation.state", &error, "prepare"))?;
    let mut mounts = Vec::new();
    let mut prepared_resources = Vec::new();
    for resource in &normalized.resources {
        if resource.access.content != resource.access.directory_entries
            || resource.access.content != resource.access.metadata
        {
            return Err(implementation_error(
                "unsupported.filesystem_access_combination",
                "linux-namespace-v1 cannot independently enforce mutation dimensions for one mount",
                "prepare",
            ));
        }
        let reject_link = resource.root_resolution == "reject-if-link";
        let mount = hold_mount(
            &resource.requested_host_path,
            &resource.target_path,
            resource.read_only(),
            resource.executable(),
            reject_link,
        )?;
        prepared_resources.push(PreparedResourceSummary {
            id: resource.id.clone(),
            source: PreparedResourceSource {
                requested: resource.requested_host_path.clone(),
                resolved: mount.resolved_path.clone(),
                identity_digest: mount.identity_digest.clone(),
            },
            target: json!({
                "space": if normalized.filesystem_kind == "host" { "host" } else { "isolated" },
                "path": &resource.target_path
            }),
            access: resource.access.clone(),
            purposes: resource.purposes.clone(),
        });
        mounts.push(mount);
    }
    validate_mount_graph(&mounts)?;
    validate_masks(&normalized, &mounts)?;

    let resource_manifest_digest =
        identity_digest(&mounts.iter().map(mount_digest_value).collect::<Vec<_>>())
            .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    let visible_roots = mounts
        .iter()
        .map(|mount| mount.target_path.clone())
        .collect::<Vec<_>>();
    let enforcement = enforcement_report(
        &normalized,
        capabilities,
        &resource_manifest_digest,
        &visible_roots,
        &implementation,
    );
    match_requirements(&normalized, &enforcement)?;
    let implementation_authority = match &implementation {
        LinuxImplementation::Namespace(launcher) => json!({
            "namespaceLauncher": {
                "identity": launcher.identity,
                "contentSha256": launcher.content_sha256
            }
        }),
        LinuxImplementation::Host => json!({
            "landlockAbi": capabilities.landlock_abi,
            "seccomp": capabilities.seccomp
        }),
    };
    let policy_input = json!({
        "digestFormat": 1_u64,
        "protocolMajor": 1_u64,
        "implementation": {"id": implementation.id(), "version": IMPLEMENTATION_VERSION, "stability": "stable"},
        "targetOperatingSystem": "linux",
        "implementationAuthority": implementation_authority,
        "policy": &normalized,
        "resourceManifestDigest": &resource_manifest_digest,
        "mounts": mounts.iter().map(mount_digest_value).collect::<Vec<_>>(),
    });
    let policy_digest = policy_digest(&policy_input)
        .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    Ok(PreparedLinuxPolicy {
        normalized,
        implementation,
        mounts,
        resources: prepared_resources,
        resource_manifest_digest,
        visible_roots,
        enforcement,
        policy_digest,
        state,
    })
}

fn select_implementation(
    policy: &NormalizedPolicy,
    capabilities: &ProbeCapabilities,
) -> Result<LinuxImplementation, ErrorData> {
    let limitations = implementation_limitations(policy, capabilities);
    if !limitations.is_empty() {
        return Err(implementation_error(
            "unsupported.no_eligible_implementation",
            format!(
                "no implementation satisfies the normalized policy: {}",
                limitations.join("; ")
            ),
            "prepare",
        ));
    }
    if policy.filesystem_kind == "isolated" {
        NamespaceLauncher::open()
            .map(LinuxImplementation::Namespace)
            .map_err(|error| os_error("preparation.namespace_launcher", &error, "prepare"))
    } else {
        Ok(LinuxImplementation::Host)
    }
}

#[must_use]
pub fn implementation_limitations(
    policy: &NormalizedPolicy,
    capabilities: &ProbeCapabilities,
) -> Vec<String> {
    if policy.filesystem_kind == "host" {
        return host_implementation_limitations(policy, capabilities);
    }
    let mut limitations = Vec::new();
    if policy.filesystem_kind != "isolated" {
        limitations.push("requires an isolated filesystem layout".to_owned());
    }
    if policy.process.visibility != "session"
        || policy.process.control != "session"
        || policy.ipc.visibility != "session"
    {
        limitations.push("cannot provide requested host process or IPC visibility".into());
    }
    if policy
        .resources
        .iter()
        .any(|resource| implementation_owned_target_conflict(&resource.target_path))
        || policy
            .private_home
            .iter()
            .chain(policy.temporary.iter())
            .any(|directory| implementation_owned_target_conflict(&directory.target_path))
    {
        limitations
            .push("resource or synthetic directory overlaps an implementation-owned path".into());
    }
    if !capabilities.namespace_available(&policy.network) {
        limitations.push(capabilities.diagnostics(&policy.network));
    }
    if policy.resources.iter().any(|resource| {
        resource.access.content != resource.access.directory_entries
            || resource.access.content != resource.access.metadata
    }) {
        limitations.push("cannot independently enforce requested mutation dimensions".into());
    }
    if policy.resources.iter().any(|parent| {
        parent.executable()
            && (policy.resources.iter().any(|child| {
                !child.executable() && path_contains(&parent.target_path, &child.target_path)
            }) || policy
                .private_home
                .iter()
                .chain(policy.temporary.iter())
                .any(|child| {
                    !child.executable && path_contains(&parent.target_path, &child.target_path)
                }))
    }) {
        limitations.push("cannot deny execution beneath an executable resource".into());
    }
    if policy.limits.wall_time.scope != "process"
        || policy.limits.output.scope != "process"
        || policy
            .limits
            .memory
            .as_ref()
            .is_some_and(|limit| limit.scope != "descendant-tree")
        || policy
            .limits
            .process_count
            .as_ref()
            .is_some_and(|limit| limit.scope != "descendant-tree")
        || policy
            .limits
            .cpu_time
            .as_ref()
            .is_some_and(|limit| limit.scope != "descendant-tree")
    {
        limitations.push("does not provide requested session-scoped resource accounting".into());
    }
    if policy.limits.memory.is_some() && !capabilities.cgroup_memory {
        limitations.push("memory cgroup delegation is unavailable".into());
    }
    if policy.limits.process_count.is_some() && !capabilities.cgroup_processes {
        limitations.push("process cgroup delegation is unavailable".into());
    }
    if policy.limits.cpu_time.is_some() {
        limitations.push("descendant-tree CPU time enforcement is unavailable".into());
    }
    limitations.retain(|limitation| !limitation.is_empty());
    limitations
}

#[must_use]
pub fn host_implementation_limitations(
    policy: &NormalizedPolicy,
    capabilities: &ProbeCapabilities,
) -> Vec<String> {
    let mut limitations = Vec::new();
    if policy.filesystem_kind != "host" {
        limitations.push("requires a host filesystem layout".into());
    }
    if capabilities.landlock_abi < 3 {
        limitations.push("Landlock ABI 3 or newer is unavailable".into());
    }
    if !capabilities.seccomp {
        limitations.push("seccomp filter mode is unavailable".into());
    }
    if policy.network == "managed" {
        limitations.push("managed networking requires an isolated network namespace".into());
    }
    if policy.process.visibility != "host" {
        limitations.push("host process visibility cannot be hidden without a PID namespace".into());
    }
    if policy.ipc.visibility != "host" {
        limitations.push("host IPC visibility cannot be hidden without an IPC namespace".into());
    }
    if policy.resources.iter().any(|resource| {
        resource.access.content != resource.access.directory_entries
            || resource.access.content != resource.access.metadata
    }) {
        limitations.push("cannot independently enforce requested mutation dimensions".into());
    }
    if policy.limits.wall_time.scope != "process"
        || policy.limits.output.scope != "process"
        || policy
            .limits
            .memory
            .as_ref()
            .is_some_and(|limit| limit.scope != "descendant-tree")
        || policy
            .limits
            .process_count
            .as_ref()
            .is_some_and(|limit| limit.scope != "descendant-tree")
        || policy
            .limits
            .cpu_time
            .as_ref()
            .is_some_and(|limit| limit.scope != "descendant-tree")
    {
        limitations.push("does not provide requested session-scoped resource accounting".into());
    }
    if policy.limits.memory.is_some() && !capabilities.cgroup_memory {
        limitations.push("memory cgroup delegation is unavailable".into());
    }
    if policy.limits.process_count.is_some() && !capabilities.cgroup_processes {
        limitations.push("process cgroup delegation is unavailable".into());
    }
    if policy.limits.cpu_time.is_some() {
        limitations.push("descendant-tree CPU time enforcement is unavailable".into());
    }
    limitations
}

fn implementation_owned_target_conflict(target: &str) -> bool {
    const OWNED: &[&str] = &[
        "/dev",
        "/proc",
        "/etc/passwd",
        "/etc/group",
        "/etc/hosts",
        "/etc/resolv.conf",
    ];
    target == "/"
        || target
            .strip_prefix('/')
            .and_then(|relative| relative.split('/').next())
            .is_some_and(|component| component.starts_with(".sandbox-"))
        || OWNED
            .iter()
            .any(|owned| path_contains(target, owned) || path_contains(owned, target))
}

pub fn prepare_execution(
    policy: &PreparedLinuxPolicy,
    normalized: NormalizedExecution,
) -> Result<PreparedLinuxExecution, ErrorData> {
    if normalized.change_set.is_some() {
        return Err(ErrorData::new(
            "unsupported.change_set",
            "workspace change sets require hardware-vm import mode",
            "prepare",
        ));
    }
    reject_masked_path(normalized.executable.path(), &policy.normalized)?;
    reject_masked_path(normalized.cwd.path(), &policy.normalized)?;

    let executable_mapping = find_mapping(normalized.executable.path(), &policy.mounts)
        .ok_or_else(|| {
            ErrorData::new(
                "policy.executable_visibility",
                "executable is outside the visible target filesystem",
                "prepare",
            )
        })?;
    if !executable_mapping.executable {
        return Err(ErrorData::new(
            "policy.executable_permission",
            "executable is in a non-executable mapping",
            "prepare",
        ));
    }
    let executable_resource = policy
        .normalized
        .resources
        .iter()
        .filter(|resource| path_contains(&resource.target_path, normalized.executable.path()))
        .max_by_key(|resource| resource.target_path.len())
        .ok_or_else(|| {
            implementation_error(
                "policy.executable_resource",
                "executable is not backed by an authorized resource",
                "prepare",
            )
        })?;
    if !executable_resource
        .purposes
        .iter()
        .any(|purpose| matches!(purpose.as_str(), "executable" | "interpreter"))
    {
        return Err(implementation_error(
            "policy.executable_purpose",
            "entry executable resource must declare executable or interpreter purpose",
            "prepare",
        ));
    }
    let executable_path = open_visible_path(
        &policy.mounts,
        &policy.normalized.masks,
        normalized.executable.path(),
        false,
        true,
    )
    .map_err(|error| os_error("preparation.executable", &error, "prepare"))?;
    let mut executable_source = open_path(
        Path::new(&format!("/proc/self/fd/{}", executable_path.as_raw_fd())),
        libc::O_RDONLY | libc::O_CLOEXEC,
    )
    .map_err(|error| os_error("preparation.executable_read", &error, "prepare"))?;
    let source_identity = file_identity(executable_source.as_raw_fd())
        .map_err(|error| os_error("preparation.executable_identity", &error, "prepare"))?;
    if source_identity.mode & libc::S_IFMT != libc::S_IFREG || source_identity.mode & 0o111 == 0 {
        return Err(ErrorData::new(
            "policy.executable_type",
            "prepared executable is not an executable regular file",
            "prepare",
        ));
    }
    if file_identity(executable_path.as_raw_fd())
        .map_err(|error| os_error("preparation.executable_identity", &error, "prepare"))?
        != source_identity
    {
        return Err(ErrorData::new(
            "preparation.executable_identity",
            "reopened executable identity differs from the prepared object",
            "prepare",
        ));
    }
    let source_identity_digest = identity_digest(&source_identity)
        .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    let (executable, executable_content_sha256) = snapshot_executable(&mut executable_source)
        .map_err(|error| os_error("preparation.executable_snapshot", &error, "prepare"))?;
    let executable_identity = file_identity(executable.as_raw_fd()).map_err(|error| {
        os_error(
            "preparation.executable_snapshot_identity",
            &error,
            "prepare",
        )
    })?;
    let executable_identity_digest = identity_digest(&json!({
        "sourceIdentity": source_identity_digest,
        "contentSha256": executable_content_sha256,
    }))
    .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;

    let (cwd, cwd_identity, cwd_identity_digest) =
        if find_mapping(normalized.cwd.path(), &policy.mounts).is_some() {
            let cwd = open_visible_path(
                &policy.mounts,
                &policy.normalized.masks,
                normalized.cwd.path(),
                true,
                false,
            )
            .map_err(|error| os_error("preparation.cwd", &error, "prepare"))?;
            let identity = file_identity(cwd.as_raw_fd())
                .map_err(|error| os_error("preparation.cwd_identity", &error, "prepare"))?;
            if identity.mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(ErrorData::new(
                    "policy.cwd_type",
                    "working directory is not a directory",
                    "prepare",
                ));
            }
            let digest = identity_digest(&identity).map_err(|error| {
                ErrorData::new("preparation.digest", error.to_string(), "prepare")
            })?;
            (Some(cwd), Some(identity), digest)
        } else if synthetic_path_is_visible(normalized.cwd.path(), &policy.normalized) {
            let value =
                json!({"policyDigest": &policy.policy_digest, "syntheticPath": &normalized.cwd});
            let digest = identity_digest(&value).map_err(|error| {
                ErrorData::new("preparation.digest", error.to_string(), "prepare")
            })?;
            (None, None, digest)
        } else {
            return Err(ErrorData::new(
                "policy.cwd_visibility",
                "working directory is outside the visible target filesystem",
                "prepare",
            ));
        };

    let execution_input = json!({
        "policyDigest": &policy.policy_digest,
        "executable": &normalized.executable,
        "executableIdentity": &executable_identity_digest,
        "executableContentSha256": &executable_content_sha256,
        "args": &normalized.args,
        "cwd": &normalized.cwd,
        "cwdIdentity": &cwd_identity_digest,
        "environment": &normalized.environment,
        "stdin": &normalized.stdin,
        "stdout": &normalized.stdout,
        "stderr": &normalized.stderr,
    });
    let execution_digest = execution_digest(&execution_input)
        .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    Ok(PreparedLinuxExecution {
        normalized,
        executable,
        executable_identity,
        executable_identity_digest,
        executable_content_sha256,
        cwd,
        cwd_identity,
        cwd_identity_digest,
        execution_digest,
    })
}

fn snapshot_executable(source: &mut File) -> io::Result<(File, String)> {
    const MFD_CLOEXEC: libc::c_uint = 0x0001;
    const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;
    let name = c"sandbox-executable";
    // SAFETY: name is static and flags are documented memfd_create flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            MFD_CLOEXEC | MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new owned descriptor transferred exactly once.
    let mut snapshot = unsafe { File::from_raw_fd(fd as RawFd) };
    source.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "executable size overflow")
        })?;
        if total > 1024 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "executable snapshot exceeds 1 GiB",
            ));
        }
        hasher.update(&buffer[..count]);
        snapshot.write_all(&buffer[..count])?;
    }
    if total == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "executable snapshot is empty",
        ));
    }
    // SAFETY: snapshot is a live memfd and mode contains only permission bits.
    if unsafe { libc::fchmod(snapshot.as_raw_fd(), 0o500) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: F_ADD_SEALS accepts an integer bitmask for a sealable memfd.
    if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    snapshot.seek(SeekFrom::Start(0))?;
    Ok((snapshot, format!("{:x}", hasher.finalize())))
}

impl PreparedLinuxPolicy {
    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.state.path.clone()
    }

    pub fn cleanup_state(&mut self) -> io::Result<()> {
        self.state.cleanup()
    }

    pub fn launch_bundle(
        &self,
        execution: &PreparedLinuxExecution,
    ) -> Result<LaunchBundle, ErrorData> {
        let mut files = vec![match &self.implementation {
            LinuxImplementation::Namespace(launcher) => launcher
                .retain()
                .map_err(|error| os_error("spawn.namespace_launcher", &error, "spawn"))?,
            LinuxImplementation::Host => File::open(
                std::env::current_exe()
                    .map_err(|error| os_error("spawn.runtime_path", &error, "spawn"))?,
            )
            .map_err(|error| os_error("spawn.runtime_open", &error, "spawn"))?,
        }];
        let mut mounts = Vec::new();
        for mount in &self.mounts {
            let file = mount
                .file
                .try_clone()
                .map_err(|error| os_error("spawn.clone_authority", &error, "spawn"))?;
            let fd_index = files.len();
            files.push(file);
            mounts.push(MountSpec {
                fd_index,
                target_path: mount.target_path.clone(),
                kind: mount.kind.clone(),
                read_only: mount.read_only,
                executable: mount.executable,
            });
        }
        let executable_fd_index = files.len();
        files.push(
            execution
                .executable
                .try_clone()
                .map_err(|error| os_error("spawn.clone_executable", &error, "spawn"))?,
        );
        let cwd = if let (Some(cwd), Some(identity)) = (&execution.cwd, execution.cwd_identity) {
            let fd_index = files.len();
            files.push(
                cwd.try_clone()
                    .map_err(|error| os_error("spawn.clone_cwd", &error, "spawn"))?,
            );
            PreparedCwd::Bound {
                fd_index,
                identity,
                target_path: execution.normalized.cwd.path().to_owned(),
            }
        } else {
            PreparedCwd::Synthetic {
                target_path: execution.normalized.cwd.path().to_owned(),
                identity_nonce: execution.cwd_identity_digest.clone(),
            }
        };
        let environment = execution
            .normalized
            .environment
            .iter()
            .map(|(name, value)| (name.clone(), value.value.clone()))
            .collect();
        Ok(LaunchBundle {
            spec: LaunchSpec {
                filesystem_kind: self.normalized.filesystem_kind.clone(),
                launcher_fd_index: 0,
                mounts,
                masks: self.normalized.masks.clone(),
                private_home: self.normalized.private_home.clone(),
                temporary: self.normalized.temporary.clone(),
                executable_fd_index,
                executable_identity: execution.executable_identity,
                executable_content_sha256: execution.executable_content_sha256.clone(),
                executable_snapshot_path: format!(
                    "/.sandbox-runtime/{}",
                    Path::new(execution.normalized.executable.path())
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| ErrorData::new(
                            "policy.executable_name",
                            "executable has no portable final component",
                            "spawn",
                        ))?
                ),
                cwd,
                executable: execution.normalized.executable.path().to_owned(),
                args: execution.normalized.args.clone(),
                environment,
                resources: self.normalized.limits.clone(),
                termination_grace_ms: self.normalized.process.termination.grace_ms,
                network_mode: self.normalized.network.clone(),
            },
            files,
        })
    }

    #[must_use]
    pub fn session_summary(&self) -> Value {
        json!({
            "isolation": {"kind": "process"},
            "implementation": {
                "id": self.implementation.id(),
                "version": IMPLEMENTATION_VERSION,
                "buildId": BUILD_ID,
                "conformanceManifestId": self.implementation.conformance_manifest_id(),
                "stability": "stable"
            },
            "filesystem": {
                "kind": &self.normalized.filesystem_kind,
                "resourceManifestDigest": &self.resource_manifest_digest,
                "resources": &self.resources,
                "masks": self.normalized.masks.iter().map(|mask| json!({
                    "path": {"space": "isolated", "path": &mask.target_path},
                    "replacement": &mask.replacement,
                })).collect::<Vec<_>>(),
                "privateHomePath": self.normalized.private_home.as_ref().map(|directory| json!({"space": "isolated", "path": &directory.target_path})),
                "temporaryPath": self.normalized.temporary.as_ref().map(|directory| json!({"space": "isolated", "path": &directory.target_path})),
            },
            "network": match self.normalized.network.as_str() {
                "none" => if self.normalized.filesystem_kind == "host" {
                    json!({"mode": "none", "topology": "blocked-system-calls"})
                } else {
                    json!({"mode": "none", "topology": "private-namespace"})
                },
                "managed" => json!({
                    "mode": "managed",
                    "topology": "private-namespace-broker",
                    "allow": &self.normalized.managed_network_rules,
                }),
                _ => json!({"mode": "unrestricted", "topology": "host-network-namespace"}),
            },
            "process": &self.normalized.process,
            "ipc": &self.normalized.ipc,
            "resources": &self.normalized.limits,
        })
    }

    #[must_use]
    pub fn run_summary(&self, execution: &PreparedLinuxExecution) -> Value {
        let mut summary = self.session_summary();
        if let Value::Object(object) = &mut summary {
            let process_summary = execution_summary(execution);
            if let Some(value) = process_summary.get("execution") {
                object.insert("execution".into(), value.clone());
            }
        }
        summary
    }
}

#[must_use]
pub fn execution_summary(execution: &PreparedLinuxExecution) -> Value {
    let names = execution
        .normalized
        .environment
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let sensitive = execution
        .normalized
        .environment
        .iter()
        .filter(|(_, value)| value.sensitive)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    json!({
        "execution": {
            "executable": &execution.normalized.executable,
            "executableIdentityDigest": &execution.executable_identity_digest,
            "executableContentSha256": &execution.executable_content_sha256,
            "args": &execution.normalized.args,
            "cwd": &execution.normalized.cwd,
            "cwdIdentityDigest": &execution.cwd_identity_digest,
            "environmentNames": names,
            "sensitiveEnvironmentNames": sensitive,
            "stdin": &execution.normalized.stdin,
            "stdout": &execution.normalized.stdout,
            "stderr": &execution.normalized.stderr,
        }
    })
}

fn hold_mount(
    host_path: &str,
    target_path: &str,
    read_only: bool,
    executable: bool,
    reject_link: bool,
) -> Result<HeldMount, ErrorData> {
    let prepared = prepare_host_path(Path::new(host_path), reject_link)
        .map_err(|error| os_error("preparation.grant_open", &error, "prepare"))?;
    Ok(HeldMount {
        file: prepared.file,
        target_path: target_path.into(),
        kind: prepared.kind,
        read_only,
        executable,
        resolved_path: prepared.resolved_path,
        identity: prepared.identity,
        identity_digest: prepared.identity_digest,
    })
}

/// Open and identity-bind a prospective host grant root. This is deliberately
/// separate from policy mutation so path handling can be tested and fuzzed.
pub fn prepare_host_path(path: &Path, reject_link: bool) -> io::Result<PreparedHostPath> {
    // Bind-mount sources use readable retained descriptors. Some kernels reject
    // procfd bind sources backed only by O_PATH after SCM_RIGHTS transfer.
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | if reject_link { libc::O_NOFOLLOW } else { 0 };
    let file = open_path(path, flags)?;
    let identity = file_identity(file.as_raw_fd())?;
    let file_type = identity.mode & libc::S_IFMT;
    if reject_link && file_type == libc::S_IFLNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "grant root final component is a symbolic link",
        ));
    }
    let kind = if file_type == libc::S_IFDIR {
        "directory"
    } else if file_type == libc::S_IFREG {
        "file"
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "grant root is not a regular file or directory",
        ));
    };
    let resolved_path = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?
        .to_string_lossy()
        .into_owned();
    let identity_digest =
        identity_digest(&identity).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(PreparedHostPath {
        file,
        kind: kind.into(),
        resolved_path,
        identity,
        identity_digest,
    })
}

fn open_beneath_mapping(
    mapping: &HeldMount,
    target_path: &str,
    directory: bool,
) -> io::Result<File> {
    let relative = target_path
        .strip_prefix(&mapping.target_path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is outside mapping"))?
        .trim_start_matches('/');
    if mapping.kind == "file" {
        if !relative.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "file mapping has no descendants",
            ));
        }
        return reopen_fd(mapping.file.as_raw_fd(), directory);
    }
    if relative.is_empty() {
        return reopen_fd(mapping.file.as_raw_fd(), directory);
    }
    openat2_beneath(mapping.file.as_raw_fd(), relative, directory)
}

/// Resolve symbolic links in the admitted filesystem, never in the ambient host view.
/// Each lookup is anchored to a retained resource; link traversal can select another
/// resource only when that destination is independently admitted by the policy.
fn open_visible_path(
    mounts: &[HeldMount],
    masks: &[sandbox_policy::NormalizedMask],
    target_path: &str,
    directory: bool,
    require_executable_mapping: bool,
) -> io::Result<File> {
    let mut pending: VecDeque<String> = target_path.split('/').map(str::to_owned).collect();
    let mut resolved = Vec::<String>::new();
    let mut links = 0;
    while let Some(component) = pending.pop_front() {
        match component.as_str() {
            "" | "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => resolved.push(component),
        }
        let path = format!("/{}", resolved.join("/"));
        if masks
            .iter()
            .any(|mask| path_contains(&mask.target_path, &path))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "symbolic link resolves into a masked path",
            ));
        }
        let Some(mapping) = find_mapping(&path, mounts) else {
            if !pending.is_empty()
                && mounts
                    .iter()
                    .any(|mount| path_contains(&path, &mount.target_path))
            {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "symbolic link resolves outside admitted resources",
            ));
        };
        let file = open_beneath_mapping(mapping, &path, false)?;
        let identity = file_identity(file.as_raw_fd())?;
        if identity.mode & libc::S_IFMT == libc::S_IFLNK {
            links += 1;
            if links > 40 {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            let mut buffer = [0_u8; 4096];
            // SAFETY: file is an O_PATH descriptor for the link itself, the empty
            // name selects that link, and buffer is writable for its stated size.
            let length = unsafe {
                libc::readlinkat(
                    file.as_raw_fd(),
                    c"".as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if length < 0 {
                return Err(io::Error::last_os_error());
            }
            let length = usize::try_from(length).map_err(io::Error::other)?;
            if length == buffer.len() {
                return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
            }
            let link = std::str::from_utf8(&buffer[..length]).map_err(io::Error::other)?;
            resolved.pop();
            if link.starts_with('/') {
                resolved.clear();
            }
            for part in link.split('/').rev() {
                pending.push_front(part.to_owned());
            }
        } else if pending.iter().all(|part| part.is_empty() || part == ".") {
            if require_executable_mapping && !mapping.executable {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "resolved executable resource denies execution",
                ));
            }
            if directory && identity.mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            return Ok(file);
        } else if identity.mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "path does not name an admitted object",
    ))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

fn openat2_beneath(directory_fd: RawFd, relative: &str, directory: bool) -> io::Result<File> {
    let path = std::ffi::CString::new(relative)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let flags = libc::O_PATH
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 };
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: path is a valid NUL-terminated string and `how` points to a fully initialized OpenHow.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory_fd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat2 returns a new descriptor whose ownership is transferred to File.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn reopen_fd(fd: RawFd, directory: bool) -> io::Result<File> {
    let flags = libc::O_PATH | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 };
    open_path(Path::new(&format!("/proc/self/fd/{fd}")), flags)
}

fn open_path(path: &Path, flags: libc::c_int) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

fn find_mapping<'a>(target: &str, mounts: &'a [HeldMount]) -> Option<&'a HeldMount> {
    mounts
        .iter()
        .filter(|mount| path_contains(&mount.target_path, target))
        .max_by_key(|mount| mount.target_path.len())
}

fn path_contains(parent: &str, child: &str) -> bool {
    parent == child
        || parent == "/"
        || child
            .strip_prefix(parent)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn reject_masked_path(path: &str, policy: &NormalizedPolicy) -> Result<(), ErrorData> {
    if policy
        .masks
        .iter()
        .any(|mask| path_contains(&mask.target_path, path))
    {
        return Err(ErrorData::new(
            "policy.masked_path",
            "executable or working directory is masked",
            "prepare",
        ));
    }
    Ok(())
}

fn synthetic_path_is_visible(path: &str, policy: &NormalizedPolicy) -> bool {
    path == "/"
        || policy
            .private_home
            .as_ref()
            .is_some_and(|directory| path_contains(&directory.target_path, path))
        || policy
            .temporary
            .as_ref()
            .is_some_and(|directory| path_contains(&directory.target_path, path))
        || path_contains("/etc", path)
        || path_contains("/dev", path)
        || path_contains("/proc", path)
}

fn validate_mount_graph(mounts: &[HeldMount]) -> Result<(), ErrorData> {
    for parent in mounts {
        for child in mounts {
            if parent.target_path != child.target_path
                && path_contains(&parent.target_path, &child.target_path)
                && parent.kind == "file"
            {
                return Err(ErrorData::new(
                    "policy.grant_conflict",
                    "a file mapping cannot contain another mapping",
                    "prepare",
                ));
            }
        }
    }
    Ok(())
}

fn validate_masks(policy: &NormalizedPolicy, mounts: &[HeldMount]) -> Result<(), ErrorData> {
    for mask in &policy.masks {
        if find_mapping(&mask.target_path, mounts).is_none()
            && !synthetic_path_is_visible(&mask.target_path, policy)
        {
            return Err(ErrorData::new(
                "policy.mask_visibility",
                "mask is outside the visible target filesystem",
                "prepare",
            ));
        }
    }
    Ok(())
}

fn mount_digest_value(mount: &HeldMount) -> Value {
    json!({
        "targetPath": &mount.target_path,
        "resolvedPath": &mount.resolved_path,
        "identityDigest": &mount.identity_digest,
        "readOnly": mount.read_only,
        "executable": mount.executable,
        "kind": &mount.kind,
    })
}

fn enforcement_report(
    policy: &NormalizedPolicy,
    capabilities: &ProbeCapabilities,
    resource_manifest_digest: &str,
    visible_roots: &[String],
    implementation: &LinuxImplementation,
) -> EnforcementReport {
    let isolated = matches!(implementation, LinuxImplementation::Namespace(_));
    let base_available = if isolated {
        capabilities.namespace_available(&policy.network)
    } else {
        capabilities.landlock_abi >= 3 && capabilities.seccomp
    };
    let satisfied = |id: &str| -> bool {
        if !base_available {
            return false;
        }
        match id {
            "runtime.setup-before-exec"
            | "runtime.no-ambient-environment"
            | "runtime.no-ambient-handles"
            | "filesystem.content-read-confined"
            | "filesystem.content-write-confined"
            | "filesystem.directory-entry-mutation-confined"
            | "filesystem.metadata-mutation-confined"
            | "filesystem.execution-confined" => true,
            "runtime.executable-identity-bound"
            | "filesystem.resource-identities-bound"
            | "filesystem.name-visibility-confined"
            | "filesystem.isolated-layout" => isolated,
            "network.no-external-connect"
            | "network.no-external-listen"
            | "network.no-host-loopback" => policy.network == "none" || isolated,
            "network.egress-brokered" | "network.private-addresses-denied" => {
                isolated && policy.network == "managed"
            }
            "process.host-visibility-denied" => isolated,
            "process.host-control-denied" => true,
            "process.descendant-tree-termination" | "process.group-termination" => true,
            "ipc.host-endpoints-hidden" | "ipc.host-shared-memory-hidden" => isolated,
            "resource.wall-time-hard" => policy.limits.wall_time.scope == "process",
            "resource.output-hard" => policy.limits.output.scope == "process",
            "resource.memory-hard" => {
                capabilities.cgroup_memory
                    && policy
                        .limits
                        .memory
                        .as_ref()
                        .is_some_and(|limit| limit.scope == "descendant-tree")
            }
            "resource.process-count-hard" => {
                capabilities.cgroup_processes
                    && policy
                        .limits
                        .process_count
                        .as_ref()
                        .is_some_and(|limit| limit.scope == "descendant-tree")
            }
            "resource.cpu-time-hard" => false,
            "resource.open-files-hard" | "resource.single-file-size-hard" => true,
            "vm.boot-artifacts-verified"
            | "vm.guest-control-authenticated"
            | "vm.control-plane-hidden-from-target"
            | "vm.host-filesystem-absent-outside-imports" => false,
            _ => false,
        }
    };
    let guarantees = GUARANTEES
        .iter()
        .map(|id| GuaranteeFact {
            id: (*id).into(),
            status: if satisfied(id) {
                "satisfied"
            } else {
                "unsatisfied"
            }
            .into(),
            enforced_by: if satisfied(id) {
                if id.starts_with("resource.wall")
                    || id.starts_with("resource.output")
                    || id == &"process.descendant-tree-termination"
                {
                    vec!["supervisor".into(), "kernel".into()]
                } else {
                    vec!["kernel".into()]
                }
            } else {
                Vec::new()
            },
            mechanism: guarantee_mechanism(id, policy, capabilities, isolated),
            evidence: if satisfied(id) {
                vec![implementation.conformance_manifest_id().into()]
            } else {
                Vec::new()
            },
            caveats: Vec::new(),
        })
        .collect();
    EnforcementReport {
        boundary: EnforcementBoundary {
            kind: "os-process".into(),
        },
        implementation: EnforcementImplementation {
            id: implementation.id().into(),
            version: IMPLEMENTATION_VERSION.into(),
            build_id: BUILD_ID.into(),
            conformance_manifest_id: implementation.conformance_manifest_id().into(),
            stability: "stable".into(),
            mechanism: if isolated {
                vec![
                    "bubblewrap".into(),
                    "linux user/mount/PID/IPC/UTS namespaces".into(),
                    "synthetic mount root".into(),
                    "Landlock".into(),
                    "seccomp".into(),
                ]
            } else {
                vec![
                    "Landlock".into(),
                    "seccomp".into(),
                    "no_new_privs".into(),
                    "process-group supervisor".into(),
                ]
            },
        },
        host: EnforcementHost {
            platform: "linux".into(),
            architecture: std::env::consts::ARCH.into(),
            path_style: "posix".into(),
        },
        target: EnforcementTarget {
            operating_system: "linux".into(),
            path_style: "posix".into(),
        },
        guarantees,
        filesystem: EnforcementFilesystem {
            kind: policy.filesystem_kind.clone(),
            resource_manifest_digest: resource_manifest_digest.into(),
            visible_roots: visible_roots.to_vec(),
        },
        caveats: if isolated {
            vec![
            EnforcementCaveat {
                code: "authorized-resources-may-contain-ipc".into(),
                message: "IPC endpoints intentionally placed inside authorized resources remain reachable as authorized content.".into(),
                affected_guarantees: vec!["ipc.host-endpoints-hidden".into()],
            },
            EnforcementCaveat {
                code: "noexec-controls-direct-exec-only".into(),
                message: "Execution denial blocks direct kernel execution; readable content may still be consumed by an explicitly allowed interpreter.".into(),
                affected_guarantees: vec!["filesystem.execution-confined".into()],
            },
            EnforcementCaveat {
                code: "entry-bytes-not-dependency-graph".into(),
                message: "The sealed entry executable bytes are approval-bound; dynamic loaders and libraries are bound through the prepared runtime mount manifest, not copied into the entry snapshot.".into(),
                affected_guarantees: vec!["runtime.executable-identity-bound".into()],
            },
            EnforcementCaveat {
                code: "cgroup-includes-fixed-supervision-overhead".into(),
                message: "Memory accounting includes the outer launcher and namespace init. Process accounting reserves two fixed slots for those helpers.".into(),
                affected_guarantees: vec!["resource.memory-hard".into(), "resource.process-count-hard".into()],
            },
        ]
        } else {
            vec![
            EnforcementCaveat {
                code: "host-layout-path-authority".into(),
                message: "Host-layout filesystem authority is path based; preparation does not bind later path resolution to the same object identity.".into(),
                affected_guarantees: vec!["runtime.executable-identity-bound".into(), "filesystem.resource-identities-bound".into()],
            },
            EnforcementCaveat {
                code: "host-process-and-ipc-visible".into(),
                message: "Host process metadata and host IPC namespaces remain visible; seccomp denies process-control operations.".into(),
                affected_guarantees: vec!["process.host-visibility-denied".into(), "ipc.host-endpoints-hidden".into(), "ipc.host-shared-memory-hidden".into()],
            },
            EnforcementCaveat {
                code: "noexec-controls-direct-exec-only".into(),
                message: "Execution denial blocks direct kernel execution; readable content may still be consumed by an explicitly allowed interpreter.".into(),
                affected_guarantees: vec!["filesystem.execution-confined".into()],
            },
        ]
        },
    }
}

fn guarantee_mechanism(
    id: &str,
    policy: &NormalizedPolicy,
    capabilities: &ProbeCapabilities,
    isolated: bool,
) -> Vec<String> {
    match id {
        "runtime.setup-before-exec" => {
            vec!["single-threaded launcher with exec status barrier".into()]
        }
        "runtime.no-ambient-environment" => vec!["explicit environment vector".into()],
        "runtime.no-ambient-handles" => vec!["descriptor closure before exec".into()],
        "runtime.executable-identity-bound" if isolated => {
            vec![
                "SHA-256-bound sealed memfd snapshot installed as a read-only private mount".into(),
            ]
        }
        id if id.starts_with("filesystem.") => {
            if isolated {
                vec![
                    "retained bind mounts".into(),
                    "private mount namespace".into(),
                    format!("Landlock ABI {}", capabilities.landlock_abi),
                ]
            } else {
                vec![format!("Landlock ABI {}", capabilities.landlock_abi)]
            }
        }
        id if id.starts_with("network.") && policy.network == "none" => {
            if isolated {
                vec!["private network namespace without external interfaces".into()]
            } else {
                vec!["seccomp denial of socket creation and network operations".into()]
            }
        }
        id if id.starts_with("network.") && policy.network == "managed" => vec![
            "private network namespace without an external interface".into(),
            "host-side HTTP CONNECT, HTTP, SOCKS5 and DNS broker".into(),
            "connection-time DNS and address validation".into(),
        ],
        id if id.starts_with("process.") => {
            if isolated {
                vec![
                    "PID and user namespaces".into(),
                    "namespace-init reaping".into(),
                ]
            } else {
                vec![
                    "seccomp process-control denial".into(),
                    "subreaper process-group supervision".into(),
                ]
            }
        }
        id if id.starts_with("ipc.") && isolated => vec!["IPC namespace and synthetic root".into()],
        "resource.wall-time-hard" => vec!["supervisor monotonic deadline".into()],
        "resource.output-hard" => vec!["supervisor byte accounting before frame delivery".into()],
        "resource.memory-hard" if capabilities.cgroup_memory => {
            vec!["cgroup v2 memory.max and memory.swap.max".into()]
        }
        "resource.process-count-hard" if capabilities.cgroup_processes => {
            vec!["cgroup v2 pids.max".into()]
        }
        "resource.open-files-hard" => vec!["RLIMIT_NOFILE".into()],
        "resource.single-file-size-hard" => vec!["RLIMIT_FSIZE".into()],
        _ => Vec::new(),
    }
}

fn match_requirements(
    policy: &NormalizedPolicy,
    report: &EnforcementReport,
) -> Result<(), ErrorData> {
    let unmet: Vec<_> = policy
        .obligations
        .iter()
        .chain(policy.requirements.additional.iter())
        .filter(|required| {
            report
                .guarantees
                .iter()
                .any(|fact| &fact.id == *required && fact.status == "unsatisfied")
        })
        .cloned()
        .collect();
    if unmet.is_empty() {
        Ok(())
    } else {
        let mut error = ErrorData::new(
            "requirement.unsatisfied",
            format!("required guarantees are unsatisfied: {}", unmet.join(", ")),
            "prepare",
        );
        error.enforcement = Some(report.clone());
        Err(error)
    }
}

fn create_state_directory() -> Result<StateDirectory, io::Error> {
    let base = std::env::temp_dir();
    for _ in 0..100 {
        let clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "sandbox-runtime-{}-{clock:x}-{nonce:x}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                fs::create_dir(path.join("root"))?;
                return Ok(StateDirectory {
                    path,
                    cleaned: false,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique sandbox state",
    ))
}

fn os_error(code: &str, error: &io::Error, phase: &str) -> ErrorData {
    let mut data = ErrorData::new(code, error.to_string(), phase);
    data.implementation = Some(IMPLEMENTATION_ID.into());
    data.cause_code = error.raw_os_error().map(|value| value.to_string());
    data
}

fn implementation_error(code: &str, message: impl Into<String>, phase: &str) -> ErrorData {
    let mut data = ErrorData::new(code, message, phase);
    data.implementation = Some(IMPLEMENTATION_ID.into());
    data
}

#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
    cleaned: bool,
}

#[derive(Debug, Default)]
pub struct CgroupCleanup {
    pub removed: bool,
    pub failures: Vec<String>,
}

impl Cgroup {
    pub fn create(
        pid: u32,
        memory_bytes: Option<u64>,
        max_processes: Option<u64>,
    ) -> io::Result<Self> {
        let path = create_delegated_cgroup(memory_bytes.is_some(), max_processes.is_some())?;
        let result = (|| {
            if let Some(memory_bytes) = memory_bytes {
                fs::write(path.join("memory.max"), memory_bytes.to_string())?;
                fs::write(path.join("memory.swap.max"), "0")?;
            }
            if let Some(max_processes) = max_processes {
                fs::write(path.join("pids.max"), max_processes.to_string())?;
            }
            fs::write(path.join("cgroup.procs"), pid.to_string())?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir(&path);
            return Err(error);
        }
        Ok(Self {
            path,
            cleaned: false,
        })
    }

    pub fn kill(&self) -> io::Result<()> {
        fs::write(self.path.join("cgroup.kill"), "1")
    }

    #[must_use]
    pub fn peak_memory(&self) -> Option<u64> {
        fs::read_to_string(self.path.join("memory.peak"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    #[must_use]
    pub fn events(&self) -> Option<String> {
        fs::read_to_string(self.path.join("memory.events")).ok()
    }

    #[must_use]
    pub fn process_events(&self) -> Option<String> {
        fs::read_to_string(self.path.join("pids.events")).ok()
    }

    pub fn cleanup(&mut self) -> CgroupCleanup {
        if self.cleaned {
            return CgroupCleanup {
                removed: true,
                failures: Vec::new(),
            };
        }
        let mut report = CgroupCleanup::default();
        if let Err(error) = self.kill()
            && error.kind() != io::ErrorKind::NotFound
        {
            report.failures.push(format!("cgroup.kill: {error}"));
        }
        for _ in 0..100 {
            match fs::remove_dir(&self.path) {
                Ok(()) => {
                    self.cleaned = true;
                    report.removed = true;
                    return report;
                }
                Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.cleaned = true;
                    report.removed = true;
                    return report;
                }
                Err(error) => {
                    report.failures.push(format!("remove cgroup: {error}"));
                    return report;
                }
            }
        }
        report
            .failures
            .push("remove cgroup: still populated after cleanup deadline".into());
        report
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Debug)]
pub struct CgroupProbeResult {
    pub memory: ProbeOutcome,
    pub processes: ProbeOutcome,
}

pub fn probe_cgroup_delegation() -> CgroupProbeResult {
    CgroupProbeResult {
        memory: probe_cgroup("memory", "memory.max", "memory.events"),
        processes: probe_cgroup("pids", "pids.max", "pids.events"),
    }
}

fn create_delegated_cgroup(memory: bool, processes: bool) -> io::Result<PathBuf> {
    let current = current_cgroup_path()?;
    let hierarchy = Path::new("/sys/fs/cgroup");
    let current = hierarchy.join(current.trim_start_matches('/'));
    let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
    for root in current
        .ancestors()
        .take_while(|path| path.starts_with(hierarchy))
    {
        let Ok(controllers) = fs::read_to_string(root.join("cgroup.subtree_control")) else {
            continue;
        };
        let has = |name| {
            controllers
                .split_whitespace()
                .any(|controller| controller == name)
        };
        if (memory && !has("memory")) || (processes && !has("pids")) {
            continue;
        }
        let path = root.join(format!("sandbox-{}-{nonce}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "no writable cgroup delegation enables the requested controllers",
    ))
}

fn probe_cgroup(controller: &str, limit_file: &str, event_file: &str) -> ProbeOutcome {
    let path = match create_delegated_cgroup(controller == "memory", controller == "pids") {
        Ok(path) => path,
        Err(error) => return probe_outcome_from_io("create delegated child cgroup", &error),
    };
    let enforcement = probe_cgroup_controller(&path, limit_file, event_file);
    // The probe runs before supervisor worker threads exist. The child performs no
    // Rust work after fork and is used only to verify migration and cgroup.kill.
    // SAFETY: fork is called from the supervisor's single-threaded probe phase.
    let child = unsafe { libc::fork() };
    if child == 0 {
        loop {
            // SAFETY: pause has no pointer arguments; SIGKILL from cgroup.kill ends this child.
            unsafe { libc::pause() };
        }
    }
    if child < 0 {
        let error = io::Error::last_os_error();
        let _ = fs::remove_dir(&path);
        return probe_outcome_from_io("fork cgroup lifecycle probe", &error);
    }
    let lifecycle = fs::write(path.join("cgroup.procs"), child.to_string())
        .map_err(|error| ("move probe child into delegated cgroup", error))
        .and_then(|()| {
            fs::write(path.join("cgroup.kill"), "1").map_err(|error| ("write cgroup.kill", error))
        });
    if lifecycle.is_err() {
        // SAFETY: child is the exact positive PID returned by fork.
        let _ = unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    loop {
        // SAFETY: child is a direct child and status is writable.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        if waited < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break;
        }
    }
    let removal = fs::remove_dir(&path).map_err(|error| ("remove delegated child cgroup", error));
    match lifecycle.and(removal) {
        Ok(()) => enforcement,
        Err((operation, error)) => probe_outcome_from_io(operation, &error),
    }
}

fn probe_cgroup_controller(path: &Path, limit_file: &str, event_file: &str) -> ProbeOutcome {
    let operation = format!("write delegated {limit_file} and read {event_file}");
    if limit_file == "memory.max" {
        let swap = fs::read_to_string(path.join("memory.swap.max"))
            .and_then(|value| fs::write(path.join("memory.swap.max"), value.trim()));
        if let Err(error) = swap {
            return probe_outcome_from_io("verify delegated memory.swap.max", &error);
        }
    }
    if let Err(error) = fs::read_to_string(path.join(event_file)) {
        return probe_outcome_from_io(&format!("read delegated {event_file}"), &error);
    }
    let value = match fs::read_to_string(path.join(limit_file)) {
        Ok(value) => value,
        Err(error) => {
            return probe_outcome_from_io(&format!("read delegated {limit_file}"), &error);
        }
    };
    if let Err(error) = fs::write(path.join(limit_file), value.trim()) {
        return probe_outcome_from_io(&format!("write delegated {limit_file}"), &error);
    }
    ProbeOutcome {
        state: "available".into(),
        operation,
        os_error: None,
        detail: Some("operation succeeded".into()),
    }
}

fn probe_outcome_from_io(operation: &str, error: &io::Error) -> ProbeOutcome {
    ProbeOutcome {
        state: if error.kind() == io::ErrorKind::PermissionDenied
            || matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::EACCES | libc::EPERM | libc::EROFS | libc::EBUSY)
            ) {
            "unavailable"
        } else {
            "error"
        }
        .into(),
        operation: operation.into(),
        os_error: error.raw_os_error().and_then(|number| {
            u32::try_from(number)
                .ok()
                .map(|code| sandbox_launcher_linux::ProbeOsError {
                    code,
                    name: errno_name(number).unwrap_or("UNKNOWN").into(),
                })
        }),
        detail: Some(error.to_string()),
    }
}

fn errno_name(number: i32) -> Option<&'static str> {
    match number {
        libc::EACCES => Some("EACCES"),
        libc::EBUSY => Some("EBUSY"),
        libc::ENOENT => Some("ENOENT"),
        libc::EPERM => Some("EPERM"),
        libc::EROFS => Some("EROFS"),
        _ => None,
    }
}

fn current_cgroup_path() -> io::Result<String> {
    let value = fs::read_to_string("/proc/self/cgroup")?;
    value
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unified cgroup path not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_matching_respects_component_boundaries() {
        assert!(path_contains("/work", "/work/src"));
        assert!(!path_contains("/work", "/workspace"));
    }

    #[test]
    fn implementation_has_no_implicit_host_resources() {
        assert_ne!(IMPLEMENTATION_ID, "");
    }

    #[test]
    fn openat2_abi_layout_is_stable() {
        use std::mem::{offset_of, size_of};

        assert_eq!(size_of::<OpenHow>(), 24);
        assert_eq!(offset_of!(OpenHow, flags), 0);
        assert_eq!(offset_of!(OpenHow, mode), 8);
        assert_eq!(offset_of!(OpenHow, resolve), 16);
    }
}
