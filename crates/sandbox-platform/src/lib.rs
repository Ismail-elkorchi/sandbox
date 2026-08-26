#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::result_large_err)]

use sandbox_digest::{execution_digest, identity_digest, policy_digest};
use sandbox_launcher_linux::{FileIdentity, LaunchSpec, MountSpec, PreparedCwd, file_identity};
use sandbox_policy::{
    BACKEND_ID, BACKEND_VERSION, BUILD_ID, CONFORMANCE_MANIFEST_ID, EnforcementBoundary,
    EnforcementCaveat, EnforcementConformance, EnforcementHost, EnforcementReport,
    EnforcementRuntimeView, EnforcementTarget, ErrorData, GUARANTEES, GuaranteeFact,
    NormalizedExecution, NormalizedPolicy,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeCapabilities {
    pub namespaces: bool,
    pub network_namespace: bool,
    pub mount_setattr: bool,
    pub landlock_abi: u32,
    pub seccomp: bool,
    pub execveat: bool,
    pub cgroup_memory: bool,
    pub cgroup_processes: bool,
    pub errors: Vec<String>,
}

impl ProbeCapabilities {
    #[must_use]
    pub fn backend_available(&self, network: &str) -> bool {
        self.namespaces
            && self.mount_setattr
            && self.landlock_abi > 0
            && self.seccomp
            && self.execveat
            && (network == "unrestricted" || self.network_namespace)
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
    pub requested_path: Option<String>,
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
pub struct PreparedGrantSummary {
    pub requested_host_path: String,
    pub resolved_host_path: String,
    pub host_identity_digest: String,
    pub target_path: String,
    pub access: String,
    pub execution: String,
}

#[derive(Debug)]
pub struct PreparedLinuxPolicy {
    pub normalized: NormalizedPolicy,
    pub mounts: Vec<HeldMount>,
    pub grants: Vec<PreparedGrantSummary>,
    pub runtime_manifest_digest: String,
    pub visible_roots: Vec<String>,
    pub enforcement: EnforcementReport,
    pub policy_digest: String,
    state: StateDirectory,
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

pub fn host_physical_memory() -> io::Result<u64> {
    // SAFETY: sysconf is called with fixed supported selector constants and has no pointer arguments.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    // SAFETY: sysconf is called with fixed supported selector constants and has no pointer arguments.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_size <= 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(pages)
        .ok()
        .and_then(|value| value.checked_mul(u64::try_from(page_size).ok()?))
        .ok_or_else(|| io::Error::other("physical memory size overflow"))
}

pub fn prepare_policy(
    normalized: NormalizedPolicy,
    capabilities: &ProbeCapabilities,
) -> Result<PreparedLinuxPolicy, ErrorData> {
    if !capabilities.backend_available(&normalized.network) {
        return Err(ErrorData::new(
            "unsupported.linux_capabilities",
            format!(
                "linux-namespace-v1 is unavailable: {}",
                capabilities.errors.join(", ")
            ),
            "probe",
        ));
    }
    let state = create_state_directory()
        .map_err(|error| os_error("preparation.state", &error, "prepare"))?;
    let mut mounts = Vec::new();
    if normalized.runtime_view == "system" {
        for (host, target, executable) in system_runtime_roots() {
            if Path::new(host).exists() {
                let mount = hold_mount(host, target, true, *executable, None, false)?;
                mounts.push(mount);
            }
        }
    }

    let mut grants = Vec::new();
    for grant in &normalized.grants {
        let reject_link = grant.root_resolution == "reject-if-link";
        let mount = hold_mount(
            &grant.requested_host_path,
            &grant.target_path,
            grant.access == "read",
            grant.execution == "allow",
            Some(grant.requested_host_path.clone()),
            reject_link,
        )?;
        grants.push(PreparedGrantSummary {
            requested_host_path: grant.requested_host_path.clone(),
            resolved_host_path: mount.resolved_path.clone(),
            host_identity_digest: mount.identity_digest.clone(),
            target_path: grant.target_path.clone(),
            access: grant.access.clone(),
            execution: grant.execution.clone(),
        });
        mounts.push(mount);
    }
    validate_mount_graph(&mounts)?;
    validate_masks(&normalized, &mounts)?;

    let runtime_mounts: Vec<_> = mounts
        .iter()
        .filter(|mount| mount.requested_path.is_none())
        .map(mount_digest_value)
        .collect();
    let runtime_manifest_digest = identity_digest(&runtime_mounts)
        .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    let visible_roots = mounts
        .iter()
        .filter(|mount| mount.requested_path.is_none())
        .map(|mount| mount.target_path.clone())
        .collect::<Vec<_>>();
    let enforcement = enforcement_report(
        &normalized,
        capabilities,
        &runtime_manifest_digest,
        &visible_roots,
    );
    match_requirements(&normalized, &enforcement)?;
    let policy_input = json!({
        "digestFormat": 1_u64,
        "protocolMajor": 1_u64,
        "backend": {"id": BACKEND_ID, "version": BACKEND_VERSION, "stability": "stable"},
        "targetOperatingSystem": "linux",
        "policy": &normalized,
        "runtimeManifestDigest": &runtime_manifest_digest,
        "mounts": mounts.iter().map(mount_digest_value).collect::<Vec<_>>(),
    });
    let policy_digest = policy_digest(&policy_input)
        .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    Ok(PreparedLinuxPolicy {
        normalized,
        mounts,
        grants,
        runtime_manifest_digest,
        visible_roots,
        enforcement,
        policy_digest,
        state,
    })
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
    reject_masked_path(&normalized.executable, &policy.normalized)?;
    reject_masked_path(&normalized.cwd, &policy.normalized)?;

    let executable_mapping =
        find_mapping(&normalized.executable, &policy.mounts).ok_or_else(|| {
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
    let executable_path = open_visible_path(
        executable_mapping,
        &policy.mounts,
        &normalized.executable,
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

    let (cwd, cwd_identity, cwd_identity_digest) = if let Some(cwd_mapping) =
        find_mapping(&normalized.cwd, &policy.mounts)
    {
        let cwd = open_visible_path(cwd_mapping, &policy.mounts, &normalized.cwd, true, false)
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
        let digest = identity_digest(&identity)
            .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
        (Some(cwd), Some(identity), digest)
    } else if synthetic_path_is_visible(&normalized.cwd, &policy.normalized) {
        let value =
            json!({"policyDigest": &policy.policy_digest, "syntheticPath": &normalized.cwd});
        let digest = identity_digest(&value)
            .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
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
        "resources": &normalized.resources,
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
        let mut files = Vec::new();
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
                target_path: execution.normalized.cwd.clone(),
            }
        } else {
            PreparedCwd::Synthetic {
                target_path: execution.normalized.cwd.clone(),
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
                root_path: self.state.path.join("root").to_string_lossy().into_owned(),
                mounts,
                masks: self.normalized.masks.clone(),
                private_home_enabled: self.normalized.private_home.enabled,
                private_home_size_bytes: self.normalized.private_home.size_bytes,
                private_home_executable: self.normalized.private_home.executable,
                temporary_size_bytes: self.normalized.temporary.size_bytes,
                temporary_executable: self.normalized.temporary.executable,
                executable_fd_index,
                executable_identity: execution.executable_identity,
                executable_content_sha256: execution.executable_content_sha256.clone(),
                executable_snapshot_path: format!(
                    "/.sandbox-runtime/{}",
                    Path::new(&execution.normalized.executable)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| ErrorData::new(
                            "policy.executable_name",
                            "executable has no portable final component",
                            "spawn",
                        ))?
                ),
                cwd,
                executable: execution.normalized.executable.clone(),
                args: execution.normalized.args.clone(),
                environment,
                resources: execution.normalized.resources.clone(),
                network_mode: self.normalized.network.clone(),
            },
            files,
        })
    }

    #[must_use]
    pub fn session_summary(&self) -> Value {
        json!({
            "isolation": {"kind": "process"},
            "backend": {"id": BACKEND_ID, "version": BACKEND_VERSION, "stability": "stable"},
            "filesystem": {
                "runtimeView": &self.normalized.runtime_view,
                "runtimeManifestDigest": &self.runtime_manifest_digest,
                "grants": &self.grants,
                "masks": &self.normalized.masks,
                "privateHomePath": if self.normalized.private_home.enabled { Value::String("/home/sandbox".into()) } else { Value::Null },
                "temporaryPath": "/tmp",
            },
            "network": match self.normalized.network.as_str() {
                "none" => json!({"mode": "none", "topology": "private-namespace"}),
                "managed" => json!({
                    "mode": "managed",
                    "topology": "private-namespace-broker",
                    "allow": &self.normalized.managed_network_rules,
                }),
                _ => json!({"mode": "unrestricted", "topology": "host-network-namespace"}),
            },
            "process": &self.normalized.process,
            "resources": &self.normalized.resources,
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
        "resources": &execution.normalized.resources,
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
    requested_path: Option<String>,
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
        requested_path,
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

fn open_visible_path(
    mapping: &HeldMount,
    mounts: &[HeldMount],
    target_path: &str,
    directory: bool,
    require_executable_mapping: bool,
) -> io::Result<File> {
    match open_beneath_mapping(mapping, target_path, directory) {
        Ok(file) => Ok(file),
        Err(error)
            if mapping.requested_path.is_none()
                && error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EXDEV || code == libc::ELOOP) =>
        {
            let file = open_path(
                Path::new(target_path),
                libc::O_PATH | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 },
            )?;
            let resolved = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
            let visible = mounts.iter().any(|candidate| {
                candidate.requested_path.is_none()
                    && (!require_executable_mapping || candidate.executable)
                    && host_path_contains(Path::new(&candidate.resolved_path), &resolved)
            });
            if visible {
                Ok(file)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "system symlink resolves outside the prepared runtime view",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn host_path_contains(parent: &Path, child: &Path) -> bool {
    parent == child || child.strip_prefix(parent).is_ok()
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_BENEATH: u64 = 0x08;

fn openat2_beneath(directory_fd: RawFd, relative: &str, directory: bool) -> io::Result<File> {
    let path = std::ffi::CString::new(relative)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let flags = libc::O_PATH | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 };
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
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
        || path_contains("/tmp", path)
        || policy.private_home.enabled && path_contains("/home/sandbox", path)
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
        "explicit": mount.requested_path.is_some(),
    })
}

fn system_runtime_roots() -> &'static [(&'static str, &'static str, bool)] {
    &[
        ("/bin", "/bin", true),
        ("/sbin", "/sbin", true),
        ("/usr/bin", "/usr/bin", true),
        ("/usr/sbin", "/usr/sbin", true),
        ("/lib", "/lib", true),
        ("/lib64", "/lib64", true),
        ("/usr/lib", "/usr/lib", true),
        ("/usr/lib64", "/usr/lib64", true),
        ("/usr/share", "/usr/share", false),
        ("/etc/alternatives", "/etc/alternatives", false),
        ("/etc/ld.so.cache", "/etc/ld.so.cache", false),
        ("/etc/ssl", "/etc/ssl", false),
        ("/etc/ca-certificates", "/etc/ca-certificates", false),
        ("/etc/localtime", "/etc/localtime", false),
        ("/etc/timezone", "/etc/timezone", false),
    ]
}

fn enforcement_report(
    policy: &NormalizedPolicy,
    capabilities: &ProbeCapabilities,
    runtime_manifest_digest: &str,
    visible_roots: &[String],
) -> EnforcementReport {
    let base_available = capabilities.backend_available(&policy.network);
    let satisfied = |id: &str| -> bool {
        if !base_available {
            return false;
        }
        match id {
            "network.no-external-connect"
            | "network.no-external-listen"
            | "network.no-host-loopback" => policy.network != "unrestricted",
            "network.egress-brokered" => policy.network == "managed",
            "network.private-addresses-denied" => policy.network == "managed",
            "ipc.host-endpoints-hidden-outside-grants" => policy.network != "unrestricted",
            "resource.memory-hard" => capabilities.cgroup_memory,
            "resource.process-count-hard" => capabilities.cgroup_processes,
            "resource.cpu-time-hard" => false,
            id if id.starts_with("vm.") => false,
            _ => true,
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
                    || id == &"process.complete-tree-termination"
                {
                    vec!["supervisor".into(), "kernel".into()]
                } else {
                    vec!["kernel".into()]
                }
            } else {
                Vec::new()
            },
            mechanism: guarantee_mechanism(id, policy, capabilities),
            evidence: if satisfied(id) {
                vec![CONFORMANCE_MANIFEST_ID.into()]
            } else {
                Vec::new()
            },
            caveats: Vec::new(),
        })
        .collect();
    EnforcementReport {
        boundary: EnforcementBoundary {
            kind: "os-process".into(),
            backend_id: BACKEND_ID.into(),
            backend_version: BACKEND_VERSION.into(),
            stability: "stable".into(),
            mechanism: vec!["linux user/mount/PID/IPC/UTS namespaces".into(), "synthetic mount root".into(), "Landlock".into(), "seccomp".into()],
        },
        host: EnforcementHost {
            platform: "linux".into(),
            architecture: std::env::consts::ARCH.into(),
            path_style: "posix".into(),
        },
        target: EnforcementTarget { operating_system: "linux".into(), path_style: "posix".into() },
        guarantees,
        runtime_view: EnforcementRuntimeView {
            kind: policy.runtime_view.clone(),
            manifest_digest: runtime_manifest_digest.into(),
            visible_roots: visible_roots.to_vec(),
        },
        caveats: vec![
            EnforcementCaveat {
                code: "explicit-grants-may-contain-ipc".into(),
                message: "IPC endpoints intentionally placed inside explicit grants are not hidden unless separately blocked by protocol controls.".into(),
                affected_guarantees: vec!["ipc.host-endpoints-hidden-outside-grants".into()],
            },
            EnforcementCaveat {
                code: "noexec-controls-direct-exec-only".into(),
                message: "A noexec mount blocks direct kernel execution; readable content may still be consumed by an explicitly allowed interpreter.".into(),
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
        ],
        conformance: EnforcementConformance { manifest_id: CONFORMANCE_MANIFEST_ID.into(), build_id: BUILD_ID.into() },
    }
}

fn guarantee_mechanism(
    id: &str,
    policy: &NormalizedPolicy,
    capabilities: &ProbeCapabilities,
) -> Vec<String> {
    match id {
        "runtime.setup-before-exec" => {
            vec!["single-threaded launcher with exec status barrier".into()]
        }
        "runtime.no-ambient-environment" => vec!["explicit environment vector".into()],
        "runtime.no-ambient-handles" => vec!["descriptor closure before exec".into()],
        "runtime.executable-identity-bound" => {
            vec![
                "SHA-256-bound sealed memfd snapshot installed as a read-only private mount".into(),
            ]
        }
        id if id.starts_with("filesystem.") => vec![
            "retained bind mounts".into(),
            "private mount namespace".into(),
            format!("Landlock ABI {}", capabilities.landlock_abi),
        ],
        id if id.starts_with("network.") && policy.network == "none" => {
            vec!["private network namespace without external interfaces".into()]
        }
        id if id.starts_with("network.") && policy.network == "managed" => vec![
            "private network namespace without an external interface".into(),
            "host-side HTTP CONNECT, HTTP, SOCKS5 and DNS broker".into(),
            "connection-time DNS and address validation".into(),
        ],
        id if id.starts_with("process.") => vec![
            "PID and user namespaces".into(),
            "namespace-init reaping".into(),
        ],
        id if id.starts_with("ipc.") => vec!["IPC namespace and synthetic root".into()],
        "resource.wall-time-hard" => vec!["supervisor monotonic deadline".into()],
        "resource.output-hard" => vec!["supervisor byte accounting before frame delivery".into()],
        "resource.memory-hard" if capabilities.cgroup_memory => vec!["cgroup v2 memory.max".into()],
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
        .requirements
        .required
        .iter()
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
    data.cause_code = error.raw_os_error().map(|value| value.to_string());
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
        let current = current_cgroup_path()?;
        let root = Path::new("/sys/fs/cgroup").join(current.trim_start_matches('/'));
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("sandbox-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        let result = (|| {
            if let Some(memory_bytes) = memory_bytes {
                fs::write(path.join("memory.max"), memory_bytes.to_string())?;
            }
            if let Some(max_processes) = max_processes {
                let total = max_processes.checked_add(2).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "process limit overflow")
                })?;
                fs::write(path.join("pids.max"), total.to_string())?;
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

pub fn probe_cgroup_delegation() -> (bool, bool) {
    let Ok(current) = current_cgroup_path() else {
        return (false, false);
    };
    let root = Path::new("/sys/fs/cgroup").join(current.trim_start_matches('/'));
    let controllers = fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
    let has_memory = controllers
        .split_whitespace()
        .any(|value| value == "memory");
    let has_pids = controllers.split_whitespace().any(|value| value == "pids");
    if !has_memory && !has_pids {
        return (false, false);
    }
    let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
    let path = root.join(format!("sandbox-probe-{}-{nonce}", std::process::id()));
    if fs::create_dir(&path).is_err() {
        return (false, false);
    }
    let memory = has_memory
        && path.join("memory.events").exists()
        && fs::read_to_string(path.join("memory.max"))
            .ok()
            .is_some_and(|value| fs::write(path.join("memory.max"), value.trim()).is_ok());
    let pids = has_pids
        && path.join("pids.events").exists()
        && fs::read_to_string(path.join("pids.max"))
            .ok()
            .is_some_and(|value| fs::write(path.join("pids.max"), value.trim()).is_ok());
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
        let _ = fs::remove_dir(path);
        return (false, false);
    }
    let moved = fs::write(path.join("cgroup.procs"), child.to_string()).is_ok();
    let killed = moved && fs::write(path.join("cgroup.kill"), "1").is_ok();
    if !killed {
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
    let removed = fs::remove_dir(path).is_ok();
    if moved && killed && removed {
        (memory, pids)
    } else {
        (false, false)
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
    fn runtime_never_includes_user_managed_roots() {
        let paths: Vec<_> = system_runtime_roots()
            .iter()
            .map(|(_, target, _)| *target)
            .collect();
        for denied in [
            "/home",
            "/root",
            "/opt",
            "/usr/local",
            "/var",
            "/run",
            "/tmp",
        ] {
            assert!(!paths.contains(&denied));
        }
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
