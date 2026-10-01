//! Operator-accepted native Linux evidence. Compilation, prerequisite probes,
//! and authenticated guest reports cannot create qualification records.
use sandsurf_native::PrivateFileAccess;
use sandsurf_native::local::{create_private_file, open_private_file};
use sandsurf_native::storage::{publish_new_file, sync_directory};
use sandsurf_protocol::{
    Counter, Digest, Domain, Qualification, Resources, VmEngine, bytes_digest, digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};
use std::path::Path;

// The complete inventory fits in one bounded HostInspection control frame.
const MAX_RECORDS: usize = 16;
const MAX_RECORD_BYTES: u64 = 12 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeConfiguration {
    pub build_digest: Digest,
    pub platform: String,
    pub architecture: String,
    pub hardware_digest: Digest,
    pub engine: VmEngine,
    pub engine_digest: Digest,
    pub image_digest: Digest,
    pub kernel_digest: Digest,
    pub initramfs_digest: Option<Digest>,
    pub nic_configuration_digest: Digest,
    pub storage_configuration_digest: Digest,
    pub resources: Resources,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationScope {
    Lifecycle,
    Resources,
    CpuTime,
    HostMemory,
    StorageBudgets,
    ManagedChannels,
    NativeNetwork,
    DiskSnapshots,
    FullState,
    Images,
    Distribution,
}

impl QualificationScope {
    fn required_checks(self) -> &'static [&'static str] {
        match self {
            Self::Lifecycle => &[
                "administrator-root",
                "ordinary-reboot",
                "management-disabled",
                "forced-power-off",
                "host-service-restart",
            ],
            Self::Resources => &[
                "cpu-quota",
                "memory-cap",
                "guest-cgroups-deleted",
                "management-disabled",
                "output-cap",
                "snapshot-cap",
                "image-cap",
                "channel-cap",
                "network-cap",
                "aggregate-physical-storage-cap",
                "shared-host-worker-cap",
            ],
            Self::CpuTime => &["cpu-quota", "guest-cgroups-deleted", "management-disabled"],
            Self::HostMemory => &[
                "memory-cap",
                "guest-cgroups-deleted",
                "management-disabled",
                "native-oom-containment",
            ],
            Self::StorageBudgets => &[
                "disk-capacity",
                "snapshot-cap",
                "image-cap",
                "output-cap",
                "interrupted-staging-budget",
            ],
            Self::ManagedChannels => &[
                "channel-cap",
                "request-cap",
                "session-cap",
                "control-responsiveness",
            ],
            Self::NativeNetwork => &[
                "network-cap",
                "management-disabled",
                "policy-revocation",
                "malformed-packet-bounds",
            ],
            Self::DiskSnapshots => &[
                "disk-capture",
                "independent-fork",
                "rollback-authority",
                "capture-interruption",
            ],
            Self::FullState => &[
                "suspend-resume",
                "restore-authority",
                "restore-output-lineage",
                "restore-interruption",
            ],
            Self::Images => &[
                "installed-image-boot",
                "package-install",
                "persistent-system-files",
                "kernel-selection",
            ],
            Self::Distribution => &["installed-package", "service-restart", "logout-lifetime"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HardwareRun {
    pub configuration: NativeConfiguration,
    pub scope: QualificationScope,
    pub observed_unix_millis: Counter,
    /// Names of host-observed checks. The accepting operator attests that these
    /// were actual VM experiments; the format itself cannot prove that claim.
    pub passed_checks: Vec<String>,
    pub evidence_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedQualification {
    pub run: HardwareRun,
    pub accepted_by: String,
    pub accepted_unix_millis: Counter,
    pub record_digest: Digest,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn build_digest() -> io::Result<Digest> {
    static BUILD: std::sync::OnceLock<Digest> = std::sync::OnceLock::new();
    if let Some(value) = BUILD.get() {
        return Ok(value.clone());
    }
    #[cfg(target_os = "linux")]
    let path = Path::new("/proc/self/exe").to_path_buf();
    #[cfg(not(target_os = "linux"))]
    let path = std::env::current_exe()?;
    let value = hash_file(&path, 256 * 1024 * 1024)?;
    let _ = BUILD.set(value.clone());
    Ok(value)
}

/// Native host facts only; no guest input, test result or compile flag can
/// stand in for the exact kernel, CPU and KVM configuration under test.
#[cfg(target_os = "linux")]
pub fn hardware_digest() -> io::Result<Digest> {
    let kernel = bounded_read(Path::new("/proc/sys/kernel/osrelease"), 4096)?;
    let cpu = bounded_read(Path::new("/proc/cpuinfo"), 1024 * 1024)?;
    // Omit changing frequency fields, retain topology/ISA/model information.
    let cpu: Vec<_> = std::str::from_utf8(&cpu)
        .map_err(io::Error::other)?
        .lines()
        .filter(|line| {
            line.starts_with("model name")
                || line.starts_with("vendor_id")
                || line.starts_with("flags")
                || line.starts_with("Features")
                || line.starts_with("CPU part")
                || line.starts_with("CPU implementer")
                || line.starts_with("cpu cores")
                || line.starts_with("siblings")
        })
        .collect();
    let kvm = bounded_read(
        Path::new("/sys/module/kvm/parameters/enable_vmware_backdoor"),
        4096,
    )
    .ok();
    digest(
        Domain::Authority,
        &(std::env::consts::ARCH, kernel, cpu, kvm),
    )
    .map_err(io::Error::other)
}

#[cfg(not(target_os = "linux"))]
pub fn hardware_digest() -> io::Result<Digest> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained native hardware qualification is Linux-only; this platform is unqualified",
    ))
}

fn validate_run(root: &Path, run: &HardwareRun) -> io::Result<()> {
    if !cfg!(target_os = "linux")
        || run.configuration.platform != "linux"
        || run.configuration.architecture != std::env::consts::ARCH
        || run.configuration.engine != VmEngine::Firecracker
        || run.configuration.build_digest != build_digest()?
        || run.configuration.hardware_digest != hardware_digest()?
    {
        return Err(invalid(
            "hardware evidence does not match this native Linux build/host",
        ));
    }
    run.configuration
        .resources
        .validate()
        .map_err(io::Error::other)?;
    if run.scope == QualificationScope::Resources
        && matches!(
            crate::resources::capabilities(root).complete_enforcement,
            sandsurf_protocol::Capability::Unsupported { .. }
        )
    {
        return Err(invalid(
            "this build does not implement complete resource enforcement; qualify implemented mechanisms individually",
        ));
    }
    if run.observed_unix_millis == Counter::ZERO
        || run.observed_unix_millis > now()?
        || run.passed_checks.len() > 64
        || run
            .passed_checks
            .iter()
            .any(|check| check.is_empty() || check.len() > 128)
        || run
            .scope
            .required_checks()
            .iter()
            .any(|required| !run.passed_checks.iter().any(|check| check == required))
    {
        return Err(invalid(
            "hardware evidence is incomplete or exceeds qualification bounds",
        ));
    }
    Ok(())
}

/// Explicit operator entry point. There is deliberately no guest/SDK command
/// and no constructor that qualifies a driver during compilation or probing.
/// The evidence is copied as actual retained bytes, not a reference or URL.
pub fn accept_linux(
    root: &Path,
    run: HardwareRun,
    evidence: &Path,
    operator: &str,
) -> io::Result<RetainedQualification> {
    validate_run(root, &run)?;
    if operator.is_empty() || operator.len() > 256 || operator.contains(['\0', '\n', '\r']) {
        return Err(invalid(
            "qualification requires an explicit operator identity",
        ));
    }
    let evidence = read_private(evidence, MAX_EVIDENCE_BYTES)?;
    if evidence.is_empty() || bytes_digest(&evidence) != run.evidence_digest {
        return Err(invalid(
            "retained hardware evidence bytes do not match the run",
        ));
    }
    let accepted_unix_millis = now()?;
    let record_digest = digest(Domain::Authority, &(&run, operator, accepted_unix_millis))
        .map_err(io::Error::other)?;
    let record = RetainedQualification {
        run,
        accepted_by: operator.into(),
        accepted_unix_millis,
        record_digest,
    };
    let directory = root.join("qualification");
    sandsurf_native::local::ensure_private_directory(&directory)?;
    let lease = match create_private_file(&directory.join("writer.lock")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_private_file(&directory.join("writer.lock"), PrivateFileAccess::ReadWrite)?
        }
        Err(error) => return Err(error),
    };
    lease.try_lock().map_err(io::Error::other)?;
    let entries: Vec<_> = std::fs::read_dir(&directory)?.collect::<Result<_, _>>()?;
    if entries.len() > MAX_RECORDS * 2 {
        return Err(invalid("retained qualification store is full"));
    }
    let encoded = serde_json::to_vec(&record).map_err(io::Error::other)?;
    if encoded.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("qualification record exceeds bound"));
    }
    publish(
        &directory,
        record.record_digest.as_str(),
        "evidence",
        &evidence,
    )?;
    publish(&directory, record.record_digest.as_str(), "json", &encoded)?;
    sync_directory(&directory)?;
    Ok(record)
}

fn publish(directory: &Path, identity: &str, suffix: &str, bytes: &[u8]) -> io::Result<()> {
    let final_path = directory.join(format!("{identity}.{suffix}"));
    let staging = directory.join(format!("{identity}.{suffix}.staging"));
    let mut file = create_private_file(&staging)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    publish_new_file(&staging, &final_path)?;
    sync_directory(directory)
}

/// Bounded inspection. Any corruption is reported to the caller, never
/// converted to a zero count or an assertion of qualification.
pub fn inspect(root: &Path) -> io::Result<Vec<RetainedQualification>> {
    if !cfg!(target_os = "linux") {
        return Ok(Vec::new());
    }
    let directory = root.join("qualification");
    match sandsurf_native::local::canonical_private_directory(&directory) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    let mut records = Vec::new();
    let mut visited = 0;
    for entry in std::fs::read_dir(&directory)? {
        visited += 1;
        if visited > MAX_RECORDS * 2 + 1 {
            return Err(invalid("qualification inventory exceeds bound"));
        }
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let encoded = read_private(&entry.path(), MAX_RECORD_BYTES)?;
        let record: RetainedQualification =
            serde_json::from_slice(&encoded).map_err(io::Error::other)?;
        if record.accepted_by.is_empty()
            || record.accepted_by.len() > 256
            || record.accepted_by.contains(['\0', '\n', '\r'])
            || record.accepted_unix_millis < record.run.observed_unix_millis
            || record.accepted_unix_millis > now()?
        {
            return Err(invalid("qualification operator acceptance is invalid"));
        }
        if digest(
            Domain::Authority,
            &(
                &record.run,
                &record.accepted_by,
                record.accepted_unix_millis,
            ),
        )
        .map_err(io::Error::other)?
            != record.record_digest
            || entry.path().file_stem().and_then(|value| value.to_str())
                != Some(record.record_digest.as_str())
        {
            return Err(invalid("qualification record identity is corrupt"));
        }
        // Records for a previous build/hardware remain retained but do not
        // qualify this build; their evidence is still validated on inspection.
        let evidence = read_private(
            &directory.join(format!("{}.evidence", record.record_digest.as_str())),
            MAX_EVIDENCE_BYTES,
        )?;
        if bytes_digest(&evidence) != record.run.evidence_digest {
            return Err(invalid("qualification evidence is corrupt"));
        }
        if validate_run(root, &record.run).is_ok() {
            records.push(record);
        }
    }
    records.sort_by(|a, b| a.record_digest.as_str().cmp(b.record_digest.as_str()));
    Ok(records)
}

pub fn lookup(
    root: &Path,
    configuration: &NativeConfiguration,
    scope: QualificationScope,
) -> Qualification {
    match inspect(root) {
        Ok(records) => records
            .into_iter()
            .find(|record| record.run.configuration == *configuration && record.run.scope == scope)
            .map_or_else(
                || {
                    unqualified(
                        "no operator-accepted hardware run for this exact native configuration",
                    )
                },
                |record| Qualification::Qualified {
                    evidence: record.record_digest,
                },
            ),
        Err(_) => unqualified("retained qualification evidence is unavailable or corrupt"),
    }
}

fn unqualified(reason: &str) -> Qualification {
    Qualification::Unqualified {
        reasons: vec![reason.into()],
    }
}

pub fn hash_file(path: &Path, bound: u64) -> io::Result<Digest> {
    let mut file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > bound {
        return Err(invalid("native artifact exceeds bound"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > bound {
            return Err(invalid("native artifact grew beyond bound"));
        }
        hash.update(&buffer[..count]);
    }
    format!("{:x}", hash.finalize())
        .try_into()
        .map_err(io::Error::other)
}

fn bounded_read(path: &Path, bound: u64) -> io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut value = Vec::new();
    file.take(bound + 1).read_to_end(&mut value)?;
    if value.len() as u64 > bound {
        return Err(invalid("native observation exceeds bound"));
    }
    Ok(value)
}

fn read_private(path: &Path, bound: u64) -> io::Result<Vec<u8>> {
    let file = open_private_file(path, PrivateFileAccess::ReadOnly)?;
    let mut value = Vec::new();
    file.take(bound + 1).read_to_end(&mut value)?;
    if value.len() as u64 > bound {
        return Err(invalid("retained qualification exceeds bound"));
    }
    Ok(value)
}

fn now() -> io::Result<Counter> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    Counter::try_from(u64::try_from(millis).map_err(io::Error::other)?).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_reports_and_compilation_are_not_hardware_qualification() {
        let identity = bytes_digest(b"a guest assertion or compile result");
        let run = HardwareRun {
            configuration: NativeConfiguration {
                build_digest: identity.clone(),
                platform: "guest-linux".into(),
                architecture: std::env::consts::ARCH.into(),
                hardware_digest: identity.clone(),
                engine: VmEngine::Firecracker,
                engine_digest: identity.clone(),
                image_digest: identity.clone(),
                kernel_digest: identity.clone(),
                initramfs_digest: None,
                nic_configuration_digest: identity.clone(),
                storage_configuration_digest: identity.clone(),
                resources: Resources::from_geometry(
                    Counter::ONE,
                    Counter::ONE,
                    Counter::ONE,
                    Counter::ONE,
                    Counter::ONE,
                )
                .unwrap(),
            },
            scope: QualificationScope::Resources,
            observed_unix_millis: Counter::ONE,
            passed_checks: QualificationScope::Resources
                .required_checks()
                .iter()
                .map(|value| (*value).into())
                .collect(),
            evidence_digest: identity,
        };
        assert!(validate_run(Path::new("/var/tmp"), &run).is_err());
        assert!(matches!(
            lookup(
                Path::new("/a-nonexistent-qualification-store"),
                &run.configuration,
                run.scope
            ),
            Qualification::Unqualified { .. }
        ));
    }

    #[test]
    fn resource_qualification_requires_external_root_boundary_checks() {
        let checks = QualificationScope::Resources.required_checks();
        assert!(checks.contains(&"guest-cgroups-deleted"));
        assert!(checks.contains(&"management-disabled"));
        assert!(checks.contains(&"network-cap"));
        assert!(!checks.contains(&"compilation"));
    }
}
