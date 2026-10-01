use sandsurf_native::storage::object_name;
use sandsurf_protocol::{
    Digest, Domain, FullSnapshotMetadata, NativeFullCapture, OperationId, Snapshot,
    SnapshotConsistency, SnapshotId, SnapshotKind, digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const COPY_BUFFER: usize = 1024 * 1024;

/// Retention follows the source machine's physical volume, including after
/// native destruction. Forks read here and write to their own distinct volume.
pub fn root(host_root: &Path, snapshot: &Snapshot) -> PathBuf {
    host_root
        .join("machines")
        .join(object_name(snapshot.request.machine_id.as_str()))
        .join("snapshots")
}

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    Json(serde_json::Error),
    Contract(sandsurf_protocol::Invalid),
    Invalid(&'static str),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "snapshot I/O: {error}"),
            Self::Json(error) => write!(output, "snapshot manifest: {error}"),
            Self::Contract(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}

impl std::error::Error for SnapshotError {}
impl From<io::Error> for SnapshotError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for SnapshotError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_protocol::Invalid> for SnapshotError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}

pub type Result<T> = std::result::Result<T, SnapshotError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotManifest {
    format_version: u16,
    snapshot_id: SnapshotId,
    request_digest: Digest,
    image_digest: Digest,
    source_generation: sandsurf_protocol::Counter,
    source_revision: sandsurf_protocol::Counter,
    disk_container: DiskContainer,
    system_disk_digest: Digest,
    system_disk_bytes: sandsurf_protocol::Counter,
    consistency: SnapshotConsistency,
    sensitive: bool,
    kind: SnapshotKind,
    full: Option<FullSnapshotMetadata>,
    boot: sandsurf_image::boot::FrozenBoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DiskContainer {
    RawExt4,
    Vhdx,
}

impl DiskContainer {
    fn system_name(self) -> &'static str {
        match self {
            Self::RawExt4 => "system.ext4",
            Self::Vhdx => "system.vhdx",
        }
    }

    fn storage_format(self) -> Result<crate::storage::DiskFormat> {
        match self {
            Self::RawExt4 => Ok(crate::storage::DiskFormat::Raw),
            #[cfg(target_os = "windows")]
            Self::Vhdx => Ok(crate::storage::DiskFormat::Vhdx),
            #[cfg(not(target_os = "windows"))]
            Self::Vhdx => Err(SnapshotError::Invalid(
                "VHDX storage requires the Windows host driver",
            )),
        }
    }
}

pub struct CaptureResult {
    pub disk_digest: Digest,
    pub manifest_digest: Digest,
    pub full: Option<FullSnapshotMetadata>,
    container: DiskContainer,
}

pub fn published_filesystem(root: &Path, snapshot: &Snapshot) -> Result<Option<CaptureResult>> {
    let directory = root.join(object_name(snapshot.request.id.as_str()));
    if !directory.exists() {
        return Ok(None);
    }
    Ok(Some(verify_published(&directory, snapshot)?))
}

pub fn capture_filesystem(
    root: &Path,
    snapshot: &Snapshot,
    source_disk: &Path,
    image: &sandsurf_image::VerifiedImage,
) -> Result<CaptureResult> {
    if snapshot.request.kind != SnapshotKind::Disk
        || image.manifest_digest != snapshot.image_digest.as_str()
    {
        return Err(SnapshotError::Invalid(
            "disk capture image differs from host admission",
        ));
    }
    private_directory(root)?;
    let final_directory = root.join(object_name(snapshot.request.id.as_str()));
    if final_directory.exists() {
        return verify_published(&final_directory, snapshot);
    }
    let stage = root.join(format!(
        ".{}.{}.capture",
        object_name(snapshot.request.id.as_str()),
        object_name(snapshot.request.operation_id.as_str())
    ));
    private_directory(&stage)?;
    let source_container = disk_container(source_disk)?;
    let container = DiskContainer::RawExt4;
    let disk = stage.join(container.system_name());
    let disk_digest = capture_disk(
        source_disk,
        &disk,
        snapshot.system_disk_bytes.get(),
        source_container,
    )?;
    let manifest = SnapshotManifest {
        format_version: 1,
        snapshot_id: snapshot.request.id.clone(),
        request_digest: snapshot.request_digest.clone(),
        image_digest: snapshot.image_digest.clone(),
        source_generation: snapshot.request.expected_generation,
        source_revision: snapshot.request.expected_revision,
        disk_container: container,
        system_disk_digest: disk_digest.clone(),
        system_disk_bytes: snapshot.system_disk_bytes,
        consistency: SnapshotConsistency::Crash,
        sensitive: snapshot.sensitive,
        kind: SnapshotKind::Disk,
        full: None,
        boot: capture_boot(image, &disk, &stage)?,
    };
    let manifest_digest = digest(Domain::Snapshot, &manifest)?;
    write_manifest(&stage.join("manifest.json"), &manifest)?;
    sync_directory(&stage)?;
    match sandsurf_native::storage::publish_new_directory(&stage, &final_directory) {
        Ok(()) => sync_directory(root)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            remove_stage(&stage)?;
            return verify_published(&final_directory, snapshot);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(CaptureResult {
        disk_digest,
        manifest_digest,
        full: None,
        container,
    })
}

pub fn capture_full(
    root: &Path,
    snapshot: &Snapshot,
    system_disk: &Path,
    native_directory: &Path,
    native: NativeFullCapture,
) -> Result<CaptureResult> {
    if snapshot.request.kind != SnapshotKind::Full || !snapshot.sensitive {
        return Err(SnapshotError::Invalid(
            "full capture requires a sensitive full snapshot admission",
        ));
    }
    if native.executions.len() > 65_536
        || serde_json::to_vec(&native.executions)?.len() > sandsurf_protocol::MAX_CONTROL_BYTES / 2
    {
        return Err(SnapshotError::Invalid(
            "full snapshot execution membership exceeds its bound",
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    for execution in &native.executions {
        if execution.admission.validate().is_err()
            || execution.admission.machine_id != snapshot.request.machine_id
            || execution.admission.generation != snapshot.request.expected_generation
            || !identities.insert(&execution.admission.execution_id)
            || execution
                .observation
                .as_ref()
                .is_some_and(|report| report.request != execution.admission)
        {
            return Err(SnapshotError::Invalid(
                "full capture execution identity mismatch",
            ));
        }
    }
    private_directory(root)?;
    let source_container = disk_container(system_disk)?;
    let container = DiskContainer::RawExt4;
    let final_directory = root.join(object_name(snapshot.request.id.as_str()));
    if final_directory.exists() {
        return verify_published(&final_directory, snapshot);
    }
    let stage = root.join(format!(
        ".{}.{}.capture",
        object_name(snapshot.request.id.as_str()),
        object_name(snapshot.request.operation_id.as_str())
    ));
    private_directory(&stage)?;
    let disk_digest = capture_disk(
        system_disk,
        &stage.join(container.system_name()),
        snapshot.system_disk_bytes.get(),
        source_container,
    )?;
    let memory_bound = snapshot
        .resources
        .memory_mib
        .get()
        .checked_mul(1024 * 1024)
        .ok_or(SnapshotError::Invalid("snapshot memory bound overflow"))?;
    let integrated_state_bound = memory_bound
        .checked_add(1024 * 1024 * 1024)
        .ok_or(SnapshotError::Invalid("snapshot state bound overflow"))?;
    if native
        .memory
        .as_ref()
        .is_some_and(|memory| memory.bytes.get() == 0 || memory.bytes.get() > memory_bound)
        || native.snapshot_state.bytes.get() == 0
        || native.snapshot_state.bytes.get() > integrated_state_bound
        || native.reconnect_state.bytes.get() == 0
        || native.reconnect_state.bytes.get() > 1024 * 1024
    {
        return Err(SnapshotError::Invalid(
            "native full snapshot artifact exceeds its bound",
        ));
    }
    for (name, artifact) in [
        ("snapshot.vmstate", &native.snapshot_state),
        ("reconnect.json", &native.reconnect_state),
    ] {
        copy_and_verify(
            &native_directory.join(name),
            &stage.join(name),
            artifact.bytes.get(),
            Some(&artifact.digest),
        )?;
    }
    if let Some(memory) = &native.memory {
        copy_and_verify(
            &native_directory.join("memory"),
            &stage.join("memory"),
            memory.bytes.get(),
            Some(&memory.digest),
        )?;
    }
    let full = FullSnapshotMetadata {
        engine: native.engine,
        engine_version: native.engine_version,
        architecture: native.architecture,
        configuration_digest: native.configuration_digest,
        snapshot_state: native.snapshot_state,
        memory: native.memory,
        reconnect_state: native.reconnect_state,
        executions: native.executions,
        generation: native.generation,
        // A capture can only become fork-safe through an explicit, separately
        // admitted defaults contract. Ordinary full snapshots default closed.
        fork_safe: false,
    };
    let manifest = SnapshotManifest {
        format_version: 1,
        snapshot_id: snapshot.request.id.clone(),
        request_digest: snapshot.request_digest.clone(),
        image_digest: snapshot.image_digest.clone(),
        source_generation: snapshot.request.expected_generation,
        source_revision: snapshot.request.expected_revision,
        disk_container: container,
        system_disk_digest: disk_digest.clone(),
        system_disk_bytes: snapshot.system_disk_bytes,
        consistency: SnapshotConsistency::Machine,
        sensitive: true,
        kind: SnapshotKind::Full,
        full: Some(full.clone()),
        boot: crate::storage::copy_boot(&native_directory.join("boot"), &stage.join("boot"))?,
    };
    let manifest_digest = digest(Domain::Snapshot, &manifest)?;
    write_manifest(&stage.join("manifest.json"), &manifest)?;
    sync_directory(&stage)?;
    match sandsurf_native::storage::publish_new_directory(&stage, &final_directory) {
        Ok(()) => sync_directory(root)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            remove_stage(&stage)?;
            return verify_published(&final_directory, snapshot);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(CaptureResult {
        disk_digest,
        manifest_digest,
        full: Some(full),
        container,
    })
}

pub fn materialize_fork(
    root: &Path,
    snapshot: &Snapshot,
    destination: &Path,
    profile: &sandsurf_image::identity::CloneProfile,
) -> Result<()> {
    let expected = snapshot
        .system_disk_digest
        .as_ref()
        .ok_or(SnapshotError::Invalid("snapshot has no defaults disk"))?;
    let source = snapshot_disk(root, snapshot)?;
    let source_container = published_container(root, snapshot)?;
    let destination_container = disk_container(destination)?;
    let parent = destination
        .parent()
        .ok_or(SnapshotError::Invalid("fork destination has no parent"))?;
    private_directory(parent)?;
    let format = destination_container.storage_format()?;
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ForkReceipt {
        source: Digest,
        profile: sandsurf_image::identity::CloneProfile,
        customized: Digest,
    }
    let receipt_path = destination.with_extension("fork.json");
    crate::storage::publish_disk(
        destination,
        snapshot.system_disk_bytes.get(),
        format,
        |staged| {
            materialize_disk(
                &source,
                staged,
                snapshot.system_disk_bytes.get(),
                expected,
                source_container,
                destination_container,
            )
            .map_err(io::Error::other)?;
            if *profile != sandsurf_image::identity::CloneProfile::Preserve {
                if destination_container != DiskContainer::RawExt4 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "managed VHDX cloning requires an isolated helper",
                    ));
                }
                sandsurf_image::identity::customize(staged, profile)?;
            }
            let customized = materialized_digest(
                staged,
                snapshot.system_disk_bytes.get(),
                destination_container,
            )
            .map_err(io::Error::other)?;
            let receipt = ForkReceipt {
                source: expected.clone(),
                profile: *profile,
                customized,
            };
            let staged_receipt = receipt_path.with_extension("fork-building");
            if staged_receipt.exists() {
                fs::remove_file(&staged_receipt)?;
            }
            let mut file = sandsurf_native::local::create_private_file(&staged_receipt)?;
            file.write_all(&serde_json::to_vec(&receipt).map_err(io::Error::other)?)?;
            file.sync_all()?;
            drop(file);
            sandsurf_native::storage::replace_journal_file(&staged_receipt, &receipt_path)
        },
    )?;
    let mut receipt_bytes = Vec::new();
    sandsurf_native::local::open_private_file(
        &receipt_path,
        sandsurf_native::PrivateFileAccess::ReadOnly,
    )?
    .take(8193)
    .read_to_end(&mut receipt_bytes)?;
    if receipt_bytes.len() > 8192 {
        return Err(SnapshotError::Invalid("fork receipt exceeds bound"));
    }
    let receipt: ForkReceipt = serde_json::from_slice(&receipt_bytes)?;
    if receipt.source != *expected || receipt.profile != *profile {
        return Err(SnapshotError::Invalid(
            "fork customization contract changed",
        ));
    }
    if materialized_digest(
        destination,
        snapshot.system_disk_bytes.get(),
        destination_container,
    )? != receipt.customized
    {
        return Err(SnapshotError::Invalid(
            "fork destination contains different state",
        ));
    }
    sync_directory(parent)
}

/// Materialize a snapshot as the initial writable-state template of a
/// derived VM-native image. The published snapshot remains immutable and
/// the template receives an independent, verified file identity.
pub fn materialize_image_template(
    root: &Path,
    snapshot: &Snapshot,
    destination: &Path,
) -> Result<Digest> {
    let expected = snapshot
        .system_disk_digest
        .as_ref()
        .ok_or(SnapshotError::Invalid("snapshot has no defaults disk"))?;
    let source = snapshot_disk(root, snapshot)?;
    if disk_container(destination)? != DiskContainer::RawExt4
        || published_container(root, snapshot)? != DiskContainer::RawExt4
    {
        return Err(SnapshotError::Invalid(
            "derived image requires a raw ext4 snapshot",
        ));
    }
    copy_and_verify(
        &source,
        destination,
        snapshot.system_disk_bytes.get(),
        Some(expected),
    )?;
    Ok(expected.clone())
}

pub fn rollback(
    root: &Path,
    snapshot: &Snapshot,
    target: &Path,
    operation: &OperationId,
) -> Result<Digest> {
    let expected = snapshot
        .system_disk_digest
        .as_ref()
        .ok_or(SnapshotError::Invalid("snapshot has no defaults disk"))?;
    let source = snapshot_disk(root, snapshot)?;
    let source_container = published_container(root, snapshot)?;
    let target_container = disk_container(target)?;
    let parent = target
        .parent()
        .ok_or(SnapshotError::Invalid("rollback target has no parent"))?;
    private_directory(parent)?;
    crate::storage::replace_disk(
        target,
        operation,
        snapshot.system_disk_bytes.get(),
        target_container.storage_format()?,
        |staged| {
            materialize_disk(
                &source,
                staged,
                snapshot.system_disk_bytes.get(),
                expected,
                source_container,
                target_container,
            )
            .map_err(io::Error::other)
        },
        |candidate| {
            materialized_digest(
                candidate,
                snapshot.system_disk_bytes.get(),
                target_container,
            )
            .map(|actual| actual == *expected)
            .map_err(io::Error::other)
        },
    )?;
    rollback_evidence(snapshot, operation)
}

fn snapshot_disk(root: &Path, snapshot: &Snapshot) -> Result<PathBuf> {
    let directory = root.join(object_name(snapshot.request.id.as_str()));
    let verified = verify_published(&directory, snapshot)?;
    if snapshot.system_disk_digest.as_ref() != Some(&verified.disk_digest)
        || snapshot.manifest_digest.as_ref() != Some(&verified.manifest_digest)
    {
        return Err(SnapshotError::Invalid(
            "published snapshot disagrees with its catalog record",
        ));
    }
    Ok(directory.join(verified.container.system_name()))
}

fn published_container(root: &Path, snapshot: &Snapshot) -> Result<DiskContainer> {
    Ok(verify_published(
        &root.join(object_name(snapshot.request.id.as_str())),
        snapshot,
    )?
    .container)
}

fn capture_boot(
    image: &sandsurf_image::VerifiedImage,
    disk: &Path,
    stage: &Path,
) -> Result<sandsurf_image::boot::FrozenBoot> {
    // Stages are private and never attachable. Interrupted extraction is
    // discarded, while published boot artifacts are always digest verified.
    let directory = stage.join("boot");
    if directory.exists() {
        fs::remove_dir_all(&directory)?;
    }
    Ok(crate::storage::freeze_boot(image, disk, &directory)?)
}

pub(crate) fn boot_artifacts(
    root: &Path,
    snapshot: &Snapshot,
) -> Result<(PathBuf, sandsurf_image::boot::FrozenBoot)> {
    let directory = root.join(object_name(snapshot.request.id.as_str()));
    verify_published(&directory, snapshot)?;
    let manifest: SnapshotManifest =
        serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    Ok((directory.join("boot"), manifest.boot))
}

fn verify_published(directory: &Path, snapshot: &Snapshot) -> Result<CaptureResult> {
    private_directory(directory)?;
    let manifest: SnapshotManifest =
        serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    sandsurf_image::boot::verify(&directory.join("boot"), &manifest.boot)?;
    if manifest.format_version != 1
        || manifest.snapshot_id != snapshot.request.id
        || manifest.request_digest != snapshot.request_digest
        || manifest.image_digest != snapshot.image_digest
        || manifest.source_generation != snapshot.request.expected_generation
        || manifest.source_revision != snapshot.request.expected_revision
        || manifest.system_disk_bytes != snapshot.system_disk_bytes
        || manifest.sensitive != snapshot.sensitive
        || manifest.kind != snapshot.request.kind
        || snapshot
            .full
            .as_ref()
            .is_some_and(|full| manifest.full.as_ref() != Some(full))
    {
        return Err(SnapshotError::Invalid(
            "snapshot manifest does not match its admitted request",
        ));
    }
    let actual = file_digest(
        &directory.join(manifest.disk_container.system_name()),
        manifest.system_disk_bytes.get(),
    )?;
    if actual != manifest.system_disk_digest {
        return Err(SnapshotError::Invalid(
            "snapshot defaults disk digest mismatch",
        ));
    }
    if let Some(full) = &manifest.full {
        for (name, artifact) in [
            ("snapshot.vmstate", &full.snapshot_state),
            ("reconnect.json", &full.reconnect_state),
        ] {
            if file_digest(&directory.join(name), artifact.bytes.get())? != artifact.digest {
                return Err(SnapshotError::Invalid(
                    "full snapshot artifact digest mismatch",
                ));
            }
        }
        if let Some(memory) = &full.memory
            && file_digest(&directory.join("memory"), memory.bytes.get())? != memory.digest
        {
            return Err(SnapshotError::Invalid(
                "full snapshot memory artifact digest mismatch",
            ));
        }
    } else if manifest.kind != SnapshotKind::Disk {
        return Err(SnapshotError::Invalid(
            "full snapshot manifest has no engine material",
        ));
    }
    Ok(CaptureResult {
        disk_digest: actual,
        manifest_digest: digest(Domain::Snapshot, &manifest)?,
        full: manifest.full,
        container: manifest.disk_container,
    })
}

fn rollback_evidence(snapshot: &Snapshot, operation: &OperationId) -> Result<Digest> {
    Ok(digest(
        Domain::Snapshot,
        &(
            "sandsurf-filesystem-rollback-applied-v1",
            &snapshot.request.id,
            &snapshot.manifest_digest,
            operation,
        ),
    )?)
}

fn capture_disk(
    source: &Path,
    destination: &Path,
    bytes: u64,
    source_container: DiskContainer,
) -> Result<Digest> {
    match source_container {
        DiskContainer::RawExt4 => copy_and_verify(source, destination, bytes, None),
        DiskContainer::Vhdx => {
            #[cfg(target_os = "windows")]
            {
                sandsurf_native::virtual_disk::export_raw(source, destination, bytes)?;
                file_digest(destination, bytes)
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (source, destination, bytes);
                Err(SnapshotError::Invalid(
                    "VHDX capture requires the Windows host driver",
                ))
            }
        }
    }
}

fn materialize_disk(
    source: &Path,
    destination: &Path,
    bytes: u64,
    expected: &Digest,
    source_container: DiskContainer,
    destination_container: DiskContainer,
) -> Result<()> {
    match (source_container, destination_container) {
        (DiskContainer::RawExt4, DiskContainer::RawExt4) => {
            copy_and_verify(source, destination, bytes, Some(expected))?;
        }
        (DiskContainer::RawExt4, DiskContainer::Vhdx) => {
            #[cfg(target_os = "windows")]
            {
                if file_digest(source, bytes)? != *expected {
                    return Err(SnapshotError::Invalid(
                        "snapshot source does not match its committed digest",
                    ));
                }
                sandsurf_native::virtual_disk::import_raw(source, destination, bytes)?;
                if materialized_digest(destination, bytes, DiskContainer::Vhdx)? != *expected {
                    return Err(SnapshotError::Invalid(
                        "converted VHDX does not match the snapshot",
                    ));
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (source, destination, bytes, expected);
                return Err(SnapshotError::Invalid(
                    "VHDX materialization requires the Windows host driver",
                ));
            }
        }
        _ => {
            return Err(SnapshotError::Invalid(
                "snapshot container conversion is unsupported",
            ));
        }
    }
    Ok(())
}

fn materialized_digest(path: &Path, bytes: u64, container: DiskContainer) -> Result<Digest> {
    match container {
        DiskContainer::RawExt4 => file_digest(path, bytes),
        DiskContainer::Vhdx => {
            #[cfg(target_os = "windows")]
            {
                let parent = path.parent().ok_or(SnapshotError::Invalid(
                    "VHDX verification path has no parent",
                ))?;
                let verification = parent.join(format!(
                    ".{}.verification.ext4",
                    path.file_name()
                        .and_then(|value| value.to_str())
                        .ok_or(SnapshotError::Invalid("VHDX name is invalid"))?
                ));
                let exported = (|| {
                    sandsurf_native::virtual_disk::export_raw(path, &verification, bytes)?;
                    file_digest(&verification, bytes)
                })();
                let cleanup = remove_file_if_present(&verification);
                exported.and_then(|digest| cleanup.map(|()| digest))
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (path, bytes);
                Err(SnapshotError::Invalid(
                    "VHDX verification requires the Windows host driver",
                ))
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn current_disk_digest(path: &Path, bytes: u64) -> Result<Digest> {
    materialized_digest(path, bytes, disk_container(path)?)
}

pub(crate) fn copy_and_verify(
    source_path: &Path,
    destination_path: &Path,
    length: u64,
    expected: Option<&Digest>,
) -> Result<Digest> {
    let mut source = open_read(source_path)?;
    if source.metadata()?.len() != length {
        return Err(SnapshotError::Invalid("snapshot disk geometry changed"));
    }
    let mut destination = open_write(destination_path)?;
    destination.set_len(0)?;
    {
        let mut buffer = vec![0_u8; COPY_BUFFER];
        let mut remaining = length;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| SnapshotError::Invalid("snapshot copy bound overflow"))?;
            source.read_exact(&mut buffer[..count])?;
            if buffer[..count].iter().all(|byte| *byte == 0) {
                destination
                    .seek(SeekFrom::Current(i64::try_from(count).map_err(|_| {
                        SnapshotError::Invalid("snapshot sparse extent overflow")
                    })?))?;
            } else {
                destination.write_all(&buffer[..count])?;
            }
            remaining -= count as u64;
        }
        // Seeking over the final zero extent does not change file length.
        destination.set_len(length)?;
    }
    sandsurf_native::storage::sync_file(&destination)?;
    let actual = file_digest(destination_path, length)?;
    if expected.is_some_and(|value| value != &actual) {
        return Err(SnapshotError::Invalid(
            "snapshot source does not match its committed digest",
        ));
    }
    if source.metadata()?.len() != length {
        return Err(SnapshotError::Invalid(
            "snapshot source changed during copy",
        ));
    }
    Ok(actual)
}

pub(crate) fn file_digest(path: &Path, length: u64) -> Result<Digest> {
    let mut file = open_read(path)?;
    if file.metadata()?.len() != length {
        return Err(SnapshotError::Invalid("disk geometry mismatch"));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER];
    let mut remaining = length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| SnapshotError::Invalid("snapshot digest bound overflow"))?;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(format!("{:x}", hash.finalize()).try_into()?)
}

fn write_manifest(path: &Path, manifest: &SnapshotManifest) -> Result<()> {
    let mut file = open_write(path)?;
    file.set_len(0)?;
    serde_json::to_writer(&mut file, manifest)?;
    file.write_all(b"\n")?;
    sandsurf_native::storage::sync_file(&file)?;
    Ok(())
}

fn open_read(path: &Path) -> io::Result<File> {
    sandsurf_native::local::open_private_file(path, sandsurf_native::PrivateFileAccess::ReadOnly)
}

fn open_write(path: &Path) -> io::Result<File> {
    match sandsurf_native::local::create_private_file(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            sandsurf_native::local::open_private_file(
                path,
                sandsurf_native::PrivateFileAccess::ReadWrite,
            )
        }
        Err(error) => Err(error),
    }
}

fn disk_container(path: &Path) -> Result<DiskContainer> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("ext4") | Some("raw") => Ok(DiskContainer::RawExt4),
        Some("vhdx") => Ok(DiskContainer::Vhdx),
        _ => Err(SnapshotError::Invalid(
            "snapshot disk container is unsupported",
        )),
    }
}

fn remove_stage(stage: &Path) -> Result<()> {
    if stage.join("boot").exists() {
        fs::remove_dir_all(stage.join("boot"))?;
    }
    for name in [
        "manifest.json",
        "system.ext4",
        "system.vhdx",
        "snapshot.vmstate",
        "memory",
        "reconnect.json",
    ] {
        remove_file_if_present(&stage.join(name))?;
    }
    match fs::remove_dir(stage) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    sandsurf_native::storage::sync_directory(path)?;
    Ok(())
}

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    sandsurf_native::local::ensure_private_directory(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::{
        Counter, Resources, SnapshotKind, SnapshotPhase, SnapshotRequest, bytes_digest,
    };
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn capture_root(&self, snapshot: &Snapshot) -> PathBuf {
            private_directory(&self.0.join("machines")).unwrap();
            private_directory(
                &self
                    .0
                    .join("machines")
                    .join(object_name(snapshot.request.machine_id.as_str())),
            )
            .unwrap();
            super::root(&self.0, snapshot)
        }
        fn image(&self, snapshot: &Snapshot) -> sandsurf_image::VerifiedImage {
            sandsurf_image::verify_image(
                &self
                    .0
                    .join("images")
                    .join(snapshot.image_digest.as_str())
                    .join("manifest.json"),
                sandsurf_image::ImageTrust::Pinned {
                    manifest_digest: snapshot.image_digest.as_str(),
                },
            )
            .unwrap()
        }
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-snapshot-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            private_directory(&path).unwrap();
            let (manifest, kernel) = fixture_image();
            let images = path.join("images");
            private_directory(&images).unwrap();
            let image = images.join(bytes_digest(&manifest).as_str());
            private_directory(&image).unwrap();
            for (name, bytes) in [
                ("manifest.json", manifest),
                ("kernel", kernel),
                ("system.ext4", b"seed".to_vec()),
            ] {
                open_write(&image.join(name))
                    .unwrap()
                    .write_all(&bytes)
                    .unwrap();
            }
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn n(value: u64) -> Counter {
        value.try_into().unwrap()
    }
    fn fixture_image() -> (Vec<u8>, Vec<u8>) {
        let mut kernel = vec![0; 120];
        kernel[..6].copy_from_slice(b"\x7fELF\x02\x01");
        kernel[6] = 1;
        kernel[16..18].copy_from_slice(&2u16.to_le_bytes());
        kernel[18..20].copy_from_slice(&62u16.to_le_bytes());
        kernel[24..32].copy_from_slice(&0x100000u64.to_le_bytes());
        kernel[32..40].copy_from_slice(&64u64.to_le_bytes());
        kernel[54..56].copy_from_slice(&56u16.to_le_bytes());
        kernel[56..58].copy_from_slice(&1u16.to_le_bytes());
        kernel[64..68].copy_from_slice(&1u32.to_le_bytes());
        kernel[68..72].copy_from_slice(&1u32.to_le_bytes());
        kernel[80..88].copy_from_slice(&0x100000u64.to_le_bytes());
        kernel[88..96].copy_from_slice(&0x100000u64.to_le_bytes());
        kernel[96..104].copy_from_slice(&120u64.to_le_bytes());
        kernel[104..112].copy_from_slice(&120u64.to_le_bytes());
        let manifest = serde_json::json!({
            "formatVersion": 1, "id": "snapshot-fixture", "version": "1", "architecture": "x64",
            "bootBundle": { "kernel": { "path": "kernel", "sha256": bytes_digest(&kernel) },
                "initramfs": null, "profile": { "kind": "pinned" }, "guestAgent": null,
                "capabilities": { "overlayfs": false, "vsock": false, "seccomp": false, "cgroupV2": false, "devpts": false } },
            "system": { "rootfs": { "path": "system.ext4", "sha256": bytes_digest(b"seed"), "format": "ext4" },
                "cloneProfile": { "kind": "preserve" }, "defaults": { "environment": {}, "user": null, "workingDirectory": null },
                "provenance": { "kind": "source-built", "sourceDigest": "a".repeat(64), "materials": { "fixture": "b".repeat(64) } } },
            "platformArtifacts": { "windowsX64": null }, "signature": null
        });
        (serde_json::to_vec(&manifest).unwrap(), kernel)
    }
    fn snapshot() -> Snapshot {
        let request = SnapshotRequest {
            id: "snapshot".try_into().unwrap(),
            operation_id: "capture".try_into().unwrap(),
            machine_id: "machine".try_into().unwrap(),
            expected_generation: n(1),
            expected_revision: n(2),
            kind: SnapshotKind::Disk,
            parent: None,
        };
        Snapshot {
            request_digest: digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request)).unwrap(),
            request,
            phase: SnapshotPhase::Capturing,
            image_digest: bytes_digest(&fixture_image().0),
            resources: Resources::from_geometry(n(1), n(128), n(4096), n(4096), n(8))
                .expect("static resource envelope"),
            consistency: None,
            system_disk_digest: None,
            system_disk_bytes: n(4096),
            manifest_digest: None,
            sensitive: false,
            full: None,
        }
    }

    #[test]
    fn snapshot_boot_identity_rejects_changed_kernel_and_never_uses_pristine_seed() {
        let temp = Temp::new();
        let disk = temp.0.join("source.raw");
        open_write(&disk).unwrap().write_all(&[3; 4096]).unwrap();
        let snapshot = snapshot();
        let root = temp.capture_root(&snapshot);
        let image = temp.image(&snapshot);
        let mut foreign = snapshot.clone();
        foreign.image_digest = bytes_digest(b"another image");
        assert!(capture_filesystem(&root, &foreign, &disk, &image).is_err());
        assert!(
            !root.exists(),
            "reject another image before allocating capture storage"
        );
        assert!(!root.parent().unwrap().join("images").exists());
        capture_filesystem(&root, &snapshot, &disk, &image).unwrap();
        let directory = root.join(object_name(snapshot.request.id.as_str()));
        let kernel = directory.join("boot/kernel");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&kernel, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            let mut permissions = fs::metadata(&kernel).unwrap().permissions();
            #[expect(
                clippy::permissions_set_readonly_false,
                reason = "Windows-only fixture clears a readonly file attribute; it preserves the private DACL"
            )]
            permissions.set_readonly(false);
            fs::set_permissions(&kernel, permissions).unwrap();
        }
        fs::write(&kernel, b"corrupt-updated-kernel").unwrap();
        assert!(published_filesystem(&root, &snapshot).is_err());
        assert!(boot_artifacts(&root, &snapshot).is_err());
        assert_eq!(fs::read(kernel).unwrap(), b"corrupt-updated-kernel");
    }

    #[test]
    fn full_capture_membership_is_immutable_and_does_not_require_a_guest_report() {
        use sandsurf_protocol::{CapturedExecution, SpawnRequest, StdioMode, VmEngine};
        let temp = Temp::new();
        let root = temp.0.join("snapshots");
        let source = temp.0.join("source.raw");
        open_write(&source)
            .unwrap()
            .write_all(&[7_u8; 4096])
            .unwrap();
        let native_root = temp.0.join("native");
        private_directory(&native_root).unwrap();
        let (_, mut kernel) = fixture_image();
        kernel.extend_from_slice(b"running-kernel-not-seed");
        let running_kernel = temp.0.join("running-kernel");
        open_write(&running_kernel)
            .unwrap()
            .write_all(&kernel)
            .unwrap();
        crate::storage::pin_boot(
            &running_kernel,
            None,
            sandsurf_image::Architecture::X64,
            &native_root.join("boot"),
        )
        .unwrap();
        // Artifact/publication fixture only, not a native-machine witness.
        let artifact = |name: &str, bytes: &[u8]| {
            open_write(&native_root.join(name))
                .unwrap()
                .write_all(bytes)
                .unwrap();
            sandsurf_protocol::SnapshotArtifact {
                digest: bytes_digest(bytes),
                bytes: n(bytes.len() as u64),
            }
        };
        let mut snapshot = snapshot();
        snapshot.request.kind = SnapshotKind::Full;
        snapshot.sensitive = true;
        snapshot.request_digest = digest(
            Domain::Snapshot,
            &("sandsurf-snapshot-v1", &snapshot.request),
        )
        .unwrap();
        let admission = SpawnRequest {
            machine_id: snapshot.request.machine_id.clone(),
            generation: n(1),
            execution_id: "uncertain-delivery".try_into().unwrap(),
            operation_id: "spawn".try_into().unwrap(),
            argv: vec!["/bin/sh".into()],
            cwd: "/root".into(),
            environment: Default::default(),
            user: None,
            stdio: StdioMode::Pipes,
            terminal_size: None,
            active_deadline_millis: None,
            elapsed_deadline_unix_millis: None,
            output_bytes: n(4096),
        };
        let membership = CapturedExecution {
            output: sandsurf_protocol::initial_output_boundary(
                &admission.machine_id,
                &admission.execution_id,
                admission.generation,
            )
            .unwrap(),
            admission,
            lineage: None,
            observation: None,
        };
        let native = NativeFullCapture {
            engine: VmEngine::Firecracker,
            engine_version: "artifact-fixture-not-virtualization".into(),
            architecture: "amd64".into(),
            configuration_digest: bytes_digest(b"configuration"),
            executions: vec![membership.clone()],
            snapshot_state: artifact("snapshot.vmstate", b"state"),
            memory: Some(artifact("memory", b"memory")),
            reconnect_state: artifact("reconnect.json", b"reconnect"),
            generation: bytes_digest(b"capture"),
        };
        let mut wrong = native.clone();
        wrong.executions[0].admission.generation = n(2);
        assert!(capture_full(&root, &snapshot, &source, &native_root, wrong).is_err());
        assert!(
            !root.exists(),
            "reject invalid identities before allocating capture storage"
        );
        let mut duplicate = native.clone();
        duplicate.executions.push(membership.clone());
        assert!(capture_full(&root, &snapshot, &source, &native_root, duplicate).is_err());
        assert!(!root.exists());

        let captured =
            capture_full(&root, &snapshot, &source, &native_root, native.clone()).unwrap();
        let (directory, running) = boot_artifacts(
            &root,
            &Snapshot {
                system_disk_digest: Some(captured.disk_digest.clone()),
                manifest_digest: Some(captured.manifest_digest.clone()),
                ..snapshot.clone()
            },
        )
        .unwrap();
        assert_eq!(running.kernel.sha256, bytes_digest(&kernel).as_str());
        assert_eq!(fs::read(directory.join("kernel")).unwrap(), kernel);
        assert_ne!(
            running.kernel.sha256,
            bytes_digest(&fixture_image().1).as_str()
        );
        assert_eq!(
            captured.full.as_ref().unwrap().executions,
            vec![membership.clone()]
        );
        // Recovery reads the original publication, not replacement observations
        // or a later runtime inventory supplied by the retried caller.
        let mut retry = native;
        retry.executions.clear();
        let recovered = capture_full(&root, &snapshot, &source, &native_root, retry).unwrap();
        assert_eq!(recovered.manifest_digest, captured.manifest_digest);
        assert_eq!(
            recovered.full.as_ref().unwrap().executions,
            vec![membership]
        );
        let directory = root.join(object_name(snapshot.request.id.as_str()));
        let mut old: SnapshotManifest =
            serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
        old.format_version = 2;
        fs::write(
            directory.join("manifest.json"),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        assert!(
            verify_published(&directory, &snapshot).is_err(),
            "superseded format has no reader or migration"
        );
    }

    #[test]
    fn capture_fork_and_rollback_are_verified_independent_copies() {
        let temp = Temp::new();
        let source = temp.0.join("source.raw");
        open_write(&source)
            .unwrap()
            .write_all(&vec![7_u8; 4096])
            .unwrap();
        let mut snapshot = snapshot();
        let root = temp.capture_root(&snapshot);
        let image = temp.image(&snapshot);
        let captured = capture_filesystem(&root, &snapshot, &source, &image).unwrap();
        snapshot.phase = SnapshotPhase::Ready;
        snapshot.consistency = Some(SnapshotConsistency::Crash);
        snapshot.system_disk_digest = Some(captured.disk_digest.clone());
        snapshot.manifest_digest = Some(captured.manifest_digest);

        let fork_directory = temp.0.join("fork");
        private_directory(&fork_directory).unwrap();
        let fork = fork_directory.join("system.ext4");
        // An interrupted fork leaves only a private, non-attachable stage.
        let interrupted = fork.with_extension("building");
        open_write(&interrupted)
            .unwrap()
            .write_all(b"partial fork")
            .unwrap();
        materialize_fork(
            &root,
            &snapshot,
            &fork,
            &sandsurf_image::identity::CloneProfile::Preserve,
        )
        .unwrap();
        assert!(!interrupted.exists());
        assert_eq!(file_digest(&fork, 4096).unwrap(), captured.disk_digest);
        fs::write(&fork, vec![8_u8; 4096]).unwrap();
        assert!(
            materialize_fork(
                &root,
                &snapshot,
                &fork,
                &sandsurf_image::identity::CloneProfile::Preserve
            )
            .is_err()
        );
        assert_eq!(fs::read(&fork).unwrap(), vec![8_u8; 4096]);
        assert_eq!(
            file_digest(
                &root.join(object_name("snapshot")).join("system.ext4"),
                4096
            )
            .unwrap(),
            captured.disk_digest
        );

        let target_directory = temp.0.join("target");
        private_directory(&target_directory).unwrap();
        let target = target_directory.join("system.ext4");
        crate::storage::publish_disk(&target, 4096, crate::storage::DiskFormat::Raw, |staged| {
            open_write(staged)?.write_all(&vec![9_u8; 4096])
        })
        .unwrap();
        rollback(&root, &snapshot, &target, &"rollback".try_into().unwrap()).unwrap();
        assert_eq!(file_digest(&target, 4096).unwrap(), captured.disk_digest);
    }

    #[test]
    fn portable_copy_preserves_zero_extents_as_sparse_storage() {
        let temp = Temp::new();
        let source = temp.0.join("sparse.raw");
        let mut source_file = open_write(&source).unwrap();
        source_file.set_len(16 * 1024 * 1024).unwrap();
        source_file.seek(SeekFrom::Start(1024 * 1024)).unwrap();
        source_file.write_all(b"allocated extent").unwrap();
        source_file.sync_all().unwrap();
        let destination = temp.0.join("copy.raw");
        let expected = file_digest(&source, 16 * 1024 * 1024).unwrap();
        assert_eq!(
            copy_and_verify(&source, &destination, 16 * 1024 * 1024, Some(&expected)).unwrap(),
            expected
        );
        let metadata = destination.metadata().unwrap();
        assert_eq!(metadata.len(), 16 * 1024 * 1024);
        #[cfg(target_os = "linux")]
        assert!(metadata.blocks() * 512 < metadata.len() / 2);
    }
}
