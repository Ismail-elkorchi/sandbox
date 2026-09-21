use sandsurf_protocol::{
    Checkpoint, CheckpointArtifact, CheckpointConsistency, CheckpointId, CheckpointKind,
    CheckpointProcessWatermark, Digest, Domain, FullCheckpointMetadata, NativeFullCapture,
    OperationId, digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const COPY_BUFFER: usize = 1024 * 1024;

#[derive(Debug)]
pub enum CheckpointError {
    Io(io::Error),
    Json(serde_json::Error),
    Contract(sandsurf_protocol::Invalid),
    Invalid(&'static str),
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "checkpoint I/O: {error}"),
            Self::Json(error) => write!(output, "checkpoint manifest: {error}"),
            Self::Contract(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}

impl std::error::Error for CheckpointError {}
impl From<io::Error> for CheckpointError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for CheckpointError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_protocol::Invalid> for CheckpointError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}

pub type Result<T> = std::result::Result<T, CheckpointError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointManifest {
    format_version: u16,
    checkpoint_id: CheckpointId,
    request_digest: Digest,
    image_digest: Digest,
    source_epoch: sandsurf_protocol::Counter,
    source_revision: sandsurf_protocol::Counter,
    disk_container: DiskContainer,
    workload_disk_digest: Digest,
    workload_disk_bytes: sandsurf_protocol::Counter,
    consistency: CheckpointConsistency,
    sensitive: bool,
    kind: CheckpointKind,
    full: Option<FullCheckpointMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DiskContainer {
    RawExt4,
    Vhdx,
}

impl DiskContainer {
    fn workload_name(self) -> &'static str {
        match self {
            Self::RawExt4 => "workload-state.ext4",
            Self::Vhdx => "workload-state.vhdx",
        }
    }

    fn control_name(self) -> &'static str {
        match self {
            Self::RawExt4 => "control-state.ext4",
            Self::Vhdx => "control-state.vhdx",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::RawExt4 => "ext4",
            Self::Vhdx => "vhdx",
        }
    }
}

pub struct CaptureResult {
    pub disk_digest: Digest,
    pub manifest_digest: Digest,
    pub full: Option<FullCheckpointMetadata>,
    container: DiskContainer,
}

pub fn published_filesystem(root: &Path, checkpoint: &Checkpoint) -> Result<Option<CaptureResult>> {
    let directory = root.join(checkpoint.request.id.as_str());
    if !directory.exists() {
        return Ok(None);
    }
    Ok(Some(verify_published(&directory, checkpoint)?))
}

pub fn capture_filesystem(
    root: &Path,
    checkpoint: &Checkpoint,
    source_disk: &Path,
) -> Result<CaptureResult> {
    private_directory(root)?;
    let final_directory = root.join(checkpoint.request.id.as_str());
    if final_directory.exists() {
        return verify_published(&final_directory, checkpoint);
    }
    let stage = root.join(format!(
        ".{}.{}.capture",
        checkpoint.request.id.as_str(),
        checkpoint.request.operation_id.as_str()
    ));
    private_directory(&stage)?;
    let source_container = disk_container(source_disk)?;
    let container = DiskContainer::RawExt4;
    let disk = stage.join(container.workload_name());
    let disk_digest = capture_disk(
        source_disk,
        &disk,
        checkpoint.workload_disk_bytes.get(),
        source_container,
    )?;
    let manifest = CheckpointManifest {
        format_version: 3,
        checkpoint_id: checkpoint.request.id.clone(),
        request_digest: checkpoint.request_digest.clone(),
        image_digest: checkpoint.image_digest.clone(),
        source_epoch: checkpoint.request.expected_epoch,
        source_revision: checkpoint.request.expected_revision,
        disk_container: container,
        workload_disk_digest: disk_digest.clone(),
        workload_disk_bytes: checkpoint.workload_disk_bytes,
        consistency: CheckpointConsistency::Filesystem,
        sensitive: checkpoint.sensitive,
        kind: CheckpointKind::Filesystem,
        full: None,
    };
    let manifest_digest = digest(Domain::Checkpoint, &manifest)?;
    write_manifest(&stage.join("manifest.json"), &manifest)?;
    sync_directory(&stage)?;
    match fs::rename(&stage, &final_directory) {
        Ok(()) => sync_directory(root)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            remove_stage(&stage)?;
            return verify_published(&final_directory, checkpoint);
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
    checkpoint: &Checkpoint,
    workload_disk: &Path,
    control_disk: &Path,
    native_directory: &Path,
    native: NativeFullCapture,
    processes: Vec<CheckpointProcessWatermark>,
) -> Result<CaptureResult> {
    if checkpoint.request.kind != CheckpointKind::Full || !checkpoint.sensitive {
        return Err(CheckpointError::Invalid(
            "full capture requires a sensitive full checkpoint admission",
        ));
    }
    private_directory(root)?;
    let source_container = disk_container(workload_disk)?;
    if disk_container(control_disk)? != source_container {
        return Err(CheckpointError::Invalid(
            "full checkpoint disk containers do not match",
        ));
    }
    let container = DiskContainer::RawExt4;
    let final_directory = root.join(checkpoint.request.id.as_str());
    if final_directory.exists() {
        return verify_published(&final_directory, checkpoint);
    }
    let stage = root.join(format!(
        ".{}.{}.capture",
        checkpoint.request.id.as_str(),
        checkpoint.request.operation_id.as_str()
    ));
    private_directory(&stage)?;
    let disk_digest = capture_disk(
        workload_disk,
        &stage.join(container.workload_name()),
        checkpoint.workload_disk_bytes.get(),
        source_container,
    )?;
    let control_bytes = disk_logical_bytes(control_disk, source_container)?;
    if control_bytes == 0 || control_bytes > 8 * 1024 * 1024 * 1024 {
        return Err(CheckpointError::Invalid(
            "full checkpoint control disk geometry is invalid",
        ));
    }
    let control_digest = capture_disk(
        control_disk,
        &stage.join(container.control_name()),
        control_bytes,
        source_container,
    )?;
    let memory_bound = checkpoint
        .resources
        .memory_mib
        .get()
        .checked_mul(1024 * 1024)
        .ok_or(CheckpointError::Invalid("checkpoint memory bound overflow"))?;
    if native.memory.bytes.get() == 0
        || native.memory.bytes.get() > memory_bound
        || native.snapshot_state.bytes.get() == 0
        || native.snapshot_state.bytes.get() > 1024 * 1024 * 1024
        || native.reconnect_state.bytes.get() == 0
        || native.reconnect_state.bytes.get() > 1024 * 1024
    {
        return Err(CheckpointError::Invalid(
            "native full checkpoint artifact exceeds its bound",
        ));
    }
    for (name, artifact) in [
        ("snapshot.vmstate", &native.snapshot_state),
        ("memory", &native.memory),
        ("reconnect.json", &native.reconnect_state),
    ] {
        copy_and_verify(
            &native_directory.join(name),
            &stage.join(name),
            artifact.bytes.get(),
            Some(&artifact.digest),
        )?;
    }
    if processes.len() > 65_536 {
        return Err(CheckpointError::Invalid(
            "full checkpoint process inventory exceeds its bound",
        ));
    }
    let full = FullCheckpointMetadata {
        engine: native.engine,
        engine_version: native.engine_version,
        architecture: native.architecture,
        configuration_digest: native.configuration_digest,
        snapshot_state: native.snapshot_state,
        memory: native.memory,
        control_disk: CheckpointArtifact {
            digest: control_digest,
            bytes: control_bytes.try_into()?,
        },
        reconnect_state: native.reconnect_state,
        processes,
        generation: native.generation,
        // A capture can only become fork-safe through an explicit, separately
        // admitted workload contract. Ordinary full checkpoints default closed.
        fork_safe: false,
    };
    let manifest = CheckpointManifest {
        format_version: 3,
        checkpoint_id: checkpoint.request.id.clone(),
        request_digest: checkpoint.request_digest.clone(),
        image_digest: checkpoint.image_digest.clone(),
        source_epoch: checkpoint.request.expected_epoch,
        source_revision: checkpoint.request.expected_revision,
        disk_container: container,
        workload_disk_digest: disk_digest.clone(),
        workload_disk_bytes: checkpoint.workload_disk_bytes,
        consistency: CheckpointConsistency::Filesystem,
        sensitive: true,
        kind: CheckpointKind::Full,
        full: Some(full.clone()),
    };
    let manifest_digest = digest(Domain::Checkpoint, &manifest)?;
    write_manifest(&stage.join("manifest.json"), &manifest)?;
    sync_directory(&stage)?;
    match fs::rename(&stage, &final_directory) {
        Ok(()) => sync_directory(root)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            remove_stage(&stage)?;
            return verify_published(&final_directory, checkpoint);
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

pub fn materialize_fork(root: &Path, checkpoint: &Checkpoint, destination: &Path) -> Result<()> {
    let expected = checkpoint
        .workload_disk_digest
        .as_ref()
        .ok_or(CheckpointError::Invalid("checkpoint has no workload disk"))?;
    let source = checkpoint_disk(root, checkpoint)?;
    let source_container = published_container(root, checkpoint)?;
    let destination_container = disk_container(destination)?;
    if destination.exists() {
        let actual = materialized_digest(
            destination,
            checkpoint.workload_disk_bytes.get(),
            destination_container,
        )?;
        return if &actual == expected {
            Ok(())
        } else {
            Err(CheckpointError::Invalid(
                "fork destination already contains different state",
            ))
        };
    }
    let parent = destination
        .parent()
        .ok_or(CheckpointError::Invalid("fork destination has no parent"))?;
    private_directory(parent)?;
    materialize_disk(
        &source,
        destination,
        checkpoint.workload_disk_bytes.get(),
        expected,
        source_container,
        destination_container,
    )?;
    sync_directory(parent)
}

/// Materialize a checkpoint as the initial writable-state template of a
/// derived VM-native image. The published checkpoint remains immutable and
/// the template receives an independent, verified file identity.
#[cfg(target_os = "linux")]
pub fn materialize_image_template(
    root: &Path,
    checkpoint: &Checkpoint,
    destination: &Path,
) -> Result<Digest> {
    let expected = checkpoint
        .workload_disk_digest
        .as_ref()
        .ok_or(CheckpointError::Invalid("checkpoint has no workload disk"))?;
    let source = checkpoint_disk(root, checkpoint)?;
    if disk_container(destination)? != DiskContainer::RawExt4
        || published_container(root, checkpoint)? != DiskContainer::RawExt4
    {
        return Err(CheckpointError::Invalid(
            "derived image requires a raw ext4 checkpoint",
        ));
    }
    copy_and_verify(
        &source,
        destination,
        checkpoint.workload_disk_bytes.get(),
        Some(expected),
    )?;
    Ok(expected.clone())
}

pub fn rollback(
    root: &Path,
    checkpoint: &Checkpoint,
    target: &Path,
    operation: &OperationId,
) -> Result<Digest> {
    let expected = checkpoint
        .workload_disk_digest
        .as_ref()
        .ok_or(CheckpointError::Invalid("checkpoint has no workload disk"))?;
    let source = checkpoint_disk(root, checkpoint)?;
    let source_container = published_container(root, checkpoint)?;
    let target_container = disk_container(target)?;
    let parent = target
        .parent()
        .ok_or(CheckpointError::Invalid("rollback target has no parent"))?;
    private_directory(parent)?;
    let next = parent.join(format!(
        ".workload-state.{}.next.{}",
        operation.as_str(),
        target_container.extension()
    ));
    let previous = parent.join(format!(".workload-state.{}.previous", operation.as_str()));

    if !target.exists() && next.exists() {
        if materialized_digest(
            &next,
            checkpoint.workload_disk_bytes.get(),
            target_container,
        )? != *expected
        {
            return Err(CheckpointError::Invalid(
                "interrupted rollback candidate disagrees with its checkpoint",
            ));
        }
        fs::rename(&next, target)?;
        sync_directory(parent)?;
    } else if !target.exists() && previous.exists() {
        fs::rename(&previous, target)?;
        sync_directory(parent)?;
    }
    if target.exists()
        && materialized_digest(
            target,
            checkpoint.workload_disk_bytes.get(),
            target_container,
        )? == *expected
    {
        remove_file_if_present(&next)?;
        remove_file_if_present(&previous)?;
        sync_directory(parent)?;
        return rollback_evidence(checkpoint, operation);
    }
    if previous.exists() {
        return Err(CheckpointError::Invalid(
            "interrupted rollback target conflicts with its retained original",
        ));
    }
    materialize_disk(
        &source,
        &next,
        checkpoint.workload_disk_bytes.get(),
        expected,
        source_container,
        target_container,
    )?;
    if target.exists() {
        fs::rename(target, &previous)?;
        sync_directory(parent)?;
    }
    if let Err(error) = fs::rename(&next, target) {
        if previous.exists() && !target.exists() {
            let _ = fs::rename(&previous, target);
            let _ = sync_directory(parent);
        }
        return Err(error.into());
    }
    sync_directory(parent)?;
    if file_digest(target, checkpoint.workload_disk_bytes.get())? != *expected {
        return Err(CheckpointError::Invalid(
            "installed rollback disk failed readback verification",
        ));
    }
    remove_file_if_present(&previous)?;
    sync_directory(parent)?;
    rollback_evidence(checkpoint, operation)
}

fn checkpoint_disk(root: &Path, checkpoint: &Checkpoint) -> Result<PathBuf> {
    let directory = root.join(checkpoint.request.id.as_str());
    let verified = verify_published(&directory, checkpoint)?;
    if checkpoint.workload_disk_digest.as_ref() != Some(&verified.disk_digest)
        || checkpoint.manifest_digest.as_ref() != Some(&verified.manifest_digest)
    {
        return Err(CheckpointError::Invalid(
            "published checkpoint disagrees with its catalog record",
        ));
    }
    Ok(directory.join(verified.container.workload_name()))
}

fn published_container(root: &Path, checkpoint: &Checkpoint) -> Result<DiskContainer> {
    Ok(verify_published(&root.join(checkpoint.request.id.as_str()), checkpoint)?.container)
}

fn verify_published(directory: &Path, checkpoint: &Checkpoint) -> Result<CaptureResult> {
    private_directory(directory)?;
    let manifest: CheckpointManifest =
        serde_json::from_slice(&fs::read(directory.join("manifest.json"))?)?;
    if manifest.format_version != 3
        || manifest.checkpoint_id != checkpoint.request.id
        || manifest.request_digest != checkpoint.request_digest
        || manifest.image_digest != checkpoint.image_digest
        || manifest.source_epoch != checkpoint.request.expected_epoch
        || manifest.source_revision != checkpoint.request.expected_revision
        || manifest.workload_disk_bytes != checkpoint.workload_disk_bytes
        || manifest.sensitive != checkpoint.sensitive
        || manifest.kind != checkpoint.request.kind
        || checkpoint
            .full
            .as_ref()
            .is_some_and(|full| manifest.full.as_ref() != Some(full))
    {
        return Err(CheckpointError::Invalid(
            "checkpoint manifest does not match its admitted request",
        ));
    }
    let actual = file_digest(
        &directory.join(manifest.disk_container.workload_name()),
        manifest.workload_disk_bytes.get(),
    )?;
    if actual != manifest.workload_disk_digest {
        return Err(CheckpointError::Invalid(
            "checkpoint workload disk digest mismatch",
        ));
    }
    if let Some(full) = &manifest.full {
        for (name, artifact) in [
            (manifest.disk_container.control_name(), &full.control_disk),
            ("snapshot.vmstate", &full.snapshot_state),
            ("memory", &full.memory),
            ("reconnect.json", &full.reconnect_state),
        ] {
            if file_digest(&directory.join(name), artifact.bytes.get())? != artifact.digest {
                return Err(CheckpointError::Invalid(
                    "full checkpoint artifact digest mismatch",
                ));
            }
        }
    } else if manifest.kind != CheckpointKind::Filesystem {
        return Err(CheckpointError::Invalid(
            "full checkpoint manifest has no engine material",
        ));
    }
    Ok(CaptureResult {
        disk_digest: actual,
        manifest_digest: digest(Domain::Checkpoint, &manifest)?,
        full: manifest.full,
        container: manifest.disk_container,
    })
}

fn rollback_evidence(checkpoint: &Checkpoint, operation: &OperationId) -> Result<Digest> {
    Ok(digest(
        Domain::Checkpoint,
        &(
            "sandsurf-filesystem-rollback-applied-v1",
            &checkpoint.request.id,
            &checkpoint.manifest_digest,
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
                Err(CheckpointError::Invalid(
                    "VHDX capture requires the Windows host driver",
                ))
            }
        }
    }
}

fn disk_logical_bytes(path: &Path, container: DiskContainer) -> Result<u64> {
    match container {
        DiskContainer::RawExt4 => Ok(path.metadata()?.len()),
        DiskContainer::Vhdx => {
            #[cfg(target_os = "windows")]
            {
                Ok(sandsurf_native::virtual_disk::virtual_disk_size(path)?)
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = path;
                Err(CheckpointError::Invalid(
                    "VHDX inspection requires the Windows host driver",
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
                    return Err(CheckpointError::Invalid(
                        "checkpoint source does not match its committed digest",
                    ));
                }
                sandsurf_native::virtual_disk::import_raw(source, destination, bytes)?;
                if materialized_digest(destination, bytes, DiskContainer::Vhdx)? != *expected {
                    return Err(CheckpointError::Invalid(
                        "converted VHDX does not match the checkpoint",
                    ));
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (source, destination, bytes, expected);
                return Err(CheckpointError::Invalid(
                    "VHDX materialization requires the Windows host driver",
                ));
            }
        }
        _ => {
            return Err(CheckpointError::Invalid(
                "checkpoint container conversion is unsupported",
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
                let parent = path.parent().ok_or(CheckpointError::Invalid(
                    "VHDX verification path has no parent",
                ))?;
                let verification = parent.join(format!(
                    ".{}.verification.ext4",
                    path.file_name()
                        .and_then(|value| value.to_str())
                        .ok_or(CheckpointError::Invalid("VHDX name is invalid"))?
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
                Err(CheckpointError::Invalid(
                    "VHDX verification requires the Windows host driver",
                ))
            }
        }
    }
}

pub(crate) fn copy_and_verify(
    source_path: &Path,
    destination_path: &Path,
    length: u64,
    expected: Option<&Digest>,
) -> Result<Digest> {
    let mut source = open_read(source_path)?;
    if source.metadata()?.len() != length {
        return Err(CheckpointError::Invalid("checkpoint disk geometry changed"));
    }
    let mut destination = open_write(destination_path)?;
    destination.set_len(0)?;
    let cloned = try_clone(&source, &destination);
    if !cloned {
        let mut buffer = vec![0_u8; COPY_BUFFER];
        let mut remaining = length;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| CheckpointError::Invalid("checkpoint copy bound overflow"))?;
            source.read_exact(&mut buffer[..count])?;
            if buffer[..count].iter().all(|byte| *byte == 0) {
                destination.seek(SeekFrom::Current(i64::try_from(count).map_err(|_| {
                    CheckpointError::Invalid("checkpoint sparse extent overflow")
                })?))?;
            } else {
                destination.write_all(&buffer[..count])?;
            }
            remaining -= count as u64;
        }
        // Seeking over the final zero extent does not change file length.
        destination.set_len(length)?;
    }
    destination.sync_all()?;
    let actual = file_digest(destination_path, length)?;
    if expected.is_some_and(|value| value != &actual) {
        return Err(CheckpointError::Invalid(
            "checkpoint source does not match its committed digest",
        ));
    }
    if source.metadata()?.len() != length {
        return Err(CheckpointError::Invalid(
            "checkpoint source changed during copy",
        ));
    }
    Ok(actual)
}

pub(crate) fn file_digest(path: &Path, length: u64) -> Result<Digest> {
    let mut file = open_read(path)?;
    if file.metadata()?.len() != length {
        return Err(CheckpointError::Invalid("disk geometry mismatch"));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER];
    let mut remaining = length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| CheckpointError::Invalid("checkpoint digest bound overflow"))?;
        file.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(format!("{:x}", hash.finalize()).try_into()?)
}

fn write_manifest(path: &Path, manifest: &CheckpointManifest) -> Result<()> {
    let mut file = open_write(path)?;
    file.set_len(0)?;
    serde_json::to_writer(&mut file, manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

fn open_write(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

fn try_clone(_: &File, _: &File) -> bool {
    // Full copy is the portable baseline. Platform clone accelerators may be
    // added only after their sharing and durability behavior is qualified.
    false
}

fn disk_container(path: &Path) -> Result<DiskContainer> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("ext4") | Some("raw") => Ok(DiskContainer::RawExt4),
        Some("vhdx") => Ok(DiskContainer::Vhdx),
        _ => Err(CheckpointError::Invalid(
            "checkpoint disk container is unsupported",
        )),
    }
}

fn remove_stage(stage: &Path) -> Result<()> {
    for name in [
        "manifest.json",
        "workload-state.ext4",
        "workload-state.vhdx",
        "control-state.ext4",
        "control-state.vhdx",
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
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    let owner = path
        .parent()
        .map(fs::symlink_metadata)
        .transpose()?
        .map_or(metadata.uid(), |value| value.uid());
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(CheckpointError::Invalid(
            "checkpoint directory is not private",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sandsurf_protocol::{
        CheckpointKind, CheckpointPhase, CheckpointRequest, Counter, Resources, bytes_digest,
    };
    use std::os::unix::fs::DirBuilderExt;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-checkpoint-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
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
    fn checkpoint() -> Checkpoint {
        let request = CheckpointRequest {
            id: "checkpoint".try_into().unwrap(),
            operation_id: "capture".try_into().unwrap(),
            sandbox_id: "sandbox".try_into().unwrap(),
            expected_epoch: n(1),
            expected_revision: n(2),
            kind: CheckpointKind::Filesystem,
            parent: None,
        };
        Checkpoint {
            request_digest: digest(Domain::Checkpoint, &("sandsurf-checkpoint-v1", &request))
                .unwrap(),
            request,
            phase: CheckpointPhase::Capturing,
            image_digest: bytes_digest(b"image"),
            resources: Resources {
                vcpus: n(1),
                memory_mib: n(128),
                disk_bytes: n(4096),
                output_bytes: n(4096),
                processes: n(8),
            },
            consistency: None,
            workload_disk_digest: None,
            workload_disk_bytes: n(4096),
            manifest_digest: None,
            sensitive: false,
            full: None,
        }
    }

    #[test]
    fn capture_fork_and_rollback_are_verified_independent_copies() {
        let temp = Temp::new();
        let root = temp.0.join("checkpoints");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let source = temp.0.join("source.raw");
        fs::write(&source, vec![7_u8; 4096]).unwrap();
        let mut checkpoint = checkpoint();
        let captured = capture_filesystem(&root, &checkpoint, &source).unwrap();
        checkpoint.phase = CheckpointPhase::Ready;
        checkpoint.consistency = Some(CheckpointConsistency::Filesystem);
        checkpoint.workload_disk_digest = Some(captured.disk_digest.clone());
        checkpoint.manifest_digest = Some(captured.manifest_digest);

        let fork_directory = temp.0.join("fork");
        let fork = fork_directory.join("workload-state.ext4");
        materialize_fork(&root, &checkpoint, &fork).unwrap();
        fs::write(&fork, vec![8_u8; 4096]).unwrap();
        assert_eq!(
            file_digest(&root.join("checkpoint/workload-state.ext4"), 4096).unwrap(),
            captured.disk_digest
        );

        let target_directory = temp.0.join("target");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&target_directory)
            .unwrap();
        let target = target_directory.join("workload-state.ext4");
        fs::write(&target, vec![9_u8; 4096]).unwrap();
        rollback(&root, &checkpoint, &target, &"rollback".try_into().unwrap()).unwrap();
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

#[cfg(windows)]
fn private_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(CheckpointError::Invalid(
            "checkpoint path is not a directory",
        ));
    }
    Ok(())
}
