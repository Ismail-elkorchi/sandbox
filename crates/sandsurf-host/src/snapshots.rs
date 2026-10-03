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

fn retirement_path(root: &Path, id: &SnapshotId) -> PathBuf {
    root.join(format!(".{}.retirement.json", object_name(id.as_str())))
}

/// Immutable-input custody transferable into the actual native consumer.
/// Use kernel file-object share denial on Windows, not process-owned locks.
fn object_lease(root: &Path, id: &SnapshotId, shared: bool) -> Result<File> {
    private_directory(root)?;
    let path = root.join(format!(".{}.object.lock", object_name(id.as_str())));
    let file = if shared {
        sandsurf_native::storage::read_lease(&path)?
    } else {
        sandsurf_native::storage::disk_lease(&path)?
    };
    Ok(file)
}

pub(crate) fn retain_input(root: &Path, id: &SnapshotId) -> Result<File> {
    let custody = object_lease(root, id, true)?;
    match fs::symlink_metadata(retirement_path(root, id)) {
        Ok(_) => return Err(SnapshotError::Invalid("snapshot storage has been retired")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(custody)
}

/// An authenticated catalog retirement is materialized before deleting any
/// bytes. The terminal marker fences delayed pre-retirement jobs after restart.
/// Nothing here touches output archives, receipts, or guest retention claims.
pub(crate) fn cleanup(
    host_root: &Path,
    snapshot: &Snapshot,
    record: &sandsurf_state::SnapshotReleaseRecord,
) -> Result<()> {
    if record.snapshot_id != snapshot.request.id
        || record.machine_id != snapshot.request.machine_id
        || snapshot.phase != sandsurf_protocol::SnapshotPhase::Retiring
        || !record.cleanup_pending
        || record.request_digest
            != digest(
                Domain::Snapshot,
                &(
                    "sandsurf-release-snapshot-v1",
                    &record.operation_id,
                    &record.snapshot_id,
                ),
            )?
    {
        return Err(SnapshotError::Invalid(
            "snapshot cleanup lacks exact retirement authority",
        ));
    }
    let root = root(host_root, snapshot);
    let _custody = object_lease(&root, &record.snapshot_id, false)?;
    // Full-state captures may be original native restore inputs, not merely
    // byte-copy sources. Keep retirement pending while that machine's VMM has
    // original attachment custody, including after guardian/control loss.
    let _native_custody = if snapshot.request.kind == SnapshotKind::Full {
        Some(crate::storage::detached_custody(
            &host_root
                .join("machines")
                .join(object_name(record.machine_id.as_str()))
                .join("disks/system.ext4"),
        )?)
    } else {
        None
    };
    let marker = retirement_path(&root, &record.snapshot_id);
    match crate::image_records::read::<sandsurf_state::SnapshotReleaseRecord>(&marker) {
        Ok(old) if old == *record => {}
        Ok(_) => {
            return Err(SnapshotError::Invalid(
                "snapshot retirement binding changed",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            crate::image_records::publish(&marker, record)?
        }
        Err(error) => return Err(error.into()),
    }
    for directory in [
        root.join(object_name(record.snapshot_id.as_str())),
        disk_stage(&root, snapshot),
        disk_stage(&root, snapshot).with_extension("input-building"),
    ] {
        remove_stage(&directory)?;
    }
    sync_directory(&root)?;
    // Interrupted QEMU preparation can leave a native state copy before the
    // integration record is published. Its name is owned by this exact
    // immutable capture; retirement also waits for original VMM disk custody.
    if snapshot.request.kind == SnapshotKind::Full {
        let restore_root = host_root
            .join("machines")
            .join(object_name(record.machine_id.as_str()))
            .join("guardian/restores");
        match fs::symlink_metadata(&restore_root) {
            Ok(_) => {
                sandsurf_native::local::Directory::open(&restore_root)?;
                let manifest = snapshot
                    .manifest_digest
                    .as_ref()
                    .ok_or(SnapshotError::Invalid(
                        "full snapshot has no manifest identity",
                    ))?;
                let copy = restore_root.join(format!("{}.vmstate", manifest.as_str()));
                match open_read(&copy) {
                    Ok(file) => {
                        drop(file);
                        fs::remove_file(copy)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                sync_directory(&restore_root)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    // Native capture duplicates belong to this exact capture operation. Native
    // detachment above excludes readers of full-state restore inputs.
    let native_root = host_root
        .join("machines")
        .join(object_name(record.machine_id.as_str()))
        .join("guardian/full-captures");
    match fs::symlink_metadata(&native_root) {
        Ok(_) => {
            sandsurf_native::local::Directory::open(&native_root)?;
            remove_stage(&native_root.join(object_name(snapshot.request.operation_id.as_str())))?;
            sync_directory(&native_root)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
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
    system_disk_digest: Digest,
    system_disk_bytes: sandsurf_protocol::Counter,
    consistency: SnapshotConsistency,
    sensitive: bool,
    kind: SnapshotKind,
    full: Option<FullSnapshotMetadata>,
    boot: sandsurf_image::boot::FrozenBoot,
}

#[derive(Debug)]
pub struct CaptureResult {
    pub disk_digest: Digest,
    pub manifest_digest: Digest,
    pub full: Option<FullSnapshotMetadata>,
}

pub fn published_filesystem(root: &Path, snapshot: &Snapshot) -> Result<Option<CaptureResult>> {
    let _custody = retain_input(root, &snapshot.request.id)?;
    let directory = root.join(object_name(snapshot.request.id.as_str()));
    if !directory.exists() {
        return Ok(None);
    }
    Ok(Some(verify_published(&directory, snapshot)?))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiskCaptureInput {
    request_digest: Digest,
    image_digest: Digest,
    bytes: sandsurf_protocol::Counter,
    disk_digest: Digest,
}

fn disk_stage(root: &Path, snapshot: &Snapshot) -> PathBuf {
    root.join(format!(
        ".{}.{}.capture",
        object_name(snapshot.request.id.as_str()),
        object_name(snapshot.request.operation_id.as_str())
    ))
}

/// A routing hint only: retained records may let finishing proceed without a
/// live machine. Neither a record nor this observation establishes completion;
/// the capture task must verify all corresponding bytes before publication.
pub(crate) fn has_capture_record(root: &Path, snapshot: &Snapshot) -> Result<bool> {
    let _custody = retain_input(root, &snapshot.request.id)?;
    let published = root
        .join(object_name(snapshot.request.id.as_str()))
        .join("manifest.json");
    let input = disk_stage(root, snapshot).join("disk-input.json");
    for path in std::iter::once(published)
        .chain((snapshot.request.kind == SnapshotKind::Disk).then_some(input))
    {
        match open_read(&path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

fn read_disk_input(stage: &Path, snapshot: &Snapshot) -> Result<Digest> {
    private_directory(stage)?;
    let input: DiskCaptureInput = crate::image_records::read(&stage.join("disk-input.json"))?;
    if input.request_digest != snapshot.request_digest
        || input.image_digest != snapshot.image_digest
        || input.bytes != snapshot.system_disk_bytes
    {
        return Err(SnapshotError::Invalid("disk capture input binding changed"));
    }
    if file_digest(&stage.join("system.ext4"), input.bytes.get())? != input.disk_digest {
        return Err(SnapshotError::Invalid("disk capture input bytes changed"));
    }
    Ok(input.disk_digest)
}

/// Observe an immutable byte capture, not the current computer or its power.
/// A resumed/rebooted source cannot alter the bytes this operation finishes.
pub(crate) fn prepared_filesystem(root: &Path, snapshot: &Snapshot) -> Result<bool> {
    let _custody = retain_input(root, &snapshot.request.id)?;
    let stage = disk_stage(root, snapshot);
    match fs::symlink_metadata(&stage) {
        Ok(_) => {
            read_disk_input(&stage, snapshot)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Copies only opaque disk bytes under the guardian's native pause boundary.
/// Publish the complete input atomically before returning. Finishing can then
/// outlive the API and its pause without reading a live machine disk again.
pub(crate) fn prepare_filesystem(
    root: &Path,
    snapshot: &Snapshot,
    source_disk: &Path,
) -> Result<()> {
    if snapshot.request.kind != SnapshotKind::Disk {
        return Err(SnapshotError::Invalid(
            "disk input requires a disk snapshot",
        ));
    }
    let _input_custody = retain_input(root, &snapshot.request.id)?;
    private_directory(root)?;
    let _custody = sandsurf_native::storage::disk_lease(&root.join(format!(
        ".{}.capture.lock",
        object_name(snapshot.request.operation_id.as_str())
    )))?;
    let stage = disk_stage(root, snapshot);
    if stage.exists() {
        read_disk_input(&stage, snapshot)?;
        return Ok(());
    }
    let pending = stage.with_extension("input-building");
    remove_stage(&pending)?;
    private_directory(&pending)?;
    let disk_digest = copy_and_verify(
        source_disk,
        &pending.join("system.ext4"),
        snapshot.system_disk_bytes.get(),
        None,
    )?;
    write_record(
        &pending.join("disk-input.json"),
        &DiskCaptureInput {
            request_digest: snapshot.request_digest.clone(),
            image_digest: snapshot.image_digest.clone(),
            bytes: snapshot.system_disk_bytes,
            disk_digest,
        },
    )?;
    sync_directory(&pending)?;
    sandsurf_native::storage::publish_new_directory(&pending, &stage)?;
    sync_directory(root)
}

pub(crate) fn finish_filesystem(
    root: &Path,
    snapshot: &Snapshot,
    image: &sandsurf_image::VerifiedImage,
) -> Result<CaptureResult> {
    if snapshot.request.kind != SnapshotKind::Disk
        || image.manifest_digest != snapshot.image_digest.as_str()
    {
        return Err(SnapshotError::Invalid(
            "disk capture image differs from host admission",
        ));
    }
    let _input_custody = retain_input(root, &snapshot.request.id)?;
    private_directory(root)?;
    let _custody = sandsurf_native::storage::disk_lease(&root.join(format!(
        ".{}.capture.lock",
        object_name(snapshot.request.operation_id.as_str())
    )))?;
    let final_directory = root.join(object_name(snapshot.request.id.as_str()));
    if final_directory.exists() {
        return verify_published(&final_directory, snapshot);
    }
    let stage = disk_stage(root, snapshot);
    let disk = stage.join("system.ext4");
    let disk_digest = read_disk_input(&stage, snapshot)?;
    let manifest = SnapshotManifest {
        format_version: 1,
        snapshot_id: snapshot.request.id.clone(),
        request_digest: snapshot.request_digest.clone(),
        image_digest: snapshot.image_digest.clone(),
        source_generation: snapshot.request.expected_generation,
        source_revision: snapshot.request.expected_revision,
        system_disk_digest: disk_digest.clone(),
        system_disk_bytes: snapshot.system_disk_bytes,
        consistency: SnapshotConsistency::Crash,
        sensitive: snapshot.sensitive,
        kind: SnapshotKind::Disk,
        full: None,
        boot: crate::storage::freeze_boot(image, &disk, &stage.join("boot"))?,
    };
    let manifest_digest = digest(Domain::Snapshot, &manifest)?;
    // Exact interrupted retries may already have a complete immutable record.
    let manifest_path = stage.join("manifest.json");
    if manifest_path.exists() {
        let previous: SnapshotManifest = crate::image_records::read(&manifest_path)?;
        if previous != manifest {
            return Err(SnapshotError::Invalid(
                "disk capture publication binding changed",
            ));
        }
    } else {
        let building = stage.join("manifest-building");
        write_record(&building, &manifest)?;
        sandsurf_native::storage::publish_new_file(&building, &manifest_path)?;
    }
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
    let _input_custody = retain_input(root, &snapshot.request.id)?;
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
    let disk_digest = copy_and_verify(
        system_disk,
        &stage.join("system.ext4"),
        snapshot.system_disk_bytes.get(),
        None,
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
        system_disk_digest: disk_digest.clone(),
        system_disk_bytes: snapshot.system_disk_bytes,
        consistency: SnapshotConsistency::Machine,
        sensitive: true,
        kind: SnapshotKind::Full,
        full: Some(full.clone()),
        boot: crate::storage::copy_boot(&native_directory.join("boot"), &stage.join("boot"))?,
    };
    let manifest_digest = digest(Domain::Snapshot, &manifest)?;
    write_record(&stage.join("manifest.json"), &manifest)?;
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
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ForkReceipt {
    source: Digest,
    profile: sandsurf_image::identity::CloneProfile,
    customized: Digest,
}

pub fn materialize_fork(
    root: &Path,
    snapshot: &Snapshot,
    destination: &Path,
    profile: &sandsurf_image::identity::CloneProfile,
) -> Result<()> {
    let _custody = retain_input(root, &snapshot.request.id)?;
    let expected = snapshot
        .system_disk_digest
        .as_ref()
        .ok_or(SnapshotError::Invalid("snapshot has no defaults disk"))?;
    let source = snapshot_disk(root, snapshot)?;
    let parent = destination
        .parent()
        .ok_or(SnapshotError::Invalid("fork destination has no parent"))?;
    private_directory(parent)?;
    let receipt_path = destination.with_extension("fork.json");
    crate::storage::publish_disk(destination, snapshot.system_disk_bytes.get(), |staged| {
        copy_and_verify(
            &source,
            staged,
            snapshot.system_disk_bytes.get(),
            Some(expected),
        )
        .map_err(io::Error::other)?;
        if *profile != sandsurf_image::identity::CloneProfile::Preserve {
            sandsurf_image::identity::customize(staged, profile)?;
        }
        let customized =
            file_digest(staged, snapshot.system_disk_bytes.get()).map_err(io::Error::other)?;
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
    })?;
    verify_fork(snapshot, destination, profile)?;
    sync_directory(parent)
}

/// The Ready storage owner and complete bytes back a fork completion. This
/// does not rerun customization or interpret the guest filesystem on retry.
pub(crate) fn verify_fork(
    snapshot: &Snapshot,
    destination: &Path,
    profile: &sandsurf_image::identity::CloneProfile,
) -> Result<Digest> {
    let expected = snapshot
        .system_disk_digest
        .as_ref()
        .ok_or(SnapshotError::Invalid("snapshot has no captured disk"))?;
    let _custody = crate::storage::attach(destination)?;
    let receipt_path = destination.with_extension("fork.json");
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
    if file_digest(destination, snapshot.system_disk_bytes.get())? != receipt.customized {
        return Err(SnapshotError::Invalid(
            "fork destination contains different state",
        ));
    }
    Ok(receipt.customized)
}

/// Materialize a snapshot as the initial writable-state template of a
/// derived VM-native image. The published snapshot remains immutable and
/// the template receives an independent, verified file identity.
pub fn materialize_image_template(
    root: &Path,
    snapshot: &Snapshot,
    destination: &Path,
) -> Result<Digest> {
    let _custody = retain_input(root, &snapshot.request.id)?;
    let expected = snapshot
        .system_disk_digest
        .as_ref()
        .ok_or(SnapshotError::Invalid("snapshot has no defaults disk"))?;
    let source = snapshot_disk(root, snapshot)?;
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
    let _custody = retain_input(root, &snapshot.request.id)?;
    let expected = snapshot
        .system_disk_digest
        .as_ref()
        .ok_or(SnapshotError::Invalid("snapshot has no defaults disk"))?;
    let source = snapshot_disk(root, snapshot)?;
    let parent = target
        .parent()
        .ok_or(SnapshotError::Invalid("rollback target has no parent"))?;
    private_directory(parent)?;
    crate::storage::replace_disk(
        target,
        operation,
        snapshot.system_disk_bytes.get(),
        |staged| {
            copy_and_verify(
                &source,
                staged,
                snapshot.system_disk_bytes.get(),
                Some(expected),
            )
            .map(|_| ())
            .map_err(io::Error::other)
        },
        |candidate| {
            file_digest(candidate, snapshot.system_disk_bytes.get())
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
    Ok(directory.join("system.ext4"))
}

pub(crate) fn boot_artifacts(
    root: &Path,
    snapshot: &Snapshot,
) -> Result<(PathBuf, sandsurf_image::boot::FrozenBoot)> {
    let directory = root.join(object_name(snapshot.request.id.as_str()));
    verify_published(&directory, snapshot)?;
    let manifest: SnapshotManifest = crate::image_records::read(&directory.join("manifest.json"))?;
    Ok((directory.join("boot"), manifest.boot))
}

fn verify_published(directory: &Path, snapshot: &Snapshot) -> Result<CaptureResult> {
    private_directory(directory)?;
    let manifest: SnapshotManifest = crate::image_records::read(&directory.join("manifest.json"))?;
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
        &directory.join("system.ext4"),
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

fn write_record(path: &Path, manifest: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)?;
    if bytes.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
        return Err(SnapshotError::Invalid("snapshot record exceeds bound"));
    }
    let mut file = open_write(path)?;
    file.set_len(0)?;
    file.write_all(&bytes)?;
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

fn remove_stage(stage: &Path) -> Result<()> {
    match fs::symlink_metadata(stage) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            private_directory(stage)?
        }
        Ok(_) => {
            return Err(SnapshotError::Invalid(
                "snapshot stage is not a private directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    // Validate the entire bounded closure before the first removal. Never
    // follow substituted directories or reclaim undeclared files on retry.
    for entry in fs::read_dir(stage)?.take(33) {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(SnapshotError::Invalid("snapshot payload name is invalid"))?;
        if name == "boot" {
            sandsurf_native::local::Directory::open(&entry.path())?;
            for artifact in fs::read_dir(entry.path())?.take(4) {
                let artifact = artifact?;
                if !matches!(
                    artifact.file_name().to_str(),
                    Some("kernel" | "initramfs" | "boot.json")
                ) {
                    return Err(SnapshotError::Invalid("undeclared snapshot boot payload"));
                }
                drop(open_read(&artifact.path())?);
            }
        } else if matches!(
            name,
            "manifest.json"
                | "manifest-building"
                | "disk-input.json"
                | "system.ext4"
                | "snapshot.vmstate"
                | "memory"
                | "reconnect.json"
                | "capture.json"
        ) {
            drop(open_read(&entry.path())?);
        } else {
            return Err(SnapshotError::Invalid("undeclared snapshot payload"));
        }
    }
    if stage.join("boot").exists() {
        fs::remove_dir_all(stage.join("boot"))?;
    }
    for name in [
        "manifest.json",
        "manifest-building",
        "disk-input.json",
        "system.ext4",
        "snapshot.vmstate",
        "memory",
        "reconnect.json",
        "capture.json",
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
            "signature": null
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

    fn retirement(snapshot: &mut Snapshot) -> sandsurf_state::SnapshotReleaseRecord {
        snapshot.phase = SnapshotPhase::Retiring;
        let operation_id: OperationId = "retire-snapshot".try_into().unwrap();
        sandsurf_state::SnapshotReleaseRecord {
            request_digest: digest(
                Domain::Snapshot,
                &(
                    "sandsurf-release-snapshot-v1",
                    &operation_id,
                    &snapshot.request.id,
                ),
            )
            .unwrap(),
            operation_id,
            machine_id: snapshot.request.machine_id.clone(),
            snapshot_id: snapshot.request.id.clone(),
            cleanup_pending: true,
        }
    }

    #[test]
    fn snapshot_retirement_excludes_all_readers_and_fences_delayed_jobs_after_deletion() {
        let temp = Temp::new();
        let source = temp.0.join("source");
        open_write(&source).unwrap().write_all(&[7; 4096]).unwrap();
        let mut snapshot = snapshot();
        let root = temp.capture_root(&snapshot);
        prepare_filesystem(&root, &snapshot, &source).unwrap();
        finish_filesystem(&root, &snapshot, &temp.image(&snapshot)).unwrap();
        let original = snapshot.clone();
        let first = retain_input(&root, &snapshot.request.id).unwrap();
        let second = retain_input(&root, &snapshot.request.id).unwrap();
        let record = retirement(&mut snapshot);
        assert!(
            matches!(cleanup(&temp.0, &snapshot, &record), Err(SnapshotError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(!retirement_path(&root, &snapshot.request.id).exists());
        drop(first);
        assert!(cleanup(&temp.0, &snapshot, &record).is_err());
        drop(second);
        cleanup(&temp.0, &snapshot, &record).unwrap();
        cleanup(&temp.0, &snapshot, &record).unwrap();
        assert!(
            !root
                .join(object_name(snapshot.request.id.as_str()))
                .exists()
        );
        assert!(retirement_path(&root, &snapshot.request.id).exists());
        assert!(retain_input(&root, &snapshot.request.id).is_err());
        assert!(prepare_filesystem(&root, &original, &source).is_err());
        assert!(published_filesystem(&root, &original).is_err());
        assert!(!disk_stage(&root, &snapshot).exists());
        let mut changed = record.clone();
        changed.operation_id = "other-retirement".try_into().unwrap();
        changed.request_digest = digest(
            Domain::Snapshot,
            &(
                "sandsurf-release-snapshot-v1",
                &changed.operation_id,
                &changed.snapshot_id,
            ),
        )
        .unwrap();
        assert!(cleanup(&temp.0, &snapshot, &changed).is_err());
    }

    #[test]
    fn interrupted_snapshot_retirement_reclaims_only_declared_bytes_and_preserves_archives() {
        let temp = Temp::new();
        let mut snapshot = snapshot();
        let root = temp.capture_root(&snapshot);
        private_directory(&root).unwrap();
        let payload = root.join(object_name(snapshot.request.id.as_str()));
        private_directory(&payload).unwrap();
        open_write(&payload.join("system.ext4"))
            .unwrap()
            .write_all(b"disk")
            .unwrap();
        open_write(&payload.join("unowned"))
            .unwrap()
            .write_all(b"unknown")
            .unwrap();
        let record = retirement(&mut snapshot);
        assert!(cleanup(&temp.0, &snapshot, &record).is_err());
        assert_eq!(fs::read(payload.join("system.ext4")).unwrap(), b"disk");
        assert_eq!(fs::read(payload.join("unowned")).unwrap(), b"unknown");
        // The marker survives interruption and excludes every future reader.
        assert!(retain_input(&root, &snapshot.request.id).is_err());
        fs::remove_file(payload.join("unowned")).unwrap();
        let archive = root.parent().unwrap().join("retained-output");
        open_write(&archive)
            .unwrap()
            .write_all(b"original output")
            .unwrap();
        cleanup(&temp.0, &snapshot, &record).unwrap();
        assert_eq!(fs::read(archive).unwrap(), b"original output");
        assert!(!payload.exists());
    }

    #[test]
    fn full_snapshot_retirement_waits_for_original_native_custody_not_power_or_control_reports() {
        let temp = Temp::new();
        let mut snapshot = snapshot();
        snapshot.request.kind = SnapshotKind::Full;
        let root = temp.capture_root(&snapshot);
        private_directory(&root).unwrap();
        let disks = root.parent().unwrap().join("disks");
        private_directory(&disks).unwrap();
        let disk = disks.join("system.ext4");
        crate::storage::publish_disk(&disk, 4096, |stage| open_write(stage)?.set_len(4096))
            .unwrap();
        let original = crate::storage::attach(&disk).unwrap();
        let native = original.try_clone().unwrap();
        drop(original);
        let record = retirement(&mut snapshot);
        assert!(
            matches!(cleanup(&temp.0, &snapshot, &record), Err(SnapshotError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(!retirement_path(&root, &snapshot.request.id).exists());
        drop(native);
        cleanup(&temp.0, &snapshot, &record).unwrap();
        assert!(retirement_path(&root, &snapshot.request.id).exists());
    }

    #[test]
    fn full_snapshot_retirement_reclaims_interrupted_native_restore_copy_only_after_detachment() {
        let temp = Temp::new();
        let mut snapshot = snapshot();
        snapshot.request.kind = SnapshotKind::Full;
        snapshot.manifest_digest = Some(bytes_digest(b"full manifest"));
        let root = temp.capture_root(&snapshot);
        private_directory(&root).unwrap();
        let machine = root.parent().unwrap();
        let disks = machine.join("disks");
        private_directory(&disks).unwrap();
        let disk = disks.join("system.ext4");
        crate::storage::publish_disk(&disk, 4096, |stage| open_write(stage)?.set_len(4096))
            .unwrap();
        let guardian = machine.join("guardian");
        private_directory(&guardian).unwrap();
        let restores = guardian.join("restores");
        private_directory(&restores).unwrap();
        let copy = restores.join(format!(
            "{}.vmstate",
            snapshot.manifest_digest.as_ref().unwrap().as_str()
        ));
        open_write(&copy)
            .unwrap()
            .write_all(b"interrupted native state copy")
            .unwrap();
        let other = restores.join("another-owner.vmstate");
        open_write(&other)
            .unwrap()
            .write_all(b"other capture")
            .unwrap();
        let archive = guardian.join("retained-output");
        open_write(&archive)
            .unwrap()
            .write_all(b"original bytes")
            .unwrap();
        let original = crate::storage::attach(&disk).unwrap();
        let record = retirement(&mut snapshot);
        assert!(cleanup(&temp.0, &snapshot, &record).is_err());
        assert_eq!(fs::read(&copy).unwrap(), b"interrupted native state copy");
        drop(original);
        cleanup(&temp.0, &snapshot, &record).unwrap();
        assert!(!copy.exists());
        assert_eq!(fs::read(other).unwrap(), b"other capture");
        assert_eq!(fs::read(archive).unwrap(), b"original bytes");
        cleanup(&temp.0, &snapshot, &record).unwrap();
    }

    #[test]
    fn immutable_disk_input_survives_source_loss_and_interrupted_finishing() {
        let temp = Temp::new();
        let disk = temp.0.join("source.raw");
        open_write(&disk).unwrap().write_all(&[3; 4096]).unwrap();
        let snapshot = snapshot();
        let root = temp.capture_root(&snapshot);
        private_directory(&root).unwrap();
        let stage = disk_stage(&root, &snapshot);
        let pending = stage.with_extension("input-building");
        private_directory(&pending).unwrap();
        open_write(&pending.join("system.ext4"))
            .unwrap()
            .write_all(b"interrupted")
            .unwrap();
        prepare_filesystem(&root, &snapshot, &disk).unwrap();
        assert!(!pending.exists());
        assert!(prepared_filesystem(&root, &snapshot).unwrap());
        fs::remove_file(&disk).unwrap();
        prepare_filesystem(&root, &snapshot, &disk).unwrap();
        assert_eq!(fs::read(stage.join("system.ext4")).unwrap(), [3; 4096]);
        let custody = sandsurf_native::storage::disk_lease(&root.join(format!(
            ".{}.capture.lock",
            object_name(snapshot.request.operation_id.as_str())
        )))
        .unwrap();
        let image = temp.image(&snapshot);
        assert!(finish_filesystem(&root, &snapshot, &image).is_err());
        drop(custody);
        // A crash while writing the final manifest must not recopy the source
        // or discard the already complete captured input.
        open_write(&stage.join("manifest-building"))
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        let captured = finish_filesystem(&root, &snapshot, &image).unwrap();
        let retried = finish_filesystem(&root, &snapshot, &image).unwrap();
        assert_eq!(captured.disk_digest, retried.disk_digest);
        assert_eq!(captured.manifest_digest, retried.manifest_digest);
        assert_eq!(
            fs::read(
                root.join(object_name(snapshot.request.id.as_str()))
                    .join("system.ext4")
            )
            .unwrap(),
            [3; 4096]
        );
    }

    #[test]
    fn captured_input_requires_matching_binding_and_actual_bytes() {
        let temp = Temp::new();
        let disk = temp.0.join("source.raw");
        open_write(&disk).unwrap().write_all(&[3; 4096]).unwrap();
        let snapshot = snapshot();
        let root = temp.capture_root(&snapshot);
        prepare_filesystem(&root, &snapshot, &disk).unwrap();
        let mut changed = snapshot.clone();
        changed.request_digest = bytes_digest(b"another request");
        assert!(prepared_filesystem(&root, &changed).is_err());
        fs::write(disk_stage(&root, &snapshot).join("system.ext4"), [9; 4096]).unwrap();
        assert!(prepared_filesystem(&root, &snapshot).is_err());
        assert!(finish_filesystem(&root, &snapshot, &temp.image(&snapshot)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn stage_cleanup_never_follows_a_directory_symlink() {
        let temp = Temp::new();
        let outside = temp.0.join("outside");
        private_directory(&outside).unwrap();
        fs::write(outside.join("system.ext4"), b"retain").unwrap();
        let stage = temp.0.join("stage");
        std::os::unix::fs::symlink(&outside, &stage).unwrap();
        assert!(remove_stage(&stage).is_err());
        assert_eq!(fs::read(outside.join("system.ext4")).unwrap(), b"retain");
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
        assert!(finish_filesystem(&root, &foreign, &image).is_err());
        assert!(
            !root.exists(),
            "reject another image before allocating capture storage"
        );
        assert!(!root.parent().unwrap().join("images").exists());
        prepare_filesystem(&root, &snapshot, &disk).unwrap();
        finish_filesystem(&root, &snapshot, &image).unwrap();
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
        prepare_filesystem(&root, &snapshot, &source).unwrap();
        let captured = finish_filesystem(&root, &snapshot, &image).unwrap();
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
        let custody = crate::storage::attach(&fork).unwrap();
        assert!(
            verify_fork(
                &snapshot,
                &fork,
                &sandsurf_image::identity::CloneProfile::Preserve
            )
            .is_err(),
            "a completion reference cannot bypass native disk custody"
        );
        drop(custody);
        assert_eq!(
            verify_fork(
                &snapshot,
                &fork,
                &sandsurf_image::identity::CloneProfile::Preserve
            )
            .unwrap(),
            captured.disk_digest
        );
        assert!(
            verify_fork(
                &snapshot,
                &fork,
                &sandsurf_image::identity::CloneProfile::Alpine
            )
            .is_err()
        );
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
        crate::storage::publish_disk(&target, 4096, |staged| {
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
