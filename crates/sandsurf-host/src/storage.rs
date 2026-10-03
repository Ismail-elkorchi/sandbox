//! One physical storage owner for machine disks. Durable slot phases fence
//! creation, replacement and retirement; only a Ready published payload may
//! be attached. Staging files never represent a VM. An attachment transfers the
//! same exclusive slot lease to the native owner until actual native exit.

use sandsurf_native::PrivateFileAccess;
use sandsurf_native::local::{create_private_file, open_private_file};
use sandsurf_native::storage::{
    object_name, publish_new_file, replace_journal_file, sync_directory, sync_file,
};
use sandsurf_protocol::OperationId;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MAX_DISK_BYTES: u64 = 128 * 1024 * 1024 * 1024;

/// Boot producers and interrupted-operation recovery share one owned namespace.
pub(crate) fn boot_stage_path(parent: &Path) -> io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
    let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    Ok(parent.join(format!(".boot-{nonce}.stage")))
}

pub(crate) fn boot_stage_name(name: &str) -> bool {
    name.strip_prefix(".boot-")
        .and_then(|name| name.strip_suffix(".stage"))
        .is_some_and(|nonce| {
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Read the host's frozen boot record, never the mutable guest's next selection.
pub(crate) fn read_boot(directory: &Path) -> io::Result<sandsurf_image::boot::FrozenBoot> {
    let file = open_private_file(&directory.join("boot.json"), PrivateFileAccess::ReadOnly)?;
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(invalid("frozen boot record exceeds bound"));
    }
    let boot = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    sandsurf_image::boot::verify(directory, &boot)?;
    Ok(boot)
}

/// Transfer the actual boot artifacts of a native owner or full snapshot.
/// Publication is atomic and retryable; a memory capture never interprets the
/// guest disk or substitutes the kernel selected for its next cold boot.
pub(crate) fn copy_boot(
    source: &Path,
    destination: &Path,
) -> io::Result<sandsurf_image::boot::FrozenBoot> {
    let boot = read_boot(source)?;
    let kernel = source.join(&boot.kernel.path);
    let initramfs = boot
        .initramfs
        .as_ref()
        .map(|value| source.join(&value.path));
    let published = publish_boot(destination, |stage| {
        let copied = copy_boot_inputs(&kernel, initramfs.as_deref(), boot.architecture, stage)?;
        if copied != boot {
            return Err(invalid("frozen boot source changed during transfer"));
        }
        Ok(copied)
    })?;
    if published != boot {
        return Err(invalid("frozen boot publication conflict"));
    }
    Ok(published)
}

#[cfg(test)]
pub(crate) fn pin_boot(
    kernel: &Path,
    initramfs: Option<&Path>,
    architecture: sandsurf_image::Architecture,
    directory: &Path,
) -> io::Result<sandsurf_image::boot::FrozenBoot> {
    publish_boot(directory, |stage| {
        copy_boot_inputs(kernel, initramfs, architecture, stage)
    })
}

fn copy_boot_inputs(
    kernel: &Path,
    initramfs: Option<&Path>,
    architecture: sandsurf_image::Architecture,
    directory: &Path,
) -> io::Result<sandsurf_image::boot::FrozenBoot> {
    use sandsurf_image::boot;
    let copy =
        |input: &Path, name: &str, maximum: u64| -> io::Result<sandsurf_image::ImageArtifact> {
            let mut source = open_private_file(input, PrivateFileAccess::ReadOnly)?;
            let mut output = create_private_file(&directory.join(name))?;
            if io::copy(
                &mut Read::by_ref(&mut source).take(maximum + 1),
                &mut output,
            )? > maximum
            {
                return Err(invalid("pinned boot artifact exceeds bound"));
            }
            sync_file(&output)?;
            drop(output);
            let artifact = boot::artifact(&directory.join(name), name, maximum)?;
            // Windows private DACLs and digest-bound publication protect these
            // bytes. Its readonly attribute is not an authority boundary and
            // would prevent the owning storage transaction from reclaiming them.
            #[cfg(unix)]
            {
                let mut permissions = fs::metadata(directory.join(name))?.permissions();
                permissions.set_readonly(true);
                fs::set_permissions(directory.join(name), permissions)?;
            }
            Ok(artifact)
        };
    let boot = boot::FrozenBoot {
        architecture,
        kernel: copy(kernel, "kernel", boot::MAX_KERNEL)?,
        initramfs: initramfs
            .map(|path| copy(path, "initramfs", boot::MAX_INITRAMFS))
            .transpose()?,
    };
    Ok(boot)
}

/// Caller owns a detached disk lease or an immutable captured disk. Corrupt
/// selection never falls back to the creation kernel.
pub(crate) fn freeze_boot(
    image: &sandsurf_image::VerifiedImage,
    disk: &Path,
    directory: &Path,
) -> io::Result<sandsurf_image::boot::FrozenBoot> {
    use sandsurf_image::boot::{self, BootProfile};
    publish_boot(directory, |stage| {
        let boot = if image.manifest.boot_bundle.profile == BootProfile::Pinned {
            let boot = copy_boot_inputs(
                &image.kernel_path,
                image.initramfs_path.as_deref(),
                image.manifest.architecture,
                stage,
            )?;
            if boot.kernel.sha256 != image.manifest.boot_bundle.kernel.sha256
                || boot.initramfs.as_ref().map(|v| &v.sha256)
                    != image
                        .manifest
                        .boot_bundle
                        .initramfs
                        .as_ref()
                        .map(|v| &v.sha256)
            {
                return Err(invalid("pinned boot inputs changed"));
            }
            boot
        } else {
            boot::extract(disk, stage, image.manifest.architecture)?
        };
        Ok(boot)
    })
}

/// One transaction for selected, pinned and captured boot artifacts. Exclusive
/// stage creation precedes cleanup ownership; creation failure cannot authorize
/// deleting a pre-existing object. The complete record publishes with its bytes.
fn publish_boot(
    directory: &Path,
    prepare: impl FnOnce(&Path) -> io::Result<sandsurf_image::boot::FrozenBoot>,
) -> io::Result<sandsurf_image::boot::FrozenBoot> {
    if object_exists(directory)? {
        return read_boot(directory);
    }
    let parent = directory
        .parent()
        .ok_or_else(|| invalid("boot object has no owner"))?;
    let stage = boot_stage_path(parent)?;
    sandsurf_native::local::create_private_directory(&stage)?;
    let result = (|| {
        let boot = prepare(&stage)?;
        sandsurf_image::boot::verify(&stage, &boot)?;
        let mut record = create_private_file(&stage.join("boot.json"))?;
        record.write_all(&serde_json::to_vec(&boot).map_err(io::Error::other)?)?;
        sync_file(&record)?;
        drop(record);
        sync_directory(&stage)?;
        match sandsurf_native::storage::publish_new_directory(&stage, directory) {
            Ok(()) => sync_directory(parent)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if read_boot(directory)? != boot {
                    return Err(invalid("frozen boot publication conflict"));
                }
            }
            Err(error) => return Err(error),
        }
        Ok(boot)
    })();
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    result
}

/// Never acquire a mutation/attachment lease, repair a slot, open a filesystem,
/// or infer native detach just to report storage observations.
pub(crate) fn inspect(destination: &Path) -> crate::api::StorageInspection {
    use crate::api::{StorageInspection, StoragePayload, StoragePhase, StorageUnavailableReason};
    let unavailable = |reason| StorageInspection::Unavailable { reason };
    let record = match read_record(destination) {
        Ok(Some(record)) => record,
        Ok(None) => return unavailable(StorageUnavailableReason::OwnershipMissing),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return unavailable(StorageUnavailableReason::OwnershipInvalid);
        }
        Err(_) => return unavailable(StorageUnavailableReason::AccessUnavailable),
    };
    let (phase, operation_id) = match record.phase {
        DiskPhase::Preparing => (StoragePhase::Preparing, None),
        DiskPhase::Ready => (StoragePhase::Published, None),
        DiskPhase::Replacing { operation } => (StoragePhase::Replacing, Some(operation)),
        DiskPhase::Retiring { replacement } => (StoragePhase::Retiring, replacement),
        DiskPhase::Retired => (StoragePhase::Retired, None),
    };
    let payload = match open_private_file(destination, PrivateFileAccess::ReadOnly)
        .and_then(|file| file.metadata())
    {
        Ok(metadata) if metadata.len() != record.bytes => StoragePayload::CapacityMismatch {
            file_bytes: metadata.len(),
        },
        Ok(metadata) => StoragePayload::Present {
            file_bytes: metadata.len(),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => StoragePayload::Missing,
        Err(_) => StoragePayload::Unavailable,
    };
    StorageInspection::Current {
        phase,
        capacity_bytes: record.bytes,
        operation_id,
        payload,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiskObject {
    family: DiskFamily,
    version: u32,
    filename: String,
    bytes: u64,
    phase: DiskPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DiskFamily {
    LinuxComputer,
}

/// One bounded reader/validator for both storage mutation and observation.
fn read_record(destination: &Path) -> io::Result<Option<DiskObject>> {
    let file = match open_private_file(
        &destination.with_extension("storage.json"),
        PrivateFileAccess::ReadOnly,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > 8192 {
        return Err(invalid("storage object record exceeds its bound"));
    }
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(invalid("storage object record exceeds its bound"));
    }
    let record: DiskObject =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid storage ownership record"))?;
    if record.version != 1
        || destination.file_name().and_then(|name| name.to_str()) != Some(record.filename.as_str())
        || record.bytes == 0
        || record.bytes > MAX_DISK_BYTES
        || !record.bytes.is_multiple_of(4096)
    {
        return Err(invalid(
            "storage object identity or geometry conflicts with this slot",
        ));
    }
    Ok(Some(record))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum DiskPhase {
    Preparing,
    Ready,
    Replacing { operation: OperationId },
    Retiring { replacement: Option<OperationId> },
    Retired,
}

/// Physical storage state, not host lifecycle intent or resource authorization.
/// All slot mutations and native attachments use the same exclusive OS lease.
struct DiskOwner {
    path: PathBuf,
    record: DiskObject,
    lease: fs::File,
}

impl DiskOwner {
    fn open(destination: &Path, creation: Option<u64>) -> io::Result<Self> {
        if !destination.is_absolute() || destination.parent().is_none() {
            return Err(invalid("storage slot requires an absolute file path"));
        }
        let filename = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("storage slot name is invalid"))?;
        let lease_path = destination.with_extension("storage.lock");
        let lease = sandsurf_native::storage::disk_lease(&lease_path)?;
        let path = destination.with_extension("storage.json");
        let old = read_record(destination)?;
        let fresh = old.is_none();
        let record = if let Some(record) = old {
            if creation.is_some_and(|bytes| bytes != record.bytes) {
                return Err(invalid(
                    "storage object identity or geometry conflicts with this slot",
                ));
            }
            record
        } else {
            let bytes = creation.ok_or_else(|| invalid("storage slot has no ownership record"))?;
            if bytes == 0
                || bytes > MAX_DISK_BYTES
                || !bytes.is_multiple_of(4096)
                || object_exists(destination)?
            {
                return Err(invalid("untracked storage cannot be adopted or replaced"));
            }
            DiskObject {
                family: DiskFamily::LinuxComputer,
                version: 1,
                filename: filename.to_owned(),
                bytes,
                phase: DiskPhase::Preparing,
            }
        };
        let mut owner = Self {
            path,
            record,
            lease,
        };
        if fresh {
            owner.persist()?;
        }
        Ok(owner)
    }

    fn set_phase(&mut self, phase: DiskPhase) -> io::Result<()> {
        self.record.phase = phase;
        self.persist()
    }

    fn persist(&mut self) -> io::Result<()> {
        let staged = self.path.with_extension("record-building");
        reclaim_staging(&staged)?;
        let mut file = create_private_file(&staged)?;
        file.write_all(&serde_json::to_vec(&self.record).map_err(io::Error::other)?)?;
        sync_file(&file)?;
        drop(file);
        // Mutable journal state under the writer lease, not immutable payload
        // publication. Never replace a disk through this metadata path.
        replace_journal_file(&staged, &self.path)
    }
}

/// Acquire custody of a published disk. The native adapter must retain this
/// open description in its actual owner, not just a request worker or a cached
/// power observation. Closing the last transferred description releases the
/// lease; explicitly unlocking any duplicate would release it too early.
pub(crate) fn attach(disk: &Path) -> io::Result<std::sync::Arc<std::fs::File>> {
    let owner = DiskOwner::open(disk, None)?;
    if owner.record.phase != DiskPhase::Ready {
        return Err(invalid("only a published Ready disk may be attached"));
    }
    validate_disk(disk, owner.record.bytes)?;
    let lease = owner.lease;
    Ok(std::sync::Arc::new(lease))
}

/// Positive native-detachment evidence after loss of the volatile VM handle.
/// Every computer VMM retains this slot's original open description until
/// native exit. Acquiring it excludes those owners; an absent process handle
/// or management endpoint does not. This never repairs or adopts a disk and
/// does not interpret its potentially corrupt guest filesystem.
pub(crate) fn observe_detached(disk: &Path) -> io::Result<Option<sandsurf_protocol::Digest>> {
    let owner = match DiskOwner::open(disk, None) {
        Ok(owner) => owner,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
        Err(error) => return Err(error),
    };
    let evidence = sandsurf_protocol::digest(
        sandsurf_protocol::Domain::Machine,
        &(
            "sandsurf-native-disk-custody-released-v1",
            disk,
            &owner.record,
        ),
    )
    .map_err(io::Error::other)?;
    // Observation only: do not install a native owner, mutate storage, or
    // retain this lease as another lifetime authority.
    drop(owner);
    Ok(Some(evidence))
}

/// Replace a detached disk under an already journaled host operation. The
/// native owner must have released its attachment before entry. Power state
/// alone is not a storage lease. Original bytes survive until the replacement
/// is published and verified; interrupted effects reconcile these exact names.
pub(crate) fn replace_disk(
    destination: &Path,
    operation: &OperationId,
    bytes: u64,
    build: impl FnOnce(&Path) -> io::Result<()>,
    matches_content: impl Fn(&Path) -> io::Result<bool>,
) -> io::Result<()> {
    if !destination.is_absolute() {
        return Err(invalid(
            "disk replacement requires an absolute storage path",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("disk replacement has no parent"))?;
    let next = parent.join(format!(
        ".system.{}.next.ext4",
        object_name(operation.as_str())
    ));
    let previous = parent.join(format!(
        ".system.{}.previous",
        object_name(operation.as_str())
    ));
    let mut owner = DiskOwner::open(destination, None)?;
    if owner.record.bytes != bytes {
        return Err(invalid(
            "replacement geometry conflicts with storage ownership",
        ));
    }
    match &owner.record.phase {
        DiskPhase::Ready => owner.set_phase(DiskPhase::Replacing {
            operation: operation.clone(),
        })?,
        DiskPhase::Replacing { operation: active } if active == operation => {}
        _ => {
            return Err(invalid(
                "storage replacement belongs to another operation or retired slot",
            ));
        }
    }

    if !object_exists(destination)? {
        if object_exists(&next)? {
            validate_disk(&next, bytes)?;
            if !matches_content(&next)? {
                return Err(invalid(
                    "interrupted replacement disagrees with its approved content",
                ));
            }
            publish_new_file(&next, destination)?;
        } else if object_exists(&previous)? {
            validate_disk(&previous, bytes)?;
            publish_new_file(&previous, destination)?;
        }
    }
    if object_exists(destination)? {
        validate_disk(destination, bytes)?;
        if matches_content(destination)? {
            reclaim_staging(&next.with_extension("building"))?;
            reclaim_staging(&next)?;
            reclaim_staging(&previous)?;
            sync_directory(parent)?;
            return owner.set_phase(DiskPhase::Ready);
        }
    }
    if object_exists(&previous)? {
        return Err(invalid("replacement conflicts with its retained original"));
    }
    publish_prepared(&next, bytes, |staged| {
        build(staged)?;
        if !matches_content(staged)? {
            return Err(invalid(
                "prepared replacement does not match its approved content",
            ));
        }
        Ok(())
    })?;
    if !matches_content(&next)? {
        return Err(invalid("replacement does not match its approved content"));
    }
    if object_exists(destination)? {
        publish_new_file(destination, &previous)?;
    }
    if let Err(error) = publish_new_file(&next, destination) {
        if object_exists(&previous)? && !object_exists(destination)? {
            // Recover only this operation's original, without overwriting an
            // unexpected name or converting a failed publication into success.
            let _ = publish_new_file(&previous, destination);
        }
        return Err(error);
    }
    validate_disk(destination, bytes)?;
    if !matches_content(destination)? {
        return Err(invalid("installed replacement failed content verification"));
    }
    reclaim_staging(&previous)?;
    sync_directory(parent)?;
    owner.set_phase(DiskPhase::Ready)
}

fn object_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Prepare only native storage geometry and allocation. A creation seed can
/// derive from a root-controlled machine; never interpret its guest filesystem
/// here. Published disks never enter preparation again.
pub(crate) fn materialize(
    source: &Path,
    destination: &Path,
    bytes: u64,
    prepare_storage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if !source.is_absolute() {
        return Err(invalid("creation seed path must be absolute"));
    }
    publish_disk(destination, bytes, |staged| {
        let mut input = open_private_file(source, PrivateFileAccess::ReadOnly)?;
        let source_metadata = input.metadata()?;
        if source_metadata.len() == 0 || source_metadata.len() > MAX_DISK_BYTES {
            return Err(invalid("creation seed must be a bounded regular file"));
        }
        if source_metadata.len() > bytes {
            return Err(invalid(
                "creation seed exceeds the authorized disk capacity",
            ));
        }
        let mut output = create_private_file(staged)?;
        if io::copy(
            &mut Read::by_ref(&mut input).take(source_metadata.len() + 1),
            &mut output,
        )? != source_metadata.len()
            || input.metadata()?.len() != source_metadata.len()
        {
            return Err(invalid("creation seed changed during materialization"));
        }
        output.set_len(bytes)?;
        sync_file(&output)?;
        drop(output);
        prepare_storage(staged)
    })
}

/// The single publication path for creation seeds and snapshot-derived forks.
/// Only this owner makes a prepared raw machine disk attachable.
pub(crate) fn publish_disk(
    destination: &Path,
    bytes: u64,
    build: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let mut owner = DiskOwner::open(destination, Some(bytes))?;
    match owner.record.phase {
        DiskPhase::Preparing => {}
        DiskPhase::Ready if object_exists(destination)? => {}
        DiskPhase::Ready => {
            return Err(invalid(
                "published machine disk is missing; seed recreation is forbidden",
            ));
        }
        _ => {
            return Err(invalid(
                "storage is replacing or retired; attachment is forbidden",
            ));
        }
    }
    publish_prepared(destination, bytes, build)?;
    if owner.record.phase != DiskPhase::Ready {
        owner.set_phase(DiskPhase::Ready)?;
    }
    Ok(())
}

fn publish_prepared(
    destination: &Path,
    bytes: u64,
    build: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if !destination.is_absolute()
        || bytes == 0
        || bytes > MAX_DISK_BYTES
        || !bytes.is_multiple_of(4096)
    {
        return Err(invalid("persistent disk paths or geometry are invalid"));
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            validate_disk(destination, bytes)?;
            reserve_allocation(destination, bytes)?;
            reclaim_staging(&destination.with_extension("building"))?;
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let staged = destination.with_extension("building");
    // An interrupted build was never attachable. Recreate it from the
    // verified seed instead of treating partial contents as complete.
    reclaim_staging(&staged)?;
    build(&staged)?;
    validate_disk(&staged, bytes)?;
    reserve_allocation(&staged, bytes)?;
    publish_new_file(&staged, destination)
}

fn reserve_allocation(path: &Path, bytes: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let file = open_private_file(path, PrivateFileAccess::ReadWrite)?;
        sandsurf_native::storage::reserve_raw_capacity(&file, bytes)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (path, bytes);
    Ok(())
}

fn reclaim_staging(staged: &Path) -> io::Result<()> {
    match open_private_file(staged, PrivateFileAccess::ReadOnly) {
        Ok(file) => {
            drop(file);
            fs::remove_file(staged)?;
            sync_directory(staged.parent().expect("validated storage path"))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Called by the host only after the guardian's committed native detach/exit.
/// Never removes the machine root, output ledger, artifacts, or snapshots.
pub(crate) fn retire(disk: &Path, bytes: u64) -> io::Result<()> {
    if !disk.is_absolute() || disk.parent().is_none() {
        return Err(invalid("disk retirement requires an absolute storage path"));
    }
    // Destruction can precede the first successful native boot. Establish a
    // retired slot even when materialization never started; never adopt an
    // existing payload without its ownership record.
    let mut owner = DiskOwner::open(disk, Some(bytes))?;
    let replacement = match &owner.record.phase {
        DiskPhase::Retired => return Ok(()),
        DiskPhase::Replacing { operation } => Some(operation.clone()),
        DiskPhase::Retiring { replacement } => replacement.clone(),
        _ => None,
    };
    owner.set_phase(DiskPhase::Retiring {
        replacement: replacement.clone(),
    })?;
    if let Some(operation) = replacement {
        let parent = disk.parent().expect("validated parent");
        let next = parent.join(format!(
            ".system.{}.next.ext4",
            object_name(operation.as_str())
        ));
        reclaim_staging(&next.with_extension("building"))?;
        reclaim_staging(&next)?;
        reclaim_staging(&parent.join(format!(
            ".system.{}.previous",
            object_name(operation.as_str())
        )))?;
    }
    reclaim_staging(&disk.with_extension("building"))?;
    reclaim_staging(disk)?;
    sync_directory(disk.parent().expect("validated parent"))?;
    owner.set_phase(DiskPhase::Retired)
}

fn validate_disk(path: &Path, bytes: u64) -> io::Result<()> {
    let file = open_private_file(path, PrivateFileAccess::ReadOnly)?;
    let actual = file.metadata()?.len();
    drop(file);
    if actual != bytes {
        return Err(invalid(
            "persistent disk capacity differs from host authority",
        ));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_native::local::create_private_directory;
    use std::io::Write;

    struct Fixture(std::path::PathBuf);

    fn pinned_image(root: &Path, kernel: &Path) -> sandsurf_image::VerifiedImage {
        let mut manifest: sandsurf_image::ImageManifest = serde_json::from_str(include_str!(
            "../../../packages/sandsurf/images/development-x64/manifest.json"
        ))
        .unwrap();
        manifest.boot_bundle.profile = sandsurf_image::boot::BootProfile::Pinned;
        manifest.boot_bundle.initramfs = None;
        manifest.boot_bundle.kernel =
            sandsurf_image::boot::artifact(kernel, "kernel", 8192).unwrap();
        sandsurf_image::VerifiedImage {
            manifest,
            manifest_path: root.join("manifest.json"),
            manifest_digest: "unused".into(),
            kernel_path: kernel.into(),
            initramfs_path: None,
            system_path: root.join("unused-disk"),
        }
    }

    #[test]
    fn offline_boot_publication_is_atomic_retries_complete_bytes_and_never_adopts_partial_records()
    {
        let fixture = Fixture::new();
        let kernel = fixture.0.join("kernel-input");
        create_private_file(&kernel)
            .unwrap()
            .write_all(b"invalid kernel")
            .unwrap();
        let target = fixture.0.join("frozen-boot");
        let image = pinned_image(&fixture.0, &kernel);
        assert!(freeze_boot(&image, &image.system_path, &target).is_err());
        assert!(!target.exists());
        assert!(
            !fs::read_dir(&fixture.0).unwrap().any(|v| v
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".stage"))
        );
        let mut bytes = vec![0; 4096];
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        bytes[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        bytes[0x236] = 1;
        bytes[0x206..0x208].copy_from_slice(&0x020c_u16.to_le_bytes());
        fs::write(&kernel, &bytes).unwrap();
        let image = pinned_image(&fixture.0, &kernel);
        let boot = freeze_boot(&image, &image.system_path, &target).unwrap();
        fs::remove_file(&kernel).unwrap();
        assert_eq!(
            freeze_boot(&image, &image.system_path, &target).unwrap(),
            boot
        );
        assert_eq!(fs::read(target.join("kernel")).unwrap(), bytes);
        let partial = fixture.0.join("partial-boot");
        create_private_directory(&partial).unwrap();
        fs::write(partial.join("kernel"), b"partial").unwrap();
        assert!(freeze_boot(&image, &image.system_path, &partial).is_err());
        assert_eq!(fs::read(partial.join("kernel")).unwrap(), b"partial");
    }

    #[test]
    fn running_boot_publication_preserves_bytes_and_rejects_reference_only_or_changed_sources() {
        let fixture = Fixture::new();
        let kernel = fixture.0.join("kernel");
        let mut bytes = vec![0; 4096];
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        bytes[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        bytes[0x236] = 1;
        bytes[0x206..0x208].copy_from_slice(&0x020c_u16.to_le_bytes());
        create_private_file(&kernel)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let source = fixture.0.join("native-boot");
        let published = fixture.0.join("snapshot-boot");
        let boot = pin_boot(&kernel, None, sandsurf_image::Architecture::X64, &source).unwrap();
        assert_eq!(copy_boot(&source, &published).unwrap(), boot);
        assert_eq!(
            copy_boot(&source, &published).unwrap(),
            boot,
            "exact retries reuse publication"
        );
        fs::remove_file(source.join("kernel")).unwrap();
        assert!(copy_boot(&source, &fixture.0.join("reference-only")).is_err());
        assert_eq!(
            read_boot(&published).unwrap(),
            boot,
            "original deletion cannot erase captured bytes"
        );
        assert_eq!(fs::read(published.join("kernel")).unwrap(), bytes);
    }

    #[test]
    fn failed_boot_preparation_reclaims_its_stage_not_another_owners_destination() {
        let fixture = Fixture::new();
        let destination = fixture.0.join("frozen-boot");
        let result = publish_boot(&destination, |stage| {
            create_private_file(&stage.join("selection.json"))?
                .write_all(b"interrupted selection")?;
            create_private_directory(&destination)?;
            create_private_file(&destination.join("another-owner"))?
                .write_all(b"retain original")?;
            Err(io::Error::other("interrupted before boot verification"))
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(destination.join("another-owner")).unwrap(),
            b"retain original"
        );
        assert!(
            !fs::read_dir(&fixture.0)
                .unwrap()
                .any(|entry| { boot_stage_name(entry.unwrap().file_name().to_str().unwrap()) })
        );
        assert!(
            publish_boot(&destination, |_| panic!(
                "partial destinations cannot be rebuilt"
            ))
            .is_err()
        );
        assert_eq!(
            fs::read(destination.join("another-owner")).unwrap(),
            b"retain original"
        );
    }

    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0_u8; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let root = std::env::temp_dir().join(format!(
                "sandsurf-private-storage-{:032x}",
                u128::from_le_bytes(nonce)
            ));
            create_private_directory(&root).unwrap();
            create_private_file(&root.join("seed"))
                .unwrap()
                .write_all(b"seed bytes")
                .unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn create_disk(target: &Path, byte: u8) {
        publish_disk(target, 4096, |staged| {
            create_private_file(staged)?.write_all(&vec![byte; 4096])
        })
        .unwrap();
    }

    fn replacement_path(root: &Path, suffix: &str) -> PathBuf {
        root.join(format!(".system.{}.{suffix}", object_name("replace")))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn attachment_custody_fences_every_mutation_until_last_native_description_closes() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        create_disk(&target, 1);
        let guardian = attach(&target).unwrap();
        let native_owner = guardian.try_clone().unwrap();
        drop(guardian);
        let operation = "replace".try_into().unwrap();
        for error in [
            attach(&target).unwrap_err(),
            publish_disk(&target, 4096, |_| {
                panic!("an attached slot must not be materialized")
            })
            .unwrap_err(),
            replace(&target, &operation).unwrap_err(),
            retire(&target, 4096).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(fs::read(&target).unwrap(), vec![1; 4096]);
        drop(native_owner);
        replace(&target, &operation).unwrap();
        assert_eq!(fs::read(&target).unwrap(), vec![2; 4096]);
        retire(&target, 4096).unwrap();
        assert!(attach(&target).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn detachment_observation_never_repairs_adopts_or_requires_guest_disk_health() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        assert!(observe_detached(&target).is_err());
        assert!(!target.with_extension("storage.json").exists());
        create_disk(&target, 1);
        let record = fs::read(target.with_extension("storage.json")).unwrap();
        let guardian = attach(&target).unwrap();
        let native = guardian.try_clone().unwrap();
        drop(guardian);
        assert_eq!(observe_detached(&target).unwrap(), None);
        drop(native);
        let evidence = observe_detached(&target).unwrap().unwrap();
        fs::remove_file(&target).unwrap();
        assert_eq!(observe_detached(&target).unwrap(), Some(evidence));
        assert_eq!(
            fs::read(target.with_extension("storage.json")).unwrap(),
            record
        );
        assert!(!target.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn attachment_refuses_partial_missing_shared_and_replacing_payloads() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        let preparing = DiskOwner::open(&target, Some(4096)).unwrap();
        drop(preparing);
        assert!(attach(&target).is_err());
        create_disk(&target, 1);
        let alias = fixture.0.join("alias");
        fs::hard_link(&target, &alias).unwrap();
        assert!(attach(&target).is_err());
        fs::remove_file(alias).unwrap();
        let mut owner = DiskOwner::open(&target, None).unwrap();
        owner
            .set_phase(DiskPhase::Replacing {
                operation: "replace".try_into().unwrap(),
            })
            .unwrap();
        drop(owner);
        assert!(attach(&target).is_err());
        replace(&target, &"replace".try_into().unwrap()).unwrap();
        fs::remove_file(&target).unwrap();
        assert!(attach(&target).is_err());
    }

    fn replace(target: &Path, operation: &OperationId) -> io::Result<()> {
        replace_disk(
            target,
            operation,
            4096,
            |staged| create_private_file(staged)?.write_all(&vec![2; 4096]),
            |candidate| Ok(fs::read(candidate)? == vec![2; 4096]),
        )
    }

    #[test]
    fn inspection_observes_one_owner_without_mutating_or_releasing_its_lease() {
        use crate::api::{
            StorageInspection, StoragePayload, StoragePhase, StorageUnavailableReason,
        };
        let fixture = Fixture::new();
        let disk = fixture.0.join("system.ext4");
        assert_eq!(
            inspect(&disk),
            StorageInspection::Unavailable {
                reason: StorageUnavailableReason::OwnershipMissing
            }
        );
        let mut owner = DiskOwner::open(&disk, Some(4096)).unwrap();
        assert!(matches!(
            inspect(&disk),
            StorageInspection::Current {
                phase: StoragePhase::Preparing,
                payload: StoragePayload::Missing,
                ..
            }
        ));
        create_private_file(&disk)
            .unwrap()
            .write_all(&vec![1; 4096])
            .unwrap();
        owner.set_phase(DiskPhase::Ready).unwrap();
        let record = fs::read(disk.with_extension("storage.json")).unwrap();
        assert!(matches!(
            inspect(&disk),
            StorageInspection::Current {
                phase: StoragePhase::Published,
                ..
            }
        ));
        assert_eq!(
            fs::read(disk.with_extension("storage.json")).unwrap(),
            record
        );
        assert_eq!(
            DiskOwner::open(&disk, None).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(owner);
        fs::remove_file(&disk).unwrap();
        assert!(matches!(
            inspect(&disk),
            StorageInspection::Current {
                phase: StoragePhase::Published,
                payload: StoragePayload::Missing,
                ..
            }
        ));
        assert!(
            !disk.exists(),
            "inspection must never reseed missing storage"
        );
    }

    #[test]
    fn inspection_reports_corrupt_ownership_and_partial_raw_payload_without_repair() {
        use crate::api::{StorageInspection, StoragePayload, StorageUnavailableReason};
        let fixture = Fixture::new();
        let disk = fixture.0.join("system.ext4");
        let mut owner = DiskOwner::open(&disk, Some(4096)).unwrap();
        create_private_file(&disk)
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        owner.set_phase(DiskPhase::Ready).unwrap();
        assert!(matches!(
            inspect(&disk),
            StorageInspection::Current {
                payload: StoragePayload::CapacityMismatch { file_bytes: 7 },
                ..
            }
        ));
        drop(owner);
        fs::write(disk.with_extension("storage.json"), b"invalid").unwrap();
        assert_eq!(
            inspect(&disk),
            StorageInspection::Unavailable {
                reason: StorageUnavailableReason::OwnershipInvalid
            }
        );
        assert_eq!(fs::read(disk).unwrap(), b"partial");
    }

    #[test]
    fn missing_published_and_retired_disks_cannot_be_reseeded() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        create_disk(&target, 1);
        fs::remove_file(&target).unwrap();
        assert!(
            publish_disk(&target, 4096, |_| panic!("lost disk must not be recreated")).is_err()
        );
        assert!(!target.exists());
        retire(&target, 4096).unwrap();
        retire(&target, 4096).unwrap();
        assert!(
            publish_disk(&target, 4096, |_| panic!(
                "retired slot must not be recreated"
            ))
            .is_err()
        );
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Retired
        );
    }

    #[test]
    fn destroying_before_first_boot_permanently_retires_the_slot() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        retire(&target, 4096).unwrap();
        assert!(!target.exists());
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Retired
        );
        assert!(
            publish_disk(&target, 4096, |_| panic!(
                "destroyed unbooted machine must not be created"
            ))
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sparse_disk_publication_reserves_capacity_before_ready_and_reopen_never_rebuilds() {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        publish_disk(&target, 65536, |staged| {
            create_private_file(staged)?.set_len(65536)
        })
        .unwrap();
        assert!(fs::metadata(&target).unwrap().blocks() * 512 >= 65536);
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Ready
        );
        publish_disk(&target, 65536, |_| {
            panic!("capacity checks must not rebuild a published disk")
        })
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), vec![0; 65536]);
        assert!(fs::metadata(&target).unwrap().blocks() * 512 >= 65536);
    }

    #[test]
    fn published_payload_before_ready_commit_is_recovered_without_rebuilding() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        let owner = DiskOwner::open(&target, Some(4096)).unwrap();
        publish_prepared(&target, 4096, |staged| {
            create_private_file(staged)?.write_all(&vec![3; 4096])
        })
        .unwrap();
        drop(owner);
        publish_disk(&target, 4096, |_| panic!("published payload is complete")).unwrap();
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Ready
        );
        assert_eq!(fs::read(&target).unwrap(), vec![3; 4096]);
    }

    #[test]
    fn storage_has_one_writer_and_does_not_adopt_untracked_payloads() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        let owner = DiskOwner::open(&target, Some(4096)).unwrap();
        assert_eq!(
            DiskOwner::open(&target, None).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(owner);
        let untracked = fixture.0.join("untracked.ext4");
        create_private_file(&untracked)
            .unwrap()
            .write_all(&vec![9; 4096])
            .unwrap();
        assert!(
            publish_disk(&untracked, 4096, |_| panic!(
                "untracked original must remain intact"
            ))
            .is_err()
        );
        assert_eq!(fs::read(&untracked).unwrap(), vec![9; 4096]);
        assert!(!untracked.with_extension("storage.json").exists());
    }

    #[test]
    #[ignore = "child fixture for killed_storage_owner_recovers_without_reseed"]
    fn storage_owner_child() {
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(15));
            std::process::exit(70);
        });
        let root = PathBuf::from(std::env::var_os("SANDSURF_STORAGE_OWNER_FIXTURE").unwrap());
        let target = root.join("system.ext4");
        create_disk(&target, 1);
        let mut owner = DiskOwner::open(&target, None).unwrap();
        owner
            .set_phase(DiskPhase::Replacing {
                operation: "replace".try_into().unwrap(),
            })
            .unwrap();
        let next = replacement_path(&root, "next.ext4");
        let stage: u8 = std::env::var("SANDSURF_STORAGE_OWNER_STAGE")
            .unwrap()
            .parse()
            .unwrap();
        // Real process death at every publication boundary; no in-process
        // surrogate that releases the writer lock cleanly.
        if (1..=3).contains(&stage) {
            publish_prepared(&next, 4096, |staged| {
                create_private_file(staged)?.write_all(&vec![2; 4096])
            })
            .unwrap();
        }
        if stage >= 2 {
            publish_new_file(&target, &replacement_path(&root, "previous")).unwrap();
        }
        if stage == 3 {
            publish_new_file(&next, &target).unwrap();
        }
        if stage == 4 {
            create_private_file(&next.with_extension("building"))
                .unwrap()
                .write_all(b"partial")
                .unwrap();
        }
        println!("STORAGE-OWNER-READY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }

    #[test]
    fn killed_storage_owner_recovers_without_reseed() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        struct ChildOwner(std::process::Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        for stage in 0..5 {
            let fixture = Fixture::new();
            let mut child = ChildOwner(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "storage::tests::storage_owner_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("SANDSURF_STORAGE_OWNER_FIXTURE", &fixture.0)
                    .env("SANDSURF_STORAGE_OWNER_STAGE", stage.to_string())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let mut stdout = std::io::BufReader::new(child.0.stdout.take().unwrap());
            loop {
                let mut line = String::new();
                assert_ne!(
                    stdout.read_line(&mut line).unwrap(),
                    0,
                    "storage owner fixture exited before readiness"
                );
                if line.trim().ends_with("STORAGE-OWNER-READY") {
                    break;
                }
            }
            let target = fixture.0.join("system.ext4");
            assert_eq!(target.exists(), stage < 2 || stage == 3);
            assert_eq!(
                publish_disk(&target, 4096, |_| panic!(
                    "active writer must not be replaced"
                ))
                .unwrap_err()
                .kind(),
                io::ErrorKind::WouldBlock
            );
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(
                publish_disk(&target, 4096, |_| panic!(
                    "interrupted replacement must not be reseeded"
                ))
                .is_err()
            );
            assert!(replace(&target, &"other-operation".try_into().unwrap()).is_err());
            replace(&target, &"replace".try_into().unwrap()).unwrap();
            assert_eq!(fs::read(&target).unwrap(), vec![2; 4096]);
            assert_eq!(
                DiskOwner::open(&target, None).unwrap().record.phase,
                DiskPhase::Ready
            );
            for name in ["next.ext4", "next.building", "previous"] {
                assert!(!replacement_path(&fixture.0, name).exists());
            }
            replace(&target, &"replace".try_into().unwrap()).unwrap();
        }
    }

    #[test]
    fn invalid_replacement_preserves_original_and_remains_unattachable() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        create_disk(&target, 1);
        let operation: OperationId = "replace".try_into().unwrap();
        assert!(
            replace_disk(
                &target,
                &operation,
                4096,
                |staged| create_private_file(staged)?.write_all(&vec![8; 4096]),
                |candidate| Ok(fs::read(candidate)? == vec![2; 4096])
            )
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), vec![1; 4096]);
        assert!(publish_disk(&target, 4096, |_| Ok(())).is_err());
        replace(&target, &operation).unwrap();
        assert_eq!(fs::read(&target).unwrap(), vec![2; 4096]);
    }

    #[test]
    fn retirement_reclaims_only_its_replacement_and_preserves_archives() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        create_disk(&target, 1);
        let mut owner = DiskOwner::open(&target, None).unwrap();
        owner
            .set_phase(DiskPhase::Replacing {
                operation: "replace".try_into().unwrap(),
            })
            .unwrap();
        drop(owner);
        let owned = [
            replacement_path(&fixture.0, "next.ext4"),
            replacement_path(&fixture.0, "next.building"),
            replacement_path(&fixture.0, "previous"),
        ];
        for path in &owned {
            create_private_file(path)
                .unwrap()
                .write_all(b"owned")
                .unwrap();
        }
        let retained = ["retained-output", ".system.unrelated.previous"];
        for name in retained {
            create_private_file(&fixture.0.join(name))
                .unwrap()
                .write_all(b"retained")
                .unwrap();
        }
        retire(&target, 4096).unwrap();
        for path in &owned {
            assert!(!path.exists());
        }
        for name in retained {
            assert_eq!(fs::read(fixture.0.join(name)).unwrap(), b"retained");
        }
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Retired
        );
    }

    #[test]
    fn corrupt_ownership_records_are_rejected_without_touching_payload() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        create_disk(&target, 1);
        let record_path = target.with_extension("storage.json");
        let original = fs::read(&record_path).unwrap();
        for corrupt in [
            b"{}".to_vec(),
            vec![0; 8193],
            original
                .iter()
                .copied()
                .chain(b" trailing".iter().copied())
                .collect(),
        ] {
            fs::write(&record_path, &corrupt).unwrap();
            assert!(
                publish_disk(&target, 4096, |_| panic!(
                    "invalid record must never prepare"
                ))
                .is_err()
            );
            assert!(retire(&target, 4096).is_err());
            assert_eq!(fs::read(&record_path).unwrap(), corrupt);
            assert_eq!(fs::read(&target).unwrap(), vec![1; 4096]);
        }
    }

    #[test]
    fn previous_storage_generation_is_rejected_without_rewriting_disk_or_record() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        create_disk(&target, 1);
        let path = target.with_extension("storage.json");
        let mut old: DiskObject = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        old.version = 2;
        let original = serde_json::to_vec(&old).unwrap();
        fs::write(&path, &original).unwrap();
        assert!(DiskOwner::open(&target, None).is_err());
        assert!(retire(&target, 4096).is_err());
        assert_eq!(fs::read(path).unwrap(), original);
        assert_eq!(fs::read(target).unwrap(), vec![1; 4096]);
    }

    #[test]
    fn shared_disk_identity_is_never_attached_or_deleted() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.raw");
        materialize(&fixture.0.join("seed"), &target, 4096, |_| Ok(())).unwrap();
        let alias = fixture.0.join("other-owner.raw");
        fs::hard_link(&target, &alias).unwrap();
        assert!(
            materialize(&fixture.0.join("seed"), &target, 4096, |_| panic!(
                "shared live disk must not be prepared"
            ))
            .is_err()
        );
        assert!(retire(&target, 4096).is_err());
        assert!(target.exists());
        assert!(alias.exists());
        fs::remove_file(alias).unwrap();
        retire(&target, 4096).unwrap();
    }

    #[test]
    fn linked_interrupted_stage_cannot_reclaim_another_owners_seed() {
        let fixture = Fixture::new();
        let source = fixture.0.join("seed");
        let target = fixture.0.join("system.raw");
        let staged = target.with_extension("building");
        fs::hard_link(&source, &staged).unwrap();
        assert!(
            materialize(&source, &target, 4096, |_| panic!(
                "unowned stage must not be prepared"
            ))
            .is_err()
        );
        assert!(!target.exists());
        assert_eq!(fs::read(&source).unwrap(), b"seed bytes");
        assert!(staged.exists());
    }

    #[test]
    fn invalid_prepared_geometry_never_publishes_and_recovery_recreates_owned_stage() {
        let fixture = Fixture::new();
        let source = fixture.0.join("seed");
        let target = fixture.0.join("system.raw");
        assert!(
            materialize(&source, &target, 4096, |staged| {
                open_private_file(staged, PrivateFileAccess::ReadWrite)?.set_len(8192)
            })
            .is_err()
        );
        assert!(!target.exists());
        assert_eq!(
            fs::metadata(target.with_extension("building"))
                .unwrap()
                .len(),
            8192
        );
        materialize(&source, &target, 4096, |_| Ok(())).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().len(), 4096);
        assert_eq!(&fs::read(target).unwrap()[..10], b"seed bytes");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_seed_stage_and_published_disk_are_rejected_intact() {
        let fixture = Fixture::new();
        let source = fixture.0.join("seed");
        let alias = fixture.0.join("seed-link");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        let target = fixture.0.join("system.raw");
        assert!(materialize(&alias, &target, 4096, |_| Ok(())).is_err());
        std::os::unix::fs::symlink(&source, target.with_extension("building")).unwrap();
        assert!(materialize(&source, &target, 4096, |_| Ok(())).is_err());
        assert!(retire(&target, 4096).is_err());
        fs::remove_file(target.with_extension("building")).unwrap();
        std::os::unix::fs::symlink(&source, &target).unwrap();
        assert!(materialize(&source, &target, 4096, |_| Ok(())).is_err());
        assert!(retire(&target, 4096).is_err());
        assert_eq!(fs::read(source).unwrap(), b"seed bytes");
        assert!(
            fs::symlink_metadata(target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn interrupted_preparation_never_publishes_and_restart_never_interprets_live_disk() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-storage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_private_directory(&root).unwrap();
        let source = root.join("seed.ext4");
        let target = root.join("system.ext4");
        create_private_file(&source)
            .unwrap()
            .write_all(b"verified-seed")
            .unwrap();
        assert!(
            materialize(&source, &target, 4096, |_| {
                Err(io::Error::other("interrupted seed preparation"))
            })
            .is_err()
        );
        assert!(!target.exists());
        assert!(target.with_extension("building").exists());
        materialize(&source, &target, 4096, |_| Ok(())).unwrap();
        assert!(!target.with_extension("building").exists());
        fs::remove_file(&source).unwrap();
        let disk = open_private_file(&target, PrivateFileAccess::ReadWrite).unwrap();
        (&disk).write_all(b"guest-owned!").unwrap();
        drop(disk);
        create_private_file(&target.with_extension("building"))
            .unwrap()
            .write_all(b"unpublished build")
            .unwrap();
        materialize(&source, &target, 4096, |_| {
            panic!("published guest disk must never enter seed preparation")
        })
        .unwrap();
        assert!(!target.with_extension("building").exists());
        assert_eq!(&fs::read(&target).unwrap()[..12], b"guest-owned!");
        assert!(materialize(&source, &target, 8192, |_| Ok(())).is_err());
        let retained = root.join("retained-output");
        create_private_file(&retained)
            .unwrap()
            .write_all(b"protected bytes")
            .unwrap();
        retire(&target, 4096).unwrap();
        assert!(!target.exists());
        retire(&target, 4096).unwrap();
        assert_eq!(fs::read(&retained).unwrap(), b"protected bytes");
        fs::remove_file(retained).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
