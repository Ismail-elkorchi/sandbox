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
    if destination.exists() {
        if read_boot(destination)? != boot {
            return Err(invalid("frozen boot publication conflict"));
        }
        return Ok(boot);
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("boot destination has no owner"))?;
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
    let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let stage = parent.join(format!(".boot-{nonce}.stage"));
    sandsurf_native::local::create_private_directory(&stage)?;
    let result = (|| {
        for (artifact, bound) in std::iter::once((&boot.kernel, sandsurf_image::boot::MAX_KERNEL))
            .chain(
                boot.initramfs
                    .iter()
                    .map(|v| (v, sandsurf_image::boot::MAX_INITRAMFS)),
            )
        {
            let mut input =
                open_private_file(&source.join(&artifact.path), PrivateFileAccess::ReadOnly)?;
            let mut output = create_private_file(&stage.join(&artifact.path))?;
            if io::copy(&mut Read::by_ref(&mut input).take(bound + 1), &mut output)? > bound {
                return Err(invalid("frozen boot artifact exceeds bound"));
            }
            sync_file(&output)?;
            drop(output);
            #[cfg(unix)]
            {
                let mut permissions = fs::metadata(stage.join(&artifact.path))?.permissions();
                permissions.set_readonly(true);
                fs::set_permissions(stage.join(&artifact.path), permissions)?;
            }
        }
        sandsurf_image::boot::verify(&stage, &boot)?;
        let mut record = create_private_file(&stage.join("boot.json"))?;
        record.write_all(&serde_json::to_vec(&boot).map_err(io::Error::other)?)?;
        sync_file(&record)?;
        drop(record);
        sync_directory(&stage)?;
        match sandsurf_native::storage::publish_new_directory(&stage, destination) {
            Ok(()) => sync_directory(parent),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if read_boot(destination)? != boot {
                    return Err(invalid("frozen boot publication conflict"));
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    })();
    // Only this call's freshly created stage is reclaimed.
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    result?;
    Ok(boot)
}

pub(crate) fn pin_boot(
    kernel: &Path,
    initramfs: Option<&Path>,
    architecture: sandsurf_image::Architecture,
    directory: &Path,
) -> io::Result<sandsurf_image::boot::FrozenBoot> {
    use sandsurf_image::boot;
    sandsurf_native::local::create_private_directory(directory)?;
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
    boot::verify(directory, &boot)?;
    let mut record = create_private_file(&directory.join("boot.json"))?;
    record.write_all(&serde_json::to_vec(&boot).map_err(io::Error::other)?)?;
    sync_file(&record)?;
    sync_directory(directory)?;
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
    if image.manifest.boot_bundle.profile == BootProfile::Pinned {
        let boot = pin_boot(
            &image.kernel_path,
            image.initramfs_path.as_deref(),
            image.manifest.architecture,
            directory,
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
        return Ok(boot);
    }
    sandsurf_native::local::create_private_directory(directory)?;
    let boot = boot::extract(disk, directory, image.manifest.architecture)?;
    boot::verify(directory, &boot)?;
    let mut record = create_private_file(&directory.join("boot.json"))?;
    record.write_all(&serde_json::to_vec(&boot).map_err(io::Error::other)?)?;
    sync_file(&record)?;
    sync_directory(directory)?;
    Ok(boot)
}

/// Never acquire a mutation/attachment lease, repair a slot, open a filesystem,
/// or infer native detach just to report storage observations.
pub(crate) fn inspect(destination: &Path) -> crate::api::StorageInspection {
    use crate::api::{
        StorageFormat, StorageInspection, StoragePayload, StoragePhase, StorageUnavailableReason,
    };
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
        #[cfg(windows)]
        DiskPhase::Attached { .. } => (StoragePhase::Attached, None),
        DiskPhase::Replacing { operation } => (StoragePhase::Replacing, Some(operation)),
        DiskPhase::Retiring { replacement } => (StoragePhase::Retiring, replacement),
        DiskPhase::Retired => (StoragePhase::Retired, None),
    };
    let payload = match open_private_file(destination, PrivateFileAccess::ReadOnly)
        .and_then(|file| file.metadata())
    {
        Ok(metadata) if record.format == DiskFormat::Raw && metadata.len() != record.bytes => {
            StoragePayload::CapacityMismatch {
                file_bytes: metadata.len(),
            }
        }
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
        format: match record.format {
            DiskFormat::Raw => StorageFormat::Raw,
            #[cfg(windows)]
            DiskFormat::Vhdx => StorageFormat::Vhdx,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DiskFormat {
    Raw,
    #[cfg(windows)]
    Vhdx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DiskObject {
    family: DiskFamily,
    version: u32,
    filename: String,
    bytes: u64,
    format: DiskFormat,
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
    #[cfg(windows)]
    Attached {
        compute_system: String,
    },
    Replacing {
        operation: OperationId,
    },
    Retiring {
        replacement: Option<OperationId>,
    },
    Retired,
}

/// Physical storage state, not host lifecycle intent or resource authorization.
/// All slot mutations and native attachments use the same exclusive OS lease.
struct DiskOwner {
    path: PathBuf,
    record: DiskObject,
    lease: Option<std::fs::File>,
}

impl Drop for DiskOwner {
    fn drop(&mut self) {
        if let Some(lease) = &self.lease {
            let _ = lease.unlock();
        }
    }
}

impl DiskOwner {
    fn open(destination: &Path, creation: Option<(u64, DiskFormat)>) -> io::Result<Self> {
        if !destination.is_absolute() || destination.parent().is_none() {
            return Err(invalid("storage slot requires an absolute file path"));
        }
        let filename = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("storage slot name is invalid"))?;
        let lease_path = destination.with_extension("storage.lock");
        let lease = match create_private_file(&lease_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_private_file(&lease_path, PrivateFileAccess::ReadWrite)?
            }
            Err(error) => return Err(error),
        };
        lease.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "storage slot already has a writer",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        let path = destination.with_extension("storage.json");
        let old = read_record(destination)?;
        let fresh = old.is_none();
        let record = if let Some(record) = old {
            if creation
                .is_some_and(|(bytes, format)| bytes != record.bytes || format != record.format)
            {
                return Err(invalid(
                    "storage object identity or geometry conflicts with this slot",
                ));
            }
            record
        } else {
            let (bytes, format) =
                creation.ok_or_else(|| invalid("storage slot has no ownership record"))?;
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
                format,
                phase: DiskPhase::Preparing,
            }
        };
        let mut owner = Self {
            path,
            record,
            lease: Some(lease),
        };
        if fresh {
            owner.persist()?;
        }
        #[cfg(windows)]
        owner.reconcile_attachment(destination)?;
        Ok(owner)
    }

    #[cfg(windows)]
    fn reconcile_attachment(&mut self, disk: &Path) -> io::Result<()> {
        self.reconcile_attachment_using(
            disk,
            sandsurf_native::storage::compute_system_absent,
            sandsurf_native::storage::revoke_disk_attachment_access,
        )
    }

    #[cfg(windows)]
    fn reconcile_attachment_using(
        &mut self,
        disk: &Path,
        absent: impl FnOnce(&str) -> io::Result<bool>,
        revoke: impl FnOnce(&str, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let DiskPhase::Attached { compute_system } = &self.record.phase else {
            return Ok(());
        };
        if !absent(compute_system)? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native compute system still owns this disk",
            ));
        }
        match fs::symlink_metadata(disk) {
            Ok(_) => revoke(compute_system, disk)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.set_phase(DiskPhase::Ready)
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn attach(disk: &Path) -> io::Result<std::sync::Arc<std::fs::File>> {
    let mut owner = DiskOwner::open(disk, None)?;
    if owner.record.phase != DiskPhase::Ready {
        return Err(invalid("only a published Ready disk may be attached"));
    }
    validate_disk(disk, owner.record.bytes, owner.record.format)?;
    let lease = owner.lease.take().expect("storage owner retains its lease");
    Ok(std::sync::Arc::new(lease))
}

/// Journal out-of-process HCS attachment before native creation. After a crash
/// the native fence remains until HCS proves absence and access is reclaimed.
#[cfg(windows)]
pub(crate) fn attach_hyper_v(
    disk: &Path,
    compute_system: &str,
) -> io::Result<std::sync::Arc<std::fs::File>> {
    let mut owner = DiskOwner::open(disk, None)?;
    if owner.record.phase != DiskPhase::Ready {
        return Err(invalid("only a published Ready disk may be attached"));
    }
    validate_disk(disk, owner.record.bytes, owner.record.format)?;
    if !sandsurf_native::storage::compute_system_absent(compute_system)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "native attachment identity already exists",
        ));
    }
    owner.set_phase(DiskPhase::Attached {
        compute_system: compute_system.to_owned(),
    })?;
    let lease = owner.lease.take().expect("storage owner retains its lease");
    Ok(std::sync::Arc::new(lease))
}

impl DiskFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Raw => "ext4",
            #[cfg(windows)]
            Self::Vhdx => "vhdx",
        }
    }
    fn is_raw(self) -> bool {
        match self {
            Self::Raw => true,
            #[cfg(windows)]
            Self::Vhdx => false,
        }
    }
}

/// Replace a detached disk under an already journaled host operation. The
/// native owner must have released its attachment before entry. Power state
/// alone is not a storage lease. Original bytes survive until the replacement
/// is published and verified; interrupted effects reconcile these exact names.
pub(crate) fn replace_disk(
    destination: &Path,
    operation: &OperationId,
    bytes: u64,
    format: DiskFormat,
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
        ".system.{}.next.{}",
        object_name(operation.as_str()),
        format.extension()
    ));
    let previous = parent.join(format!(
        ".system.{}.previous",
        object_name(operation.as_str())
    ));
    let mut owner = DiskOwner::open(destination, None)?;
    if owner.record.bytes != bytes || owner.record.format != format {
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
            validate_disk(&next, bytes, format)?;
            if !matches_content(&next)? {
                return Err(invalid(
                    "interrupted replacement disagrees with its approved content",
                ));
            }
            publish_new_file(&next, destination)?;
        } else if object_exists(&previous)? {
            validate_disk(&previous, bytes, format)?;
            publish_new_file(&previous, destination)?;
        }
    }
    if object_exists(destination)? {
        validate_disk(destination, bytes, format)?;
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
    publish_prepared(&next, bytes, format, |staged| {
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
    validate_disk(destination, bytes, format)?;
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
    format: DiskFormat,
    prepare_storage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if !source.is_absolute() {
        return Err(invalid("creation seed path must be absolute"));
    }
    publish_disk(destination, bytes, format, |staged| {
        let mut input = open_private_file(source, PrivateFileAccess::ReadOnly)?;
        let source_metadata = input.metadata()?;
        if source_metadata.len() == 0 || source_metadata.len() > MAX_DISK_BYTES {
            return Err(invalid("creation seed must be a bounded regular file"));
        }
        if format.is_raw() && source_metadata.len() > bytes {
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
        if format.is_raw() {
            output.set_len(bytes)?;
        }
        sync_file(&output)?;
        drop(output);
        prepare_storage(staged)
    })
}

/// The single publication path for creation seeds and snapshot-derived forks.
/// Callers may construct raw/VHDX content, but only this owner makes it attachable.
pub(crate) fn publish_disk(
    destination: &Path,
    bytes: u64,
    format: DiskFormat,
    build: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let mut owner = DiskOwner::open(destination, Some((bytes, format)))?;
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
    publish_prepared(destination, bytes, format, build)?;
    if owner.record.phase != DiskPhase::Ready {
        owner.set_phase(DiskPhase::Ready)?;
    }
    Ok(())
}

fn publish_prepared(
    destination: &Path,
    bytes: u64,
    format: DiskFormat,
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
            validate_disk(destination, bytes, format)?;
            reserve_allocation(destination, bytes, format)?;
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
    validate_disk(&staged, bytes, format)?;
    reserve_allocation(&staged, bytes, format)?;
    publish_new_file(&staged, destination)
}

fn reserve_allocation(path: &Path, bytes: u64, format: DiskFormat) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if format == DiskFormat::Raw {
        let file = open_private_file(path, PrivateFileAccess::ReadWrite)?;
        sandsurf_native::storage::reserve_raw_capacity(&file, bytes)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (path, bytes, format);
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
pub(crate) fn retire(disk: &Path, bytes: u64, format: DiskFormat) -> io::Result<()> {
    if !disk.is_absolute() || disk.parent().is_none() {
        return Err(invalid("disk retirement requires an absolute storage path"));
    }
    // Destruction can precede the first successful native boot. Establish a
    // retired slot even when materialization never started; never adopt an
    // existing payload without its ownership record.
    let mut owner = DiskOwner::open(disk, Some((bytes, format)))?;
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
            ".system.{}.next.{}",
            object_name(operation.as_str()),
            owner.record.format.extension()
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

fn validate_disk(path: &Path, bytes: u64, format: DiskFormat) -> io::Result<()> {
    let file = open_private_file(path, PrivateFileAccess::ReadOnly)?;
    let actual = match format {
        DiskFormat::Raw => file.metadata()?.len(),
        #[cfg(windows)]
        DiskFormat::Vhdx => sandsurf_native::virtual_disk::virtual_disk_size(path)?,
    };
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

    #[test]
    fn running_boot_publication_preserves_bytes_and_rejects_reference_only_or_changed_sources() {
        let fixture = Fixture::new();
        let kernel = fixture.0.join("kernel");
        let mut bytes = vec![0; 4096];
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        bytes[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        bytes[0x236] = 1;
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
        publish_disk(target, 4096, DiskFormat::Raw, |staged| {
            create_private_file(staged)?.write_all(&vec![byte; 4096])
        })
        .unwrap();
    }

    fn replacement_path(root: &Path, suffix: &str) -> PathBuf {
        root.join(format!(".system.{}.{suffix}", object_name("replace")))
    }

    #[cfg(windows)]
    #[test]
    fn native_attachment_record_survives_uncertainty_and_failed_access_cleanup() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        create_disk(&target, 1);
        let identity = "00000000-0000-0000-0000-000000000001";
        let mut owner = DiskOwner::open(&target, None).unwrap();
        let attached = DiskPhase::Attached {
            compute_system: identity.into(),
        };
        owner.set_phase(attached.clone()).unwrap();
        assert_eq!(
            owner
                .reconcile_attachment_using(
                    &target,
                    |id| {
                        assert_eq!(id, identity);
                        Ok(false)
                    },
                    |_, _| panic!("a present native owner cannot lose disk access")
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            owner
                .reconcile_attachment_using(
                    &target,
                    |_| Err(io::Error::other("HCS unavailable")),
                    |_, _| panic!("unavailable native evidence cannot free storage")
                )
                .is_err()
        );
        assert!(
            owner
                .reconcile_attachment_using(
                    &target,
                    |_| Ok(true),
                    |_, _| Err(io::Error::other(
                        "exclusive disk/access cleanup unavailable"
                    ))
                )
                .is_err()
        );
        assert_eq!(owner.record.phase, attached);
        let persisted: DiskObject =
            serde_json::from_slice(&fs::read(&owner.path).unwrap()).unwrap();
        assert_eq!(persisted.phase, attached);
        assert_eq!(fs::read(&target).unwrap(), vec![1; 4096]);
        owner
            .reconcile_attachment_using(
                &target,
                |_| Ok(true),
                |id, path| {
                    assert_eq!(id, identity);
                    assert_eq!(path, target);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(owner.record.phase, DiskPhase::Ready);
        drop(owner);
        replace(&target, &"replace".try_into().unwrap()).unwrap();
        assert_eq!(fs::read(target).unwrap(), vec![2; 4096]);
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
            publish_disk(&target, 4096, DiskFormat::Raw, |_| {
                panic!("an attached slot must not be materialized")
            })
            .unwrap_err(),
            replace(&target, &operation).unwrap_err(),
            retire(&target, 4096, DiskFormat::Raw).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(fs::read(&target).unwrap(), vec![1; 4096]);
        drop(native_owner);
        replace(&target, &operation).unwrap();
        assert_eq!(fs::read(&target).unwrap(), vec![2; 4096]);
        retire(&target, 4096, DiskFormat::Raw).unwrap();
        assert!(attach(&target).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn attachment_refuses_partial_missing_shared_and_replacing_payloads() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.ext4");
        let preparing = DiskOwner::open(&target, Some((4096, DiskFormat::Raw))).unwrap();
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
            DiskFormat::Raw,
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
        let mut owner = DiskOwner::open(&disk, Some((4096, DiskFormat::Raw))).unwrap();
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
        let mut owner = DiskOwner::open(&disk, Some((4096, DiskFormat::Raw))).unwrap();
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
            publish_disk(&target, 4096, DiskFormat::Raw, |_| panic!(
                "lost disk must not be recreated"
            ))
            .is_err()
        );
        assert!(!target.exists());
        retire(&target, 4096, DiskFormat::Raw).unwrap();
        retire(&target, 4096, DiskFormat::Raw).unwrap();
        assert!(
            publish_disk(&target, 4096, DiskFormat::Raw, |_| panic!(
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
        retire(&target, 4096, DiskFormat::Raw).unwrap();
        assert!(!target.exists());
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Retired
        );
        assert!(
            publish_disk(&target, 4096, DiskFormat::Raw, |_| panic!(
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
        publish_disk(&target, 65536, DiskFormat::Raw, |staged| {
            create_private_file(staged)?.set_len(65536)
        })
        .unwrap();
        assert!(fs::metadata(&target).unwrap().blocks() * 512 >= 65536);
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Ready
        );
        publish_disk(&target, 65536, DiskFormat::Raw, |_| {
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
        let owner = DiskOwner::open(&target, Some((4096, DiskFormat::Raw))).unwrap();
        publish_prepared(&target, 4096, DiskFormat::Raw, |staged| {
            create_private_file(staged)?.write_all(&vec![3; 4096])
        })
        .unwrap();
        drop(owner);
        publish_disk(&target, 4096, DiskFormat::Raw, |_| {
            panic!("published payload is complete")
        })
        .unwrap();
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
        let owner = DiskOwner::open(&target, Some((4096, DiskFormat::Raw))).unwrap();
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
            publish_disk(&untracked, 4096, DiskFormat::Raw, |_| panic!(
                "untracked original must remain intact"
            ))
            .is_err()
        );
        assert_eq!(fs::read(&untracked).unwrap(), vec![9; 4096]);
        assert!(!untracked.with_extension("storage.json").exists());
    }

    #[test]
    fn interrupted_replacement_recovers_each_namespace_stage() {
        // 0: admitted; 1: next published; 2: original moved; 3: replacement
        // installed; 4: original moved while next is still only a build.
        for stage in 0..5 {
            let fixture = Fixture::new();
            let target = fixture.0.join("system.ext4");
            create_disk(&target, 1);
            let operation: OperationId = "replace".try_into().unwrap();
            let next = replacement_path(&fixture.0, "next.ext4");
            let previous = replacement_path(&fixture.0, "previous");
            let mut owner = DiskOwner::open(&target, None).unwrap();
            owner
                .set_phase(DiskPhase::Replacing {
                    operation: operation.clone(),
                })
                .unwrap();
            if (1..=3).contains(&stage) {
                publish_prepared(&next, 4096, DiskFormat::Raw, |staged| {
                    create_private_file(staged)?.write_all(&vec![2; 4096])
                })
                .unwrap();
            }
            if stage >= 2 {
                publish_new_file(&target, &previous).unwrap();
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
            drop(owner);
            assert!(
                publish_disk(&target, 4096, DiskFormat::Raw, |_| panic!(
                    "unsettled replacement must not attach"
                ))
                .is_err()
            );
            assert!(replace(&target, &"other-operation".try_into().unwrap()).is_err());
            replace(&target, &operation).unwrap();
            assert_eq!(fs::read(&target).unwrap(), vec![2; 4096]);
            assert!(!next.exists());
            assert!(!next.with_extension("building").exists());
            assert!(!previous.exists());
            assert_eq!(
                DiskOwner::open(&target, None).unwrap().record.phase,
                DiskPhase::Ready
            );
            replace(&target, &operation).unwrap();
        }
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
        publish_prepared(&next, 4096, DiskFormat::Raw, |staged| {
            create_private_file(staged)?.write_all(&vec![2; 4096])
        })
        .unwrap();
        publish_new_file(&target, &replacement_path(&root, "previous")).unwrap();
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
        assert!(!target.exists());
        assert_eq!(
            publish_disk(&target, 4096, DiskFormat::Raw, |_| panic!(
                "active writer must not be replaced"
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(
            publish_disk(&target, 4096, DiskFormat::Raw, |_| panic!(
                "interrupted replacement must not be reseeded"
            ))
            .is_err()
        );
        replace(&target, &"replace".try_into().unwrap()).unwrap();
        assert_eq!(fs::read(&target).unwrap(), vec![2; 4096]);
        assert_eq!(
            DiskOwner::open(&target, None).unwrap().record.phase,
            DiskPhase::Ready
        );
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
                DiskFormat::Raw,
                |staged| create_private_file(staged)?.write_all(&vec![8; 4096]),
                |candidate| Ok(fs::read(candidate)? == vec![2; 4096])
            )
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), vec![1; 4096]);
        assert!(publish_disk(&target, 4096, DiskFormat::Raw, |_| Ok(())).is_err());
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
        retire(&target, 4096, DiskFormat::Raw).unwrap();
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
                publish_disk(&target, 4096, DiskFormat::Raw, |_| panic!(
                    "invalid record must never prepare"
                ))
                .is_err()
            );
            assert!(retire(&target, 4096, DiskFormat::Raw).is_err());
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
        assert!(retire(&target, 4096, DiskFormat::Raw).is_err());
        assert_eq!(fs::read(path).unwrap(), original);
        assert_eq!(fs::read(target).unwrap(), vec![1; 4096]);
    }

    #[test]
    fn shared_disk_identity_is_never_attached_or_deleted() {
        let fixture = Fixture::new();
        let target = fixture.0.join("system.raw");
        materialize(
            &fixture.0.join("seed"),
            &target,
            4096,
            DiskFormat::Raw,
            |_| Ok(()),
        )
        .unwrap();
        let alias = fixture.0.join("other-owner.raw");
        fs::hard_link(&target, &alias).unwrap();
        assert!(
            materialize(
                &fixture.0.join("seed"),
                &target,
                4096,
                DiskFormat::Raw,
                |_| panic!("shared live disk must not be prepared")
            )
            .is_err()
        );
        assert!(retire(&target, 4096, DiskFormat::Raw).is_err());
        assert!(target.exists());
        assert!(alias.exists());
        fs::remove_file(alias).unwrap();
        retire(&target, 4096, DiskFormat::Raw).unwrap();
    }

    #[test]
    fn linked_interrupted_stage_cannot_reclaim_another_owners_seed() {
        let fixture = Fixture::new();
        let source = fixture.0.join("seed");
        let target = fixture.0.join("system.raw");
        let staged = target.with_extension("building");
        fs::hard_link(&source, &staged).unwrap();
        assert!(
            materialize(&source, &target, 4096, DiskFormat::Raw, |_| panic!(
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
            materialize(&source, &target, 4096, DiskFormat::Raw, |staged| {
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
        materialize(&source, &target, 4096, DiskFormat::Raw, |_| Ok(())).unwrap();
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
        assert!(materialize(&alias, &target, 4096, DiskFormat::Raw, |_| Ok(())).is_err());
        std::os::unix::fs::symlink(&source, target.with_extension("building")).unwrap();
        assert!(materialize(&source, &target, 4096, DiskFormat::Raw, |_| Ok(())).is_err());
        assert!(retire(&target, 4096, DiskFormat::Raw).is_err());
        fs::remove_file(target.with_extension("building")).unwrap();
        std::os::unix::fs::symlink(&source, &target).unwrap();
        assert!(materialize(&source, &target, 4096, DiskFormat::Raw, |_| Ok(())).is_err());
        assert!(retire(&target, 4096, DiskFormat::Raw).is_err());
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
            materialize(&source, &target, 4096, DiskFormat::Raw, |_| {
                Err(io::Error::other("interrupted seed preparation"))
            })
            .is_err()
        );
        assert!(!target.exists());
        assert!(target.with_extension("building").exists());
        materialize(&source, &target, 4096, DiskFormat::Raw, |_| Ok(())).unwrap();
        assert!(!target.with_extension("building").exists());
        fs::remove_file(&source).unwrap();
        let disk = open_private_file(&target, PrivateFileAccess::ReadWrite).unwrap();
        (&disk).write_all(b"guest-owned!").unwrap();
        drop(disk);
        create_private_file(&target.with_extension("building"))
            .unwrap()
            .write_all(b"unpublished build")
            .unwrap();
        materialize(&source, &target, 4096, DiskFormat::Raw, |_| {
            panic!("published guest disk must never enter seed preparation")
        })
        .unwrap();
        assert!(!target.with_extension("building").exists());
        assert_eq!(&fs::read(&target).unwrap()[..12], b"guest-owned!");
        assert!(materialize(&source, &target, 8192, DiskFormat::Raw, |_| Ok(())).is_err());
        let retained = root.join("retained-output");
        create_private_file(&retained)
            .unwrap()
            .write_all(b"protected bytes")
            .unwrap();
        retire(&target, 4096, DiskFormat::Raw).unwrap();
        assert!(!target.exists());
        retire(&target, 4096, DiskFormat::Raw).unwrap();
        assert_eq!(fs::read(&retained).unwrap(), b"protected bytes");
        fs::remove_file(retained).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
