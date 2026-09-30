//! One materialization transaction for machine-owned writable disks. Only the
//! published name may be attached. The guardian's exclusive ownership is held
//! throughout preparation and recovery; staging files never represent a VM.

use sandsurf_native::PrivateFileAccess;
use sandsurf_native::local::{create_private_file, open_private_file};
use sandsurf_native::storage::{publish_new_file, sync_directory, sync_file};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

const MAX_DISK_BYTES: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum DiskFormat {
    #[cfg(any(unix, test))]
    Raw,
    #[cfg(windows)]
    Vhdx,
}

impl DiskFormat {
    fn is_raw(self) -> bool {
        match self {
            #[cfg(any(unix, test))]
            Self::Raw => true,
            #[cfg(windows)]
            Self::Vhdx => false,
        }
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
    publish_new_file(&staged, destination)
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
pub(crate) fn retire(disk: &Path) -> io::Result<()> {
    if !disk.is_absolute() || disk.parent().is_none() {
        return Err(invalid("disk retirement requires an absolute storage path"));
    }
    reclaim_staging(&disk.with_extension("building"))?;
    reclaim_staging(disk)?;
    sync_directory(disk.parent().expect("validated parent"))?;
    Ok(())
}

fn validate_disk(path: &Path, bytes: u64, format: DiskFormat) -> io::Result<()> {
    let file = open_private_file(path, PrivateFileAccess::ReadOnly)?;
    let actual = match format {
        #[cfg(any(unix, test))]
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
        assert!(retire(&target).is_err());
        assert!(target.exists());
        assert!(alias.exists());
        fs::remove_file(alias).unwrap();
        retire(&target).unwrap();
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
        assert!(retire(&target).is_err());
        fs::remove_file(target.with_extension("building")).unwrap();
        std::os::unix::fs::symlink(&source, &target).unwrap();
        assert!(materialize(&source, &target, 4096, DiskFormat::Raw, |_| Ok(())).is_err());
        assert!(retire(&target).is_err());
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
        retire(&target).unwrap();
        assert!(!target.exists());
        retire(&target).unwrap();
        assert_eq!(fs::read(&retained).unwrap(), b"protected bytes");
        fs::remove_file(retained).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
