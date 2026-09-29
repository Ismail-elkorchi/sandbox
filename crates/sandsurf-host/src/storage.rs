//! One materialization transaction for machine-owned writable disks. Only the
//! published name may be attached. The guardian's exclusive ownership is held
//! throughout preparation and recovery; staging files never represent a VM.

use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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

/// `prepare_seed` may interpret only a verified, never-booted creation seed.
/// It is never called for a published disk, which guest root may have changed.
pub(crate) fn materialize(
    source: &Path,
    destination: &Path,
    bytes: u64,
    format: DiskFormat,
    prepare_seed: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if !source.is_absolute()
        || !destination.is_absolute()
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
    let source_metadata = fs::symlink_metadata(source)?;
    if !source_metadata.is_file()
        || source_metadata.file_type().is_symlink()
        || source_metadata.len() == 0
        || source_metadata.len() > MAX_DISK_BYTES
    {
        return Err(invalid("creation seed must be a bounded regular file"));
    }
    if format.is_raw() && source_metadata.len() > bytes {
        return Err(invalid(
            "creation seed exceeds the authorized disk capacity",
        ));
    }
    let staged = destination.with_extension("building");
    // An interrupted build was never attachable. Recreate it from the
    // verified seed instead of treating partial contents as complete.
    reclaim_staging(&staged)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut output = options.open(&staged)?;
    let mut input = File::open(source)?;
    if io::copy(&mut input, &mut output)? != source_metadata.len() {
        return Err(invalid("creation seed changed during materialization"));
    }
    if format.is_raw() {
        output.set_len(bytes)?;
    }
    output.sync_all()?;
    drop(output);
    prepare_seed(&staged)?;
    validate_disk(&staged, bytes, format)?;
    sandsurf_native::storage::publish_new_file(&staged, destination)
}

fn reclaim_staging(staged: &Path) -> io::Result<()> {
    match fs::symlink_metadata(staged) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(staged)
        }
        Ok(_) => Err(invalid("interrupted storage build is not a regular file")),
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
    #[cfg(unix)]
    File::open(disk.parent().expect("validated parent"))?.sync_all()?;
    Ok(())
}

fn validate_disk(path: &Path, bytes: u64, format: DiskFormat) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("persistent disk is not a regular file"));
    }
    let actual = match format {
        #[cfg(any(unix, test))]
        DiskFormat::Raw => metadata.len(),
        #[cfg(windows)]
        DiskFormat::Vhdx => sandsurf_native::virtual_disk::virtual_disk_size(path)?,
    };
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
        fs::create_dir(&root).unwrap();
        let source = root.join("seed.ext4");
        let target = root.join("system.ext4");
        fs::write(&source, b"verified-seed").unwrap();
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
        let disk = OpenOptions::new().write(true).open(&target).unwrap();
        use std::io::Write;
        (&disk).write_all(b"guest-owned!").unwrap();
        drop(disk);
        fs::hard_link(&target, target.with_extension("building")).unwrap();
        materialize(&source, &target, 4096, DiskFormat::Raw, |_| {
            panic!("published guest disk must never enter seed preparation")
        })
        .unwrap();
        assert!(!target.with_extension("building").exists());
        assert_eq!(&fs::read(&target).unwrap()[..12], b"guest-owned!");
        assert!(materialize(&source, &target, 8192, DiskFormat::Raw, |_| Ok(())).is_err());
        let retained = root.join("retained-output");
        fs::write(&retained, b"protected bytes").unwrap();
        retire(&target).unwrap();
        assert!(!target.exists());
        retire(&target).unwrap();
        assert_eq!(fs::read(&retained).unwrap(), b"protected bytes");
        fs::remove_file(retained).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
