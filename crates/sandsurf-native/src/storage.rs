//! Publication of host-owned storage objects. Publication never overwrites an
//! existing object; callers retain their operation intent until it completes.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

/// Durable payload flush, including Apple's drive-cache flush. Directory
/// publication and authoritative journal commits remain separate steps.
pub fn sync_file(file: &File) -> io::Result<()> {
    file.sync_all()?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: F_FULLFSYNC operates on this live owned file without pointers.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn publish_new_file(staged: &Path, destination: &Path) -> io::Result<()> {
    if !staged.is_absolute()
        || !destination.is_absolute()
        || staged.parent() != destination.parent()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage publication requires absolute paths in one directory",
        ));
    }
    sync_file(&OpenOptions::new().read(true).write(true).open(staged)?)?;
    publish(staged, destination)
}

/// Flush publication metadata where the OS provides a directory fsync. On
/// Windows, validate the directory handle without claiming a POSIX-style
/// directory flush: payload files and the authoritative journal are flushed
/// independently, and interrupted publications are recovered from that journal.
#[cfg(unix)]
pub fn sync_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?
        .sync_all()
}

#[cfg(windows)]
pub fn sync_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    use std::os::windows::fs::MetadataExt;
    let attributes = file.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "publication target is a reparse point or not a directory",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn publish(staged: &Path, destination: &Path) -> io::Result<()> {
    // A hard link is a no-replace publication on the same filesystem. If the
    // owner dies after publication, the destination is already complete and
    // the remaining staging name is safe to reclaim during recovery.
    std::fs::hard_link(staged, destination)?;
    let parent = File::open(destination.parent().expect("validated parent"))?;
    parent.sync_all()?;
    std::fs::remove_file(staged)?;
    parent.sync_all()
}

#[cfg(windows)]
fn publish(staged: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        value.push(0);
        Ok(value)
    }
    let source = wide(staged)?;
    let target = wide(destination)?;
    // SAFETY: both paths are terminated and remain live for the synchronous
    // call. Omitting REPLACE_EXISTING and COPY_ALLOWED prevents overwrite and
    // cross-volume copy. WRITE_THROUGH waits for native disk publication.
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn private_storage_access_is_explicit_and_never_adopts_aliases() {
        use crate::PrivateFileAccess;
        use crate::local::{
            canonical_private_directory, create_private_directory, create_private_file,
            ensure_private_directory, open_private_file,
        };
        use std::io::{Read, Seek, Write};
        let root = std::env::temp_dir().join(format!(
            "sandsurf-private-storage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_directory(&root).unwrap();
        assert!(create_private_directory(&root).is_err());
        ensure_private_directory(&root).unwrap();
        assert_eq!(
            canonical_private_directory(&root).unwrap(),
            fs::canonicalize(&root).unwrap()
        );
        let path = root.join("payload");
        let mut file = create_private_file(&path).unwrap();
        file.write_all(b"original").unwrap();
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        sync_file(&file).unwrap();
        drop(file);
        let mut readonly = open_private_file(&path, PrivateFileAccess::ReadOnly).unwrap();
        assert!(readonly.write_all(b"forbidden").is_err());
        drop(readonly);
        let mut writable = open_private_file(&path, PrivateFileAccess::ReadWrite).unwrap();
        writable.write_all(b"replaced").unwrap();
        sync_file(&writable).unwrap();
        drop(writable);
        assert_eq!(fs::read(&path).unwrap(), b"replaced");
        let alias = root.join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(open_private_file(&path, PrivateFileAccess::ReadOnly).is_err());
        assert!(open_private_file(&path, PrivateFileAccess::ReadWrite).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn publication_directory_validation_rejects_files_and_missing_paths() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        sync_directory(&root).unwrap();
        let file = root.join("file");
        fs::write(&file, b"payload").unwrap();
        assert!(sync_directory(&file).is_err());
        assert!(sync_directory(&root.join("missing")).is_err());
        #[cfg(unix)]
        {
            let link = root.join("link");
            std::os::unix::fs::symlink(&root, &link).unwrap();
            assert!(sync_directory(&link).is_err());
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
