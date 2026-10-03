//! Publication of host-owned storage objects. Publication never overwrites an
//! existing object; callers retain their operation intent until it completes.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

/// A single native disk-slot lease. On Unix flock follows the shared open
/// description. Windows uses share denial on the file object, not a byte lock
/// owned by a process that can die before its out-of-process VMM is contained.
pub fn disk_lease(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        crate::local::disk_lease(path)
    }
    #[cfg(unix)]
    {
        let lease = match crate::local::create_private_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                crate::local::open_private_file(path, crate::PrivateFileAccess::ReadWrite)?
            }
            Err(error) => return Err(error),
        };
        lease.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "storage slot already has an owner",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        Ok(lease)
    }
}

/// Shared immutable-input custody follows the original native file object.
/// Windows uses read-only share denial, not process-owned LockFileEx locks.
/// Unix uses shared flock on an original open description. Every retirement
/// must acquire the exclusive disk_lease of this same private lease name.
pub fn read_lease(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        crate::local::read_lease(path)
    }
    #[cfg(unix)]
    {
        let lease = match crate::local::create_private_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                crate::local::open_private_file(path, crate::PrivateFileAccess::ReadOnly)?
            }
            Err(error) => return Err(error),
        };
        lease.try_lock_shared().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "immutable input has an exclusive owner",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        Ok(lease)
    }
}

/// Check the received original lease against the admitted private name without
/// locking another description. Retention, not pathname observation, owns it.
pub fn verify_transferred_lease(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        crate::local::verify_transferred_lease(file, path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let observed = crate::local::open_private_file(path, crate::PrivateFileAccess::ReadOnly)?;
        let held = file.metadata()?;
        let named = observed.metadata()?;
        // SAFETY: getuid is a scalar credential query.
        if !held.is_file()
            || held.nlink() != 1
            || held.mode() & 0o077 != 0
            || held.uid() != unsafe { libc::getuid() }
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transferred storage custody changed private identity",
            ));
        }
        Ok(())
    }
}

/// Portable address for an opaque logical identifier, not another identity or
/// authorization decision. Never embed identifiers directly in host filenames:
/// case folding and reserved device names must not collapse distinct owners.
pub fn object_name(identifier: &str) -> String {
    format!(
        "id-{}",
        sandsurf_protocol::bytes_digest(identifier.as_bytes()).as_str()
    )
}

/// Transfer a held authority description across exec in a single-threaded
/// launcher or post-fork child. Do not call this on ambient descriptors in a
/// multithreaded parent. No path is opened and no lease is reacquired/unlocked.
#[cfg(unix)]
pub fn retain_descriptor_for_exec(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if file.as_raw_fd() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "custody must not alias stdio",
        ));
    }
    // SAFETY: file owns the live descriptor, and the scalar fcntl operation
    // changes only its exec-inheritance flag; it does not release flock custody.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reserve a raw disk's allocation through its held writable descriptor.
/// This does not interpret Linux filesystem bytes or change logical capacity.
/// Shared/reflink attribution and global pool admission remain separate facts.
#[cfg(target_os = "linux")]
pub fn reserve_raw_capacity(file: &File, bytes: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let length = i64::try_from(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "raw allocation exceeds the native offset range",
        )
    })?;
    if bytes == 0 || file.metadata()?.len() != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "raw allocation must match the published geometry",
        ));
    }
    // SAFETY: the live writable descriptor is retained; the checked offset
    // range has no pointers. KEEP_SIZE cannot extend or truncate the disk.
    if unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    sync_file(file)?;
    let metadata = file.metadata()?;
    if metadata.len() != bytes
        || metadata
            .blocks()
            .checked_mul(512)
            .is_none_or(|allocated| allocated < bytes)
    {
        return Err(io::Error::other(
            "raw disk capacity was not fully allocated",
        ));
    }
    Ok(())
}

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
    publish_name(staged, destination)
}

/// Commit mutable owner-journal metadata. The caller must hold its exclusive
/// writer lease; immutable disk/image/output payloads use publish_new_file.
pub fn replace_journal_file(staged: &Path, destination: &Path) -> io::Result<()> {
    if !staged.is_absolute()
        || !destination.is_absolute()
        || staged.parent() != destination.parent()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal replacement requires absolute paths in one directory",
        ));
    }
    sync_file(&crate::local::open_private_file(
        staged,
        crate::PrivateFileAccess::ReadWrite,
    )?)?;
    #[cfg(unix)]
    {
        std::fs::rename(staged, destination)?;
        sync_directory(destination.parent().expect("validated journal path"))
    }
    #[cfg(windows)]
    move_name(staged, destination, true)
}

/// Atomically publish a prepared directory without replacing another object.
/// Payload and nested directory flushes belong to the materializing owner.
pub fn publish_new_directory(staged: &Path, destination: &Path) -> io::Result<()> {
    if !staged.is_absolute()
        || !destination.is_absolute()
        || staged.parent() != destination.parent()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory publication requires absolute paths in one directory",
        ));
    }
    sync_directory(staged)?;
    publish_name(staged, destination)
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
pub(crate) fn publish_name(staged: &Path, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(staged.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let target = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // Publish one name atomically. A hard-link publication would transiently
    // violate private-file identity checks when concurrent captures encounter
    // the same content digest. Unsupported native rename semantics fail closed.
    #[cfg(target_os = "linux")]
    // SAFETY: both terminated paths remain live; same-directory publication
    // was checked above. The syscall avoids a libc-symbol dependency on musl.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: both terminated paths remain live; RENAME_EXCL forbids replacing
    // any existing destination rather than adopting a different identity.
    let result = unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    sync_directory(destination.parent().expect("validated parent"))
}

#[cfg(windows)]
pub(crate) fn publish_name(staged: &Path, destination: &Path) -> io::Result<()> {
    move_name(staged, destination, false)
}

#[cfg(windows)]
fn move_name(staged: &Path, destination: &Path, replace: bool) -> io::Result<()> {
    crate::local::rename_private_object(staged, destination, replace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn immutable_readers_share_original_custody_and_exclude_retirement_until_last_close() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-read-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        crate::local::create_private_directory(&root).unwrap();
        let path = root.join("object.lock");
        let first = read_lease(&path).unwrap();
        let second = read_lease(&path).unwrap();
        let original = first.try_clone().unwrap();
        verify_transferred_lease(&original, &path).unwrap();
        assert_eq!(
            disk_lease(&path).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(first);
        drop(second);
        #[cfg(windows)]
        assert!(
            fs::remove_file(&path).is_err(),
            "the inherited read object must deny deletion too"
        );
        assert_eq!(
            disk_lease(&path).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(original);
        let writer = disk_lease(&path).unwrap();
        assert_eq!(
            read_lease(&path).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(writer);
        drop(read_lease(&path).unwrap());
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn transferred_custody_verification_never_reacquires_or_releases_the_slot() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-transferred-slot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        crate::local::create_private_directory(&root).unwrap();
        let path = root.join("pool.lock");
        let other = root.join("other.lock");
        let parent = disk_lease(&path).unwrap();
        let child = parent.try_clone().unwrap();
        drop(parent);
        verify_transferred_lease(&child, &path).unwrap();
        let unrelated = disk_lease(&other).unwrap();
        assert!(verify_transferred_lease(&child, &other).is_err());
        assert_eq!(
            disk_lease(&path).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(unrelated);
        drop(child);
        let replacement = disk_lease(&path).unwrap();
        verify_transferred_lease(&replacement, &path).unwrap();
        drop(replacement);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mutation_custody_survives_transfer_until_the_last_native_owner_closes() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-disk-transaction-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        crate::local::create_private_directory(&root).unwrap();
        let path = root.join("disk.lock");
        let transaction = disk_lease(&path).unwrap();
        let worker = transaction.try_clone().unwrap();
        assert!(disk_lease(&path).is_err());
        drop(transaction);
        // A filesystem mutation may have transferred this exact description
        // to an appliance. Parent completion must not unlock a surviving VM.
        assert!(disk_lease(&path).is_err());
        let native = worker.try_clone().unwrap();
        drop(worker);
        assert!(disk_lease(&path).is_err());
        drop(native);
        drop(disk_lease(&path).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn logical_case_and_reserved_names_have_independent_portable_objects() {
        use crate::local::{create_private_directory, create_private_file};
        use std::io::Write;
        let root = std::env::temp_dir().join(format!(
            "sandsurf-object-addresses-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_directory(&root).unwrap();
        let identifiers = ["CON", "con", "Foo", "foo", "NUL", "nul", "AUX", "aux"];
        for id in identifiers {
            let name = object_name(id);
            assert_eq!(name.len(), 67);
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            );
            let directory = root.join(name);
            create_private_directory(&directory).unwrap();
            create_private_file(&directory.join("payload"))
                .unwrap()
                .write_all(id.as_bytes())
                .unwrap();
        }
        for id in identifiers {
            assert_eq!(
                fs::read(root.join(object_name(id)).join("payload")).unwrap(),
                id.as_bytes()
            );
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), identifiers.len());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raw_allocation_preserves_content_and_rejects_geometry_changes() {
        use crate::local::{create_private_directory, create_private_file};
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::MetadataExt;
        let root = std::env::temp_dir().join(format!(
            "sandsurf-raw-allocation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_directory(&root).unwrap();
        let path = root.join("disk.raw");
        let mut file = create_private_file(&path).unwrap();
        file.set_len(65536).unwrap();
        file.seek(SeekFrom::Start(8192)).unwrap();
        file.write_all(b"root-controlled bytes").unwrap();
        let original = fs::read(&path).unwrap();
        assert!(reserve_raw_capacity(&file, 131072).is_err());
        assert!(reserve_raw_capacity(&file, 0).is_err());
        reserve_raw_capacity(&file, 65536).unwrap();
        reserve_raw_capacity(&file, 65536).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(file.metadata().unwrap().blocks() * 512 >= 65536);
        drop(file);
        let readonly =
            crate::local::open_private_file(&path, crate::PrivateFileAccess::ReadOnly).unwrap();
        assert!(reserve_raw_capacity(&readonly, 65536).is_err());
        drop(readonly);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_journal_replacement_commits_one_complete_record() {
        use crate::local::{create_private_directory, create_private_file};
        use std::io::Write;
        let root = std::env::temp_dir().join(format!(
            "sandsurf-journal-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_directory(&root).unwrap();
        let stage = root.join("record-building");
        let target = root.join("record.json");
        for bytes in [b"original".as_slice(), b"replacement".as_slice()] {
            create_private_file(&stage)
                .unwrap()
                .write_all(bytes)
                .unwrap();
            replace_journal_file(&stage, &target).unwrap();
            assert!(!stage.exists());
            assert_eq!(fs::read(&target).unwrap(), bytes);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_publication_never_replaces_an_existing_identity() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-directory-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        crate::local::create_private_directory(&root).unwrap();
        let stage = root.join("stage");
        let target = root.join("target");
        crate::local::create_private_directory(&stage).unwrap();
        fs::write(stage.join("identity"), b"original").unwrap();
        publish_new_directory(&stage, &target).unwrap();
        crate::local::create_private_directory(&stage).unwrap();
        fs::write(stage.join("identity"), b"replacement").unwrap();
        assert_eq!(
            publish_new_directory(&stage, &target).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(target.join("identity")).unwrap(), b"original");
        assert_eq!(fs::read(stage.join("identity")).unwrap(), b"replacement");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_transfers_one_identity_and_never_replaces_existing_bytes() {
        use crate::local::{create_private_directory, create_private_file, open_private_file};
        use std::io::Write;
        let root = std::env::temp_dir().join(format!(
            "sandsurf-publication-transfer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        create_private_directory(&root).unwrap();
        let staged = root.join("staged");
        let destination = root.join("published");
        let mut writer = create_private_file(&staged).unwrap();
        writer.write_all(b"protected original").unwrap();
        drop(writer);
        publish_new_file(&staged, &destination).unwrap();
        assert!(!staged.exists());
        // A retained reader is entitled to keep its protected original open.
        // On Windows it intentionally denies DELETE sharing. No-replace
        // publication must still classify the existing object as existing,
        // without attempting to delete/replace it or asking readers to retry.
        let original = open_private_file(&destination, crate::PrivateFileAccess::ReadOnly).unwrap();
        let mut writer = create_private_file(&staged).unwrap();
        writer.write_all(b"different bytes").unwrap();
        drop(writer);
        assert_eq!(
            publish_new_file(&staged, &destination).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&destination).unwrap(), b"protected original");
        assert_eq!(fs::read(&staged).unwrap(), b"different bytes");
        drop(original);
        fs::remove_dir_all(&root).unwrap();
    }

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
    fn independent_services_can_admit_one_shared_private_parent_concurrently() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-concurrent-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let barrier = std::sync::Barrier::new(16);
        std::thread::scope(|scope| {
            let workers = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        crate::local::ensure_private_directory(&root).unwrap();
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                worker.join().unwrap();
            }
        });
        crate::local::canonical_private_directory(&root).unwrap();
        assert!(
            crate::local::create_private_directory(&root).is_err(),
            "new-owner creation remains exclusive"
        );
        fs::remove_dir_all(root).unwrap();
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
