//! Publication of host-owned storage objects. Publication never overwrites an
//! existing object; callers retain their operation intent until it completes.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

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

/// Only explicit absence of the exact HCS identity frees its attachment fence.
/// Stopped, query errors and unavailable HCS are not absence. The probe never
/// starts or modifies a compute system.
#[cfg(windows)]
pub fn compute_system_absent(id: &str) -> io::Result<bool> {
    use windows_sys::Win32::Foundation::GENERIC_ALL;
    use windows_sys::Win32::System::HostComputeSystem::{
        HCS_SYSTEM, HcsCloseComputeSystem, HcsOpenComputeSystem,
    };
    if id.len() != 36
        || !id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native compute-system identity",
        ));
    }
    let encoded: Vec<u16> = id.encode_utf16().chain([0]).collect();
    let mut system: HCS_SYSTEM = std::ptr::null_mut();
    // SAFETY: encoded is NUL-terminated and system is a live output slot. HCS
    // requires GENERIC_ALL even for this existence-only probe.
    let result = unsafe { HcsOpenComputeSystem(encoded.as_ptr(), GENERIC_ALL, &mut system) };
    let absent = compute_system_outcome(result, !system.is_null())?;
    if !absent {
        // SAFETY: successful open transferred exactly this live native handle.
        unsafe { HcsCloseComputeSystem(system) };
    }
    Ok(absent)
}

#[cfg(windows)]
fn compute_system_outcome(result: i32, has_handle: bool) -> io::Result<bool> {
    use windows_sys::Win32::Foundation::HCS_E_SYSTEM_NOT_FOUND;
    if result >= 0 && has_handle {
        return Ok(false);
    }
    if result == HCS_E_SYSTEM_NOT_FOUND && !has_handle {
        return Ok(true);
    }
    Err(io::Error::other(format!(
        "native attachment observation unavailable: {result:#x}"
    )))
}

/// Remove only the recorded native attachment's access entry after absence.
/// Never repairs unrelated file ownership.
#[cfg(windows)]
pub fn revoke_disk_attachment_access(id: &str, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    use windows_sys::Win32::System::HostComputeSystem::HcsRevokeVmAccess;
    let identity: Vec<u16> = id.encode_utf16().chain([0]).collect();
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if id.contains('\0') || encoded.contains(&0) || !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recorded attachment access",
        ));
    }
    encoded.push(0);
    // Exclusive data-file access proves old native disk handles have drained,
    // and prevents pathname replacement while the owned ACL entry is removed.
    // Do not require the final private ACL before removing the recorded VM ACE.
    let disk = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = disk.metadata()?;
    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: disk retains the live handle and information is a writable output.
    if unsafe { GetFileInformationByHandle(disk.as_raw_handle(), information.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful native call initialized information completely.
    let information = unsafe { information.assume_init() };
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.nNumberOfLinks != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recorded attachment disk has an alias",
        ));
    }
    // SAFETY: the exact host-recorded identity and absolute path are terminated
    // and live for this removal of that VM's access entry only.
    let result = unsafe { HcsRevokeVmAccess(identity.as_ptr(), encoded.as_ptr()) };
    if result < 0 {
        return Err(io::Error::other(format!(
            "native attachment access cleanup failed: {result:#x}"
        )));
    }
    drop(disk);
    crate::local::open_private_file(path, crate::PrivateFileAccess::ReadOnly)?;
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
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
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
    // COPY_ALLOWED is never enabled. Only the owner-journal transaction
    // requests replacement; immutable publication cannot overwrite a name.
    // WRITE_THROUGH waits for native publication before journal-dependent effects.
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    // SAFETY: both terminated paths remain live for this synchronous call.
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), flags) } == 0 {
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

    #[cfg(windows)]
    #[test]
    fn native_compute_absence_is_not_stopped_unavailable_or_denied() {
        use windows_sys::Win32::Foundation::{
            E_ACCESSDENIED, HCS_E_SERVICE_DISCONNECT, HCS_E_SYSTEM_ALREADY_STOPPED,
            HCS_E_SYSTEM_NOT_FOUND,
        };
        assert!(compute_system_outcome(HCS_E_SYSTEM_NOT_FOUND, false).unwrap());
        assert!(!compute_system_outcome(0, true).unwrap());
        for (result, handle) in [
            (HCS_E_SYSTEM_ALREADY_STOPPED, false),
            (HCS_E_SERVICE_DISCONNECT, false),
            (E_ACCESSDENIED, false),
            (0, false),
            (HCS_E_SYSTEM_NOT_FOUND, true),
        ] {
            assert!(compute_system_outcome(result, handle).is_err());
        }
        for id in [
            "",
            "not-a-compute-system",
            "00000000-0000-0000-0000-00000000000G",
        ] {
            assert_eq!(
                compute_system_absent(id).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
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
        drop(open_private_file(&destination, crate::PrivateFileAccess::ReadOnly).unwrap());
        let mut writer = create_private_file(&staged).unwrap();
        writer.write_all(b"different bytes").unwrap();
        drop(writer);
        assert_eq!(
            publish_new_file(&staged, &destination).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&destination).unwrap(), b"protected original");
        assert_eq!(fs::read(&staged).unwrap(), b"different bytes");
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
