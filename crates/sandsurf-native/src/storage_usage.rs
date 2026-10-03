//! Host-filesystem observations, not guest free space or exclusive physical
//! ownership. Reflink/shared extents can be attributed to more than one object.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageUsage {
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

const MAX_ENTRIES: usize = 1_000_000;
const MAX_DEPTH: usize = 128;

/// Observe one regular file or directory through a held, no-follow handle.
/// Directory allocation is counted, but directory length is not file payload.
pub fn object_usage(path: &Path) -> io::Result<StorageUsage> {
    if !path.is_absolute() {
        return Err(invalid(
            "storage observation requires an absolute host path",
        ));
    }
    let file = open_object(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(invalid("storage object is not a regular file or directory"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid("storage observation cannot adopt a reparse point"));
        }
    }
    Ok(StorageUsage {
        logical_bytes: if metadata.is_file() {
            metadata.len()
        } else {
            0
        },
        allocated_bytes: allocation(&file, &metadata)?,
    })
}

/// Bounded traversal of a host-owned tree. This is an observation, not an
/// atomic snapshot or a capacity reservation. Unix socket names have no file
/// payload and belong to the native lifecycle owner, not retained storage.
/// Links and other special files fail closed.
pub fn tree_usage(root: &Path) -> io::Result<StorageUsage> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("storage tree root is not a directory"));
    }
    let mut count = 0;
    let mut usage = StorageUsage::default();
    visit(root, 0, &mut count, &mut usage)?;
    Ok(usage)
}

fn visit(path: &Path, depth: usize, count: &mut usize, total: &mut StorageUsage) -> io::Result<()> {
    if depth > MAX_DEPTH || *count >= MAX_ENTRIES {
        return Err(invalid("storage observation exceeds its traversal bound"));
    }
    *count += 1;
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            // Observe the original no-follow object. A kernel AF_UNIX name is
            // transient IPC, not a retained output file or a traversable alias.
            crate::socket_io::verify_windows_socket(&open_object(path)?)?;
            return Ok(());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if metadata.file_type().is_socket() {
            return Ok(());
        }
    }
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(invalid("storage tree contains a link or special file"));
    }
    let observed = object_usage(path)?;
    total.logical_bytes = total
        .logical_bytes
        .checked_add(observed.logical_bytes)
        .ok_or_else(|| invalid("logical storage observation overflow"))?;
    total.allocated_bytes = total
        .allocated_bytes
        .checked_add(observed.allocated_bytes)
        .ok_or_else(|| invalid("allocated storage observation overflow"))?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            visit(&entry?.path(), depth + 1, count, total)?;
        }
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(unix)]
fn open_object(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(windows)]
fn open_object(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn allocation(_file: &File, metadata: &fs::Metadata) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| invalid("native allocated storage observation overflow"))
}

#[cfg(windows)]
fn allocation(file: &File, _metadata: &fs::Metadata) -> io::Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_STANDARD_INFO::default();
    // SAFETY: the owned file handle remains live; the output buffer is exactly
    // the native FILE_STANDARD_INFO requested and stays live for this call.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            (&mut info as *mut FILE_STANDARD_INFO).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(info.AllocationSize)
        .map_err(|_| invalid("native allocated storage observation is negative"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Tree(std::path::PathBuf);
    impl Tree {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "sandsurf-storage-usage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            crate::local::create_private_directory(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn tree_observation_uses_native_allocation_and_counts_directory_overhead() {
        let tree = Tree::new();
        let child = tree.0.join("child");
        crate::local::create_private_directory(&child).unwrap();
        let path = child.join("payload");
        let mut file = crate::local::create_private_file(&path).unwrap();
        file.write_all(&vec![7; 8193]).unwrap();
        file.sync_all().unwrap();
        let payload = object_usage(&path).unwrap();
        assert_eq!(payload.logical_bytes, 8193);
        assert!(payload.allocated_bytes > 0);
        assert_ne!(
            payload.allocated_bytes, payload.logical_bytes,
            "allocation must come from the native filesystem, not file length"
        );
        assert_eq!(object_usage(&tree.0).unwrap().logical_bytes, 0);
        let observed = tree_usage(&tree.0).unwrap();
        assert_eq!(observed.logical_bytes, payload.logical_bytes);
        assert_eq!(
            observed.allocated_bytes,
            payload.allocated_bytes
                + object_usage(&child).unwrap().allocated_bytes
                + object_usage(&tree.0).unwrap().allocated_bytes
        );
        assert!(object_usage(Path::new("relative")).is_err());
        assert!(tree_usage(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sparse_storage_is_not_reported_as_fully_allocated() {
        let tree = Tree::new();
        let path = tree.0.join("sparse");
        let file = crate::local::create_private_file(&path).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        file.sync_all().unwrap();
        let usage = object_usage(&path).unwrap();
        assert_eq!(usage.logical_bytes, 64 * 1024 * 1024);
        assert!(usage.allocated_bytes < usage.logical_bytes / 2);
    }

    #[cfg(unix)]
    #[test]
    fn native_ipc_names_are_not_retained_file_payload() {
        let tree = Tree::new();
        let socket = tree.0.join("control.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert_eq!(tree_usage(&tree.0).unwrap(), object_usage(&tree.0).unwrap());
        assert!(object_usage(&socket).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn native_ipc_names_are_not_retained_file_payload() {
        let tree = Tree::new();
        let path = tree.0.join("control.sock");
        let socket =
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        socket
            .bind(&socket2::SockAddr::unix(&path).unwrap())
            .unwrap();
        assert_eq!(tree_usage(&tree.0).unwrap(), object_usage(&tree.0).unwrap());
        assert!(object_usage(&path).is_err());
        drop(socket);
    }

    #[cfg(unix)]
    #[test]
    fn traversal_rejects_aliases_special_files_and_excessive_depth() {
        let tree = Tree::new();
        let alias = tree.0.join("alias");
        std::os::unix::fs::symlink(&tree.0, &alias).unwrap();
        assert!(object_usage(&alias).is_err());
        assert!(tree_usage(&tree.0).is_err());
        fs::remove_file(alias).unwrap();
        assert!(object_usage(Path::new("/dev/null")).is_err());
        let mut path = tree.0.clone();
        for _ in 0..=MAX_DEPTH {
            path = path.join("d");
            fs::create_dir(&path).unwrap();
        }
        assert!(tree_usage(&tree.0).is_err());
    }
}
