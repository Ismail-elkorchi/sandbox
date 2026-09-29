use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Private storage belongs to the service account, independently of the owner
/// of a protected ancestor such as root-owned sticky /tmp.
pub fn require_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no pointer or resource-ownership preconditions.
    let owner = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage directory is not private to the service account",
        ));
    }
    #[cfg(target_os = "macos")]
    crate::macos::require_private_path_acl(path)?;
    require_protected_ancestors(&fs::canonicalize(path)?)
}

/// Select a root-owned host executable without trusting PATH or writable
/// ancestors. These are host tools, never executables from a guest filesystem.
pub fn protected_tool(candidates: &[&str]) -> io::Result<PathBuf> {
    for candidate in candidates {
        let Ok(path) = fs::canonicalize(candidate) else {
            continue;
        };
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
        {
            require_protected_ancestors(&path)?;
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "required protected host tool is unavailable",
    ))
}

/// The caller has already canonicalized the path while retaining/checking its
/// final identity. Every ancestor must prevent a different account from moving
/// that identity out of the way between validation and path-based native calls.
/// This complements, not replaces, final-component mode/owner/ACL/handle checks.
pub fn require_protected_ancestors(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private path must be absolute",
        ));
    }
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    let uid = unsafe { libc::geteuid() };
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let metadata = fs::symlink_metadata(ancestor)?;
        // Root/account-owned sticky directories permit /tmp without allowing a
        // foreign account to replace entries owned by this account or root.
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private state ancestor permits foreign path replacement",
            ));
        }
        #[cfg(target_os = "macos")]
        crate::macos::require_protected_ancestor_acl(ancestor)?;
    }
    Ok(())
}
