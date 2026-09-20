use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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
