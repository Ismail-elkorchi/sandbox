//! Native macOS permission checks. POSIX mode bits alone cannot establish private
//! ownership when an extended ACL grants access. These checks never rewrite ACLs.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

// Darwin ABI: apple-oss-distributions/Libc/include/sys/acl.h. Keep ACLs opaque;
// never decode Apple's private in-memory structs or its serialized ACL payload.
const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_EXTENDED_ALLOW: c_int = 1;
const ACL_EXTENDED_DENY: c_int = 2;
const ACL_MAX_ENTRIES: usize = 128;
const READ_ONLY_PERMISSIONS: u64 =
    (1 << 1) | (1 << 3) | (1 << 7) | (1 << 9) | (1 << 11) | (1 << 20);

// SAFETY: signatures match Darwin's public sys/acl.h; opaque values are obtained
// only from these functions, inspected while alive, and released with acl_free.
unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
    fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
    fn acl_valid(acl: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
    fn acl_free(value: *mut c_void) -> c_int;
}

struct Acl(*mut c_void);
impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: this is one non-null ACL returned by acl_get_* and owned here.
        unsafe { acl_free(self.0) };
    }
}

/// Require that mode/owner checks are not broadened by any ACL grant. Deny-only
/// ACLs remain valid; evaluating account/group-specific grants is not qualified.
pub fn require_private_file_acl(file: &File) -> io::Result<()> {
    // SAFETY: file owns a live descriptor; the returned allocation is adopted by check_acl.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    check_acl(acl, 0)
}

/// As above, for a socket/directory path. The caller must also validate type,
/// ownership, modes and protected ancestry. Final-component links are rejected.
pub fn require_private_path_acl(path: &Path) -> io::Result<()> {
    check_path(path, 0)
}

/// Ancestors may grant read/search, but not replacement, metadata mutation or
/// ownership/security changes. Mode/ownership/sticky-bit checks are also required.
pub fn require_protected_ancestor_acl(path: &Path) -> io::Result<()> {
    check_path(path, READ_ONLY_PERMISSIONS)
}

fn check_path(path: &Path, allowed: u64) -> io::Result<()> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ACL path is a link",
        ));
    }
    let text = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ACL path contains NUL"))?;
    // SAFETY: text is NUL terminated; no-follow ACL lookup returns an owned ACL.
    let acl = unsafe { acl_get_link_np(text.as_ptr(), ACL_TYPE_EXTENDED) };
    check_acl(acl, allowed)?;
    let after = fs::symlink_metadata(path)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ACL path identity changed",
        ));
    }
    Ok(())
}

fn check_acl(raw: *mut c_void, allowed: u64) -> io::Result<()> {
    if raw.is_null() {
        let error = io::Error::last_os_error();
        // Darwin filesec_get_property reports ENOENT when this existing object's
        // ACL property is absent. A held fd or before/after path check establishes
        // object existence. ENOTSUP and all other failures remain unavailable.
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let acl = Acl(raw);
    // SAFETY: acl holds the live opaque allocation returned by Darwin.
    if unsafe { acl_valid(acl.0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for index in 0..=ACL_MAX_ENTRIES {
        let mut entry = std::ptr::null_mut();
        let selector = if index == 0 {
            ACL_FIRST_ENTRY
        } else {
            ACL_NEXT_ENTRY
        };
        // SAFETY: acl is valid and alive; entry is initialized writable pointer storage.
        if unsafe { acl_get_entry(acl.0, selector, &mut entry) } != 0 {
            let error = io::Error::last_os_error();
            // Unlike Linux's ACL API, Darwin returns -1/EINVAL at iterator end.
            return if error.raw_os_error() == Some(libc::EINVAL) {
                Ok(())
            } else {
                Err(error)
            };
        }
        if entry.is_null() || index == ACL_MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native ACL bounds",
            ));
        }
        let mut tag = 0;
        let mut permissions = 0;
        // SAFETY: entry is borrowed from the still-live ACL; both outputs have the
        // exact initialized storage types declared in Darwin's public ABI.
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: entry is live and permissions is writable u_int64_t-sized storage.
        if unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if tag != ACL_EXTENDED_DENY && (tag != ACL_EXTENDED_ALLOW || permissions & !allowed != 0) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ACL grants unqualified access to private state",
            ));
        }
    }
    unreachable!("ACL iteration either terminates or rejects its bound")
}
