use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetExplicitEntriesFromAclW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::PWSTR;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this value uniquely owns the live Win32 handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this allocation came from a Win32 LocalAlloc-returning API.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct UserToken {
    _token: Handle,
    buffer: Vec<usize>,
}
impl UserToken {
    fn current() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: token is a live output slot and the pseudo process handle is valid.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle(token);
        let mut bytes = 0_u32;
        // SAFETY: a zero-length query with a null buffer requests the required size.
        let first = unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut bytes) };
        if first != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes < size_of::<TOKEN_USER>() as u32
        {
            return Err(io::Error::last_os_error());
        }
        let words = (bytes as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        // SAFETY: the aligned buffer has the exact byte capacity reported above.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _token: token,
            buffer,
        })
    }

    fn sid(&self) -> PSID {
        // SAFETY: successful TokenUser retrieval initialized TOKEN_USER at the
        // aligned beginning of the buffer, which remains owned by this value.
        unsafe { (&*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn sid_string(&self) -> io::Result<String> {
        let mut value: PWSTR = null_mut();
        // SAFETY: sid is valid for this token buffer and value is a live output slot.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allocation = LocalAllocation(value.cast());
        let mut length = 0_usize;
        // SAFETY: ConvertSidToStringSidW returns a NUL-terminated LocalAlloc string.
        while unsafe { *value.add(length) } != 0 {
            length += 1;
            if length > 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "current user SID string exceeds its bound",
                ));
            }
        }
        // SAFETY: the loop established exactly `length` initialized UTF-16 units.
        let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "current user SID is invalid"));
        drop(allocation);
        result
    }
}

fn current_user_descriptor(inheritable: bool) -> io::Result<LocalAllocation> {
    let user = UserToken::current()?;
    let inheritance = if inheritable { "OICI" } else { "" };
    let sddl = wide(&format!(
        "O:{0}D:P(A;{inheritance};GA;;;{0})",
        user.sid_string()?
    ));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: SDDL is NUL-terminated and descriptor is a live output slot.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalAllocation(descriptor))
}

pub(crate) fn create_private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state root must be an absolute Windows path",
        ));
    }
    let descriptor = current_user_descriptor(true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path_wide = wide_os(path)?;
    // SAFETY: path and security descriptor are initialized and live for this call.
    if unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let directory = open_directory(path)?;
        validate(&directory, true, true)?;
        Ok(())
    })();
    drop(descriptor);
    if result.is_err() {
        let _ = fs::remove_dir(path);
    }
    result
}

pub(crate) fn canonical_directory(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state root must be an absolute Windows path",
        ));
    }
    let original = open_directory(path)?;
    let original_identity = validate(&original, true, true)?;
    let canonical = fs::canonicalize(path)?;
    let resolved = open_directory(&canonical)?;
    if validate(&resolved, true, true)? != original_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state root changed during canonicalization",
        ));
    }
    Ok(canonical)
}

pub(crate) fn private_file(path: &Path, create: bool) -> io::Result<File> {
    let file = if create {
        let descriptor = current_user_descriptor(false)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let path = wide_os(path)?;
        // SAFETY: path and security attributes are initialized for this call;
        // a successful handle is transferred exactly once into File.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW returned one newly owned file-compatible handle.
        unsafe { File::from_raw_handle(handle.cast()) }
    } else {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path)?
    };
    validate(&file, false, false)?;
    Ok(file)
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    let directory = open_directory(path)?;
    let information = information(&directory)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state publication directory is a reparse point or not a directory",
        ));
    }
    // NTFS/ReFS directory metadata is journaled; Windows exposes no supported
    // directory-handle equivalent of POSIX fsync. Files and SQLite are flushed
    // separately before their references become authoritative.
    Ok(())
}

fn open_directory(path: &Path) -> io::Result<File> {
    let path = wide_os(path)?;
    // Omit FILE_SHARE_DELETE so this live handle fences replacement while checked.
    // SAFETY: path is NUL-terminated and all scalar flags are valid.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned one newly owned live handle.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn validate(file: &File, directory: bool, protected: bool) -> io::Result<(u32, u64)> {
    let information = information(file)?;
    let attributes = information.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && information.nNumberOfLinks != 1)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private state object has an unsafe type, link, or reparse identity",
        ));
    }
    validate_acl(file, protected)?;
    Ok((
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}

fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain output storage initialized by
    // GetFileInformationByHandle before any field is observed.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: information is writable and file owns a live kernel handle.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

fn validate_acl(file: &File, protected: bool) -> io::Result<()> {
    let user = UserToken::current()?;
    let mut owner: PSID = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: all outputs are live and descriptor is released below.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor_allocation = LocalAllocation(descriptor);
    // SAFETY: owner belongs to the live descriptor and the token SID is valid.
    if owner.is_null() || unsafe { EqualSid(owner, user.sid()) } == 0 || acl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private state owner or DACL is unavailable",
        ));
    }
    if protected {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: descriptor is live and both scalar outputs are writable.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private state root inherits replaceable access",
            ));
        }
    }
    let mut count = 0_u32;
    let mut entries: *mut EXPLICIT_ACCESS_W = null_mut();
    // SAFETY: ACL belongs to the live descriptor and outputs are writable.
    let status = unsafe { GetExplicitEntriesFromAclW(acl, &mut count, &mut entries) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let entries_allocation = LocalAllocation(entries.cast());
    if count > 64 || (count != 0 && entries.is_null()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private state DACL exceeds its trusted bound",
        ));
    }
    if count != 0 {
        // SAFETY: successful enumeration returned exactly count initialized entries.
        for entry in unsafe { std::slice::from_raw_parts(entries, count as usize) } {
            if (entry.grfAccessMode == GRANT_ACCESS || entry.grfAccessMode == SET_ACCESS)
                && (entry.Trustee.TrusteeForm != TRUSTEE_IS_SID
                    // SAFETY: SID-form trustees expose a valid SID for the descriptor lifetime.
                    || unsafe { EqualSid(entry.Trustee.ptstrName.cast(), user.sid()) } == 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private state DACL grants another principal access",
                ));
            }
            if entry.grfAccessMode != GRANT_ACCESS
                && entry.grfAccessMode != SET_ACCESS
                && entry.grfAccessMode != DENY_ACCESS
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private state DACL contains an unsupported audit entry",
                ));
            }
        }
    }
    drop(entries_allocation);
    drop(descriptor_allocation);
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn wide_os(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows state path contains NUL",
        ));
    }
    value.push(0);
    Ok(value)
}
