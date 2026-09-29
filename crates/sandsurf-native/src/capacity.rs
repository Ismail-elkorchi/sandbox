//! External storage measurements. Guest filesystem reports are not inputs.

use std::io;
use std::path::Path;

#[cfg(unix)]
pub fn available_storage_bytes(root: &Path) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(root)?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: fstatvfs writes a complete structure for the retained descriptor.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call initialized the structure.
    let value = unsafe { value.assume_init() };
    u64::try_from(u128::from(value.f_bavail) * u128::from(value.f_frsize))
        .map_err(|_| io::Error::other("filesystem capacity exceeds accounting range"))
}

#[cfg(windows)]
pub fn available_storage_bytes(root: &Path) -> io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut path: Vec<u16> = root.as_os_str().encode_wide().collect();
    if path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage path contains NUL",
        ));
    }
    path.push(0);
    let mut available = 0_u64;
    // SAFETY: path is terminated and available is a live output pointer.
    if unsafe {
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(available)
}

#[cfg(not(any(unix, windows)))]
pub fn available_storage_bytes(_: &Path) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host storage measurement is unsupported",
    ))
}
