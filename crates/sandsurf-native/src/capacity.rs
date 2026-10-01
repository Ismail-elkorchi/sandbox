//! External storage measurements. Guest filesystem reports are not inputs.

use std::io;
use std::path::Path;

/// Known RAM filesystems cannot back persistent VM disks. Their file pages
/// consume the writer's host memory budget and cannot be reclaimed to disk.
pub fn require_persistent_storage(root: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open(root)?;
        let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: fstatfs initializes the retained directory descriptor's complete output.
        if unsafe { libc::fstatfs(file.as_raw_fd(), value.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful syscall initialized the output above.
        let value = unsafe { value.assume_init() };
        // linux/magic.h; libc exposes TMPFS_MAGIC but not RAMFS_MAGIC.
        const RAMFS_MAGIC: libc::c_long = 0x858458f6;
        if matches!(value.f_type, libc::TMPFS_MAGIC | RAMFS_MAGIC) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "persistent machine/image storage cannot use tmpfs or ramfs; provide a durable filesystem directory",
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = root;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn available_memory_bytes() -> io::Result<u64> {
    use std::io::Read;
    let mut value = String::new();
    std::fs::File::open("/proc/meminfo")?
        .take(65537)
        .read_to_string(&mut value)?;
    if value.len() > 65536 {
        return Err(io::Error::other("host memory observation exceeds bound"));
    }
    let amount = value
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .ok_or_else(|| io::Error::other("native available-memory observation unavailable"))?;
    let parts: Vec<_> = amount.split_whitespace().collect();
    if parts.len() != 2 || parts[1] != "kB" {
        return Err(io::Error::other("invalid native memory units"));
    }
    parts[0]
        .parse::<u64>()
        .map_err(io::Error::other)?
        .checked_mul(1024)
        .ok_or_else(|| io::Error::other("native memory observation overflow"))
}

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
