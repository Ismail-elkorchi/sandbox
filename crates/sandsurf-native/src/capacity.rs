//! External storage measurements. Guest filesystem reports are not inputs.

use std::io;
use std::path::Path;

#[cfg(target_os = "macos")]
// SAFETY: these declarations match the public Mach host/port C ABI. Callers
// retain the send right and provide initialized outputs with the exact types.
unsafe extern "C" {
    fn host_page_size(host: libc::mach_port_t, size: *mut libc::vm_size_t) -> libc::kern_return_t;
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

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

#[cfg(target_os = "macos")]
pub fn available_memory_bytes() -> io::Result<u64> {
    // Mach VM statistics observe the native host. Inactive pages are reclaimable
    // estimates, not exclusive memory reservations; native envelopes enforce
    // each admitted allocation independently of subsequent host pressure.
    #[allow(deprecated)]
    let (statistics, page_size) = {
        // SAFETY: vm_statistics64 is an integer-only Mach ABI output layout.
        let mut statistics: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
        let mut count = libc::HOST_VM_INFO64_COUNT;
        let mut page_size = 0;
        // SAFETY: mach_host_self has no pointer preconditions and returns this
        // process's host send right. Both outputs have the exact ABI sizes.
        let host = unsafe { libc::mach_host_self() };
        // SAFETY: the host right is live and count bounds the writable statistics.
        let status = unsafe {
            libc::host_statistics64(
                host,
                libc::HOST_VM_INFO64,
                (&raw mut statistics).cast(),
                &mut count,
            )
        };
        // SAFETY: host right is live and page_size is a writable vm_size_t.
        let page_status = unsafe { host_page_size(host, &mut page_size) };
        // SAFETY: this function owns the host send right returned above, not a
        // pseudo-port. Releasing it does not terminate or mutate host authority.
        unsafe { mach_port_deallocate(libc::mach_task_self(), host) };
        if status != 0 || page_status != 0 || count != libc::HOST_VM_INFO64_COUNT || page_size == 0
        {
            return Err(io::Error::other(
                "native host memory observation unavailable",
            ));
        }
        (statistics, page_size)
    };
    u64::from(statistics.free_count)
        .checked_add(u64::from(statistics.inactive_count))
        .and_then(|pages| pages.checked_mul(page_size as u64))
        .ok_or_else(|| io::Error::other("native host memory observation overflow"))
}

#[cfg(windows)]
pub fn available_memory_bytes() -> io::Result<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: dwLength identifies a complete initialized MEMORYSTATUSEX output.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status.ullAvailPhys)
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
