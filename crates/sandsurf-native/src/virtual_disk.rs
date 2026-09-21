//! Narrow Windows Virtual Disk API adapter.
//!
//! Host orchestration stays free of raw handles and unsafe FFI. This module
//! validates paths, owns each native handle, and exposes only the VHDX
//! operations required by the Hyper-V guardian.

use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::Vhd::{
    EXPAND_VIRTUAL_DISK_FLAG_NONE, EXPAND_VIRTUAL_DISK_PARAMETERS,
    EXPAND_VIRTUAL_DISK_PARAMETERS_0, EXPAND_VIRTUAL_DISK_PARAMETERS_0_0,
    EXPAND_VIRTUAL_DISK_VERSION_1, ExpandVirtualDisk, GET_VIRTUAL_DISK_INFO,
    GET_VIRTUAL_DISK_INFO_0, GET_VIRTUAL_DISK_INFO_SIZE, GetVirtualDiskInformation,
    OPEN_VIRTUAL_DISK_FLAG_NONE, OPEN_VIRTUAL_DISK_PARAMETERS, OPEN_VIRTUAL_DISK_PARAMETERS_0,
    OPEN_VIRTUAL_DISK_PARAMETERS_0_0, OPEN_VIRTUAL_DISK_VERSION_1, OpenVirtualDisk,
    VIRTUAL_DISK_ACCESS_METAOPS, VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
    VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
};

struct VirtualDisk(HANDLE);

impl Drop for VirtualDisk {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns a successful OpenVirtualDisk result.
        unsafe { CloseHandle(self.0) };
    }
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    if !path.is_absolute() || path.as_os_str().encode_wide().any(|value| value == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VHDX path must be absolute and contain no NUL",
        ));
    }
    Ok(path.as_os_str().encode_wide().chain(Some(0)).collect())
}

fn open_vhdx(path: &Path) -> io::Result<VirtualDisk> {
    let storage = VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    let parameters = OPEN_VIRTUAL_DISK_PARAMETERS {
        Version: OPEN_VIRTUAL_DISK_VERSION_1,
        Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
            Version1: OPEN_VIRTUAL_DISK_PARAMETERS_0_0 { RWDepth: 1 },
        },
    };
    let wide = wide_path(path)?;
    let mut handle = ptr::null_mut();
    // SAFETY: structures use documented versions; the terminated path and
    // writable output handle remain live for this synchronous call.
    let result = unsafe {
        OpenVirtualDisk(
            &storage,
            wide.as_ptr(),
            VIRTUAL_DISK_ACCESS_METAOPS,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            &parameters,
            &mut handle,
        )
    };
    if result != 0 || handle.is_null() {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(VirtualDisk(handle))
}

/// Return the declared virtual capacity of a VHDX, not its sparse host size.
pub fn virtual_disk_size(path: &Path) -> io::Result<u64> {
    let disk = open_vhdx(path)?;
    let mut info = GET_VIRTUAL_DISK_INFO {
        Version: GET_VIRTUAL_DISK_INFO_SIZE,
        Anonymous: GET_VIRTUAL_DISK_INFO_0::default(),
    };
    let mut size = size_of::<GET_VIRTUAL_DISK_INFO>() as u32;
    let mut used = 0;
    // SAFETY: info selects the size union arm and all outputs remain valid for
    // the synchronous query.
    let result = unsafe { GetVirtualDiskInformation(disk.0, &mut size, &mut info, &mut used) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    // SAFETY: successful GET_VIRTUAL_DISK_INFO_SIZE initializes this union arm.
    Ok(unsafe { info.Anonymous.Size.VirtualSize })
}

/// Grow a VHDX to an exact capacity. Shrinking is deliberately unsupported.
pub fn grow_virtual_disk(path: &Path, bytes: u64) -> io::Result<()> {
    let current = virtual_disk_size(path)?;
    if current > bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VHDX is larger than the requested capacity",
        ));
    }
    if current == bytes {
        return Ok(());
    }
    let disk = open_vhdx(path)?;
    let parameters = EXPAND_VIRTUAL_DISK_PARAMETERS {
        Version: EXPAND_VIRTUAL_DISK_VERSION_1,
        Anonymous: EXPAND_VIRTUAL_DISK_PARAMETERS_0 {
            Version1: EXPAND_VIRTUAL_DISK_PARAMETERS_0_0 { NewSize: bytes },
        },
    };
    // SAFETY: the handle is live, parameters use version 1, and a null
    // OVERLAPPED requests completion before returning.
    let result = unsafe {
        ExpandVirtualDisk(
            disk.0,
            EXPAND_VIRTUAL_DISK_FLAG_NONE,
            &parameters,
            ptr::null(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}
