//! Narrow Windows Virtual Disk API adapter.
//!
//! Host orchestration stays free of raw handles and unsafe FFI. This module
//! validates paths, owns each native handle, and exposes only the VHDX
//! operations required by the Hyper-V guardian.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::Vhd::{
    ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY,
    ATTACH_VIRTUAL_DISK_PARAMETERS, ATTACH_VIRTUAL_DISK_PARAMETERS_0,
    ATTACH_VIRTUAL_DISK_PARAMETERS_0_0, ATTACH_VIRTUAL_DISK_VERSION_1, AttachVirtualDisk,
    CREATE_VIRTUAL_DISK_FLAG_NONE, CREATE_VIRTUAL_DISK_PARAMETERS,
    CREATE_VIRTUAL_DISK_PARAMETERS_0, CREATE_VIRTUAL_DISK_PARAMETERS_0_0,
    CREATE_VIRTUAL_DISK_VERSION_1, CreateVirtualDisk, DETACH_VIRTUAL_DISK_FLAG_NONE,
    DetachVirtualDisk, EXPAND_VIRTUAL_DISK_FLAG_NONE, EXPAND_VIRTUAL_DISK_PARAMETERS,
    EXPAND_VIRTUAL_DISK_PARAMETERS_0, EXPAND_VIRTUAL_DISK_PARAMETERS_0_0,
    EXPAND_VIRTUAL_DISK_VERSION_1, ExpandVirtualDisk, GET_VIRTUAL_DISK_INFO,
    GET_VIRTUAL_DISK_INFO_0, GET_VIRTUAL_DISK_INFO_SIZE, GetVirtualDiskInformation,
    GetVirtualDiskPhysicalPath, OPEN_VIRTUAL_DISK_FLAG_NONE, OPEN_VIRTUAL_DISK_PARAMETERS,
    OPEN_VIRTUAL_DISK_PARAMETERS_0, OPEN_VIRTUAL_DISK_PARAMETERS_0_0, OPEN_VIRTUAL_DISK_VERSION_1,
    OpenVirtualDisk, VIRTUAL_DISK_ACCESS_ALL, VIRTUAL_DISK_ACCESS_METAOPS, VIRTUAL_STORAGE_TYPE,
    VIRTUAL_STORAGE_TYPE_DEVICE_VHDX, VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
};

const COPY_BUFFER: usize = 1024 * 1024;

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

fn open_vhdx_with_access(path: &Path, access: i32) -> io::Result<VirtualDisk> {
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
            access,
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

fn open_vhdx(path: &Path) -> io::Result<VirtualDisk> {
    open_vhdx_with_access(path, VIRTUAL_DISK_ACCESS_METAOPS)
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

struct AttachedDisk(VirtualDisk);

impl AttachedDisk {
    fn attach(disk: VirtualDisk, read_only: bool) -> io::Result<Self> {
        let parameters = ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: ATTACH_VIRTUAL_DISK_VERSION_1,
            Anonymous: ATTACH_VIRTUAL_DISK_PARAMETERS_0 {
                Version1: ATTACH_VIRTUAL_DISK_PARAMETERS_0_0 { Reserved: 0 },
            },
        };
        let flags = ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER
            | if read_only {
                ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY
            } else {
                0
            };
        // SAFETY: the handle is live, the versioned parameters are initialized,
        // no security descriptor is installed, and null OVERLAPPED makes this
        // operation synchronous.
        let result = unsafe {
            AttachVirtualDisk(disk.0, ptr::null_mut(), flags, 0, &parameters, ptr::null())
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        Ok(Self(disk))
    }

    fn physical_path(&self) -> io::Result<PathBuf> {
        let mut buffer = vec![0_u16; 32_768];
        let mut bytes = u32::try_from(buffer.len() * size_of::<u16>())
            .map_err(|_| io::Error::other("physical disk path buffer overflow"))?;
        // SAFETY: buffer has `bytes` writable storage and the attached handle
        // remains live for this synchronous query.
        let result =
            unsafe { GetVirtualDiskPhysicalPath(self.0.0, &mut bytes, buffer.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let length = buffer.iter().position(|value| *value == 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "physical disk path is not terminated",
            )
        })?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "physical disk path is empty",
            ));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(
            &buffer[..length],
        )))
    }
}

impl Drop for AttachedDisk {
    fn drop(&mut self) {
        // SAFETY: this object owns a successfully attached live disk handle.
        unsafe {
            DetachVirtualDisk(self.0.0, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        }
    }
}

fn create_vhdx(path: &Path, bytes: u64) -> io::Result<VirtualDisk> {
    if bytes == 0 || !bytes.is_multiple_of(1024 * 1024) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VHDX capacity must be a positive MiB multiple",
        ));
    }
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "VHDX destination already exists",
        ));
    }
    let storage = VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
        Version: CREATE_VIRTUAL_DISK_VERSION_1,
        Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
            Version1: CREATE_VIRTUAL_DISK_PARAMETERS_0_0 {
                MaximumSize: bytes,
                SectorSizeInBytes: 512,
                ..CREATE_VIRTUAL_DISK_PARAMETERS_0_0::default()
            },
        },
    };
    let wide = wide_path(path)?;
    let mut handle = ptr::null_mut();
    // SAFETY: the terminated path, storage type, initialized versioned
    // parameters, and writable output handle remain live synchronously.
    let result = unsafe {
        CreateVirtualDisk(
            &storage,
            wide.as_ptr(),
            VIRTUAL_DISK_ACCESS_ALL,
            ptr::null_mut(),
            CREATE_VIRTUAL_DISK_FLAG_NONE,
            0,
            &parameters,
            ptr::null(),
            &mut handle,
        )
    };
    if result != 0 || handle.is_null() {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(VirtualDisk(handle))
}

/// Export the exact virtual bytes of an unpartitioned VHDX to a raw image.
/// A private copy is attached so the running VM's disk handle is never shared
/// with the host conversion path.
pub fn export_raw(source: &Path, destination: &Path, bytes: u64) -> io::Result<()> {
    if !source.is_absolute() || !destination.is_absolute() || bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VHDX export paths and geometry are invalid",
        ));
    }
    let temporary = destination.with_extension("export-source.vhdx");
    let result = (|| {
        let copied = fs::copy(source, &temporary)?;
        if copied == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VHDX source copy is empty",
            ));
        }
        File::open(&temporary)?.sync_all()?;
        let disk = open_vhdx_with_access(&temporary, VIRTUAL_DISK_ACCESS_ALL)?;
        if virtual_disk_size(&temporary)? != bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VHDX virtual capacity changed",
            ));
        }
        let attached = AttachedDisk::attach(disk, true)?;
        let mut physical = OpenOptions::new()
            .read(true)
            .open(attached.physical_path()?)?;
        let mut raw = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(destination)?;
        copy_sparse(&mut physical, &mut raw, bytes)?;
        raw.sync_all()
    })();
    let cleanup = match fs::remove_file(&temporary) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    result.and(cleanup)
}

/// Materialize a raw, unpartitioned Linux disk as a dynamic VHDX without
/// mounting or interpreting the guest filesystem on the Windows host.
pub fn import_raw(source: &Path, destination: &Path, bytes: u64) -> io::Result<()> {
    if !source.is_absolute() || !destination.is_absolute() || source.metadata()?.len() != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "raw import paths or geometry are invalid",
        ));
    }
    let result = (|| {
        let disk = create_vhdx(destination, bytes)?;
        let attached = AttachedDisk::attach(disk, false)?;
        let mut physical = OpenOptions::new()
            .read(true)
            .write(true)
            .open(attached.physical_path()?)?;
        let mut raw = File::open(source)?;
        copy_exact(&mut raw, &mut physical, bytes)?;
        physical.flush()?;
        physical.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn copy_sparse(source: &mut File, destination: &mut File, bytes: u64) -> io::Result<()> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; COPY_BUFFER];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(COPY_BUFFER as u64))
            .map_err(|_| io::Error::other("disk copy bound overflow"))?;
        source.read_exact(&mut buffer[..count])?;
        if buffer[..count].iter().all(|byte| *byte == 0) {
            destination
                .seek(SeekFrom::Current(i64::try_from(count).map_err(|_| {
                    io::Error::other("sparse disk extent overflow")
                })?))?;
        } else {
            destination.write_all(&buffer[..count])?;
        }
        remaining -= count as u64;
    }
    destination.set_len(bytes)
}

fn copy_exact(source: &mut File, destination: &mut File, bytes: u64) -> io::Result<()> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; COPY_BUFFER];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(COPY_BUFFER as u64))
            .map_err(|_| io::Error::other("disk copy bound overflow"))?;
        source.read_exact(&mut buffer[..count])?;
        destination.write_all(&buffer[..count])?;
        remaining -= count as u64;
    }
    if source.read(&mut [0_u8; 1])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "raw disk exceeds declared geometry",
        ));
    }
    Ok(())
}
