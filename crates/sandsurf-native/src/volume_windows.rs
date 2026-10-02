//! A fixed NTFS volume, not a directory quota or arbitrary junction. Mounted
//! folders are accepted only when their reparse data names an entire registered
//! volume. Both the mount object and resolved root retain private ACL checks.
#[cfg(windows)]
use super::BoundedVolume;
use super::unsupported;
use std::io;

fn volume_guid(value: &str) -> bool {
    let Some(guid) = value
        .strip_prefix(r"\\?\Volume{")
        .and_then(|tail| tail.strip_suffix("}\\"))
    else {
        return false;
    };
    guid.len() == 36
        && guid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn reparse_volume(bytes: &[u8]) -> io::Result<String> {
    // REPARSE_DATA_BUFFER's mount-point header is 16 bytes, with UTF-16
    // offsets relative to PathBuffer. Never cast a variable native buffer.
    if bytes.len() < 16
        || u32::from_le_bytes(bytes[..4].try_into().expect("header")) != 0xa000_0003
        || bytes[6..8] != [0, 0]
    {
        return Err(unsupported("storage reparse object is not a volume mount"));
    }
    let field =
        |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("header")) as usize;
    let declared = field(4) + 8;
    if declared != bytes.len() || declared > 16384 {
        return Err(unsupported("invalid native volume reparse length"));
    }
    for offset in [8, 12] {
        let start = field(offset);
        let length = field(offset + 2);
        if start % 2 != 0 || length % 2 != 0 || start + length > bytes.len() - 16 {
            return Err(unsupported("invalid native volume reparse field"));
        }
    }
    let start = 16 + field(8);
    let end = start + field(10);
    let name = String::from_utf16(
        &bytes[start..end]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| unsupported("invalid native volume target encoding"))?;
    let guid = name
        .strip_prefix(r"\??\")
        .map(|tail| format!(r"\\?\{tail}"))
        .filter(|value| volume_guid(value))
        .ok_or_else(|| {
            unsupported("junction targets and volume subdirectories are not storage boundaries")
        })?;
    Ok(guid)
}

fn permitted_mount(relative: &str, shared: bool) -> bool {
    shared
        && relative
            .strip_prefix("machines\\id-")
            .and_then(|tail| tail.strip_suffix('\\'))
            .is_some_and(|slot| {
                slot.len() == 64 && slot.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::mem::size_of;
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FindFirstVolumeMountPointW, FindNextVolumeMountPointW, FindVolumeMountPointClose,
        GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, GetVolumePathNamesForVolumeNameW,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        FSCTL_GET_REPARSE_POINT, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO,
        VOLUME_DISK_EXTENTS,
    };

    fn wide(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
        let mut value: Vec<_> = value.encode_wide().collect();
        if value.len() > 32767 || value.contains(&0) {
            return Err(unsupported("native volume path exceeds bound"));
        }
        value.push(0);
        Ok(value)
    }
    fn terminated(bytes: &[u16]) -> io::Result<String> {
        let end = bytes
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| unsupported("unterminated native volume field"))?;
        String::from_utf16(&bytes[..end])
            .map_err(|_| unsupported("invalid native volume field encoding"))
    }
    fn name(path: &Path) -> io::Result<String> {
        let mut path = wide(path.as_os_str())?;
        path.pop();
        if path.last() != Some(&92) {
            path.push(92);
        }
        path.push(0);
        let mut output = [0u16; 64];
        // SAFETY: terminated native path and complete fixed writable GUID output.
        if unsafe {
            GetVolumeNameForVolumeMountPointW(
                path.as_ptr(),
                output.as_mut_ptr(),
                output.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let value = terminated(&output)?;
        if !volume_guid(&value) {
            return Err(unsupported("native volume identity is malformed"));
        }
        Ok(value)
    }

    fn registered_mount(guid: &str) -> io::Result<PathBuf> {
        let guid = wide(std::ffi::OsStr::new(guid))?;
        let mut aliases = [0u16; 32768];
        let mut required = 0;
        // SAFETY: initialized bounded MULTI_SZ output and length slot.
        if unsafe {
            GetVolumePathNamesForVolumeNameW(
                guid.as_ptr(),
                aliases.as_mut_ptr(),
                aliases.len() as u32,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if required < 2
            || required as usize > aliases.len()
            || aliases[required as usize - 2..required as usize] != [0, 0]
        {
            return Err(unsupported("native volume alias inventory exceeds bound"));
        }
        let mut paths = aliases[..required as usize]
            .split(|unit| *unit == 0)
            .filter(|path| !path.is_empty());
        let first = paths
            .next()
            .ok_or_else(|| unsupported("bounded volume must have one registered mount"))?;
        let first =
            String::from_utf16(first).map_err(|_| unsupported("invalid mount path encoding"))?;
        if paths.next().is_some() {
            return Err(unsupported(
                "physical storage volume has competing mounts or aliases",
            ));
        }
        Ok(PathBuf::from(first))
    }

    fn mount_name(path: &Path) -> io::Result<String> {
        let value = path
            .to_str()
            .ok_or_else(|| unsupported("mount path is not Unicode"))?;
        Ok(value
            .strip_prefix(r"\\?\")
            .unwrap_or(value)
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase())
    }

    pub(crate) fn mount_point_target(file: &File, path: &Path) -> io::Result<PathBuf> {
        let mut bytes = [0u8; 16384];
        let mut count = 0;
        // SAFETY: retained non-following mount handle and bounded byte output.
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                FSCTL_GET_REPARSE_POINT,
                std::ptr::null(),
                0,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                &mut count,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let target = reparse_volume(
            bytes
                .get(..count as usize)
                .ok_or_else(|| unsupported("native reparse result exceeds buffer"))?,
        )?;
        if !target.eq_ignore_ascii_case(&name(path)?) {
            return Err(unsupported(
                "mount target is not the registered whole volume",
            ));
        }
        if mount_name(path)? != mount_name(&registered_mount(&target)?)? {
            return Err(unsupported(
                "whole-volume junction is not its registered native mount",
            ));
        }
        Ok(PathBuf::from(target))
    }

    struct MountSearch(HANDLE);
    impl Drop for MountSearch {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns a successful native mount search.
            unsafe { FindVolumeMountPointClose(self.0) };
        }
    }
    fn check_children(guid: &[u16], shared: bool) -> io::Result<()> {
        let mut relative = [0u16; 32768];
        // SAFETY: complete terminated volume GUID and bounded native string output.
        let handle = unsafe {
            FindFirstVolumeMountPointW(guid.as_ptr(), relative.as_mut_ptr(), relative.len() as u32)
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                Ok(())
            } else {
                Err(error)
            };
        }
        let search = MountSearch(handle);
        for _ in 0..1024 {
            if !permitted_mount(&terminated(&relative)?, shared) {
                return Err(unsupported(
                    "descendant mount escapes the physical storage boundary",
                ));
            }
            // SAFETY: live search and complete fixed writable native path buffer.
            if unsafe {
                FindNextVolumeMountPointW(search.0, relative.as_mut_ptr(), relative.len() as u32)
            } == 0
            {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    Ok(())
                } else {
                    Err(error)
                };
            }
        }
        Err(unsupported(
            "native descendant mount inventory exceeds bound",
        ))
    }

    pub(crate) fn inspect(root: &Path, shared: bool) -> io::Result<BoundedVolume> {
        if !root.is_absolute() || crate::local::canonical_private_directory(root)? != root {
            return Err(unsupported("volume path must be canonical and private"));
        }
        let guid = name(root)?;
        // Whole-volume equality, not the fact that a directory lives on NTFS.
        if std::fs::canonicalize(Path::new(&guid))? != root {
            return Err(unsupported(
                "provision a whole NTFS volume at the exact storage root",
            ));
        }
        let wide_guid = wide(std::ffi::OsStr::new(&guid))?;
        if std::fs::canonicalize(registered_mount(&guid)?)? != root {
            return Err(unsupported(
                "physical storage volume has competing mounts or aliases",
            ));
        }
        check_children(&wide_guid, shared)?;
        let mut serial = 0;
        let mut flags = 0;
        let mut filesystem = [0u16; 32];
        // SAFETY: live GUID and initialized scalar/string native outputs; optional outputs null.
        if unsafe {
            GetVolumeInformationW(
                wide_guid.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut serial,
                std::ptr::null_mut(),
                &mut flags,
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        const FILE_READ_ONLY_VOLUME: u32 = 0x80000;
        if terminated(&filesystem)? != "NTFS" || flags & FILE_READ_ONLY_VOLUME != 0 {
            return Err(unsupported("require one writable bounded NTFS volume"));
        }
        let volume = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(guid.trim_end_matches('\\'))?;
        let mut extents = VOLUME_DISK_EXTENTS::default();
        let mut count = 0;
        // SAFETY: owned volume and exact initialized single-extent output layout.
        if unsafe {
            DeviceIoControl(
                volume.as_raw_handle().cast(),
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                std::ptr::null(),
                0,
                (&raw mut extents).cast(),
                size_of::<VOLUME_DISK_EXTENTS>() as u32,
                &mut count,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if count as usize != size_of::<VOLUME_DISK_EXTENTS>()
            || extents.NumberOfDiskExtents != 1
            || extents.Extents[0].StartingOffset < 0
        {
            return Err(unsupported(
                "spanned or unverified volume cannot be a physical storage bound",
            ));
        }
        let mut length = GET_LENGTH_INFORMATION::default();
        // SAFETY: retained volume and exact initialized native capacity output.
        if unsafe {
            DeviceIoControl(
                volume.as_raw_handle().cast(),
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                (&raw mut length).cast(),
                size_of::<GET_LENGTH_INFORMATION>() as u32,
                &mut count,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if count as usize != size_of::<GET_LENGTH_INFORMATION>()
            || length.Length != extents.Extents[0].ExtentLength
            || length.Length < 64 * 1024 * 1024
            || length.Length >= (1i64 << 53)
            || name(root)? != guid
        {
            return Err(unsupported(
                "native volume capacity or identity is inconsistent",
            ));
        }
        Ok(BoundedVolume {
            device: u64::from(serial),
            bytes: length.Length as u64,
        })
    }
}
#[cfg(windows)]
pub(super) use native::inspect;
#[cfg(windows)]
pub(crate) use native::mount_point_target;

#[cfg(test)]
mod tests {
    use super::*;
    fn record(target: &str) -> Vec<u8> {
        let encoded: Vec<u8> = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa000_0003u32.to_le_bytes());
        bytes.extend_from_slice(&((8 + encoded.len()) as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&encoded);
        bytes
    }
    #[test]
    fn only_whole_volume_guid_mounts_are_accepted() {
        let target = r"\??\Volume{12345678-1234-1234-abcd-1234567890ab}\";
        assert_eq!(
            reparse_volume(&record(target)).unwrap(),
            r"\\?\Volume{12345678-1234-1234-abcd-1234567890ab}\"
        );
        for target in [
            r"\??\C:\other",
            r"\??\Volume{12345678-1234-1234-abcd-1234567890ab}\subdir\",
            r"\??\Volume{invalid}\",
        ] {
            assert!(reparse_volume(&record(target)).is_err());
        }
        let bytes = record(target);
        for length in 0..bytes.len() {
            assert!(reparse_volume(&bytes[..length]).is_err());
        }
        for offset in [0, 4, 6, 8, 10, 12, 14] {
            let mut malformed = bytes.clone();
            malformed[offset] = 0xff;
            assert!(reparse_volume(&malformed).is_err());
        }
    }
    #[test]
    fn only_exact_machine_volume_slots_can_descend_from_shared_storage() {
        let slot = format!("machines\\id-{}\\", "a".repeat(64));
        assert!(permitted_mount(&slot, true));
        assert!(!permitted_mount(&slot, false));
        for path in [
            "logs\\",
            "machines\\id-short\\",
            "machines\\..\\",
            "machines\\id-aaa\\nested\\",
        ] {
            assert!(!permitted_mount(path, true));
        }
    }
}
