//! Operator-provisioned physical boundaries, not directory reservations.
//! Sandsurf neither mounts nor resizes these volumes. Unmounting/replacing one
//! is an operator action and must only happen with all owners stopped.
use std::{io, path::Path};

#[cfg(any(windows, test))]
#[path = "volume_windows.rs"]
mod windows;
#[cfg(windows)]
pub(crate) use windows::mount_point_target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedVolume {
    pub device: u64,
    pub bytes: u64,
}

pub fn inspect(root: &Path) -> io::Result<BoundedVolume> {
    inspect_owned(root, true)
}

fn inspect_owned(root: &Path, shared: bool) -> io::Result<BoundedVolume> {
    #[cfg(target_os = "linux")]
    {
        use std::{io::Read, os::unix::fs::MetadataExt};
        crate::capacity::require_persistent_storage(root)?;
        let canonical = crate::local::canonical_private_directory(root)?;
        if canonical != root || !root.is_absolute() {
            return Err(unsupported("volume path must be canonical and absolute"));
        }
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(unsupported("volume must be a directory, not an alias"));
        }
        let mut mounts = String::new();
        std::fs::File::open("/proc/self/mountinfo")?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut mounts)?;
        if mounts.len() > 1024 * 1024 {
            return Err(unsupported("mount table exceeds verification bound"));
        }
        let target = root
            .to_str()
            .ok_or_else(|| unsupported("volume path is not UTF-8"))?;
        let device = mount_device(&mounts, target, shared)?;
        let parent = root
            .parent()
            .ok_or_else(|| unsupported("host root filesystem is not a Sandsurf volume"))?;
        if std::fs::metadata(parent)?.dev() == metadata.dev() {
            return Err(unsupported(
                "bind mounts do not establish an independent physical boundary",
            ));
        }
        let major = libc::major(metadata.dev());
        let minor = libc::minor(metadata.dev());
        if device != format!("{major}:{minor}") {
            return Err(unsupported(
                "mounted volume device changed during inspection",
            ));
        }
        let mut size = String::new();
        std::fs::File::open(format!("/sys/dev/block/{device}/size"))?
            .take(65)
            .read_to_string(&mut size)?;
        let bytes = size
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|_| size.len() <= 64)
            .and_then(|blocks| blocks.checked_mul(512))
            .filter(|bytes| *bytes >= 64 * 1024 * 1024 && *bytes < (1_u64 << 53))
            .ok_or_else(|| unsupported("invalid bounded block-device capacity"))?;
        Ok(BoundedVolume {
            device: metadata.dev(),
            bytes,
        })
    }
    #[cfg(target_os = "macos")]
    {
        darwin::inspect(root, shared)
    }
    #[cfg(windows)]
    {
        windows::inspect(root, shared)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (root, shared);
        Err(unsupported(
            "bounded physical-volume verification is not implemented on this host platform",
        ))
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;
    use std::fs::OpenOptions;
    use std::mem::{MaybeUninit, size_of};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;

    fn field(bytes: &[libc::c_char]) -> io::Result<String> {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| unsupported("native mount field is unterminated"))?;
        String::from_utf8(bytes[..end].iter().map(|byte| *byte as u8).collect())
            .map_err(|_| unsupported("native mount field is not UTF-8"))
    }

    pub fn inspect(root: &Path, shared: bool) -> io::Result<BoundedVolume> {
        if !root.is_absolute() || crate::local::canonical_private_directory(root)? != root {
            return Err(unsupported("volume path must be canonical and absolute"));
        }
        let metadata = std::fs::symlink_metadata(root)?;
        let parent = root
            .parent()
            .ok_or_else(|| unsupported("host filesystem is not an owned volume"))?;
        if !metadata.is_dir() || metadata.dev() == std::fs::metadata(parent)?.dev() {
            return Err(unsupported(
                "provision a whole bounded HFS+ volume at this exact path",
            ));
        }
        // SAFETY: null output and zero capacity query the mount count only.
        let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        if !(1..=1024).contains(&count) {
            return Err(unsupported("native mount inventory exceeds bound"));
        }
        let mut mounts: Vec<MaybeUninit<libc::statfs>> =
            (0..=count).map(|_| MaybeUninit::uninit()).collect();
        // SAFETY: the aligned vector holds count+1 complete statfs outputs;
        // getfsstat initializes only the returned number, checked below.
        let actual = unsafe {
            libc::getfsstat(
                mounts.as_mut_ptr().cast(),
                (mounts.len() * size_of::<libc::statfs>()) as i32,
                libc::MNT_NOWAIT,
            )
        };
        if actual < 0 {
            return Err(io::Error::last_os_error());
        }
        if actual as usize >= mounts.len() {
            return Err(unsupported(
                "native mount inventory changed during inspection",
            ));
        }
        let mut records = Vec::with_capacity(actual as usize);
        for mount in mounts.into_iter().take(actual as usize) {
            // SAFETY: this index is within the successful syscall's output count.
            let mount = unsafe { mount.assume_init() };
            records.push(MountRecord {
                path: field(&mount.f_mntonname)?,
                source: field(&mount.f_mntfromname)?,
                filesystem: field(&mount.f_fstypename)?,
                writable: mount.f_flags & libc::MNT_RDONLY as u32 == 0,
            });
        }
        let source = bounded_mount(&records, root, shared)?;
        // APFS space-sharing containers, disk-image files and directory quotas
        // are not accepted as an independent hard physical boundary. A whole
        // operator-provisioned HFS+ block volume provides a native fixed bound.
        let source = PathBuf::from(source);
        if source.parent() != Some(Path::new("/dev"))
            || !source
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("disk"))
        {
            return Err(unsupported("volume source is not a native block device"));
        }
        let device = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&source)?;
        let disk_metadata = device.metadata()?;
        if !disk_metadata.file_type().is_block_device() || disk_metadata.rdev() != metadata.dev() {
            return Err(unsupported(
                "native volume device does not match its mounted filesystem",
            ));
        }
        let mut block_size = 0u32;
        let mut block_count = 0u64;
        // XNU sys/disk.h: _IOR('d',24,uint32_t), _IOR('d',25,uint64_t).
        // SAFETY: borrowed live block device and exact initialized ioctl outputs.
        if unsafe { libc::ioctl(device.as_raw_fd(), 0x4004_6418, &mut block_size) } != 0
            || unsafe { libc::ioctl(device.as_raw_fd(), 0x4008_6419, &mut block_count) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let bytes = block_count
            .checked_mul(u64::from(block_size))
            .filter(|bytes| *bytes >= 64 * 1024 * 1024 && *bytes < (1u64 << 53))
            .ok_or_else(|| unsupported("invalid native block volume capacity"))?;
        if std::fs::metadata(root)?.dev() != metadata.dev() {
            return Err(unsupported("mounted volume changed during inspection"));
        }
        Ok(BoundedVolume {
            device: metadata.dev(),
            bytes,
        })
    }
}

#[cfg(any(target_os = "macos", test))]
struct MountRecord {
    path: String,
    source: String,
    filesystem: String,
    writable: bool,
}

#[cfg(any(target_os = "macos", test))]
fn bounded_mount<'a>(
    mounts: &'a [MountRecord],
    target: &Path,
    shared: bool,
) -> io::Result<&'a str> {
    let target = target
        .to_str()
        .ok_or_else(|| unsupported("volume path is not UTF-8"))?;
    let mut candidates = mounts.iter().filter(|mount| mount.path == target);
    let mount = candidates
        .next()
        .ok_or_else(|| unsupported("provision a bounded HFS+ volume at the exact storage path"))?;
    if candidates.next().is_some() || !mount.writable || mount.filesystem != "hfs" {
        return Err(unsupported(
            "require one writable whole HFS+ volume; APFS shared containers and stacked mounts are not admitted",
        ));
    }
    for other in mounts {
        if other.path != target && other.source == mount.source {
            return Err(unsupported(
                "a physical volume cannot be aliased by another mount or machine",
            ));
        }
        if !allowed_descendant(target, &other.path, shared) {
            return Err(unsupported(
                "unexpected descendant mount escapes the storage boundary",
            ));
        }
    }
    Ok(&mount.source)
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn allowed_descendant(target: &str, path: &str, shared: bool) -> bool {
    let Some(descendant) = path.strip_prefix(&format!("{target}/")) else {
        return true;
    };
    shared
        && descendant.strip_prefix("machines/id-").is_some_and(|slot| {
            slot.len() == 64 && slot.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

pub fn require(root: &Path, maximum: u64) -> io::Result<BoundedVolume> {
    let volume = inspect_owned(root, false)?;
    if volume.bytes > maximum {
        return Err(unsupported(
            "operator-provisioned volume exceeds the authorized physical-storage cap; reservations are not quotas",
        ));
    }
    Ok(volume)
}

fn unsupported(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, reason)
}

#[cfg(any(target_os = "linux", test))]
fn mount_device(mounts: &str, target: &str, shared: bool) -> io::Result<String> {
    let mut matched = None;
    for line in mounts.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<_> = before.split_whitespace().collect();
        let fs: Vec<_> = after.split_whitespace().collect();
        if fields.len() < 6 || fs.len() < 3 {
            continue;
        }
        let path = fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        if path != target {
            continue;
        }
        if matched.is_some()
            || fields[3] != "/"
            || fs[0] != "ext4"
            || !fields[5].split(',').any(|option| option == "rw")
        {
            return Err(unsupported(
                "require one writable whole ext4 block volume; subvolume, overlay and stacked mounts are not admitted",
            ));
        }
        matched = Some(fields[2].to_owned());
    }
    let device = matched.ok_or_else(|| {
        unsupported("provision a dedicated bounded ext4 block volume at this exact storage path")
    })?;
    for line in mounts.lines() {
        let Some((before, _)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<_> = before.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let path = fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        if fields[2] == device && path != target {
            return Err(unsupported(
                "a physical volume cannot be aliased by another mount or machine",
            ));
        }
        if !allowed_descendant(target, &path, shared) {
            return Err(unsupported(
                "unexpected descendant mount escapes the storage boundary",
            ));
        }
    }
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn darwin_volume_proof_rejects_shared_containers_aliases_and_submounts() {
        let make = |path: &str, source: &str| MountRecord {
            path: path.into(),
            source: source.into(),
            filesystem: "hfs".into(),
            writable: true,
        };
        let root = Path::new("/Volumes/sandsurf");
        let mut mounts = vec![make("/Volumes/sandsurf", "/dev/disk4s1")];
        assert_eq!(bounded_mount(&mounts, root, true).unwrap(), "/dev/disk4s1");
        mounts[0].filesystem = "apfs".into();
        assert!(bounded_mount(&mounts, root, true).is_err());
        mounts[0].filesystem = "hfs".into();
        mounts.push(make("/Volumes/alias", "/dev/disk4s1"));
        assert!(bounded_mount(&mounts, root, true).is_err());
        mounts.pop();
        mounts.push(make("/Volumes/sandsurf/logs", "/dev/disk5s1"));
        assert!(bounded_mount(&mounts, root, true).is_err());
        mounts[1].path = format!("/Volumes/sandsurf/machines/id-{}", "a".repeat(64));
        assert!(bounded_mount(&mounts, root, true).is_ok());
        assert!(bounded_mount(&mounts, root, false).is_err());
    }
    #[test]
    fn mount_proof_rejects_unbounded_directories_aliases_and_competing_mounts() {
        let good = "30 20 7:1 / /srv/sandsurf rw - ext4 /dev/loop1 rw\n";
        assert_eq!(mount_device(good, "/srv/sandsurf", true).unwrap(), "7:1");
        assert!(mount_device(good, "/srv/sandsurf/machines/a", false).is_err());
        assert!(
            mount_device(
                &good.replace(" / /srv", " /alias /srv"),
                "/srv/sandsurf",
                true
            )
            .is_err()
        );
        assert!(mount_device(&good.replace("ext4", "tmpfs"), "/srv/sandsurf", true).is_err());
        assert!(mount_device(&format!("{good}{good}"), "/srv/sandsurf", true).is_err());
        assert!(
            mount_device(
                &format!("{good}31 20 7:1 / /other rw - ext4 /dev/loop1 rw\n"),
                "/srv/sandsurf",
                true
            )
            .is_err()
        );
        assert!(
            mount_device(
                &format!("{good}31 30 7:2 / /srv/sandsurf/logs rw - ext4 /dev/loop2 rw\n"),
                "/srv/sandsurf",
                true
            )
            .is_err()
        );
        assert_eq!(
            mount_device(
                &good.replace("/srv/sandsurf", "/srv/my\\040volume"),
                "/srv/my volume",
                true
            )
            .unwrap(),
            "7:1"
        );
        let nested = format!(
            "{good}31 30 7:2 / /srv/sandsurf/machines/id-{} rw - ext4 /dev/loop2 rw\n",
            "a".repeat(64)
        );
        assert!(mount_device(&nested, "/srv/sandsurf", true).is_ok());
        assert!(mount_device(&nested, "/srv/sandsurf", false).is_err());
    }
    #[test]
    fn an_ordinary_directory_is_not_a_physical_cap() {
        let root = std::env::temp_dir().canonicalize().unwrap();
        assert!(inspect(&root).is_err());
    }
}
