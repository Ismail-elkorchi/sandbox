//! Operator-provisioned physical boundaries, not directory reservations.
//! Sandsurf neither mounts nor resizes these volumes. Unmounting/replacing one
//! is an operator action and must only happen with all owners stopped.
use std::{io, path::Path};

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
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, shared);
        Err(unsupported(
            "bounded physical-volume verification is not implemented on this host platform",
        ))
    }
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
        if let Some(descendant) = path.strip_prefix(&format!("{target}/")) {
            // Shared storage has one intentional boundary per machine. No
            // other descendant mount may move writes outside its hard cap.
            let slot = descendant.strip_prefix("machines/id-");
            if !shared
                || !slot.is_some_and(|slot| {
                    slot.len() == 64 && slot.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return Err(unsupported(
                    "unexpected descendant mount escapes the storage boundary",
                ));
            }
        }
    }
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
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
