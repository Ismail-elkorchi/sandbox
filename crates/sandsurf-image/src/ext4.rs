//! Complete Linux filesystem construction from bounded canonical archives.
//! Never used to interpret or repair a root-controlled runtime disk.
use std::fmt;
use std::io;
use std::path::Path;

pub const BUILDER_ID: &str = "libguestfs-appliance-ext4-linux";
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MIN_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
pub enum Ext4Error {
    Io(io::Error),
    Invalid(String),
    Unsupported,
}
impl fmt::Display for Ext4Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "ext4 builder I/O: {error}"),
            Self::Invalid(message) => output.write_str(message),
            Self::Unsupported => output.write_str("ext4 construction requires a Linux builder"),
        }
    }
}
impl std::error::Error for Ext4Error {}
impl From<io::Error> for Ext4Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Returns the digest of the builder contract and protected tool executables.
/// A newly generated journaled seed is verified before publication. No guest
/// scripts run on the host and no filesystem is mounted in the host kernel.
pub fn materialize_tar(tar: &Path, output: &Path, bytes: u64) -> Result<String, Ext4Error> {
    if !tar.is_absolute()
        || !output.is_absolute()
        || !(MIN_IMAGE_BYTES..=MAX_IMAGE_BYTES).contains(&bytes)
        || !bytes.is_multiple_of(4096)
    {
        return Err(Ext4Error::Invalid(
            "ext4 image paths or geometry are outside the builder envelope".into(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Ext4Error::Unsupported)
    }
    #[cfg(target_os = "linux")]
    {
        linux::materialize(tar, output, bytes)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Component;

    pub(super) fn materialize(tar: &Path, output: &Path, bytes: u64) -> Result<String, Ext4Error> {
        validate_archive(tar, bytes)?;
        sandsurf_native::filesystem::require_protected_ancestors(output)?;
        let tool = sandsurf_native::filesystem::protected_tool(&["/usr/bin/guestfish"])?;
        let mut builder = Sha256::new();
        builder.update(BUILDER_ID);
        hash_file(&tool, &mut builder)?;
        let builder = format!("{:x}", builder.finalize());
        let file = sandsurf_native::local::create_private_file(output)?;
        file.set_len(bytes)?;
        file.sync_all()?;
        crate::appliance::run(
            output,
            true,
            &[
                crate::appliance::Operation::MakeExt4,
                crate::appliance::Operation::Mount { writable: true },
                crate::appliance::Operation::ImportTar {
                    source: tar.into(),
                    compression: crate::appliance::Compression::None,
                },
                crate::appliance::Operation::Sync,
                crate::appliance::Operation::Unmount,
                crate::appliance::Operation::CheckExt4,
            ],
        )?;
        File::open(output)?.sync_all()?;
        Ok(builder)
    }

    fn hash_file(path: &Path, hash: &mut Sha256) -> io::Result<()> {
        struct HashWriter<'a>(&'a mut Sha256);
        impl Write for HashWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        io::copy(&mut File::open(path)?, &mut HashWriter(hash))?;
        Ok(())
    }

    fn relative(path: &Path) -> Result<(), Ext4Error> {
        if path.as_os_str().is_empty()
            || path.as_os_str().len() > 4096
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(Ext4Error::Invalid(
                "noncanonical filesystem archive path".into(),
            ));
        }
        Ok(())
    }

    fn validate_archive(path: &Path, disk_bytes: u64) -> Result<(), Ext4Error> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_IMAGE_BYTES
        {
            return Err(Ext4Error::Invalid(
                "ext4 source must be a bounded regular canonical tar".into(),
            ));
        }
        let mut archive = crate::archive::Archive::new(
            File::open(path)?,
            crate::archive::Limits {
                headers: 100_000,
                bytes: MAX_IMAGE_BYTES,
                file_bytes: disk_bytes,
                path_bytes: 4096,
            },
        );
        let mut entries = BTreeMap::new();
        let mut payload = 0_u64;
        while let Some(entry) = archive.next_entry()? {
            let path = entry.path().to_owned();
            relative(&path)?;
            let kind = entry.header().entry_type();
            if entries.len() >= 100_000
                || entries.contains_key(&path)
                || !(kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link())
                || entry.header().mode()? > 0o7777
                || entry.header().uid()? > u32::MAX as u64
                || entry.header().gid()? > u32::MAX as u64
            {
                return Err(Ext4Error::Invalid(
                    "filesystem archive metadata is outside the supported profile".into(),
                ));
            }
            for parent in path
                .ancestors()
                .skip(1)
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                if entries
                    .get(parent)
                    .is_none_or(|kind: &tar::EntryType| !kind.is_dir())
                {
                    return Err(Ext4Error::Invalid(
                        "filesystem archive requires preceding directory parents".into(),
                    ));
                }
            }
            if kind.is_hard_link() {
                let target = entry
                    .link_name()
                    .ok_or_else(|| Ext4Error::Invalid("hardlink target missing".into()))?;
                relative(target)?;
                if entries
                    .get(target)
                    .is_none_or(|kind| !(kind.is_file() || kind.is_hard_link()))
                {
                    return Err(Ext4Error::Invalid(
                        "hardlink must name a preceding archive file".into(),
                    ));
                }
            }
            if kind.is_file() {
                payload = payload
                    .checked_add(entry.size())
                    .filter(|value| *value <= disk_bytes)
                    .ok_or_else(|| {
                        Ext4Error::Invalid("filesystem payload exceeds disk capacity".into())
                    })?;
            } else if entry.size() != 0 {
                return Err(Ext4Error::Invalid(
                    "non-file archive entry carries payload".into(),
                ));
            }
            entries.insert(path, kind);
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    #[ignore = "native KVM/libguestfs image qualification; run explicitly with --ignored"]
    fn isolated_materialization_preserves_linux_metadata() {
        let root = std::path::Path::new("/var/tmp").join(format!(
            "sandsurf-ext4-builder-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let tar = root.join("root.tar");
        let mut archive = tar::Builder::new(File::create_new(&tar).unwrap());
        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_mode(0o755);
        directory.set_uid(0);
        directory.set_gid(0);
        directory.set_mtime(0);
        directory.set_size(0);
        directory.set_cksum();
        archive
            .append_data(&mut directory, "etc", io::empty())
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o4755);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_mtime(0);
        header.set_size(8);
        header.set_cksum();
        archive
            .append_data(&mut header, "etc/identity", &b"sandsurf"[..])
            .unwrap();
        let long_target = format!("/{}tool", "directory/".repeat(30));
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_mode(0o777);
        link.set_uid(0);
        link.set_gid(0);
        link.set_mtime(0);
        link.set_size(0);
        archive
            .append_link(&mut link, "etc/long-link", &long_target)
            .unwrap();
        archive.finish().unwrap();
        drop(archive);
        let first = root.join("first.ext4");
        let second = root.join("second.ext4");
        assert_eq!(
            materialize_tar(&tar, &first, MIN_IMAGE_BYTES).unwrap(),
            materialize_tar(&tar, &second, MIN_IMAGE_BYTES).unwrap()
        );
        use crate::appliance::{Operation, Reply, run};
        let read = run(
            &first,
            false,
            &[
                Operation::Mount { writable: false },
                Operation::Cat {
                    path: "/etc/identity".into(),
                },
            ],
        )
        .unwrap()
        .text()
        .unwrap();
        assert_eq!(read.trim_end_matches('\n'), "sandsurf");
        let stat = run(
            &first,
            false,
            &[
                Operation::Mount { writable: false },
                Operation::Stat {
                    path: "/etc/identity".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(
            stat,
            Reply::Stat(crate::appliance::Stat {
                uid: 1000,
                gid: 1000,
                mode: 35309,
                bytes: 8
            })
        );
        let link = run(
            &first,
            false,
            &[
                Operation::Mount { writable: false },
                Operation::Readlink {
                    path: "/etc/long-link".into(),
                },
            ],
        )
        .unwrap()
        .text()
        .unwrap();
        assert_eq!(link, long_target);
        assert!(materialize_tar(&tar, &root.join("undersized"), 32 * 1024 * 1024).is_err());
        assert!(!root.join("undersized").exists());
        for path in [tar, first, second] {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir_all(root.join(".appliance")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
