//! Deterministic, cross-platform ext4 materialization for verified image trees.
//! The formatter is pure userspace: callers never mount or ask the host kernel
//! to interpret the untrusted filesystem being constructed.

use arcbox_ext4::{FormatOptions, Formatter};
use sha2::{Digest as _, Sha256};
use std::fmt;
#[cfg(any(unix, test))]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use uuid::Uuid;

pub const BUILDER_ID: &str = "arcbox-ext4-0.1.2+sandsurf-deterministic-v2";
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug)]
pub enum Ext4Error {
    Io(io::Error),
    Invalid(String),
}

impl fmt::Display for Ext4Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "ext4 builder I/O: {error}"),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}

impl std::error::Error for Ext4Error {}
impl From<io::Error> for Ext4Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Materialize a canonical tar stream as an unpartitioned ext4 filesystem.
/// The output path must not exist. The returned digest identifies the exact
/// formatter contract and is intended for conversion provenance.
pub fn materialize_tar(tar: &Path, output: &Path, bytes: u64) -> Result<String, Ext4Error> {
    if !tar.is_absolute()
        || !output.is_absolute()
        || bytes == 0
        || bytes > MAX_IMAGE_BYTES
        || !bytes.is_multiple_of(4096)
    {
        return Err(Ext4Error::Invalid(
            "ext4 image paths or geometry are outside the builder envelope".into(),
        ));
    }
    let metadata = tar.symlink_metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_IMAGE_BYTES
    {
        return Err(Ext4Error::Invalid(
            "ext4 source must be a bounded regular canonical tar".into(),
        ));
    }
    let mut identity = Sha256::new();
    identity.update(BUILDER_ID.as_bytes());
    identity.update(bytes.to_be_bytes());
    io::copy(&mut File::open(tar)?, &mut HashWriter(&mut identity))?;
    let digest = identity.finalize();
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let mut reservation = OpenOptions::new();
    reservation.write(true).create_new(true);
    #[cfg(unix)]
    reservation.mode(0o600);
    drop(reservation.open(output)?);

    let options = FormatOptions::new(bytes)
        .uuid(Uuid::from_bytes(uuid))
        .label("Sandsurf");
    let mut formatter = Formatter::with_options(output, options)
        .map_err(|error| Ext4Error::Invalid(format!("ext4 builder setup: {error}")))?;
    formatter
        .unpack_tar(File::open(tar)?)
        .map_err(|error| Ext4Error::Invalid(format!("ext4 tree materialization: {error}")))?;
    formatter
        .close()
        .map_err(|error| Ext4Error::Invalid(format!("ext4 image publication: {error}")))?;
    normalize_formatter_metadata(output)?;
    #[cfg(unix)]
    fs::set_permissions(output, fs::Permissions::from_mode(0o600))?;
    File::open(output)?.sync_all()?;
    Ok(format!("{:x}", Sha256::digest(BUILDER_ID.as_bytes())))
}

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

/// Arcbox intentionally timestamps formatter-created directories and inode
/// change times. Sandsurf's canonical tree gives every entry a zero timestamp,
/// so clear every inode timestamp to make conversion bit-reproducible.
fn normalize_formatter_metadata(path: &Path) -> Result<(), Ext4Error> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut superblock = [0_u8; 1024];
    file.seek(SeekFrom::Start(1024))?;
    file.read_exact(&mut superblock)?;
    let log_block_size = u32::from_le_bytes(superblock[24..28].try_into().unwrap());
    let block_size = 1024_u64
        .checked_shl(log_block_size)
        .ok_or_else(|| Ext4Error::Invalid("ext4 block size overflow".into()))?;
    let inode_size = u16::from_le_bytes(superblock[88..90].try_into().unwrap()) as u64;
    let inode_count = u32::from_le_bytes(superblock[0..4].try_into().unwrap()) as u64;
    let inodes_per_group = u32::from_le_bytes(superblock[40..44].try_into().unwrap()) as u64;
    if block_size != 4096 || inode_size < 160 || inodes_per_group == 0 || inode_count == 0 {
        return Err(Ext4Error::Invalid(
            "portable ext4 builder emitted unsupported geometry".into(),
        ));
    }
    let groups = inode_count.div_ceil(inodes_per_group);
    for group in 0..groups {
        let mut descriptor = [0_u8; 32];
        file.seek(SeekFrom::Start(block_size + group * 32))?;
        file.read_exact(&mut descriptor)?;
        let inode_table = u32::from_le_bytes(descriptor[8..12].try_into().unwrap()) as u64;
        let count = (inode_count - group * inodes_per_group).min(inodes_per_group);
        let table_bytes = count
            .checked_mul(inode_size)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Ext4Error::Invalid("ext4 inode table size overflow".into()))?;
        let table_offset = inode_table
            .checked_mul(block_size)
            .ok_or_else(|| Ext4Error::Invalid("ext4 inode table offset overflow".into()))?;
        let mut table = vec![0_u8; table_bytes];
        file.seek(SeekFrom::Start(table_offset))?;
        file.read_exact(&mut table)?;
        for inode in table.chunks_exact_mut(inode_size as usize) {
            inode[8..24].fill(0);
            inode[132..152].fill(0);
        }
        file.seek(SeekFrom::Start(table_offset))?;
        file.write_all(&table)?;
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn materialization_is_reproducible_and_readable() {
        let directory = std::env::temp_dir().join(format!(
            "sandsurf-ext4-builder-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let archive_path = directory.join("rootfs.tar");
        let archive_file = File::create_new(&archive_path).unwrap();
        let mut archive = tar::Builder::new(archive_file);
        archive.mode(tar::HeaderMode::Deterministic);
        let mut header = tar::Header::new_gnu();
        header.set_path("etc/identity").unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(8);
        header.set_cksum();
        archive.append(&header, &b"sandsurf"[..]).unwrap();
        archive.finish().unwrap();
        drop(archive);

        let first = directory.join("first.ext4");
        let second = directory.join("second.ext4");
        materialize_tar(&archive_path, &first, 256 * 1024 * 1024).unwrap();
        materialize_tar(&archive_path, &second, 256 * 1024 * 1024).unwrap();
        assert_eq!(file_digest(&first), file_digest(&second));
        let mut reader = arcbox_ext4::Reader::new(&first).unwrap();
        assert_eq!(
            reader.read_file("/etc/identity", 0, None).unwrap(),
            b"sandsurf"
        );

        for path in [&archive_path, &first, &second] {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }

    fn file_digest(path: &Path) -> String {
        let mut file = File::open(path).unwrap();
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        format!("{:x}", hash.finalize())
    }
}
