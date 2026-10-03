//! Complete Linux filesystem construction from bounded canonical archives.
//! Filesystems and distribution programs execute only in the offline VM.
use crate::appliance::{Executor, Filesystem};
use sandsurf_protocol::disk::{DiskCompression, DiskOperation};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::sync::Arc;

pub const BUILDER_ID: &str = "sandsurf-offline-ext4-v1";
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MIN_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

pub fn materialize_tar(
    executor: &mut dyn Executor,
    custody: Vec<Arc<File>>,
    tar: &Path,
    output: &Path,
    bytes: u64,
) -> io::Result<String> {
    if !tar.is_absolute()
        || !output.is_absolute()
        || !(MIN_IMAGE_BYTES..=MAX_IMAGE_BYTES).contains(&bytes)
        || !bytes.is_multiple_of(4096)
    {
        return Err(invalid(
            "ext4 image paths or geometry are outside the builder envelope",
        ));
    }
    validate_archive(tar, bytes)?;
    let identity = executor.identity()?;
    let builder =
        sandsurf_format::identity_digest(&(BUILDER_ID, &identity)).map_err(io::Error::other)?;
    let file = sandsurf_native::local::create_private_file(output)?;
    file.set_len(bytes)?;
    file.sync_all()?;
    drop(file);
    let mut appliance = executor.open(output, true, custody)?;
    appliance.run(DiskOperation::MakeExt4)?;
    appliance.run(DiskOperation::Mount { writable: true })?;
    appliance.import_tar(tar, DiskCompression::None)?;
    appliance.run(DiskOperation::Sync)?;
    appliance.run(DiskOperation::Unmount)?;
    appliance.run(DiskOperation::CheckExt4)?;
    appliance.finish()?;
    File::open(output)?.sync_all()?;
    Ok(builder)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn validate_archive(path: &Path, disk_bytes: u64) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_IMAGE_BYTES
    {
        return Err(invalid(
            "ext4 source must be a bounded regular canonical tar",
        ));
    }
    let mut archive = sandsurf_format::archive::CanonicalArchive::new(
        File::open(path)?,
        sandsurf_format::archive::Limits {
            headers: 100_000,
            bytes: MAX_IMAGE_BYTES,
            file_bytes: disk_bytes,
            path_bytes: 4096,
        },
        disk_bytes,
    );
    while archive.next_entry()?.is_some() {}
    Ok(())
}
