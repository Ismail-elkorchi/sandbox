//! Publication of host-owned storage objects. Publication never overwrites an
//! existing object; callers retain their operation intent until it completes.

#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

pub fn publish_new_file(staged: &Path, destination: &Path) -> io::Result<()> {
    if !staged.is_absolute()
        || !destination.is_absolute()
        || staged.parent() != destination.parent()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage publication requires absolute paths in one directory",
        ));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(staged)?
        .sync_all()?;
    publish(staged, destination)
}

#[cfg(unix)]
fn publish(staged: &Path, destination: &Path) -> io::Result<()> {
    // A hard link is a no-replace publication on the same filesystem. If the
    // owner dies after publication, the destination is already complete and
    // the remaining staging name is safe to reclaim during recovery.
    std::fs::hard_link(staged, destination)?;
    let parent = File::open(destination.parent().expect("validated parent"))?;
    parent.sync_all()?;
    std::fs::remove_file(staged)?;
    parent.sync_all()
}

#[cfg(windows)]
fn publish(staged: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        value.push(0);
        Ok(value)
    }
    let source = wide(staged)?;
    let target = wide(destination)?;
    // SAFETY: both paths are terminated and remain live for the synchronous
    // call. Omitting REPLACE_EXISTING and COPY_ALLOWED prevents overwrite and
    // cross-volume copy. WRITE_THROUGH waits for native disk publication.
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
