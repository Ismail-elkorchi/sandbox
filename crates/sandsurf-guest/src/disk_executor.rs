//! PID-1 filesystem worker in the reviewed offline boot image. All parsing,
//! mounts and distribution programs run behind the hardware boundary. The
//! native host still treats every returned byte as bounded guest information.
use sandsurf_protocol::disk::{
    DiskChannel, DiskCompression, DiskOperation, DiskReply, MAX_DISK_OPERATIONS, MAX_DISK_TRANSFER,
};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

const TARGET: &str = "/run/target";
const DEVICE: &str = "/dev/vdb";
// Linux UAPI linux/fs.h, for the supported 64-bit x86/ARM guest ABIs.
// libc's ioctl builders preserve its actual musl/glibc request-argument ABI.

pub fn prepare() -> io::Result<bool> {
    if std::process::id() != 1 {
        return Err(invalid("offline worker must be guest PID 1"));
    }
    tool(
        "/bin/mount",
        &["-t", "tmpfs", "-o", "size=32m,mode=0700", "tmpfs", "/run"],
    )?;
    fs::create_dir(TARGET)?;
    let target = File::open(DEVICE)?;
    let mut read_only = 0_i32;
    // SAFETY: live block-device descriptor and writable BLKROGET scalar output.
    if unsafe { libc::ioctl(target.as_raw_fd(), libc::_IO(0x12, 94), &mut read_only) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut size = 0_u64;
    // SAFETY: live block-device descriptor and exact BLKGETSIZE64 output storage.
    if unsafe { libc::ioctl(target.as_raw_fd(), libc::_IOR::<u64>(0x12, 114), &mut size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if size == 0 || size > 128 * 1024 * 1024 * 1024 || !(0..=1).contains(&read_only) {
        return Err(invalid("invalid offline block device"));
    }
    Ok(read_only == 0)
}

pub fn serve(file: File, writable: bool) -> io::Result<()> {
    let native_fd = file.as_raw_fd();
    let mut channel = DiskChannel::new(file);
    let mut mounted = false;
    for _ in 0..MAX_DISK_OPERATIONS {
        let operation: DiskOperation = channel.metadata()?;
        operation.validate(writable)?;
        let result = (|| match &operation {
            DiskOperation::Mount { writable } if !mounted => {
                tool(
                    "/bin/mount",
                    &[
                        "-t",
                        "ext4",
                        "-o",
                        if *writable { "rw" } else { "ro,noload" },
                        DEVICE,
                        TARGET,
                    ],
                )?;
                mounted = true;
                channel.send_metadata(&DiskReply::Complete)
            }
            DiskOperation::MakeExt4 if !mounted => {
                tool("/sbin/mkfs.ext4", &["-F", "-m", "0", DEVICE])?;
                channel.send_metadata(&DiskReply::Complete)
            }
            DiskOperation::Unmount if mounted => {
                tool("/bin/umount", &[TARGET])?;
                mounted = false;
                channel.send_metadata(&DiskReply::Complete)
            }
            DiskOperation::CheckExt4 if !mounted => {
                tool("/sbin/e2fsck", &["-f", "-n", DEVICE])?;
                channel.send_metadata(&DiskReply::Complete)
            }
            DiskOperation::Sync => {
                tool("/bin/sync", &[])?;
                channel.send_metadata(&DiskReply::Complete)
            }
            _ if mounted => rooted_operation(&mut channel, native_fd, &operation),
            _ => Err(invalid("invalid offline mount transition")),
        })();
        if let Err(error) = result {
            let message = error.to_string().chars().take(1024).collect();
            let _ = channel.send_metadata(&DiskReply::Failed { message });
            return Err(error);
        }
    }
    Err(invalid("offline operation count exhausted"))
}

/// Metadata paths have ordinary absolute Linux symlink semantics inside the
/// target root. No lexical prefix or host filesystem parser emulates chroot.
fn rooted_operation(
    channel: &mut DiskChannel<File>,
    native_fd: i32,
    operation: &DiskOperation,
) -> io::Result<()> {
    let (parent, child) = UnixStream::pair()?;
    // SAFETY: PID 1's request loop is single-threaded. The child has a closed
    // rooted job and terminates with _exit, never running parent destructors.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(parent);
        // SAFETY: this child drops its inherited original device connection;
        // the parent's file stays live. _exit avoids a second Rust close.
        unsafe { libc::close(native_fd) };
        let mut local = DiskChannel::new(child);
        let result = (|| {
            // SAFETY: only this single-threaded child changes mount namespace.
            if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: constant live C strings; recursively private propagation
            // prevents a distribution command changing the PID-1 mount view.
            if unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the target is the sole explicitly attached disk mount.
            if unsafe { libc::chroot(c"/run/target".as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            std::env::set_current_dir("/")?;
            execute_rooted(operation, &mut local)
        })();
        if let Err(error) = &result {
            let _ = local.send_metadata(&DiskReply::Failed {
                message: error.to_string().chars().take(1024).collect(),
            });
        }
        // SAFETY: the post-fork child exclusively owns this bounded job; never
        // unwind the PID-1 transport or mount-state stack in the child.
        unsafe { libc::_exit(i32::from(result.is_err())) };
    }
    drop(child);
    let mut local = DiskChannel::new(parent);
    let result = (|| {
        if let DiskOperation::ImportTar { bytes, .. } = operation {
            local.send_data(&mut channel.data_reader(*bytes)?, *bytes)?;
        }
        let reply: DiskReply = local.metadata()?;
        reply.validate_for(operation)?;
        if let DiskReply::Failed { message } = &reply {
            return Err(io::Error::other(message.clone()));
        }
        channel.send_metadata(&reply)?;
        if let DiskOperation::Download { bytes, .. } = operation {
            if reply != (DiskReply::Size { bytes: *bytes }) {
                return Err(invalid("offline download credit changed"));
            }
            channel.send_data(&mut local.data_reader(*bytes)?, *bytes)?;
        }
        Ok(())
    })();
    drop(local);
    let mut status = 0;
    // SAFETY: pid is the exact child created above; status is writable output.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
    result?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(invalid("offline rooted worker failed"));
    }
    Ok(())
}

fn execute_rooted(
    operation: &DiskOperation,
    channel: &mut DiskChannel<UnixStream>,
) -> io::Result<()> {
    let reply = match operation {
        DiskOperation::ImportTar { bytes, compression } => {
            let input = channel.data_reader(*bytes)?;
            match compression {
                DiskCompression::None => extract(input)?,
                DiskCompression::Gzip => {
                    let mut decoder =
                        flate2::bufread::GzDecoder::new(BufReader::with_capacity(65536, input));
                    extract(&mut decoder)?;
                    if decoder.into_inner().read(&mut [0])? != 0 {
                        return Err(invalid("trailing compressed archive"));
                    }
                }
            }
            DiskReply::Complete
        }
        DiskOperation::Execute { argv } => {
            tool(
                &argv[0],
                &argv[1..].iter().map(String::as_str).collect::<Vec<_>>(),
            )?;
            DiskReply::Complete
        }
        DiskOperation::Remove { path } => {
            match fs::remove_file(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                result => result?,
            };
            DiskReply::Complete
        }
        DiskOperation::Write { path, bytes } => {
            let mut file = File::create(path)?;
            file.write_all(bytes.as_bytes())?;
            file.sync_all()?;
            DiskReply::Complete
        }
        DiskOperation::Chmod { path, mode } => {
            fs::set_permissions(path, fs::Permissions::from_mode(*mode))?;
            DiskReply::Complete
        }
        DiskOperation::Mkdir { path } => {
            fs::create_dir_all(path)?;
            DiskReply::Complete
        }
        DiskOperation::ZeroFreeSpace => {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open("/sandsurf-zero")?;
            let buffer = [0; 65536];
            loop {
                match file.write_all(&buffer) {
                    Ok(()) => {}
                    Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => break,
                    Err(error) => return Err(error),
                }
            }
            file.sync_all()?;
            drop(file);
            fs::remove_file("/sandsurf-zero")?;
            DiskReply::Complete
        }
        DiskOperation::Realpath { path } => DiskReply::Text {
            value: fs::canonicalize(path)?
                .into_os_string()
                .into_string()
                .map_err(|_| invalid("resolved guest path is not UTF-8"))?,
        },
        DiskOperation::FileSize { path } => DiskReply::Size {
            bytes: fs::metadata(path)?.len(),
        },
        DiskOperation::Download {
            path,
            offset,
            bytes,
        } => {
            let mut file = File::open(path)?;
            if !file.metadata()?.is_file()
                || offset
                    .checked_add(*bytes)
                    .is_none_or(|end| end > file.metadata().map(|m| m.len()).unwrap_or(0))
            {
                return Err(invalid("invalid guest download range"));
            }
            file.seek(SeekFrom::Start(*offset))?;
            channel.send_metadata(&DiskReply::Size { bytes: *bytes })?;
            return channel.send_data(&mut file, *bytes);
        }
        DiskOperation::Cat { path } => {
            let mut bytes = Vec::new();
            File::open(path)?.take(16385).read_to_end(&mut bytes)?;
            if bytes.len() > 16384 {
                return Err(invalid("guest text exceeds bound"));
            }
            DiskReply::Text {
                value: String::from_utf8(bytes).map_err(|_| invalid("guest text is not UTF-8"))?,
            }
        }
        DiskOperation::Stat { path } => {
            let stat = fs::symlink_metadata(path)?;
            DiskReply::Stat {
                uid: stat.uid(),
                gid: stat.gid(),
                mode: stat.mode(),
                bytes: stat.len(),
            }
        }
        DiskOperation::Readlink { path } => DiskReply::Text {
            value: fs::read_link(path)?
                .into_os_string()
                .into_string()
                .map_err(|_| invalid("guest link is not UTF-8"))?,
        },
        DiskOperation::Exists { path } => DiskReply::Exists {
            value: match fs::symlink_metadata(path) {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            },
        },
        _ => return Err(invalid("operation is not a rooted disk operation")),
    };
    channel.send_metadata(&reply)
}

fn extract(input: impl Read) -> io::Result<()> {
    use sandsurf_format::archive::{Archive, Limits};
    use std::collections::BTreeMap;
    use std::path::Component;
    let mut archive = Archive::new(
        input,
        Limits {
            headers: 100000,
            bytes: MAX_DISK_TRANSFER,
            file_bytes: MAX_DISK_TRANSFER,
            path_bytes: 4096,
        },
    );
    let mut entries = BTreeMap::new();
    let mut directory_times = BTreeMap::new();
    while let Some(mut entry) = archive.next_entry()? {
        let path = entry.path().to_owned();
        let kind = entry.header().entry_type();
        let mtime = i64::try_from(entry.header().mtime()?)
            .map_err(|_| invalid("archive timestamp exceeds the guest time ABI"))?;
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            || entries.contains_key(&path)
            || entries.len() >= 100000
            || !(kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link())
            || entry.header().mode()? > 0o7777
            || entry.header().uid()? > u32::MAX as u64
            || entry.header().gid()? > u32::MAX as u64
        {
            return Err(invalid("unsupported canonical filesystem archive member"));
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|path| !path.as_os_str().is_empty())
        {
            if entries.get(parent).is_none_or(|kind: &u8| *kind != b'5') {
                return Err(invalid("archive parent is not a preceding directory"));
            }
        }
        if kind.is_dir() {
            fs::create_dir_all(&path)?;
        } else if kind.is_file() {
            let mut file = File::create(&path)?;
            if io::copy(&mut entry, &mut file)? != entry.size() {
                return Err(invalid("truncated archive member"));
            }
        } else {
            let target = entry
                .link_name()
                .ok_or_else(|| invalid("archive link has no target"))?;
            if kind.is_symlink() {
                std::os::unix::fs::symlink(target, &path)?;
            } else {
                if target
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
                    || !entries
                        .get(target)
                        .is_some_and(|kind| *kind == b'0' || *kind == b'1')
                {
                    return Err(invalid("archive hardlink is not a preceding file"));
                }
                fs::hard_link(target, &path)?;
            }
        }
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| invalid("archive path has NUL"))?;
        // SAFETY: bounded validated path and representable guest UID/GID;
        // lchown preserves link identity, never following its final target.
        if unsafe {
            libc::lchown(
                name.as_ptr(),
                entry.header().uid()? as u32,
                entry.header().gid()? as u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if !kind.is_symlink() {
            fs::set_permissions(&path, fs::Permissions::from_mode(entry.header().mode()?))?;
        }
        if kind.is_dir() {
            directory_times.insert(path.clone(), mtime);
        } else {
            set_mtime(&path, mtime)?;
        }
        // GNU regular entries can use either NUL or '0'; they are one kind.
        entries.insert(path, if kind.is_file() { b'0' } else { kind.as_byte() });
    }
    // Creating children updates directory mtimes. Restore them leaf-first only
    // after the complete bounded archive has been consumed successfully.
    for (path, mtime) in directory_times.iter().rev() {
        set_mtime(path, *mtime)?;
    }
    Ok(())
}

fn set_mtime(path: &std::path::Path, seconds: i64) -> io::Result<()> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| invalid("archive path has NUL"))?;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    ];
    // SAFETY: exact two-element timespec storage and validated live C path.
    // Final symlinks have their own timestamp, not their target's timestamp.
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn tool(program: &str, arguments: &[&str]) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| invalid("disk tool has no output pipe"))?;
    let bytes = io::copy(&mut output, &mut io::sink())?;
    if !child.wait()?.success() || bytes > 16384 {
        return Err(invalid("disk tool failed or exceeded output bound"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    #[test]
    fn archive_preserves_modes_links_times_and_never_follows_link_metadata() {
        // The real extractor uses relative guest paths after chroot. A separate
        // test process gets its own cwd; no parallel test sees a changed cwd.
        if let Some(root) = std::env::var_os("SANDSURF_DISK_ARCHIVE_TEST") {
            let root = std::path::PathBuf::from(root);
            std::env::set_current_dir(root.join("target")).unwrap();
            extract(File::open(root.join("input.tar")).unwrap()).unwrap();
            let file = fs::metadata("etc/file").unwrap();
            let hard = fs::metadata("etc/hard").unwrap();
            assert_eq!(file.ino(), hard.ino());
            assert_eq!(file.mode() & 0o7777, 0o4755);
            assert_eq!(file.mtime(), 42);
            assert_eq!(fs::metadata("etc").unwrap().mtime(), 42);
            assert_eq!(fs::symlink_metadata("etc/link").unwrap().mtime(), 42);
            assert_eq!(fs::metadata(root.join("outside")).unwrap().mtime(), 77);
            assert_eq!(fs::read("etc/file").unwrap(), b"payload");
            return;
        }
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "sandsurf-disk-{}",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("target"))
            .unwrap();
        let outside = root.join("outside");
        fs::write(&outside, b"not a guest file").unwrap();
        set_mtime(&outside, 77).unwrap();
        let owner = fs::metadata(&outside).unwrap();
        let header = |kind, size, mode| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_uid(u64::from(owner.uid()));
            header.set_gid(u64::from(owner.gid()));
            header.set_mode(mode);
            header.set_size(size);
            header.set_mtime(42);
            header.set_cksum();
            header
        };
        let mut archive = tar::Builder::new(File::create_new(root.join("input.tar")).unwrap());
        archive
            .append_data(
                &mut header(tar::EntryType::Directory, 0, 0o700),
                "etc",
                io::empty(),
            )
            .unwrap();
        archive
            .append_data(
                &mut header(tar::EntryType::new(0), 7, 0o4755),
                "etc/file",
                &b"payload"[..],
            )
            .unwrap();
        archive
            .append_link(
                &mut header(tar::EntryType::Link, 0, 0o4755),
                "etc/hard",
                "etc/file",
            )
            .unwrap();
        archive
            .append_link(
                &mut header(tar::EntryType::Symlink, 0, 0o777),
                "etc/link",
                &outside,
            )
            .unwrap();
        archive.finish().unwrap();
        drop(archive);
        let status = Command::new(std::env::current_exe().unwrap()).args(["--exact", "disk_executor::tests::archive_preserves_modes_links_times_and_never_follows_link_metadata", "--test-threads=1"]).env("SANDSURF_DISK_ARCHIVE_TEST", &root).status().unwrap();
        assert!(status.success());
        // Explicit own nonce directory only; no arbitrary guest link is walked.
        fs::remove_dir_all(root).unwrap();
    }
}
