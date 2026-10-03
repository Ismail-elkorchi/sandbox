//! Bootstrap-only producer for the reviewed execution image. This module is
//! compiled into the image-assembly example, never the installed host runtime.
//! It needs no preexisting Sandsurf image and has no production fallback role.
use sandsurf_image::appliance::Filesystem;
use sandsurf_protocol::disk::{DiskOperation, DiskReply};
use std::io::{self, Read};
use std::path::Path;

pub struct Producer<'a> {
    pub disk: &'a Path,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn host_path(path: &Path) -> io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("producer path is not UTF-8"))?;
    if !path.is_absolute() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(invalid("producer requires bounded absolute host paths"));
    }
    Ok(value.into())
}

pub fn invoke(disk: &Path, writable: bool, commands: &[Vec<String>]) -> io::Result<Vec<u8>> {
    if commands.is_empty()
        || commands.len() > 64
        || commands.iter().any(|args| {
            args.is_empty()
                || args.len() > 16
                || args
                    .iter()
                    .any(|arg| arg.len() > 8192 || arg.contains('\0') || arg == ":")
        })
    {
        return Err(invalid("invalid compiled producer command"));
    }
    use std::process::{Command, Stdio};
    let scratch = disk
        .parent()
        .ok_or_else(|| invalid("appliance disk has no storage owner"))?
        .join(".appliance");
    sandsurf_native::local::ensure_private_directory(&scratch)?;
    // QEMU overlays, appliance cache and temporary files stay on the same
    // physical boundary as the owned disk, never the system RAM tmpdir.
    sandsurf_native::capacity::require_persistent_storage(&scratch)?;
    let disk = host_path(disk)?;
    let held_disk = sandsurf_native::local::open_private_file(
        Path::new(&disk),
        if writable {
            sandsurf_native::PrivateFileAccess::ReadWrite
        } else {
            sandsurf_native::PrivateFileAccess::ReadOnly
        },
    )?;
    if held_disk.metadata()?.len() == 0 || held_disk.metadata()?.len() > 128 * 1024 * 1024 * 1024 {
        return Err(invalid("appliance disk exceeds bound"));
    }
    let guestfish = sandsurf_native::filesystem::protected_tool(&["/usr/bin/guestfish"])?;
    let timeout =
        sandsurf_native::filesystem::protected_tool(&["/usr/bin/timeout", "/bin/timeout"])?;
    // Verify the executable selected by the library too; environment
    // overrides for appliances, QEMU wrappers, credentials and tracing are
    // removed. The distribution's protected appliance is the trusted TCB.
    let qemu = sandsurf_native::filesystem::protected_tool(if cfg!(target_arch = "aarch64") {
        &["/usr/bin/qemu-system-aarch64"]
    } else {
        &["/usr/bin/qemu-system-x86_64"]
    })?;
    let mut command = Command::new(timeout);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LIBGUESTFS_BACKEND", "direct")
        .env("LIBGUESTFS_BACKEND_SETTINGS", "force_kvm")
        .env("LIBGUESTFS_HV", qemu)
        .env("LIBGUESTFS_MEMSIZE", "512")
        .env("TMPDIR", &scratch)
        .env("LIBGUESTFS_TMPDIR", &scratch)
        .env("LIBGUESTFS_CACHEDIR", &scratch)
        .args([
            "--signal=KILL",
            "300",
            guestfish.to_str().ok_or_else(|| invalid("tool path"))?,
            "--no-progress-bars",
            "--format=raw",
        ]);
    if !writable {
        command.arg("--ro");
    }
    command.args([
        "-a",
        &disk,
        "set-pgroup",
        "false",
        ":",
        "set-network",
        "false",
        ":",
        "run",
    ]);
    for arguments in commands {
        command.arg(":").args(arguments);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("appliance output missing"))?;
    let mut bytes = Vec::new();
    let capture = stdout
        .by_ref()
        .take(16385)
        .read_to_end(&mut bytes)
        .and_then(|_| io::copy(&mut stdout, &mut io::sink()).map(|_| ()));
    // Drain without allocating; timeout kills the entire process group,
    // including QEMU, even for a wedged filesystem or hostile program.
    drop(stdout);
    let status = child.wait()?;
    capture?;
    if !status.success() || bytes.len() > 16384 {
        return Err(invalid(
            "isolated appliance failed, timed out, or exceeded output bound",
        ));
    }
    Ok(bytes)
}

impl Filesystem for Producer<'_> {
    fn run(&mut self, operation: DiskOperation) -> io::Result<DiskReply> {
        operation.validate(false)?;
        let DiskOperation::Realpath { path } = &operation else {
            return Err(invalid("producer only supports boot-path observations"));
        };
        let bytes = invoke(
            self.disk,
            false,
            &[
                vec![
                    "mount-options".into(),
                    "ro,noload".into(),
                    "/dev/sda".into(),
                    "/".into(),
                ],
                vec!["realpath".into(), path.clone()],
            ],
        )?;
        let value =
            String::from_utf8(bytes).map_err(|_| invalid("producer observation is not UTF-8"))?;
        let reply = DiskReply::Text {
            value: value.trim_end_matches('\n').into(),
        };
        reply.validate_for(&operation)?;
        Ok(reply)
    }
    fn download(&mut self, guest: &str, output: &Path, maximum: u64) -> io::Result<()> {
        DiskOperation::FileSize { path: guest.into() }.validate(false)?;
        let mount = vec![
            "mount-options".into(),
            "ro,noload".into(),
            "/dev/sda".into(),
            "/".into(),
        ];
        let bytes = invoke(
            self.disk,
            false,
            &[mount.clone(), vec!["filesize".into(), guest.into()]],
        )?;
        let size: u64 = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("producer size encoding"))?
            .trim()
            .parse()
            .map_err(|_| invalid("producer size encoding"))?;
        if size == 0 || size > maximum {
            return Err(invalid("producer artifact exceeds its bound"));
        }
        let name = host_path(output)?;
        // Drain this creator before libguestfs opens the destination on Windows;
        // the producer itself is Linux-only and never enters installed hosts.
        drop(sandsurf_native::local::create_private_file(output)?);
        invoke(
            self.disk,
            false,
            &[
                mount,
                vec![
                    "download-offset".into(),
                    guest.into(),
                    name,
                    "0".into(),
                    size.to_string(),
                ],
            ],
        )?;
        let file = sandsurf_native::local::open_private_file(
            output,
            sandsurf_native::PrivateFileAccess::ReadOnly,
        )?;
        if file.metadata()?.len() != size {
            return Err(invalid("incomplete producer artifact"));
        }
        sandsurf_native::storage::sync_file(&file)
    }
}
