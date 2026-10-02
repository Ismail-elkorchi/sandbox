//! The only executor for disk filesystems and distribution programs. libguestfs
//! runs them in a disposable QEMU appliance, never in the host kernel/chroot.
//! No inspection, auto format detection, shared directories, host shell, or
//! network is enabled. Inputs are explicit raw whole-device ext4 disks.
use std::io;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::path::Path;

mod operations;
pub use operations::{Compression, Operation, Reply, Stat};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn host_path(path: &Path) -> io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("appliance path is not UTF-8"))?;
    if !path.is_absolute() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(invalid("appliance requires bounded absolute host paths"));
    }
    Ok(value.to_owned())
}

/// Commands are argv tokens, separated with guestfish's ':' argument. Never
/// submit a guest-controlled guestfish script: '!', pipes and interpolation
/// are host execution facilities in its script language.
pub fn run(disk: &Path, writable: bool, operations: &[Operation]) -> io::Result<Reply> {
    if operations.is_empty() || operations.len() > 64 {
        return Err(invalid("invalid disk operation count"));
    }
    for (index, operation) in operations.iter().enumerate() {
        if operation.mutation() && !writable {
            return Err(invalid("mutation requested against a read-only disk"));
        }
        if operation.query()
            && (index + 1 != operations.len()
                || operations
                    .iter()
                    .any(|op| matches!(op, Operation::Execute { .. })))
        {
            return Err(invalid(
                "only the final disk operation may return an observation",
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (disk, writable, operations);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "isolated disk/build appliance requires a Linux libguestfs host",
        ))
    }
    #[cfg(target_os = "linux")]
    {
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
        if held_disk.metadata()?.len() == 0
            || held_disk.metadata()?.len() > 128 * 1024 * 1024 * 1024
        {
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
        for operation in operations {
            command.arg(":").args(operation.arguments()?);
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
        operations
            .last()
            .expect("validated operation count")
            .reply(bytes)
    }
}

/// Copy exactly a bounded file from the appliance. Size and transfer both occur
/// against the same offline disk; the host never walks its filesystem.
pub fn download(disk: &Path, guest: &str, output: &Path, maximum: u64) -> io::Result<()> {
    let size = run(
        disk,
        false,
        &[
            Operation::Mount { writable: false },
            Operation::FileSize { path: guest.into() },
        ],
    )?
    .size()?;
    if size == 0 || size > maximum {
        return Err(invalid("guest artifact is empty or exceeds its bound"));
    }
    let output_name = host_path(output)?;
    let output = sandsurf_native::local::create_private_file(Path::new(&output_name))?;
    run(
        disk,
        false,
        &[
            Operation::Mount { writable: false },
            Operation::Download {
                path: guest.into(),
                destination: output_name.into(),
                offset: 0,
                bytes: size,
            },
        ],
    )?;
    sandsurf_native::storage::sync_file(&output)?;
    if output.metadata()?.len() != size {
        return Err(invalid("disk download did not cover the selected artifact"));
    }
    Ok(())
}
