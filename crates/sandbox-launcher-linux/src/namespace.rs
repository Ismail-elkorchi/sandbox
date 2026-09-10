use super::*;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

const RUNTIME_PATH: &str = "/.sandbox-launcher";

/// Retain the host-authorized namespace launcher through policy approval and execution.
#[derive(Debug)]
pub struct NamespaceLauncher {
    pub file: File,
    pub identity: FileIdentity,
    pub content_sha256: String,
}

impl NamespaceLauncher {
    pub fn open() -> io::Result<Self> {
        let path = fs::canonicalize("/usr/bin/bwrap")?;
        for ancestor in path.ancestors() {
            let metadata = fs::metadata(ancestor)?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "namespace launcher and its parent directories must be owned by root and not writable by other users",
                ));
            }
        }
        let file = File::open(path)?;
        let identity = file_identity(file.as_raw_fd())?;
        let content_sha256 = sha256_file(&file)?;
        Ok(Self {
            file,
            identity,
            content_sha256,
        })
    }

    pub fn retain(&self) -> io::Result<File> {
        if file_identity(self.file.as_raw_fd())? != self.identity
            || sha256_file(&self.file)? != self.content_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "namespace launcher changed after preparation",
            ));
        }
        self.file.try_clone()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Handoff {
    spec: LaunchSpec,
    descriptors: Vec<RawFd>,
    parent_process: RawFd,
}

/// The namespace helper preserves unconsumed descriptors across exec. Mount input
/// descriptors are separate from the authority retained by the isolated supervisor.
pub(super) fn launch(spec: &LaunchSpec, files: &[File]) -> io::Result<i32> {
    let mut command = namespace_command(
        &files[spec.launcher_fd_index],
        spec.network_mode != "unrestricted",
    );
    let mut inputs = vec![File::open(std::env::current_exe()?)?];
    data_mount(&mut command, &inputs[0], RUNTIME_PATH, "0500");
    if spec.network_mode == "managed" {
        // This sysctl belongs to the newly created network namespace. Its unprivileged
        // supervisor must bind DNS after the helper drops every capability.
        let ports = sealed_data(b"0\n")?;
        command
            .arg("--file")
            .arg(ports.as_raw_fd().to_string())
            .arg("/proc/sys/net/ipv4/ip_unprivileged_port_start");
        inputs.push(ports);
    }
    command.args(["--remount-ro", "/proc"]);
    let mut mounts: Vec<_> = spec.mounts.iter().collect();
    mounts.sort_by_key(|mount| component_count(&mount.target_path));
    for mount in mounts {
        let source = &files[mount.fd_index];
        command.arg(if mount.target_path.starts_with("/dev/") {
            "--dev-bind"
        } else if mount.read_only {
            "--ro-bind"
        } else {
            "--bind"
        });
        command.arg(descriptor_path(source)).arg(&mount.target_path);
    }
    let mut snapshot = files[spec.executable_fd_index].try_clone()?;
    snapshot.seek(SeekFrom::Start(0))?;
    data_mount(
        &mut command,
        &snapshot,
        &spec.executable_snapshot_path,
        "0500",
    );
    inputs.push(snapshot);

    for directory in spec.private_home.iter().chain(spec.temporary.iter()) {
        command.args([
            "--perms",
            if spec
                .private_home
                .as_ref()
                .is_some_and(|home| home.target_path == directory.target_path)
            {
                "0700"
            } else {
                "1777"
            },
        ]);
        command
            .arg("--size")
            .arg(directory.size_bytes.to_string())
            .arg("--tmpfs")
            .arg(&directory.target_path);
    }
    for mask in &spec.masks {
        let mapping = spec
            .mounts
            .iter()
            .filter(|mount| contains(&mount.target_path, &mask.target_path))
            .max_by_key(|mount| mount.target_path.len())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mask must name an admitted resource",
                )
            })?;
        let relative = mask
            .target_path
            .strip_prefix(&mapping.target_path)
            .unwrap_or("")
            .trim_start_matches('/');
        let target = mask_target(&files[mapping.fd_index], relative)?;
        let kind = file_identity(target.as_raw_fd())?.mode & libc::S_IFMT;
        if kind == libc::S_IFDIR && mask.replacement != "empty-file" {
            command
                .args([
                    "--perms",
                    if mask.replacement == "inaccessible" {
                        "0000"
                    } else {
                        "0755"
                    },
                    "--size",
                    "4096",
                    "--tmpfs",
                ])
                .arg(&mask.target_path)
                .arg("--remount-ro")
                .arg(&mask.target_path);
        } else if kind == libc::S_IFREG && mask.replacement != "empty-directory" {
            let empty = sealed_data(&[])?;
            data_mount(
                &mut command,
                &empty,
                &mask.target_path,
                if mask.replacement == "inaccessible" {
                    "0000"
                } else {
                    "0444"
                },
            );
            inputs.push(empty);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mask replacement type conflicts with target",
            ));
        }
    }
    let resolver = match spec.network_mode.as_str() {
        "managed" => "nameserver 127.0.0.1\noptions timeout:1 attempts:2\n".to_owned(),
        "unrestricted" => fs::read_to_string("/etc/resolv.conf")?,
        _ => String::new(),
    };
    for (path, content) in [
        (
            "/etc/passwd",
            "sandbox:x:0:0:Sandbox:/home/sandbox:/bin/sh\n",
        ),
        ("/etc/group", "sandbox:x:0:\n"),
        ("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n"),
        ("/etc/resolv.conf", resolver.as_str()),
    ] {
        let file = sealed_data(content.as_bytes())?;
        data_mount(&mut command, &file, path, "0444");
        inputs.push(file);
    }
    let parent = open_pidfd(std::process::id())?;
    let handoff = sealed_data(
        &serde_json::to_vec(&Handoff {
            spec: spec.clone(),
            descriptors: files.iter().map(AsRawFd::as_raw_fd).collect(),
            parent_process: parent.as_raw_fd(),
        })
        .map_err(invalid_data)?,
    )?;
    command
        .args(["--remount-ro", "/", "--", RUNTIME_PATH, "--linux-isolated"])
        .arg(handoff.as_raw_fd().to_string());
    for file in files.iter().chain(inputs.iter()).chain([&handoff, &parent]) {
        inherit(file)?;
    }
    Err(command.exec())
}

pub fn isolated_main(descriptor: Option<OsString>) -> i32 {
    // SAFETY: isolated mode exclusively owns the inherited private control socket as fd 0.
    let mut control = unsafe { UnixStream::from_raw_fd(0) };
    let result = (|| -> io::Result<i32> {
        // SAFETY: getpid takes no arguments. PID 1 is required before using namespace-wide cleanup.
        if unsafe { libc::getpid() } != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "isolated supervisor must be PID 1",
            ));
        }
        let fd = descriptor
            .and_then(|value| value.into_string().ok())
            .and_then(|value| value.parse::<RawFd>().ok())
            .filter(|fd| *fd >= 3)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid handoff descriptor")
            })?;
        // SAFETY: the launcher transfers ownership of this inherited handoff descriptor exactly once.
        let input = unsafe { File::from_raw_fd(fd) };
        let handoff: Handoff = serde_json::from_reader(input.take(MAX_INTERNAL_MESSAGE as u64))
            .map_err(invalid_data)?;
        if handoff.parent_process < 3 || handoff.parent_process == fd {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid parent process descriptor",
            ));
        }
        let mut distinct = BTreeSet::new();
        distinct.insert(handoff.parent_process);
        if handoff
            .descriptors
            .iter()
            .any(|value| *value < 3 || *value == fd || !distinct.insert(*value))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid authority descriptor set",
            ));
        }
        let files: Vec<_> = handoff
            .descriptors
            .into_iter()
            .map(|fd| {
                // SAFETY: each unique descriptor is transferred from the launcher to one owning File.
                unsafe { File::from_raw_fd(fd) }
            })
            .collect();
        // SAFETY: PR_SET_DUMPABLE takes scalar arguments. The supervisor retains host
        // authority during setup, so targets must not inspect its memory or /proc fds.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the handoff transfers this distinct pidfd exactly once.
        let parent = unsafe { File::from_raw_fd(handoff.parent_process) };
        // SAFETY: install the signal before checking the retained parent identity,
        // closing the setup race where the helper died before configuring PDEATHSIG.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut status = libc::pollfd {
            fd: parent.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: status is one initialized writable pollfd and a zero timeout never blocks.
        let polled = unsafe { libc::poll(&mut status, 1, 0) };
        if polled < 0 {
            return Err(io::Error::last_os_error());
        }
        if polled != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "namespace launcher exited during setup",
            ));
        }
        drop(parent);
        validate_spec(&handoff.spec, files.len())?;
        for mount in &handoff.spec.mounts {
            if handoff
                .spec
                .masks
                .iter()
                .any(|mask| contains(&mask.target_path, &mount.target_path))
            {
                continue;
            }
            let mounted = open_path(
                Path::new(&mount.target_path),
                libc::O_PATH | libc::O_CLOEXEC,
            )?;
            if file_identity(mounted.as_raw_fd())?
                != file_identity(files[mount.fd_index].as_raw_fd())?
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "mounted resource identity differs from prepared authority",
                ));
            }
        }
        namespace_init(&mut control, &handoff.spec, files)
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            let failure = LauncherSetupError {
                code: "setup.namespace".into(),
                message: bounded_error(&error),
            };
            if let Ok(payload) = serde_json::to_vec(&failure) {
                let _ = write_internal(&mut control, INTERNAL_SETUP_ERROR, &payload);
            }
            125
        }
    }
}

fn namespace_command(launcher: &File, network: bool) -> Command {
    let mut command = Command::new(descriptor_path(launcher));
    command.env_clear().args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--as-pid-1",
        "--die-with-parent",
        "--uid",
        "0",
        "--gid",
        "0",
        "--hostname",
        "sandbox",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--chdir",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
    ]);
    if network {
        command.arg("--unshare-net");
    }
    command
}

pub(super) fn probe(network: bool) -> ProbeOutcome {
    let result = (|| -> io::Result<()> {
        let launcher = NamespaceLauncher::open()?;
        let runtime = File::open(std::env::current_exe()?)?;
        let mut command = namespace_command(&launcher.file, network);
        data_mount(&mut command, &runtime, RUNTIME_PATH, "0500");
        command.args(["--", RUNTIME_PATH, "--linux-namespace-probe"]);
        inherit(&launcher.file)?;
        inherit(&runtime)?;
        let output = command.output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        }
    })();
    probe_outcome(
        if network {
            "bubblewrap isolated network and process boundary"
        } else {
            "bubblewrap isolated filesystem and process boundary"
        },
        result,
    )
}

pub fn namespace_probe_main() -> i32 {
    // SAFETY: getpid takes no arguments and is checked before using PID-namespace-specific behavior.
    if unsafe { libc::getpid() } == 1
        && fs::read_to_string("/proc/sys/kernel/hostname")
            .is_ok_and(|value| value.trim() == "sandbox")
    {
        0
    } else {
        1
    }
}

fn descriptor_path(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

fn mask_target(root: &File, relative: &str) -> io::Result<File> {
    let mut target = root.try_clone()?;
    for component in relative.split('/').filter(|part| !part.is_empty()) {
        let component = CString::new(component).map_err(invalid_data)?;
        // SAFETY: target is a retained directory descriptor and component is one
        // NUL-terminated path component; O_NOFOLLOW binds the named object itself.
        let fd = unsafe {
            libc::openat(
                target.as_raw_fd(),
                component.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor whose ownership transfers once to File.
        target = unsafe { File::from_raw_fd(fd) };
        if file_identity(target.as_raw_fd())?.mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mask paths cannot traverse symbolic links",
            ));
        }
    }
    Ok(target)
}

fn inherit(file: &File) -> io::Result<()> {
    // SAFETY: this single-threaded launcher owns the descriptor and intentionally transfers it across exec.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn data_mount(command: &mut Command, file: &File, target: &str, mode: &str) {
    command
        .args(["--perms", mode, "--ro-bind-data"])
        .arg(file.as_raw_fd().to_string())
        .arg(target);
}

fn sealed_data(bytes: &[u8]) -> io::Result<File> {
    // SAFETY: memfd_create receives a static NUL-terminated name and supported flag bits.
    let fd = unsafe {
        libc::memfd_create(
            c"sandbox-namespace".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new descriptor whose ownership transfers once to File.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(SeekFrom::Start(0))?;
    // SAFETY: F_ADD_SEALS applies monotonically restrictive seals to this owned memfd.
    if unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn contains(parent: &str, child: &str) -> bool {
    parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
