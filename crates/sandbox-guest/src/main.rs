#![deny(unsafe_op_in_unsafe_fn)]

use sandbox_guest::{AUTHENTICATION_MAGIC, GUEST_CONTROL_PORT};
use sandsurf_protocol::{
    AUTHENTICATION_BYTES, BootCapability, Counter, Digest, Frame, FrameKind, GuestChallenge,
    GuestFinish, GuestHandshake, GuestHello, SandboxId,
};
use sandsurf_workload::{
    CgroupLimits, CgroupManager, FilesystemService, GuestServiceRequest, PersistentWorkloadService,
    ProcessSupervisor,
};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::ptr;

const MAX_AUTHENTICATION_DISK: u64 = 4096;
const WORKLOAD_ROOT: &str = "/sandsurf/workload";
const CONTROL_ROOT: &str = "/sandsurf/control";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/sandsurf-workload";

struct BootIdentity {
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_digest: Digest,
    capability: BootCapability,
}

fn main() {
    if let Err(error) = supervisor_main() {
        eprintln!(
            "sandsurf guest supervisor failure: {}",
            bounded(&error.to_string())
        );
        // SAFETY: sync has no pointer or ownership preconditions and preserves
        // the strongest available disk boundary before PID 1 exits.
        unsafe { libc::sync() };
        std::process::exit(1);
    }
}

fn supervisor_main() -> io::Result<()> {
    harden_supervisor()?;
    mount_control_filesystems()?;
    let identity = read_boot_identity()?;
    let listener = listen_vsock(GUEST_CONTROL_PORT)?;
    prepare_persistent_workload()?;
    establish_workload_namespaces()?;
    let _init = start_workload_init()?;

    let processes = create_process_supervisor(&identity)?;
    let filesystem =
        FilesystemService::open(Path::new(WORKLOAD_ROOT), "/").map_err(io::Error::other)?;
    let service = PersistentWorkloadService::new(processes, filesystem);

    loop {
        let Ok(connection) = accept_connection(listener.as_raw_fd()) else {
            continue;
        };
        // SAFETY: accept_connection returned one newly owned descriptor.
        let mut connection = unsafe { File::from_raw_fd(connection) };
        let _ = serve_connection(&mut connection, &identity, &service);
    }
}

fn create_process_supervisor(identity: &BootIdentity) -> io::Result<ProcessSupervisor> {
    let spool = Path::new(CONTROL_ROOT).join("processes");
    fs::create_dir_all(&spool)?;
    fs::create_dir_all(CGROUP_ROOT)?;
    let limits = CgroupLimits {
        memory_max: None,
        pids_max: Some(4096),
        cpu_max: None,
    };
    match CgroupManager::open(Path::new(CGROUP_ROOT)) {
        Ok(cgroups) => ProcessSupervisor::create_in_workload_with_cgroups(
            &spool,
            Path::new(WORKLOAD_ROOT),
            identity.sandbox_id.clone(),
            identity.epoch,
            cgroups,
            limits,
        ),
        Err(_) => ProcessSupervisor::create_in_workload(
            &spool,
            Path::new(WORKLOAD_ROOT),
            identity.sandbox_id.clone(),
            identity.epoch,
        ),
    }
    .map_err(io::Error::other)
}

fn serve_connection(
    connection: &mut File,
    identity: &BootIdentity,
    service: &PersistentWorkloadService,
) -> io::Result<()> {
    let (handshake, challenge) = accept_handshake(connection, identity)?;
    send_unauthed(connection, &challenge)?;
    let finish: GuestFinish = read_unauthed(connection)?;
    let mut codec = handshake
        .finish(&finish)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
    let mut outgoing = Counter::ZERO;

    loop {
        let Some(frame) = Frame::read(connection)? else {
            return Ok(());
        };
        let frame = codec
            .open(frame)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
        if frame.kind != FrameKind::Control || frame.stream != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest service accepts requests on the reserved control stream",
            ));
        }
        let request: GuestServiceRequest = serde_json::from_slice(&frame.payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let payload = serde_json::to_vec(&service.handle(request)).map_err(io::Error::other)?;
        if payload.len() > sandsurf_protocol::MAX_CONTROL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest response exceeds the control-frame bound",
            ));
        }
        outgoing = outgoing
            .next()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let response = codec
            .seal(Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: outgoing,
                authentication: [0; AUTHENTICATION_BYTES],
                payload,
            })
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        response.write(connection)?;
        connection.flush()?;
    }
}

fn accept_handshake(
    connection: &mut File,
    identity: &BootIdentity,
) -> io::Result<(GuestHandshake, GuestChallenge)> {
    let hello: GuestHello = read_unauthed(connection)?;
    GuestHandshake::accept(
        identity.capability.clone(),
        &identity.sandbox_id,
        identity.epoch,
        &identity.boot_digest,
        &hello,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))
}

fn read_unauthed<T: serde::de::DeserializeOwned>(connection: &mut File) -> io::Result<T> {
    let frame = Frame::read(connection)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "guest handshake ended"))?;
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence != Counter::ZERO
        || frame.authentication != [0; AUTHENTICATION_BYTES]
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid unauthenticated guest handshake frame",
        ));
    }
    serde_json::from_slice(&frame.payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn send_unauthed<T: serde::Serialize>(connection: &mut File, value: &T) -> io::Result<()> {
    let frame = Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ZERO,
        authentication: [0; AUTHENTICATION_BYTES],
        payload: serde_json::to_vec(value).map_err(io::Error::other)?,
    };
    frame.write(connection)?;
    connection.flush()
}

fn mount_control_filesystems() -> io::Result<()> {
    for directory in [
        "/dev",
        "/proc",
        "/run",
        "/tmp",
        "/sys/fs/cgroup",
        "/sandsurf",
        CONTROL_ROOT,
    ] {
        fs::create_dir_all(directory)?;
    }
    mount_if_absent(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("mode=0755"),
    )?;
    mount_if_absent(
        Some("proc"),
        "/proc",
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    mount_if_absent(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("size=32m,mode=0755"),
    )?;
    mount_if_absent(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=256m,mode=1777"),
    )?;
    mount_if_absent(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    let _ = fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+cpu +memory +pids +io\n",
    );
    Ok(())
}

fn prepare_persistent_workload() -> io::Result<()> {
    for directory in ["/sandsurf/state", "/sandsurf/lower", WORKLOAD_ROOT] {
        fs::create_dir_all(directory)?;
    }
    mount(
        Some("/dev/vdb"),
        "/sandsurf/state",
        Some("ext4"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("errors=remount-ro"),
    )?;
    let lower_device = if Path::new("/dev/vdd").exists() {
        "/dev/vdd"
    } else {
        "/dev/vda"
    };
    mount(
        Some(lower_device),
        "/sandsurf/lower",
        Some("ext4"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        Some("errors=remount-ro"),
    )?;
    fs::create_dir_all("/sandsurf/state/upper")?;
    fs::create_dir_all("/sandsurf/state/work")?;
    mount(
        Some("overlay"),
        WORKLOAD_ROOT,
        Some("overlay"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(
            "lowerdir=/sandsurf/lower,upperdir=/sandsurf/state/upper,workdir=/sandsurf/state/work",
        ),
    )?;
    for relative in [
        "dev",
        "dev/pts",
        "home/agent",
        "proc",
        "run",
        "tmp",
        "workspace",
    ] {
        fs::create_dir_all(Path::new(WORKLOAD_ROOT).join(relative))?;
    }
    mount(
        Some("tmpfs"),
        &format!("{WORKLOAD_ROOT}/dev"),
        Some("tmpfs"),
        libc::MS_NOSUID,
        Some("size=8m,mode=0755"),
    )?;
    fs::create_dir_all(format!("{WORKLOAD_ROOT}/dev/pts"))?;
    mount(
        Some("devpts"),
        &format!("{WORKLOAD_ROOT}/dev/pts"),
        Some("devpts"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )?;
    for name in ["null", "zero", "random", "urandom"] {
        bind_device(name)?;
    }
    let ptmx = Path::new(WORKLOAD_ROOT).join("dev/ptmx");
    if !ptmx.exists() {
        std::os::unix::fs::symlink("pts/ptmx", ptmx)?;
    }
    mount(
        Some("proc"),
        &format!("{WORKLOAD_ROOT}/proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("hidepid=2"),
    )?;
    for (relative, size, mode) in [("run", "32m", "0755"), ("tmp", "512m", "1777")] {
        mount(
            Some("tmpfs"),
            &format!("{WORKLOAD_ROOT}/{relative}"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some(&format!("size={size},mode={mode}")),
        )?;
    }
    fs::set_permissions(
        Path::new(WORKLOAD_ROOT).join("workspace"),
        fs::Permissions::from_mode(0o755),
    )?;
    Ok(())
}

fn bind_device(name: &str) -> io::Result<()> {
    let source = format!("/dev/{name}");
    let target = format!("{WORKLOAD_ROOT}/dev/{name}");
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&target)?;
    mount(Some(&source), &target, None, libc::MS_BIND, None)
}

fn establish_workload_namespaces() -> io::Result<()> {
    let flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWNET;
    // SAFETY: unshare receives a fixed namespace flag set and affects only this
    // dedicated guest supervisor.
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = fs::write("/proc/self/setgroups", "deny\n");
    fs::write("/proc/self/uid_map", "0 0 65536\n")?;
    fs::write("/proc/self/gid_map", "0 0 65536\n")?;
    let hostname = CString::new("sandsurf").expect("static hostname");
    // SAFETY: hostname points to initialized bytes for the supplied length.
    if unsafe { libc::sethostname(hostname.as_ptr().cast(), 8) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn start_workload_init() -> io::Result<libc::pid_t> {
    // SAFETY: fork is called before any workload service threads are started.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        close_inherited_descriptors();
        workload_init();
    }
    Ok(pid)
}

fn workload_init() -> ! {
    // SAFETY: fixed signal dispositions and waitpid arguments are valid.
    // SAFETY: SIGTERM/SIGINT and SIG_IGN are valid signal API constants.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
    loop {
        let mut status = 0_i32;
        // SAFETY: PID -1 selects any orphaned child in the workload namespace.
        let result = unsafe { libc::waitpid(-1, &mut status, 0) };
        if result < 0 {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}

fn close_inherited_descriptors() {
    // SAFETY: closing an unopened descriptor number is harmless.
    for fd in 3..1024 {
        unsafe { libc::close(fd) };
    }
}

fn read_boot_identity() -> io::Result<BootIdentity> {
    let mut file = File::open("/dev/vdc")?;
    if file.metadata()?.len() > MAX_AUTHENTICATION_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authentication disk exceeds bound",
        ));
    }
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != AUTHENTICATION_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authentication disk identity is invalid",
        ));
    }
    let mut size = [0_u8; 2];
    file.read_exact(&mut size)?;
    let size = usize::from(u16::from_be_bytes(size));
    if size == 0 || size > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox identity is invalid",
        ));
    }
    let mut sandbox = vec![0; size];
    file.read_exact(&mut sandbox)?;
    let sandbox_id = std::str::from_utf8(&sandbox)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sandbox identity is not UTF-8"))?
        .try_into()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut epoch = [0_u8; 8];
    file.read_exact(&mut epoch)?;
    let epoch = Counter::try_from(u64::from_be_bytes(epoch))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if epoch == Counter::ZERO {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "epoch is zero"));
    }
    let mut digest = [0_u8; 32];
    file.read_exact(&mut digest)?;
    let boot_digest = Digest::try_from(hex(&digest))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut capability = [0_u8; 32];
    file.read_exact(&mut capability)?;
    Ok(BootIdentity {
        sandbox_id,
        epoch,
        boot_digest,
        capability: BootCapability::from_bytes(capability),
    })
}

fn harden_supervisor() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE and fixed signal dispositions have no pointer
    // preconditions.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIGTERM/SIGINT and SIG_IGN are valid signal API constants.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
    Ok(())
}

fn listen_vsock(port: u32) -> io::Result<File> {
    // SAFETY: arguments request a standard close-on-exec AF_VSOCK stream.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zero is a valid initial representation for sockaddr_vm.
    let mut address: libc::sockaddr_vm = unsafe { zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_port = port;
    address.svm_cid = libc::VMADDR_CID_ANY;
    // SAFETY: address has the exact sockaddr_vm layout and lifetime.
    let result = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_vm).cast(),
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    // SAFETY: fd remains live and locally owned during setup.
    if result != 0 || unsafe { libc::listen(fd, 8) } != 0 {
        let error = io::Error::last_os_error();
        // SAFETY: fd remains locally owned on setup failure.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    // SAFETY: successful setup transfers the sole descriptor ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn accept_connection(listener: RawFd) -> io::Result<RawFd> {
    // SAFETY: listener is borrowed and peer address outputs are intentionally null.
    let fd = unsafe {
        libc::accept4(
            listener,
            ptr::null_mut(),
            ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn mount_if_absent(
    source: Option<&str>,
    target: &str,
    filesystem: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    match mount(source, target, filesystem, flags, data) {
        Err(error) if error.raw_os_error() == Some(libc::EBUSY) => Ok(()),
        value => value,
    }
}

fn mount(
    source: Option<&str>,
    target: &str,
    filesystem: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = c_string(source)?;
    let target = CString::new(target).map_err(io::Error::other)?;
    let filesystem = c_string(filesystem)?;
    let data = c_string(data)?;
    // SAFETY: all optional C strings remain live for the duration of mount.
    let result = unsafe {
        libc::mount(
            source.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            filesystem
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref()
                .map_or(ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn c_string(value: Option<&str>) -> io::Result<Option<CString>> {
    value
        .map(CString::new)
        .transpose()
        .map_err(io::Error::other)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn bounded(value: &str) -> String {
    value.chars().take(2048).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_disk_fields_are_strict() {
        assert_eq!(AUTHENTICATION_MAGIC.len(), 8);
        assert!(SandboxId::try_from("box-1").is_ok());
        assert!(Counter::try_from(1).is_ok());
    }
}
