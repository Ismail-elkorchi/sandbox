#![deny(unsafe_op_in_unsafe_fn)]

mod direct_network;

use sandbox_guest::{
    AUTHENTICATION_MAGIC, GUEST_BOOTSTRAP_PORT, GUEST_CONTROL_PORT, GUEST_EXPOSURE_PORT,
    NETWORK_AUTH_MAGIC, NETWORK_DNS_TCP_PORT, NETWORK_DNS_UDP_PORT, NETWORK_HTTP_PORT,
    NETWORK_SOCKS_PORT,
};
use sandsurf_protocol::{
    AUTHENTICATION_BYTES, BootCapability, Counter, Digest, Frame, FrameKind, GuestChallenge,
    GuestFinish, GuestHandshake, GuestHello, SandboxId,
};
use sandsurf_protocol::{GuestServiceRequest, GuestServiceResponse, bytes_digest};
use sandsurf_workload::{
    CgroupLimits, CgroupManager, FilesystemService, PersistentWorkloadService, ProcessSupervisor,
};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

const MAX_AUTHENTICATION_DISK: u64 = 4096;
const WORKLOAD_ROOT: &str = "/sandsurf/workload";
const CONTROL_ROOT: &str = "/sandsurf/control";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/sandsurf-workload";
const SUPERVISOR_CGROUP: &str = "/sys/fs/cgroup/sandsurf-supervisor";
const MAX_CONTROL_CONNECTIONS: usize = 64;

#[derive(Clone)]
struct BootIdentity {
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_digest: Digest,
    capability: BootCapability,
    network_capability: [u8; 32],
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
    harden_supervisor().map_err(|error| stage("harden protected supervisor", error))?;
    mount_control_filesystems().map_err(|error| stage("mount control filesystems", error))?;
    let boot_identity = read_boot_identity().map_err(|error| stage("read boot identity", error))?;
    let network_capability = Arc::new(RwLock::new(boot_identity.network_capability));
    let identity = Arc::new(RwLock::new(boot_identity));
    let session_generation = Arc::new(RwLock::new(()));
    let listener = listen_vsock(GUEST_CONTROL_PORT)
        .map_err(|error| stage("listen on guest control", error))?;
    prepare_persistent_workload().map_err(|error| stage("prepare persistent workload", error))?;
    start_network_relays(Arc::clone(&network_capability))
        .map_err(|error| stage("start workload network relays", error))?;
    direct_network::start().map_err(|error| stage("start direct TCP gateway", error))?;
    let identity_snapshot = identity
        .read()
        .map_err(|_| io::Error::other("boot identity lock is unavailable"))?
        .clone();
    let (processes, cgroups) = create_process_supervisor(&identity_snapshot)
        .map_err(|error| stage("open process supervisor", error))?;
    let filesystem = FilesystemService::open(Path::new(WORKLOAD_ROOT), "/")
        .map_err(io::Error::other)
        .map_err(|error| stage("open filesystem service", error))?;
    let ledger = Path::new(CONTROL_ROOT).join("operations");
    let service = Arc::new(match cgroups {
        Some(cgroups) => {
            PersistentWorkloadService::open_with_cgroups(processes, filesystem, &ledger, cgroups)?
        }
        None => PersistentWorkloadService::open(processes, filesystem, &ledger)?,
    });
    let connections = Arc::new(AtomicUsize::new(0));

    loop {
        let Ok(connection) = accept_connection(listener.as_raw_fd()) else {
            continue;
        };
        if connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value < MAX_CONTROL_CONNECTIONS).then_some(value + 1)
            })
            .is_err()
        {
            // SAFETY: this accepted descriptor was not transferred elsewhere.
            unsafe { libc::close(connection) };
            continue;
        }
        if let Err(error) = set_socket_timeout(connection, std::time::Duration::from_secs(15)) {
            connections.fetch_sub(1, Ordering::AcqRel);
            // SAFETY: setup failed before ownership transfer.
            unsafe { libc::close(connection) };
            eprintln!(
                "sandsurf guest control timeout setup failed: {}",
                bounded(&error.to_string())
            );
            continue;
        }
        let service = Arc::clone(&service);
        let identity = Arc::clone(&identity);
        let session_generation = Arc::clone(&session_generation);
        let network_capability = Arc::clone(&network_capability);
        let connections = Arc::clone(&connections);
        std::thread::spawn(move || {
            struct ConnectionGuard(Arc<AtomicUsize>);
            impl Drop for ConnectionGuard {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _guard = ConnectionGuard(connections);
            // SAFETY: this worker receives sole ownership of the accepted descriptor.
            let mut connection = unsafe { File::from_raw_fd(connection) };
            if let Err(error) = serve_connection(
                &mut connection,
                &identity,
                &session_generation,
                &network_capability,
                &service,
            ) {
                eprintln!(
                    "sandsurf guest control connection failed: {}",
                    bounded(&error.to_string())
                );
            }
        });
    }
}

fn create_process_supervisor(
    identity: &BootIdentity,
) -> io::Result<(ProcessSupervisor, Option<CgroupManager>)> {
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
            cgroups.clone(),
            limits,
        )
        .map(|processes| (processes, Some(cgroups))),
        Err(_) => ProcessSupervisor::create_in_workload(
            &spool,
            Path::new(WORKLOAD_ROOT),
            identity.sandbox_id.clone(),
            identity.epoch,
        )
        .map(|processes| (processes, None)),
    }
    .map_err(io::Error::other)
}

fn serve_connection(
    connection: &mut File,
    identity: &Arc<RwLock<BootIdentity>>,
    session_generation: &Arc<RwLock<()>>,
    network_capability: &Arc<RwLock<[u8; 32]>>,
    service: &PersistentWorkloadService,
) -> io::Result<()> {
    let identity_snapshot = identity
        .read()
        .map_err(|_| io::Error::other("boot identity lock is unavailable"))?
        .clone();
    let (handshake, challenge) = accept_handshake(connection, &identity_snapshot)?;
    send_unauthed(connection, &challenge)?;
    let finish: GuestFinish = read_unauthed(connection)?;
    let mut codec = handshake
        .finish(&finish)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
    // The guardian owns this authenticated transport for the guest epoch.
    set_socket_timeout(connection.as_raw_fd(), std::time::Duration::ZERO)?;
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
        let rebinds_epoch = matches!(request, GuestServiceRequest::RebindEpoch { .. });
        // The generation gate is held through dispatch. A stale session can
        // neither race rebind nor make an effect after the new epoch commits.
        let ordinary_generation = if rebinds_epoch {
            None
        } else {
            Some(
                session_generation
                    .read()
                    .map_err(|_| io::Error::other("guest generation gate is unavailable"))?,
            )
        };
        let rebind_generation = if rebinds_epoch {
            Some(
                session_generation
                    .write()
                    .map_err(|_| io::Error::other("guest generation gate is unavailable"))?,
            )
        } else {
            None
        };
        {
            let current = identity
                .read()
                .map_err(|_| io::Error::other("boot identity lock is unavailable"))?;
            if !session_matches_identity(&identity_snapshot, &current) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "guest session belongs to a previous machine epoch",
                ));
            }
        }
        let response = match request {
            GuestServiceRequest::PrepareStop => {
                service.prepare_stop(std::time::Duration::from_secs(5), || {
                    sync_persistent_filesystems()
                })?;
                GuestServiceResponse::ReadyToStop {
                    evidence: bytes_digest(b"guest-processes-quiesced-and-filesystems-synced-v1"),
                }
            }
            GuestServiceRequest::PrepareFilesystemCapture { operation_id }
            | GuestServiceRequest::PrepareGuestTreeCapture { operation_id } => {
                let evidence = service
                    .prepare_filesystem_capture(&operation_id, sync_persistent_filesystems)?;
                GuestServiceResponse::FilesystemCapturePrepared { evidence }
            }
            GuestServiceRequest::FinishFilesystemCapture { operation_id }
            | GuestServiceRequest::FinishGuestTreeCapture { operation_id } => {
                let evidence = service.finish_filesystem_capture(&operation_id)?;
                GuestServiceResponse::FilesystemCaptureFinished { evidence }
            }
            GuestServiceRequest::CaptureFilesystemQuery {
                operation_id,
                request,
            } => service.capture_filesystem_query(&operation_id, request),
            GuestServiceRequest::CaptureFilesystemRead {
                operation_id,
                path,
                offset,
                maximum,
            } => service.capture_filesystem_read(&operation_id, &path, offset, maximum),
            GuestServiceRequest::RebindEpoch {
                checkpoint_id,
                capture_operation_id,
                sandbox_id,
                previous_epoch,
                epoch,
                boot_identity,
                capability,
                network_capability: next_network_capability,
                generation_seed,
            } => {
                let current = identity
                    .read()
                    .map_err(|_| io::Error::other("boot identity lock is unavailable"))?
                    .clone();
                let valid_epoch = if sandbox_id == current.sandbox_id {
                    current.epoch.next().ok() == Some(epoch)
                } else {
                    epoch == Counter::ONE
                };
                if current.epoch != previous_epoch {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "restore source epoch does not match",
                    ));
                }
                if !valid_epoch {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "restore target epoch is not the next generation",
                    ));
                }
                if capability.iter().all(|byte| *byte == 0)
                    || next_network_capability.iter().all(|byte| *byte == 0)
                    || generation_seed.iter().all(|byte| *byte == 0)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "restore generation material is invalid",
                    ));
                }
                let workload_evidence = service.rebind_epoch(
                    &checkpoint_id,
                    &capture_operation_id,
                    sandbox_id.clone(),
                    previous_epoch,
                    epoch,
                )?;
                mix_generation_seed(&generation_seed)?;
                {
                    let mut value = identity
                        .write()
                        .map_err(|_| io::Error::other("boot identity lock is unavailable"))?;
                    value.sandbox_id = sandbox_id.clone();
                    value.epoch = epoch;
                    value.boot_digest = boot_identity;
                    value.capability = BootCapability::from_bytes(capability);
                    value.network_capability = next_network_capability;
                }
                *network_capability
                    .write()
                    .map_err(|_| io::Error::other("network capability lock is unavailable"))? =
                    next_network_capability;
                GuestServiceResponse::EpochRebound {
                    evidence: sandsurf_protocol::digest(
                        sandsurf_protocol::Domain::Operation,
                        &(
                            "sandsurf-guest-epoch-rebound-v1",
                            checkpoint_id,
                            sandbox_id,
                            previous_epoch,
                            epoch,
                            workload_evidence,
                            sandsurf_protocol::bytes_digest(&generation_seed),
                        ),
                    )
                    .map_err(io::Error::other)?,
                }
            }
            GuestServiceRequest::ProbeIdentity => {
                let current = identity
                    .read()
                    .map_err(|_| io::Error::other("boot identity lock is unavailable"))?;
                GuestServiceResponse::Identity {
                    sandbox_id: current.sandbox_id.clone(),
                    epoch: current.epoch,
                    boot_identity: current.boot_digest.clone(),
                }
            }
            GuestServiceRequest::ApplyResources { resources } => {
                service.apply_guardian_resources(resources)
            }
            request => service.handle(request),
        };
        drop(ordinary_generation);
        drop(rebind_generation);
        let payload = serde_json::to_vec(&response).map_err(io::Error::other)?;
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
        outgoing = outgoing
            .next()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        codec
            .seal(Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: outgoing,
                authentication: [0; AUTHENTICATION_BYTES],
                payload: sandsurf_protocol::CONTROL_COMPLETE.to_vec(),
            })
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .write(connection)?;
        connection.flush()?;
        // A rebind changes the authenticated identity; the next request must
        // establish a fresh session with the new epoch capability.
        if rebinds_epoch {
            break;
        }
    }
    Ok(())
}

fn mix_generation_seed(seed: &[u8; 32]) -> io::Result<()> {
    // Writing caller-provided fresh host entropy mixes it into Linux's random
    // pool without claiming an entropy count. Fork-safe admission still needs
    // application reset hooks because arbitrary userspace caches are opaque.
    let mut random = OpenOptions::new().write(true).open("/dev/urandom")?;
    random.write_all(seed)?;
    random.flush()
}

fn sync_persistent_filesystems() -> io::Result<()> {
    for path in ["/sandsurf/state", CONTROL_ROOT] {
        let directory = File::open(path)?;
        // SAFETY: syncfs borrows one valid descriptor for a mounted persistent
        // filesystem and has no ownership transfer.
        if unsafe { libc::syncfs(directory.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
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

fn session_matches_identity(session: &BootIdentity, current: &BootIdentity) -> bool {
    session.sandbox_id == current.sandbox_id
        && session.epoch == current.epoch
        && session.boot_digest == current.boot_digest
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
    // Cgroup v2 does not permit domain controllers below a cgroup that also
    // contains processes. Move the protected supervisor first, then delegate a
    // distinct empty subtree whose children belong only to workload processes.
    fs::create_dir_all(SUPERVISOR_CGROUP)?;
    fs::write(format!("{SUPERVISOR_CGROUP}/cgroup.procs"), "0\n")?;
    fs::write(
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+cpu +memory +pids +io\n",
    )?;
    fs::create_dir_all(CGROUP_ROOT)?;
    fs::write(
        format!("{CGROUP_ROOT}/cgroup.subtree_control"),
        "+cpu +memory +pids +io\n",
    )?;
    Ok(())
}

fn prepare_persistent_workload() -> io::Result<()> {
    let state_device = attached_disk(2)?;
    let workload_device = attached_disk(1)?;
    let control_device = attached_disk(3)?;
    for directory in [
        "/sandsurf/state",
        "/sandsurf/lower",
        CONTROL_ROOT,
        WORKLOAD_ROOT,
    ] {
        fs::create_dir_all(directory)?;
    }
    mount(
        Some(&state_device),
        "/sandsurf/state",
        Some("ext4"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("errors=remount-ro"),
    )?;
    grow_ext4_to_device(&state_device, "/sandsurf/state")?;
    mount(
        Some(&workload_device),
        "/sandsurf/lower",
        Some("ext4"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        Some("errors=remount-ro"),
    )?;
    mount(
        Some(&control_device),
        CONTROL_ROOT,
        Some("ext4"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("errors=remount-ro"),
    )?;
    grow_ext4_to_device(&control_device, CONTROL_ROOT)?;
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

/// Grow a mounted ext4 filesystem to its host-provisioned virtual block size.
/// This keeps raw persistent disks portable to macOS and Windows hosts, which
/// must not mount guest filesystems or depend on host-installed `resize2fs`.
fn grow_ext4_to_device(device: &str, mountpoint: &str) -> io::Result<()> {
    const BLKGETSIZE64: u64 = 0x8008_1272;
    const EXT4_IOC_RESIZE_FS: u64 = 0x4008_6610;

    let mut device_file = File::open(device)?;
    let mut device_bytes = 0_u64;
    // SAFETY: BLKGETSIZE64 writes one u64 to the valid mutable pointer and the
    // descriptor is a live block-device handle retained for the call.
    if unsafe {
        libc::ioctl(
            device_file.as_raw_fd(),
            BLKGETSIZE64 as _,
            &mut device_bytes,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut superblock = [0_u8; 0x154];
    device_file.seek(SeekFrom::Start(1024))?;
    device_file.read_exact(&mut superblock)?;
    if u16::from_le_bytes([superblock[0x38], superblock[0x39]]) != 0xef53 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persistent disk is not ext4",
        ));
    }
    let logarithm = u32::from_le_bytes(superblock[0x18..0x1c].try_into().expect("four bytes"));
    let block_bytes = 1024_u64
        .checked_shl(logarithm)
        .filter(|value| (1024..=65_536).contains(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ext4 block size is invalid"))?;
    if !device_bytes.is_multiple_of(block_bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persistent disk size is not block aligned",
        ));
    }
    let current_low = u32::from_le_bytes(superblock[0x04..0x08].try_into().expect("four bytes"));
    let current_high = u32::from_le_bytes(superblock[0x150..0x154].try_into().expect("four bytes"));
    let current_blocks = u64::from(current_low) | (u64::from(current_high) << 32);
    let target_blocks = device_bytes / block_bytes;
    if target_blocks <= current_blocks {
        return Ok(());
    }
    let directory = File::open(mountpoint)?;
    // SAFETY: EXT4_IOC_RESIZE_FS reads one u64 from the valid pointer. The
    // descriptor names the mounted ext4 root and target fits the backing disk.
    if unsafe {
        libc::ioctl(
            directory.as_raw_fd(),
            EXT4_IOC_RESIZE_FS as _,
            &target_blocks,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
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

fn read_boot_identity() -> io::Result<BootIdentity> {
    if let Ok(path) = attached_disk(4) {
        let mut file = File::open(path)?;
        if file.metadata()?.len() > MAX_AUTHENTICATION_DISK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "authentication disk exceeds bound",
            ));
        }
        return parse_boot_identity(&mut file);
    }
    // Hyper-V direct boot has no safe host-side raw block update path. HCS
    // confines this one-shot service to the VM-specific owner SDDL, after
    // which the same capability-bound control protocol is used everywhere.
    let listener = listen_vsock(GUEST_BOOTSTRAP_PORT)?;
    let connection = accept_connection(listener.as_raw_fd())?;
    // SAFETY: this accepted descriptor is uniquely owned by the bootstrap
    // exchange and is closed after the bounded identity record is consumed.
    let mut connection = unsafe { File::from_raw_fd(connection) };
    parse_boot_identity(&mut connection)
}

fn parse_boot_identity(file: &mut impl Read) -> io::Result<BootIdentity> {
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
    let mut network_capability = [0_u8; 32];
    file.read_exact(&mut network_capability)?;
    Ok(BootIdentity {
        sandbox_id,
        epoch,
        boot_digest,
        capability: BootCapability::from_bytes(capability),
        network_capability,
    })
}

/// Resolve the stable attachment slot across virtio-blk and Hyper-V SCSI.
/// Sandsurf owns the complete VM device model, so an attachment index is an
/// authenticated boot-bundle fact rather than guest discovery of arbitrary
/// host storage.
fn attached_disk(index: u8) -> io::Result<String> {
    let suffix = char::from(
        b'a'.checked_add(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk index overflow"))?,
    );
    for prefix in ["vd", "sd"] {
        let path = format!("/dev/{prefix}{suffix}");
        if Path::new(&path).exists() {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Sandsurf disk attachment {index} is absent"),
    ))
}

fn start_network_relays(capability: Arc<RwLock<[u8; 32]>>) -> io::Result<()> {
    activate_loopback()?;
    let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 3128))?;
    let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, 1080))?;
    let dns_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 53))?;
    let dns_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 53))?;
    let exposure = listen_vsock(GUEST_EXPOSURE_PORT)?;
    let resolver = Path::new(WORKLOAD_ROOT).join("etc/resolv.conf");
    if let Some(parent) = resolver.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::remove_file(&resolver) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::write(
        &resolver,
        b"nameserver 127.0.0.1\noptions attempts:1 timeout:2\n",
    )?;

    for (listener, port) in [
        (http, NETWORK_HTTP_PORT),
        (socks, NETWORK_SOCKS_PORT),
        (dns_tcp, NETWORK_DNS_TCP_PORT),
    ] {
        let capability = Arc::clone(&capability);
        std::thread::spawn(move || {
            for accepted in listener.incoming() {
                let Ok(client) = accepted else { break };
                let capability = Arc::clone(&capability);
                std::thread::spawn(move || {
                    let Ok(capability) = capability.read().map(|value| *value) else {
                        return;
                    };
                    let _ = relay_network_stream(client, port, capability);
                });
            }
        });
    }
    let dns_capability = Arc::clone(&capability);
    std::thread::spawn(move || {
        let mut query = [0_u8; 4096];
        loop {
            let Ok((count, peer)) = dns_udp.recv_from(&mut query) else {
                continue;
            };
            let response = dns_capability
                .read()
                .map(|value| *value)
                .map_err(|_| io::Error::other("network capability lock is unavailable"))
                .and_then(|value| dns_query(&query[..count], value));
            if let Ok(response) = response {
                let _ = dns_udp.send_to(&response, peer);
            }
        }
    });
    let exposure_capability = Arc::clone(&capability);
    std::thread::spawn(move || {
        loop {
            let Ok(connection) = accept_connection(exposure.as_raw_fd()) else {
                continue;
            };
            let capability = Arc::clone(&exposure_capability);
            std::thread::spawn(move || {
                // SAFETY: this worker receives sole ownership of the accepted descriptor.
                let connection = unsafe { File::from_raw_fd(connection) };
                let Ok(capability) = capability.read().map(|value| *value) else {
                    return;
                };
                let _ = serve_exposure(connection, capability);
            });
        }
    });
    Ok(())
}

fn activate_loopback() -> io::Result<()> {
    // SAFETY: arguments request one standard close-on-exec IPv4 control socket.
    let descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket creation transfers sole ownership here.
    let socket = unsafe { File::from_raw_fd(descriptor) };
    // SAFETY: zero initializes every ifreq union representation, after which
    // the interface name and flags member are the only fields used by ioctl.
    let mut request: libc::ifreq = unsafe { zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: SIOCGIFFLAGS receives a writable, correctly sized ifreq.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIOCGIFFLAGS initialized the flags union member selected here.
    let flags = unsafe { request.ifr_ifru.ifru_flags } | libc::IFF_UP as libc::c_short;
    request.ifr_ifru.ifru_flags = flags;
    // SAFETY: SIOCSIFFLAGS reads the initialized interface name and flags.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn serve_exposure(mut host: File, capability: [u8; 32]) -> io::Result<()> {
    let mut authentication = [0_u8; 8 + 32];
    host.read_exact(&mut authentication)?;
    let valid_magic = &authentication[..8] == b"SSFPORT1";
    let difference = authentication[8..]
        .iter()
        .zip(capability)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        });
    if !valid_magic || difference != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "port exposure authentication failed",
        ));
    }
    let mut port = [0_u8; 2];
    host.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "port exposure target is invalid",
        ));
    }
    let mut workload = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
    let mut host_reader = host.try_clone()?;
    let mut workload_writer = workload.try_clone()?;
    let outbound = std::thread::spawn(move || io::copy(&mut host_reader, &mut workload_writer));
    let inbound = io::copy(&mut workload, &mut host);
    let _ = workload.shutdown(Shutdown::Both);
    let outbound = outbound
        .join()
        .map_err(|_| io::Error::other("exposure relay worker panicked"))?;
    inbound.and(outbound).map(drop)
}

fn relay_network_stream(mut client: TcpStream, port: u32, capability: [u8; 32]) -> io::Result<()> {
    let mut host = connect_host_vsock(port)?;
    host.write_all(NETWORK_AUTH_MAGIC)?;
    host.write_all(&capability)?;
    host.flush()?;
    let mut client_reader = client.try_clone()?;
    let mut host_writer = host.try_clone()?;
    let outbound = std::thread::spawn(move || io::copy(&mut client_reader, &mut host_writer));
    let inbound = io::copy(&mut host, &mut client);
    let _ = client.shutdown(Shutdown::Both);
    let outbound = outbound
        .join()
        .map_err(|_| io::Error::other("network relay worker panicked"))?;
    inbound.and(outbound).map(drop)
}

fn dns_query(query: &[u8], capability: [u8; 32]) -> io::Result<Vec<u8>> {
    if query.is_empty() || query.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS query is outside its bound",
        ));
    }
    let mut host = connect_host_vsock(NETWORK_DNS_UDP_PORT)?;
    host.write_all(NETWORK_AUTH_MAGIC)?;
    host.write_all(&capability)?;
    host.write_all(&(query.len() as u16).to_be_bytes())?;
    host.write_all(query)?;
    host.flush()?;
    let mut length = [0_u8; 2];
    host.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response is outside its bound",
        ));
    }
    let mut response = vec![0; length];
    host.read_exact(&mut response)?;
    Ok(response)
}

fn connect_host_vsock(port: u32) -> io::Result<File> {
    // SAFETY: arguments request one standard close-on-exec AF_VSOCK stream.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zero is a valid initial representation for sockaddr_vm.
    let mut address: libc::sockaddr_vm = unsafe { zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_port = port;
    address.svm_cid = libc::VMADDR_CID_HOST;
    // SAFETY: address has the exact sockaddr_vm layout and lifetime.
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_vm).cast(),
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        // SAFETY: fd remains locally owned on connection failure.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    // SAFETY: successful setup transfers sole ownership of fd.
    Ok(unsafe { File::from_raw_fd(fd) })
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

fn set_socket_timeout(fd: RawFd, timeout: std::time::Duration) -> io::Result<()> {
    let seconds = timeout
        .as_secs()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket timeout overflow"))?;
    let value = libc::timeval {
        tv_sec: seconds,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: fd is one live owned socket and value has the exact timeval
        // layout required by these scalar socket options.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&value as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
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

fn stage(name: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{name}: {error}"))
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

    #[test]
    fn session_identity_is_bound_to_the_current_machine_generation() {
        let session = BootIdentity {
            sandbox_id: "box-1".try_into().unwrap(),
            epoch: Counter::ONE,
            boot_digest: bytes_digest(b"boot-one"),
            capability: BootCapability::from_bytes([1; 32]),
            network_capability: [2; 32],
        };
        assert!(session_matches_identity(&session, &session));
        let mut current = session.clone();
        current.epoch = Counter::try_from(2).unwrap();
        assert!(!session_matches_identity(&session, &current));
        current = session.clone();
        current.sandbox_id = "fork-1".try_into().unwrap();
        assert!(!session_matches_identity(&session, &current));
        current = session.clone();
        current.boot_digest = bytes_digest(b"boot-two");
        assert!(!session_matches_identity(&session, &current));
    }
}
