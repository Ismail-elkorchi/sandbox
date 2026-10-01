#![deny(unsafe_op_in_unsafe_fn)]

mod binding;

use sandsurf_guest::{ConnectionBudget, ExecutionRegistry, FilesystemService, ManagementService};
#[cfg(test)]
use sandsurf_protocol::bytes_digest;
use sandsurf_protocol::{
    AUTHENTICATION_BYTES, BootCapability, Counter, Digest, Frame, FrameKind, GuestChallenge,
    GuestFinish, GuestHandshake, GuestHello, MachineId,
};
use sandsurf_protocol::{AUTHENTICATION_MAGIC, GUEST_BOOTSTRAP_PORT, GUEST_CONTROL_PORT};
use sandsurf_protocol::{AuthenticatedFrameChannel, send_binary};
use sandsurf_protocol::{GuestServiceRequest, GuestServiceResponse};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::ptr;
use std::sync::{Arc, RwLock};

const MAX_AUTHENTICATION_DISK: u64 = 4096;
const CONTROL_ROOT: &str = "/var/lib/sandsurf";
const MAX_CONTROL_CONNECTIONS: usize = 64;

#[derive(Clone)]
struct BootIdentity {
    machine_id: MachineId,
    generation: Counter,
    boot_digest: Digest,
    capability: BootCapability,
}

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 2 && args[0] == "--execution-keeper" {
        sandsurf_guest::execution_keeper_main(Path::new(&args[1]))
    } else if args.is_empty() {
        supervisor_main()
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid guest management arguments",
        ))
    };
    if let Err(error) = result {
        eprintln!(
            "sandsurf guest supervisor failure: {}",
            bounded(&error.to_string())
        );
        std::process::exit(1);
    }
}

fn supervisor_main() -> io::Result<()> {
    fs::create_dir_all(CONTROL_ROOT)?;
    let boot_id: sandsurf_protocol::GuestBootId =
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .try_into()
            .map_err(io::Error::other)?;
    let mut instance_nonce = [0u8; 16];
    getrandom::getrandom(&mut instance_nonce)
        .map_err(|_| io::Error::other("management instance entropy unavailable"))?;
    let management = Arc::new(sandsurf_protocol::GuestManagementIdentity {
        boot_id: boot_id.clone(),
        instance_id: hex(&instance_nonce).try_into().map_err(io::Error::other)?,
    });
    let binding_path = Path::new(CONTROL_ROOT).join("binding.json");
    let boot_identity = match binding::load(&binding_path, &boot_id)? {
        Some(identity) => identity,
        None => {
            let identity =
                read_boot_identity().map_err(|error| stage("read boot identity", error))?;
            binding::save(&binding_path, &boot_id, &identity)?;
            identity
        }
    };
    let identity = Arc::new(RwLock::new(boot_identity));
    let session_generation = Arc::new(RwLock::new(()));
    let listener = listen_vsock(GUEST_CONTROL_PORT)
        .map_err(|error| stage("listen on guest control", error))?;
    let identity_snapshot = identity
        .read()
        .map_err(|_| io::Error::other("boot identity lock is unavailable"))?
        .clone();
    let processes = create_process_supervisor(&identity_snapshot)
        .map_err(|error| stage("open process supervisor", error))?;
    let filesystem = FilesystemService::open(&Path::new(CONTROL_ROOT).join("watchers"))
        .map_err(|error| stage("open filesystem watch journal", io::Error::other(error)))?;
    let ledger = Path::new(CONTROL_ROOT).join("operations");
    let service = Arc::new(ManagementService::open(processes, filesystem, &ledger)?);
    let connections = ConnectionBudget::new(MAX_CONTROL_CONNECTIONS);

    loop {
        let Ok(connection) = accept_connection(listener.as_raw_fd()) else {
            continue;
        };
        let Some(lease) = connections.try_acquire() else {
            // SAFETY: this accepted descriptor was not transferred elsewhere.
            unsafe { libc::close(connection) };
            continue;
        };
        if let Err(error) = set_socket_timeout(connection, std::time::Duration::from_secs(15)) {
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
        let management = Arc::clone(&management);
        std::thread::spawn(move || {
            let _lease = lease;
            // SAFETY: this worker receives sole ownership of the accepted descriptor.
            let mut connection = unsafe { File::from_raw_fd(connection) };
            if let Err(error) = serve_connection(
                &mut connection,
                &identity,
                &session_generation,
                &management,
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

fn create_process_supervisor(identity: &BootIdentity) -> io::Result<ExecutionRegistry> {
    let spool = Path::new(CONTROL_ROOT).join("executions");
    ExecutionRegistry::create(
        &spool,
        identity.machine_id.clone(),
        identity.generation,
        &std::env::current_exe()?,
    )
    .map_err(io::Error::other)
}

fn serve_connection(
    connection: &mut File,
    identity: &Arc<RwLock<BootIdentity>>,
    session_generation: &Arc<RwLock<()>>,
    management: &sandsurf_protocol::GuestManagementIdentity,
    service: &ManagementService,
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
    // The guardian owns this authenticated transport for the guest generation.
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
        let mut wire: sandsurf_protocol::RequestEnvelope<GuestServiceRequest> =
            serde_json::from_slice(&frame.payload)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let data = if let Some(metadata) = wire.descriptor().map_err(io::Error::other)? {
            Some(sandsurf_protocol::receive_binary(
                &mut AuthenticatedFrameChannel {
                    io: connection,
                    codec: &mut codec,
                },
                metadata,
                sandsurf_protocol::MAX_RPC_DATA_BYTES,
            )?)
        } else {
            None
        };
        let request = wire.assemble(data).map_err(io::Error::other)?;
        let rebinds_generation = matches!(request, GuestServiceRequest::RebindGeneration { .. });
        // The generation gate is held through dispatch. A stale session can
        // neither race rebind nor make an effect after the new generation commits.
        let ordinary_generation = if rebinds_generation {
            None
        } else {
            Some(
                session_generation
                    .read()
                    .map_err(|_| io::Error::other("guest generation gate is unavailable"))?,
            )
        };
        let rebind_generation = if rebinds_generation {
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
                    "guest session belongs to a previous machine generation",
                ));
            }
        }
        let response = match request {
            GuestServiceRequest::RebindGeneration {
                snapshot_id,
                capture_operation_id,
                machine_id,
                previous_generation,
                generation,
                boot_identity,
                capability,
                generation_seed,
            } => {
                let current = identity
                    .read()
                    .map_err(|_| io::Error::other("boot identity lock is unavailable"))?
                    .clone();
                // The host fence advances from its current history, not from
                // the captured guest's older epoch. Memory cloning into another
                // machine is not a supported restore operation.
                let valid_generation =
                    machine_id == current.machine_id && generation > previous_generation;
                if current.generation != previous_generation {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "restore source generation does not match",
                    ));
                }
                if !valid_generation {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "restore target identity or generation is invalid",
                    ));
                }
                if capability.iter().all(|byte| *byte == 0)
                    || generation_seed.iter().all(|byte| *byte == 0)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "restore generation material is invalid",
                    ));
                }
                let workload_evidence = service.rebind_generation(
                    &snapshot_id,
                    &capture_operation_id,
                    machine_id.clone(),
                    previous_generation,
                    generation,
                )?;
                mix_generation_seed(&generation_seed)?;
                let next_identity = BootIdentity {
                    machine_id: machine_id.clone(),
                    generation,
                    boot_digest: boot_identity,
                    capability: BootCapability::from_bytes(capability),
                };
                binding::save(
                    &Path::new(CONTROL_ROOT).join("binding.json"),
                    &management.boot_id,
                    &next_identity,
                )?;
                *identity
                    .write()
                    .map_err(|_| io::Error::other("boot identity lock is unavailable"))? =
                    next_identity;
                GuestServiceResponse::GenerationRebound {
                    evidence: sandsurf_protocol::digest(
                        sandsurf_protocol::Domain::Operation,
                        &(
                            "sandsurf-guest-generation-rebound-v1",
                            snapshot_id,
                            machine_id,
                            previous_generation,
                            generation,
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
                    machine_id: current.machine_id.clone(),
                    generation: current.generation,
                    boot_identity: current.boot_digest.clone(),
                    management: management.clone(),
                }
            }
            request => service.handle(request),
        };
        drop(ordinary_generation);
        drop(rebind_generation);
        let (response, binary) = response.into_wire_parts().map_err(io::Error::other)?;
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
        if let Some(bytes) = binary {
            send_binary(
                &mut AuthenticatedFrameChannel {
                    io: connection,
                    codec: &mut codec,
                },
                bytes,
            )?;
        }
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
        // establish a fresh session with the new generation capability.
        if rebinds_generation {
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

fn accept_handshake(
    connection: &mut File,
    identity: &BootIdentity,
) -> io::Result<(GuestHandshake, GuestChallenge)> {
    let hello: GuestHello = read_unauthed(connection)?;
    GuestHandshake::accept(
        identity.capability.clone(),
        &identity.machine_id,
        identity.generation,
        &identity.boot_digest,
        &hello,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))
}

fn session_matches_identity(session: &BootIdentity, current: &BootIdentity) -> bool {
    session.machine_id == current.machine_id
        && session.generation == current.generation
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

fn read_boot_identity() -> io::Result<BootIdentity> {
    if let Ok(path) = attached_disk(1) {
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
            "machine identity is invalid",
        ));
    }
    let mut machine = vec![0; size];
    file.read_exact(&mut machine)?;
    let machine_id = std::str::from_utf8(&machine)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "machine identity is not UTF-8"))?
        .try_into()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut generation = [0_u8; 8];
    file.read_exact(&mut generation)?;
    let generation = Counter::try_from(u64::from_be_bytes(generation))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if generation == Counter::ZERO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "generation is zero",
        ));
    }
    let mut digest = [0_u8; 32];
    file.read_exact(&mut digest)?;
    let boot_digest = Digest::try_from(hex(&digest))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut capability = [0_u8; 32];
    file.read_exact(&mut capability)?;
    Ok(BootIdentity {
        machine_id,
        generation,
        boot_digest,
        capability: BootCapability::from_bytes(capability),
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
        assert!(MachineId::try_from("box-1").is_ok());
        assert!(Counter::try_from(1).is_ok());
    }

    #[test]
    fn session_identity_is_bound_to_the_current_machine_generation() {
        let session = BootIdentity {
            machine_id: "box-1".try_into().unwrap(),
            generation: Counter::ONE,
            boot_digest: bytes_digest(b"boot-one"),
            capability: BootCapability::from_bytes([1; 32]),
        };
        assert!(session_matches_identity(&session, &session));
        let mut current = session.clone();
        current.generation = Counter::try_from(2).unwrap();
        assert!(!session_matches_identity(&session, &current));
        current = session.clone();
        current.machine_id = "fork-1".try_into().unwrap();
        assert!(!session_matches_identity(&session, &current));
        current = session.clone();
        current.boot_digest = bytes_digest(b"boot-two");
        assert!(!session_matches_identity(&session, &current));
    }
}
