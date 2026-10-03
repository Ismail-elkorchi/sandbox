#![deny(unsafe_op_in_unsafe_fn)]

mod binding;
mod control_transport;

use control_transport::Connection;
use sandsurf_guest::{ConnectionBudget, ExecutionRegistry, FilesystemService, ManagementService};
use sandsurf_protocol::GUEST_CONTROL_PORT;
#[cfg(test)]
use sandsurf_protocol::bytes_digest;
use sandsurf_protocol::{
    AUTHENTICATION_BYTES, BOOT_RECORD_BYTES, BootCapability, BootIdentity, Counter, Frame,
    FrameKind, GuestChallenge, GuestFinish, GuestHandshake, GuestHello,
};
#[cfg(test)]
use sandsurf_protocol::{AUTHENTICATION_MAGIC, MachineId};
use sandsurf_protocol::{AuthenticatedFrameChannel, send_binary};
use sandsurf_protocol::{GuestServiceRequest, GuestServiceResponse};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::ptr;
use std::sync::{Arc, RwLock};

const CONTROL_ROOT: &str = "/var/lib/sandsurf";
const MAX_CONTROL_CONNECTIONS: usize = 64;

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 2 && args[0] == "--execution-keeper" {
        sandsurf_guest::execution_keeper_main(Path::new(&args[1]))
    } else if args.is_empty() && std::process::id() == 1 {
        disk_executor_main()
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

fn disk_executor_main() -> io::Result<()> {
    let writable = sandsurf_guest::disk_executor::prepare()?;
    let file = if let Some(ports) =
        control_transport::serial_ports(Path::new("/sys/class/virtio-ports"), Path::new("/dev"))?
    {
        OpenOptions::new().read(true).write(true).open(
            ports
                .first()
                .ok_or_else(|| io::Error::other("offline serial device is missing"))?,
        )?
    } else {
        let listener = listen_vsock(sandsurf_protocol::disk::DISK_EXECUTOR_PORT)?;
        let fd = accept_connection(listener.as_raw_fd())?;
        // SAFETY: accept_connection transfers this sole accepted descriptor.
        unsafe { File::from_raw_fd(fd) }
    };
    sandsurf_guest::disk_executor::serve(file, writable)
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
    if let Some(ports) =
        control_transport::serial_ports(Path::new("/sys/class/virtio-ports"), Path::new("/dev"))?
    {
        let mut ports = ports.into_iter();
        let foreground = ports
            .next()
            .ok_or_else(|| io::Error::other("guest control ports are empty"))?;
        for (index, port) in ports.enumerate() {
            let service = Arc::clone(&service);
            let identity = Arc::clone(&identity);
            let session_generation = Arc::clone(&session_generation);
            let management = Arc::clone(&management);
            std::thread::Builder::new()
                .name(format!("control-{}", index + 1))
                .spawn(move || {
                    serve_serial_port(&port, &identity, &session_generation, &management, &service)
                })?;
        }
        serve_serial_port(
            &foreground,
            &identity,
            &session_generation,
            &management,
            &service,
        );
    }
    let listener = listen_vsock(GUEST_CONTROL_PORT)
        .map_err(|error| stage("listen on guest control", error))?;
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
        // SAFETY: this accepted descriptor has sole ownership transferred here.
        let file = unsafe { File::from_raw_fd(connection) };
        let mut connection = Connection::new(file)?;
        let service = Arc::clone(&service);
        let identity = Arc::clone(&identity);
        let session_generation = Arc::clone(&session_generation);
        let management = Arc::clone(&management);
        std::thread::spawn(move || {
            let _lease = lease;
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

fn serve_serial_port(
    port: &Path,
    identity: &Arc<RwLock<BootIdentity>>,
    session_generation: &Arc<RwLock<()>>,
    management: &sandsurf_protocol::GuestManagementIdentity,
    service: &ManagementService,
) -> ! {
    loop {
        // Reopening repairs only this session, not the Linux computer.
        if let Ok(mut connection) = Connection::open_port(port) {
            let _ = serve_connection(
                &mut connection,
                identity,
                session_generation,
                management,
                service,
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
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
    connection: &mut Connection,
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
    connection.authenticated();
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
    connection: &mut impl Read,
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

fn read_unauthed<T: serde::de::DeserializeOwned>(connection: &mut impl Read) -> io::Result<T> {
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

fn send_unauthed<T: serde::Serialize>(connection: &mut impl Write, value: &T) -> io::Result<()> {
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
    let mut file = File::open(attached_disk(1)?)?;
    // Block-device st_size is zero on Linux. Bound the actual record and
    // require device EOF rather than confusing stat size with capacity.
    let identity = parse_boot_identity(&mut file)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authentication disk has invalid size",
        ));
    }
    Ok(identity)
}

fn parse_boot_identity(file: &mut impl Read) -> io::Result<BootIdentity> {
    let mut bytes = zeroize::Zeroizing::new([0; BOOT_RECORD_BYTES]);
    file.read_exact(&mut bytes[..])?;
    BootIdentity::decode(&bytes[..])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Resolve the stable virtio-blk attachment slot.
/// Sandsurf owns the complete VM device model, so an attachment index is an
/// authenticated boot-bundle fact rather than guest discovery of arbitrary
/// host storage.
fn attached_disk(index: u8) -> io::Result<String> {
    let suffix = char::from(
        b'a'.checked_add(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk index overflow"))?,
    );
    let path = format!("/dev/vd{suffix}");
    if Path::new(&path).exists() {
        return Ok(path);
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
