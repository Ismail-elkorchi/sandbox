//! Process supervision, not machine authority. This service runs independently
//! of the host API service and launches only its own fixed guardian executable.
//! It owns no grants, lifecycle intent, disk records or runtime observations.

use crate::guardian::GuardianClient;
use sandsurf_native::local::{LocalConnection, LocalListener};
use sandsurf_native::storage::object_name;
use sandsurf_protocol::{Counter, Frame, FrameKind, MachineId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const VERSION: u16 = 1;
const MAX_CHILDREN: usize = 4096;
const FRAME_TIMEOUT: Duration = Duration::from_secs(2);

struct OwnedGuardian {
    child: Child,
    #[cfg(target_os = "linux")]
    native_unit: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Inspect,
    Ensure { machine: MachineId },
    Check { machine: MachineId },
    Shutdown,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Response {
    Complete,
    Rejected { message: String },
}

pub fn call(root: &Path, request: Request) -> io::Result<()> {
    let mut connection = LocalConnection::connect(&root.join("supervision"), FRAME_TIMEOUT)?;
    let payload = serde_json::to_vec(&(VERSION, request)).map_err(io::Error::other)?;
    connection.write_frame(
        &Frame {
            kind: FrameKind::Control,
            stream: 0,
            sequence: Counter::ONE,
            authentication: [0; sandsurf_protocol::AUTHENTICATION_BYTES],
            payload,
        },
        FRAME_TIMEOUT,
    )?;
    let frame = connection
        .read_frame(FRAME_TIMEOUT)?
        .ok_or_else(|| io::Error::other("supervisor closed without a response"))?;
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence != Counter::ONE
        || frame.authentication != [0; sandsurf_protocol::AUTHENTICATION_BYTES]
        || frame.payload.len() > 4096
    {
        return Err(io::Error::other("invalid supervisor response envelope"));
    }
    let (version, response): (u16, Response) =
        serde_json::from_slice(&frame.payload).map_err(io::Error::other)?;
    if version != VERSION {
        return Err(io::Error::other("incompatible supervisor protocol"));
    }
    match response {
        Response::Complete => Ok(()),
        Response::Rejected { message } => Err(io::Error::other(message)),
    }
}

pub fn serve(root: &Path, executable: PathBuf) -> io::Result<()> {
    // Admission never repairs an existing directory's permissions or ownership.
    sandsurf_native::local::ensure_private_directory(root)?;
    let root = sandsurf_native::local::canonical_private_directory(root)?;
    sandsurf_native::local::ensure_private_directory(&root.join("supervision"))?;
    let listener = LocalListener::bind(&root.join("supervision"))?;
    let mut children = BTreeMap::<MachineId, OwnedGuardian>::new();
    loop {
        let mut reaped = Vec::new();
        for (machine, owner) in &mut children {
            if owner.child.try_wait()?.is_some() {
                reaped.push(machine.clone());
            }
        }
        for machine in reaped {
            children.remove(&machine);
        }
        let mut connection = match listener.accept(Duration::from_millis(100)) {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error),
        };
        // A malformed/idle peer has a bounded frame deadline and cannot replace
        // the service owner. No frame accepts an executable, path or arguments.
        let request = read_request(&mut connection);
        let stopping = matches!(request, Ok(Request::Shutdown));
        let result = request.and_then(|request| match request {
            Request::Inspect => Ok(()),
            Request::Ensure { machine } => ensure(&root, &executable, machine, &mut children),
            Request::Check { machine } => {
                if children
                    .get_mut(&machine)
                    .is_some_and(|owner| matches!(owner.child.try_wait(), Ok(None)))
                {
                    Ok(())
                } else {
                    GuardianClient::new(
                        root.join("machines")
                            .join(object_name(machine.as_str()))
                            .join("guardian"),
                    )
                    .owner_identity(machine)
                    .map(|_| ())
                    .map_err(io::Error::other)
                }
            }
            Request::Shutdown => {
                // Explicit host-account/service-manager containment, never SDK
                // disconnection or host API shutdown. Journals/disks are kept.
                #[cfg(target_os = "linux")]
                for (machine, owner) in &children {
                    if owner.native_unit {
                        let machine_root =
                            root.join("machines").join(object_name(machine.as_str()));
                        let mut stop = Command::new("systemctl");
                        stop.args([
                            "--user",
                            "stop",
                            &sandsurf_native::resources::unit_name(&machine_root)?,
                        ]);
                        sandsurf_native::resources::run_bounded(stop)?;
                    }
                }
                for owner in children.values_mut() {
                    if owner.child.try_wait()?.is_none()
                        && let Err(error) = owner.child.kill()
                        && owner.child.try_wait()?.is_none()
                    {
                        return Err(error);
                    }
                    owner.child.wait()?;
                }
                children.clear();
                Ok(())
            }
        });
        let stopped = stopping && result.is_ok();
        let response = match result {
            Ok(()) => Response::Complete,
            Err(error) => Response::Rejected {
                message: error.to_string().chars().take(512).collect(),
            },
        };
        let payload = serde_json::to_vec(&(VERSION, response)).map_err(io::Error::other)?;
        let _ = connection.write_frame(
            &Frame {
                kind: FrameKind::Control,
                stream: 0,
                sequence: Counter::ONE,
                authentication: [0; sandsurf_protocol::AUTHENTICATION_BYTES],
                payload,
            },
            FRAME_TIMEOUT,
        );
        if stopped {
            return Ok(());
        }
    }
}

fn read_request(connection: &mut LocalConnection) -> io::Result<Request> {
    let frame = connection
        .read_frame(FRAME_TIMEOUT)?
        .ok_or_else(|| io::Error::other("supervisor request missing"))?;
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence != Counter::ONE
        || frame.authentication != [0; sandsurf_protocol::AUTHENTICATION_BYTES]
        || frame.payload.len() > 4096
    {
        return Err(io::Error::other("invalid supervisor request envelope"));
    }
    let (version, request) =
        serde_json::from_slice::<(u16, Request)>(&frame.payload).map_err(io::Error::other)?;
    if version != VERSION {
        return Err(io::Error::other("incompatible supervisor protocol"));
    }
    Ok(request)
}

fn ensure(
    root: &Path,
    executable: &Path,
    machine: MachineId,
    children: &mut BTreeMap<MachineId, OwnedGuardian>,
) -> io::Result<()> {
    if children.contains_key(&machine) {
        return Ok(());
    }
    let machine_root = root.join("machines").join(object_name(machine.as_str()));
    // The authority service must have admitted this exact private runtime first.
    // The guardian itself verifies host authorization and acquires its sole
    // journal/native ownership leases; the supervisor cannot grant authority.
    for path in [
        &machine_root,
        &machine_root.join("runtime"),
        &machine_root.join("guardian"),
    ] {
        sandsurf_native::local::canonical_private_directory(path)?;
    }
    match GuardianClient::new(machine_root.join("guardian")).owner_identity(machine.clone()) {
        Ok(_) => return Ok(()),
        Err(crate::guardian::Error::Io(error))
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => {
            return Err(io::Error::other(format!(
                "existing guardian is unhealthy; refusing a second owner: {error}"
            )));
        }
    }
    if children.len() >= MAX_CHILDREN {
        return Err(io::Error::other("guardian supervision capacity exhausted"));
    }
    #[cfg(target_os = "linux")]
    let native_unit = {
        let journal = sandsurf_state::RuntimeJournal::open(&machine_root.join("runtime"), &machine)
            .map_err(io::Error::other)?;
        !journal
            .last_observation()
            .map_err(io::Error::other)?
            .is_some_and(|value| value.value().state == sandsurf_protocol::MachineState::Destroyed)
    };
    let path = machine_root.join("guardian/guardian.log");
    let mut log = match sandsurf_native::local::create_private_file(&path) {
        Ok(log) => log,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            sandsurf_native::local::open_private_file(
                &path,
                sandsurf_native::PrivateFileAccess::ReadWrite,
            )?
        }
        Err(error) => return Err(error),
    };
    log.seek(SeekFrom::End(0))?;
    #[cfg(target_os = "linux")]
    let mut command = if native_unit {
        let config =
            crate::linux::read_config(&machine_root.join("guardian/config.json"), &machine)
                .map_err(io::Error::other)?;
        let mut command = Command::new("systemd-run");
        command.args([
            "--user",
            "--wait",
            "--pipe",
            "--collect",
            "--quiet",
            "--service-type=exec",
        ]);
        command.arg(format!(
            "--unit={}",
            sandsurf_native::resources::unit_name(&machine_root)?
        ));
        for property in sandsurf_native::resources::systemd_properties(config.resources())? {
            command.arg(format!("--property={property}"));
        }
        // The service inherits none of the supervisor's guest descriptors.
        command.arg("--").arg(executable);
        command
    } else {
        // No VM exists. Historical access is a short-lived journal owner in
        // the bounded supervisor pool, not a resurrected VM-sized reservation.
        Command::new(executable)
    };
    #[cfg(not(target_os = "linux"))]
    let mut command = Command::new(executable);
    let child = command
        .args(["guardian", "--directory"])
        .arg(root)
        .arg("--machine")
        .arg(machine.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()?;
    children.insert(
        machine,
        OwnedGuardian {
            child,
            #[cfg(target_os = "linux")]
            native_unit,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_vocabulary_has_no_host_path_or_executable_authority() {
        for payload in [
            r#"{"kind":"ensure","machine":"box","executable":"/bin/sh"}"#,
            r#"{"kind":"ensure","machine":"../outside"}"#,
            r#"{"kind":"ensure","machine":"box","directory":"/outside"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(payload).is_err());
        }
        assert!(serde_json::from_str::<Request>(r#"{"kind":"ensure","machine":"box"}"#).is_ok());
    }
}
