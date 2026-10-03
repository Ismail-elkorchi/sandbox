use crate::appliance::{Executor, Filesystem};
use sandsurf_protocol::disk::DiskOperation;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

/// A declared cloning contract, not a universal sanitizer. Application IDs,
/// credentials and copied data remain sensitive under either contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CloneProfile {
    Alpine,
    /// Caller explicitly accepts all filesystem identity duplication.
    Preserve,
}

/// Only appliance filesystem operations, never guest-controlled executables.
/// Fresh machine-id is host random; SSH keys are removed and the declared
/// first-boot service generates new keys from the new VM's entropy.
pub fn customize(
    executor: &mut dyn Executor,
    custody: Vec<Arc<File>>,
    disk: &Path,
    profile: &CloneProfile,
) -> io::Result<()> {
    if *profile == CloneProfile::Preserve {
        return Ok(());
    }
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(io::Error::other)?;
    let identity: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut operations = vec![DiskOperation::Mount { writable: true }];
    // Remove final links first. Appliance containment also prevents malicious
    // directory links from reaching host paths; failures abort publication.
    for path in [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/var/lib/systemd/random-seed",
        "/var/lib/urandom/random-seed",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_rsa_key.pub",
        "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ecdsa_key.pub",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/etc/ssh/ssh_host_dsa_key",
        "/etc/ssh/ssh_host_dsa_key.pub",
    ] {
        operations.push(DiskOperation::Remove { path: path.into() });
    }
    operations.push(DiskOperation::Write {
        path: "/etc/machine-id".into(),
        bytes: format!("{identity}\n"),
    });
    operations.push(DiskOperation::Chmod {
        path: "/etc/machine-id".into(),
        mode: 0o644,
    });
    operations.push(DiskOperation::Write {
        path: "/etc/sandsurf-clone-pending".into(),
        bytes: "managed-alpine\n".into(),
    });
    operations.push(DiskOperation::Sync);
    let mut appliance = executor.open(disk, true, custody)?;
    for operation in operations {
        appliance.run(operation)?;
    }
    appliance.run(DiskOperation::Unmount)?;
    appliance.finish()?;
    Ok(())
}
