use crate::appliance::{self, command};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

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
pub fn customize(disk: &Path, profile: &CloneProfile) -> io::Result<()> {
    if *profile == CloneProfile::Preserve {
        return Ok(());
    }
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(io::Error::other)?;
    let identity: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut commands = vec![appliance::mount(true)];
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
        commands.push(command("rm-f", &[path]));
    }
    commands.push(command(
        "write",
        &["/etc/machine-id", &format!("{identity}\n")],
    ));
    commands.push(command("chmod", &["0644", "/etc/machine-id"]));
    commands.push(command(
        "write",
        &["/etc/sandsurf-clone-pending", "managed-alpine\n"],
    ));
    commands.push(command("sync", &[]));
    appliance::run(disk, true, &commands)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sandsurf_native::local::{create_private_directory, create_private_file};
    #[test]
    #[ignore = "native KVM/libguestfs clone qualification; run explicitly with --ignored"]
    fn managed_disk_clones_replace_os_identity_and_preserve_source() {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = Path::new("/var/tmp").join(format!(
            "sandsurf-clone-{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        create_private_directory(&root).unwrap();
        let source = root.join("source.raw");
        create_private_file(&source)
            .unwrap()
            .set_len(128 * 1024 * 1024)
            .unwrap();
        appliance::run(
            &source,
            true,
            &[
                command("mkfs", &["ext4", "/dev/sda"]),
                appliance::mount(true),
                command("mkdir-p", &["/etc/ssh"]),
                command("mkdir-p", &["/var/lib/dbus"]),
                command(
                    "write",
                    &["/etc/machine-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"],
                ),
                command(
                    "write",
                    &["/etc/ssh/ssh_host_ed25519_key", "source-host-key"],
                ),
                command("sync", &[]),
            ],
        )
        .unwrap();
        let first = root.join("first.raw");
        let second = root.join("second.raw");
        std::fs::copy(&source, &first).unwrap();
        std::fs::copy(&source, &second).unwrap();
        customize(&first, &CloneProfile::Alpine).unwrap();
        customize(&second, &CloneProfile::Alpine).unwrap();
        let read = |disk: &Path| {
            String::from_utf8(
                appliance::run(
                    disk,
                    false,
                    &[
                        appliance::mount(false),
                        command("cat", &["/etc/machine-id"]),
                    ],
                )
                .unwrap(),
            )
            .unwrap()
            .trim()
            .to_owned()
        };
        let first_id = read(&first);
        let second_id = read(&second);
        assert_ne!(first_id, second_id);
        assert_ne!(first_id, read(&source));
        assert_eq!(first_id.len(), 32);
        assert!(first_id.bytes().all(|b| b.is_ascii_hexdigit()));
        let exists = |disk: &Path| {
            appliance::run(
                disk,
                false,
                &[
                    appliance::mount(false),
                    command("exists", &["/etc/ssh/ssh_host_ed25519_key"]),
                ],
            )
            .unwrap()
        };
        assert_eq!(String::from_utf8(exists(&source)).unwrap().trim(), "true");
        assert_eq!(String::from_utf8(exists(&first)).unwrap().trim(), "false");
        let before = std::fs::read(&second).unwrap();
        customize(&second, &CloneProfile::Preserve).unwrap();
        assert_eq!(std::fs::read(&second).unwrap(), before);
        std::fs::remove_dir_all(root).unwrap();
    }
}
