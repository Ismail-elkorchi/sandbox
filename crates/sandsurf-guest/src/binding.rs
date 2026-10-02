//! Guest-owned reconnect data. Root may change or delete it; it is not host authority.

use sandsurf_protocol::{BootCapability, BootIdentity, Counter, Digest, GuestBootId, MachineId};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const MAX_BINDING_BYTES: u64 = 4096;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    boot_id: GuestBootId,
    machine_id: MachineId,
    generation: Counter,
    boot_digest: Digest,
    capability: [u8; 32],
}

pub fn load(path: &Path, boot_id: &GuestBootId) -> io::Result<Option<BootIdentity>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_BINDING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest reconnect binding exceeds its bound",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BINDING_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BINDING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest reconnect binding grew beyond its bound",
        ));
    }
    let value: Binding = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if &value.boot_id != boot_id {
        return Ok(None);
    }
    if value.generation == Counter::ZERO || value.capability.iter().all(|byte| *byte == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest reconnect binding is invalid",
        ));
    }
    Ok(Some(BootIdentity {
        machine_id: value.machine_id,
        generation: value.generation,
        boot_digest: value.boot_digest,
        capability: BootCapability::from_bytes(value.capability),
    }))
}

pub fn save(path: &Path, boot_id: &GuestBootId, identity: &BootIdentity) -> io::Result<()> {
    let value = Binding {
        boot_id: boot_id.clone(),
        machine_id: identity.machine_id.clone(),
        generation: identity.generation,
        boot_digest: identity.boot_digest.clone(),
        capability: identity.capability.secret_bytes(),
    };
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "binding requires a parent"))?;
    let temporary = parent.join(format!(".binding-{}.pending", super::hex(&nonce)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(&value).map_err(io::Error::other)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn service_restart_uses_current_binding_but_cold_boot_does_not() {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("sandsurf-binding-{}", super::super::hex(&nonce)));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("binding.json");
        let boot: GuestBootId = "linux-boot-one".try_into().unwrap();
        let mut identity = BootIdentity {
            machine_id: "machine-one".try_into().unwrap(),
            generation: Counter::ONE,
            boot_digest: sandsurf_protocol::bytes_digest(b"initial"),
            capability: BootCapability::from_bytes([1; 32]),
        };
        assert!(load(&path, &boot).unwrap().is_none());
        save(&path, &boot, &identity).unwrap();
        identity.generation = Counter::ONE.next().unwrap();
        identity.capability = BootCapability::from_bytes([3; 32]);
        save(&path, &boot, &identity).unwrap();
        let restored = load(&path, &boot).unwrap().unwrap();
        assert_eq!(restored.generation, identity.generation);
        assert_eq!(restored.capability.secret_bytes(), [3; 32]);
        assert!(
            load(&path, &"linux-boot-two".try_into().unwrap())
                .unwrap()
                .is_none()
        );
        fs::write(&path, b"interrupted or corrupt guest state").unwrap();
        assert!(load(&path, &boot).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
