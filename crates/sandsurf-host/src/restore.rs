//! Durable managed-execution integration intent, separate from native power.
//! Losing a response or failing integration does not undo an observed resume.

use crate::guardian::{Error, Result};
use sandsurf_native::PrivateFileAccess;
use sandsurf_protocol::{Counter, Digest, MachineId, OperationId, SnapshotId};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use std::path::Path;

const MAX_RECORD_BYTES: u64 = sandsurf_protocol::MAX_CONTROL_BYTES as u64;
const RECORD: &str = "restore-integration.json";

/// Captured host channel/boot input shared by native adapters. Possession of
/// its guest-held capability is not guest attestation or host authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReconnectState {
    pub format_version: u16,
    pub snapshot_id: SnapshotId,
    pub capture_operation_id: OperationId,
    pub machine_id: MachineId,
    pub generation: Counter,
    pub boot_identity: Digest,
    pub capability: [u8; 32],
    pub boot: sandsurf_image::boot::FrozenBoot,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record<T> {
    version: u16,
    manifest_digest: Digest,
    value: T,
}

fn read<T: DeserializeOwned>(root: &Path) -> Result<Option<Record<T>>> {
    let file = match sandsurf_native::local::open_private_file(
        &root.join("guardian").join(RECORD),
        PrivateFileAccess::ReadOnly,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_RECORD_BYTES {
        return Err(Error::Protocol(
            "restore integration intent exceeds its bound",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::Protocol(
            "restore integration intent exceeds its bound",
        ));
    }
    let value: Record<T> = serde_json::from_slice(&bytes)?;
    if value.version != 1 {
        return Err(Error::Protocol("incompatible restore integration intent"));
    }
    Ok(Some(value))
}

pub(crate) fn load<T: DeserializeOwned>(root: &Path) -> Result<Option<T>> {
    Ok(read::<T>(root)?.map(|record| record.value))
}

/// Reuse the exact first admission, including reconnect entropy. Never create
/// different connection material merely because a staging response was lost.
pub(crate) fn stage<T: Serialize + DeserializeOwned>(
    root: &Path,
    manifest_digest: Digest,
    create: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if let Some(record) = read::<T>(root)? {
        if record.manifest_digest != manifest_digest {
            return Err(Error::Protocol(
                "another restore owns execution integration",
            ));
        }
        return Ok(record.value);
    }
    let directory = root.join("guardian");
    sandsurf_native::local::ensure_private_directory(&directory)?;
    let record = Record {
        version: 1,
        manifest_digest,
        value: create()?,
    };
    let bytes = serde_json::to_vec(&record)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::Protocol(
            "restore integration intent exceeds its bound",
        ));
    }
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| Error::Protocol("restore publication entropy unavailable"))?;
    let staged = directory.join(format!(".restore-{}.tmp", u128::from_le_bytes(nonce)));
    let mut file = sandsurf_native::local::create_private_file(&staged)?;
    let publication = (|| -> Result<()> {
        file.write_all(&bytes)?;
        drop(file);
        sandsurf_native::storage::publish_new_file(&staged, &directory.join(RECORD))?;
        Ok(())
    })();
    if publication.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    publication?;
    Ok(record.value)
}

/// Only call after the integration journal transaction commits. No native
/// handle or storage custody is released by completing this bookkeeping step.
pub(crate) fn complete(root: &Path) -> Result<()> {
    let directory = root.join("guardian");
    let path = directory.join(RECORD);
    match sandsurf_native::local::open_private_file(&path, PrivateFileAccess::ReadOnly) {
        Ok(file) => drop(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    std::fs::remove_file(path)?;
    sandsurf_native::storage::sync_directory(&directory)?;
    Ok(())
}

/// Remove only this guardian's verified native restore-stage copy. The
/// immutable snapshot and every retained execution original remain intact.
#[cfg(any(target_os = "macos", windows, test))]
pub(crate) fn retire_stage(root: &Path, stage: &Path) -> Result<()> {
    let directory = root.join("guardian/restores");
    let valid_name = stage
        .file_stem()
        .and_then(|name| name.to_str())
        .is_some_and(|name| Digest::try_from(name.to_owned()).is_ok());
    let valid_extension = stage
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "vmstate");
    if stage.parent() != Some(directory.as_path()) || !valid_name || !valid_extension {
        return Err(Error::Protocol("restore stage escapes guardian ownership"));
    }
    match sandsurf_native::local::open_private_file(stage, PrivateFileAccess::ReadOnly) {
        Ok(file) => drop(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    std::fs::remove_file(stage)?;
    sandsurf_native::storage::sync_directory(&directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn stage_retirement_cannot_remove_snapshot_originals_or_foreign_paths() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-restore-retire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        sandsurf_native::local::create_private_directory(&root).unwrap();
        let digest = sandsurf_protocol::bytes_digest(b"snapshot");
        sandsurf_native::local::ensure_private_directory(&root.join("guardian")).unwrap();
        let directory = root.join("guardian/restores");
        sandsurf_native::local::ensure_private_directory(&directory).unwrap();
        let original = root.join(format!("{}.vmstate", digest.as_str()));
        sandsurf_native::local::create_private_file(&original)
            .unwrap()
            .write_all(b"immutable original")
            .unwrap();
        assert!(retire_stage(&root, &original).is_err());
        assert_eq!(std::fs::read(&original).unwrap(), b"immutable original");
        let stage = directory.join(format!("{}.vmstate", digest.as_str()));
        sandsurf_native::local::create_private_file(&stage)
            .unwrap()
            .write_all(b"native stage")
            .unwrap();
        retire_stage(&root, &stage).unwrap();
        retire_stage(&root, &stage).unwrap();
        assert_eq!(std::fs::read(&original).unwrap(), b"immutable original");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn admission_survives_reopen_and_conflicting_retry_cannot_replace_it() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-restore-intent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        sandsurf_native::local::create_private_directory(&root).unwrap();
        let manifest = sandsurf_protocol::bytes_digest(b"snapshot");
        let first = stage(&root, manifest.clone(), || Ok(vec![1_u8, 2, 3])).unwrap();
        assert_eq!(load::<Vec<u8>>(&root).unwrap(), Some(first.clone()));
        assert_eq!(
            stage::<Vec<u8>>(&root, manifest, || panic!("retried entropy")).unwrap(),
            first
        );
        assert!(
            stage(&root, sandsurf_protocol::bytes_digest(b"different"), || Ok(
                vec![4_u8]
            ))
            .is_err()
        );
        assert_eq!(load::<Vec<u8>>(&root).unwrap(), Some(first));
        complete(&root).unwrap();
        assert_eq!(load::<Vec<u8>>(&root).unwrap(), None);
        complete(&root).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
