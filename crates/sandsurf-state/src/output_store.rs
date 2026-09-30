//! Immutable payload objects under the guardian's sole retention ledger.
//! Filesystem publication is not capture completion: the journal must commit
//! the corresponding ordered chunk before exposing or acknowledging it.

use crate::{Error, Result, database::private_file};
use sandsurf_protocol::{Digest, MAX_STREAM_BYTES, bytes_digest};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) fn root(journal: &Path) -> PathBuf {
    journal.join("output")
}
pub(crate) fn blob_path(journal: &Path, digest: &Digest) -> PathBuf {
    root(journal).join(digest.as_str())
}
fn stage_path(journal: &Path, digest: &Digest) -> PathBuf {
    root(journal).join(format!("{}.staged", digest.as_str()))
}

pub(crate) fn create(journal: &Path) -> Result<()> {
    sandsurf_native::local::create_private_directory(&root(journal))?;
    sandsurf_native::storage::sync_directory(journal)?;
    Ok(())
}
pub(crate) fn validate(journal: &Path) -> Result<()> {
    sandsurf_native::local::canonical_private_directory(&root(journal))?;
    Ok(())
}

pub(crate) fn read(journal: &Path, digest: &Digest, length: usize) -> Result<Vec<u8>> {
    read_path(&blob_path(journal, digest), digest, length)
}

fn read_path(path: &Path, digest: &Digest, length: usize) -> Result<Vec<u8>> {
    if length == 0 || length > MAX_STREAM_BYTES {
        return Err(Error::Corrupt("immutable output object length is invalid"));
    }
    let file = sandsurf_native::local::open_private_file(
        path,
        sandsurf_native::PrivateFileAccess::ReadOnly,
    )?;
    if file.metadata()?.len() != length as u64 {
        return Err(Error::Corrupt("immutable output object length changed"));
    }
    let mut bytes = Vec::with_capacity(length);
    file.take(length as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != length || bytes_digest(&bytes) != *digest {
        return Err(Error::Corrupt(
            "immutable output object is missing or corrupt",
        ));
    }
    Ok(bytes)
}

/// Only called after the journal commits the exact pending capture intent.
/// Existing published bytes are verified, never rewritten or repaired.
pub(crate) fn publish(journal: &Path, digest: &Digest, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_STREAM_BYTES || bytes_digest(bytes) != *digest {
        return Err(Error::Corrupt(
            "output publication differs from its capture intent",
        ));
    }
    let destination = blob_path(journal, digest);
    match read(journal, digest, bytes.len()) {
        Ok(original) if original == bytes => return Ok(()),
        Ok(_) => return Err(Error::Corrupt("immutable output object bytes differ")),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let staged = stage_path(journal, digest);
    // An interrupted stage belongs to the still-committed write intent. It
    // has never been exposed as captured output and is safe to replace.
    remove(&staged)?;
    let mut file = private_file(&staged, true)?;
    file.write_all(bytes)?;
    drop(file);
    match sandsurf_native::storage::publish_new_file(&staged, &destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read(journal, digest, bytes.len())? != bytes {
                return Err(Error::Corrupt("concurrent output publication differs"));
            }
            remove(&staged)?;
            sandsurf_native::storage::sync_directory(&root(journal))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Recover only bytes justified by a pending journal intent. Partial stages
/// are uncommitted; published objects are never silently repaired.
pub(crate) fn recover(journal: &Path, digest: &Digest, length: usize) -> Result<Option<Vec<u8>>> {
    match read(journal, digest, length) {
        Ok(bytes) => return Ok(Some(bytes)),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match read_path(&stage_path(journal, digest), digest, length) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(Error::Corrupt(_)) => {
            remove_stage(journal, digest)?;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn remove_blob(journal: &Path, digest: &Digest) -> Result<()> {
    remove(&blob_path(journal, digest))?;
    sandsurf_native::storage::sync_directory(&root(journal))?;
    Ok(())
}
pub(crate) fn remove_stage(journal: &Path, digest: &Digest) -> Result<()> {
    remove(&stage_path(journal, digest))?;
    sandsurf_native::storage::sync_directory(&root(journal))?;
    Ok(())
}
fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Store(PathBuf);
    impl Store {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-output-objects-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            sandsurf_native::local::create_private_directory(&path).unwrap();
            create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Store {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn publication_verifies_and_reuses_originals_without_rewriting() {
        let store = Store::new();
        let bytes = b"original\0\xff";
        let digest = bytes_digest(bytes);
        publish(&store.0, &digest, bytes).unwrap();
        let file = private_file(&blob_path(&store.0, &digest), false).unwrap();
        let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        file.set_times(fs::FileTimes::new().set_modified(stamp))
            .unwrap();
        drop(file);
        let before = fs::metadata(blob_path(&store.0, &digest))
            .unwrap()
            .modified()
            .unwrap();
        publish(&store.0, &digest, bytes).unwrap();
        assert_eq!(
            fs::metadata(blob_path(&store.0, &digest))
                .unwrap()
                .modified()
                .unwrap(),
            before
        );
        assert_eq!(read(&store.0, &digest, bytes.len()).unwrap(), bytes);
        assert!(read(&store.0, &digest, bytes.len() + 1).is_err());
        fs::write(blob_path(&store.0, &digest), b"corrupt\0\xff").unwrap();
        assert!(publish(&store.0, &digest, bytes).is_err());
        assert_eq!(
            fs::read(blob_path(&store.0, &digest)).unwrap(),
            b"corrupt\0\xff"
        );
    }

    #[test]
    fn recovery_distinguishes_partial_stages_from_changed_published_objects() {
        let store = Store::new();
        let bytes = b"complete";
        let digest = bytes_digest(bytes);
        assert_eq!(recover(&store.0, &digest, bytes.len()).unwrap(), None);
        let stage = stage_path(&store.0, &digest);
        let mut file = private_file(&stage, true).unwrap();
        file.write_all(b"part").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(recover(&store.0, &digest, bytes.len()).unwrap(), None);
        assert!(!stage.exists());
        let mut file = private_file(&stage, true).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            recover(&store.0, &digest, bytes.len()).unwrap(),
            Some(bytes.to_vec())
        );
        publish(&store.0, &digest, bytes).unwrap();
        assert!(!stage.exists());
        fs::write(blob_path(&store.0, &digest), b"tampered").unwrap();
        assert!(recover(&store.0, &digest, bytes.len()).is_err());
        assert_eq!(fs::read(blob_path(&store.0, &digest)).unwrap(), b"tampered");
    }
}
