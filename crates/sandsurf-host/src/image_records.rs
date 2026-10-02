//! Immutable host records. Native configurations, jobs and terminal results use one
//! bounded, no-replace publication mechanism; partial writes are never results.
use sandsurf_native::local::{create_private_file, open_private_file};
use sandsurf_native::storage::{publish_new_file, sync_file};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};
use std::path::Path;

const MAXIMUM: usize = 1024 * 1024;

pub(crate) fn read<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let file = open_private_file(path, sandsurf_native::PrivateFileAccess::ReadOnly)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "image record exceeds bound",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(crate) fn publish<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAXIMUM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "image record exceeds bound",
        ));
    }
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
    let pending = path.with_extension(format!(
        "{}.pending",
        sandsurf_protocol::bytes_digest(&nonce).as_str()
    ));
    let mut file = create_private_file(&pending)?;
    file.write_all(&bytes)?;
    sync_file(&file)?;
    drop(file);
    let result = publish_new_file(&pending, path);
    if result.is_err() {
        let _ = std::fs::remove_file(&pending);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_interrupted_pending_record_is_not_an_outcome_and_cannot_replace_one() {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "sandsurf-image-records-{}",
            sandsurf_protocol::bytes_digest(&nonce).as_str()
        ));
        sandsurf_native::local::create_private_directory(&root).unwrap();
        let result = root.join("result.json");
        let pending = root.join("interrupted.pending");
        create_private_file(&pending)
            .unwrap()
            .write_all(b"{\"incomplete\":")
            .unwrap();
        assert_eq!(
            read::<serde_json::Value>(&result).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        publish(&result, &serde_json::json!({"image":"complete"})).unwrap();
        assert!(publish(&result, &serde_json::json!({"image":"different"})).is_err());
        assert_eq!(
            read::<serde_json::Value>(&result).unwrap(),
            serde_json::json!({"image":"complete"})
        );
        assert_eq!(std::fs::read(&pending).unwrap(), b"{\"incomplete\":");
        std::fs::remove_dir_all(root).unwrap();
    }
}
