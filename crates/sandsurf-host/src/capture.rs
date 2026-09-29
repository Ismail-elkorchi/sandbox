//! Guardian-owned native pause transaction. This is not lifecycle intent.
//! Persist before touching the VM so an interrupted host request can release
//! precisely its own capture, preserving a pause requested by the application.

use crate::guardian::{Error, Result};
use sandsurf_protocol::{Counter, MachineState, OperationId};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureBoundary {
    pub operation_id: OperationId,
    pub generation: Counter,
    pub preserve_pause: bool,
}

impl CaptureBoundary {
    pub fn read(root: &Path) -> Result<Option<Self>> {
        let path = root.join("guardian/capture-boundary.json");
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !file.metadata()?.is_file() || file.metadata()?.len() > 4096 {
            return Err(Error::Protocol("invalid native capture boundary"));
        }
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub fn begin(
        root: &Path,
        operation_id: OperationId,
        generation: Counter,
        state: MachineState,
    ) -> Result<Self> {
        if !matches!(state, MachineState::Running | MachineState::Paused) {
            return Err(Error::Unsupported(
                "capture requires a running or paused computer",
            ));
        }
        let boundary = Self {
            operation_id,
            generation,
            preserve_pause: state == MachineState::Paused,
        };
        if let Some(active) = Self::read(root)? {
            if active != boundary {
                return Err(Error::Protocol(
                    "another native capture owns the pause boundary",
                ));
            }
            return Ok(active);
        }
        let directory = root.join("guardian");
        crate::snapshots::private_directory(&directory)
            .map_err(|_| Error::Protocol("native capture directory is not private"))?;
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| Error::Protocol("capture nonce unavailable"))?;
        let temporary = directory.join(format!(".capture-{}.tmp", u128::from_le_bytes(nonce)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec(&boundary)?)?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join("capture-boundary.json"))?;
        crate::snapshots::sync_directory(&directory)
            .map_err(|_| Error::Protocol("native capture boundary durability failed"))?;
        Ok(boundary)
    }

    pub fn require(root: &Path, operation_id: &OperationId) -> Result<Option<Self>> {
        let active = Self::read(root)?;
        if active
            .as_ref()
            .is_some_and(|value| &value.operation_id != operation_id)
        {
            return Err(Error::Protocol(
                "capture release belongs to a different operation",
            ));
        }
        Ok(active)
    }

    pub fn clear(root: &Path) -> Result<()> {
        let directory = root.join("guardian");
        match fs::remove_file(directory.join("capture-boundary.json")) {
            Ok(()) => crate::snapshots::sync_directory(&directory)
                .map_err(|_| Error::Protocol("capture release durability failed")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn interrupted_capture_retains_exact_operation_and_public_pause() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-capture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut directory = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(&root).unwrap();
        let operation: OperationId = "capture".try_into().unwrap();
        let original =
            CaptureBoundary::begin(&root, operation.clone(), Counter::ONE, MachineState::Paused)
                .unwrap();
        assert!(
            CaptureBoundary::read(&root)
                .unwrap()
                .unwrap()
                .preserve_pause
        );
        assert_eq!(
            original,
            CaptureBoundary::begin(&root, operation.clone(), Counter::ONE, MachineState::Paused)
                .unwrap()
        );
        assert!(CaptureBoundary::require(&root, &"wrong".try_into().unwrap()).is_err());
        assert!(
            CaptureBoundary::begin(
                &root,
                operation.clone(),
                Counter::ONE.next().unwrap(),
                MachineState::Paused
            )
            .is_err()
        );
        CaptureBoundary::require(&root, &operation).unwrap();
        CaptureBoundary::clear(&root).unwrap();
        assert!(CaptureBoundary::read(&root).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
