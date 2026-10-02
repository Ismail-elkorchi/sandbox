//! Guardian-owned native pause transaction. This is not lifecycle intent.
//! Persist before touching the VM so an interrupted host request can release
//! precisely its own capture, preserving a pause requested by the application.

use crate::guardian::{Error, Result};
use sandsurf_protocol::{Counter, MachineState, OperationId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) fn full_directory(root: &Path, operation_id: &OperationId) -> PathBuf {
    root.join("guardian/full-captures")
        .join(sandsurf_native::storage::object_name(operation_id.as_str()))
}

/// Reclaim only an unpublished host copy, while this operation still owns the
/// native pause. The engine's own save files are not in this directory. A
/// committed capture is immutable and must instead be released after copying
/// its complete contents into the durable snapshot store.
pub(crate) fn reset_unpublished_full(root: &Path, operation_id: &OperationId) -> Result<()> {
    CaptureBoundary::require(root, operation_id)?
        .ok_or(Error::Protocol("capture staging has no pause owner"))?;
    let directory = full_directory(root, operation_id);
    match sandsurf_native::local::open_private_file(
        &directory.join("capture.json"),
        sandsurf_native::PrivateFileAccess::ReadOnly,
    ) {
        Ok(_) => return Err(Error::Protocol("cannot reset a committed full capture")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    remove_full(root, operation_id)
}

/// Remove the exact guardian-owned working copy, never a published snapshot.
pub(crate) fn remove_full(root: &Path, operation_id: &OperationId) -> Result<()> {
    let directory = full_directory(root, operation_id);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(Error::Protocol("capture staging is not an owned directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    sandsurf_native::local::ensure_private_directory(&directory)?;
    // Recursive removal does not follow symlinks. Unknown files remain owned
    // by this unpublished stage too (e.g. an interrupted boot publication).
    fs::remove_dir_all(&directory)?;
    sandsurf_native::storage::sync_directory(
        directory
            .parent()
            .ok_or(Error::Protocol("capture staging has no parent"))?,
    )?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureBoundary {
    pub operation_id: OperationId,
    pub generation: Counter,
    pub preserve_pause: bool,
}

impl CaptureBoundary {
    /// Only a positively observed native transition can retire an interrupted
    /// pause. Running alone cannot clear its owner; management health is absent
    /// from this decision. Both native adapters use this same recovery rule.
    pub fn reconcile_transition(
        root: &Path,
        outcome: &sandsurf_machine::MachineOutcome,
    ) -> Result<bool> {
        let sandsurf_machine::MachineOutcome::Observed(values) = outcome else {
            return Ok(false);
        };
        let Some(last) = values.last() else {
            return Ok(false);
        };
        if matches!(
            last.state,
            MachineState::Suspended | MachineState::Stopped | MachineState::Destroyed
        ) {
            Self::clear(root)?;
        }
        Ok(matches!(
            last.state,
            MachineState::Running
                | MachineState::Suspended
                | MachineState::Stopped
                | MachineState::Destroyed
        ) && Self::read(root)?.is_none())
    }

    /// A lost native resume response is not permission to resume twice, and a
    /// failed preparation is not proof that the computer was ever paused.
    pub fn needs_resume(&self, observed: MachineState) -> Result<bool> {
        match observed {
            MachineState::Paused => Ok(!self.preserve_pause),
            MachineState::Running | MachineState::Stopped | MachineState::Failed => Ok(false),
            _ => Err(Error::Unsupported(
                "native capture power state is indeterminate",
            )),
        }
    }

    pub fn read(root: &Path) -> Result<Option<Self>> {
        let path = root.join("guardian/capture-boundary.json");
        let file = match sandsurf_native::local::open_private_file(
            &path,
            sandsurf_native::PrivateFileAccess::ReadOnly,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if file.metadata()?.len() > 4096 {
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
        if let Some(active) = Self::read(root)? {
            if active.operation_id != operation_id || active.generation != generation {
                return Err(Error::Protocol(
                    "another native capture owns the pause boundary",
                ));
            }
            return Ok(active);
        }
        let boundary = Self {
            operation_id,
            generation,
            preserve_pause: state == MachineState::Paused,
        };
        let directory = root.join("guardian");
        crate::snapshots::private_directory(&directory)
            .map_err(|_| Error::Protocol("native capture directory is not private"))?;
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| Error::Protocol("capture nonce unavailable"))?;
        let temporary = directory.join(format!(".capture-{}.tmp", u128::from_le_bytes(nonce)));
        let mut file = sandsurf_native::local::create_private_file(&temporary)?;
        let publication = (|| -> Result<()> {
            file.write_all(&serde_json::to_vec(&boundary)?)?;
            drop(file);
            sandsurf_native::storage::publish_new_file(
                &temporary,
                &directory.join("capture-boundary.json"),
            )?;
            Ok(())
        })();
        if publication.is_err() {
            // Only this newly created stage is reclaimed, after its protected
            // writer closes. A published ownership record is left for recovery.
            let _ = fs::remove_file(&temporary);
        }
        publication?;
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
        let path = directory.join("capture-boundary.json");
        match sandsurf_native::local::open_private_file(
            &path,
            sandsurf_native::PrivateFileAccess::ReadOnly,
        ) {
            Ok(file) => drop(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        fs::remove_file(path)?;
        sandsurf_native::storage::sync_directory(&directory)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn uncertain_or_running_power_never_retires_an_interrupted_capture() {
        let root = Temp::new();
        CaptureBoundary::begin(
            &root.0,
            "capture".try_into().unwrap(),
            Counter::ONE,
            MachineState::Running,
        )
        .unwrap();
        assert!(
            !CaptureBoundary::reconcile_transition(
                &root.0,
                &sandsurf_machine::MachineOutcome::Unknown
            )
            .unwrap()
        );
        let observed = |state| {
            sandsurf_machine::MachineOutcome::Observed(vec![sandsurf_machine::MachineTransition {
                generation: Counter::ONE,
                state,
                evidence_digest: sandsurf_protocol::bytes_digest(b"native transition"),
            }])
        };
        for state in [
            MachineState::Running,
            MachineState::Paused,
            MachineState::Failed,
        ] {
            assert!(!CaptureBoundary::reconcile_transition(&root.0, &observed(state)).unwrap());
            assert!(CaptureBoundary::read(&root.0).unwrap().is_some());
        }
        assert!(
            CaptureBoundary::reconcile_transition(&root.0, &observed(MachineState::Stopped))
                .unwrap()
        );
        assert!(CaptureBoundary::read(&root.0).unwrap().is_none());
        assert!(
            CaptureBoundary::reconcile_transition(&root.0, &observed(MachineState::Running))
                .unwrap()
        );
    }

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "sandsurf-capture-stage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            sandsurf_native::local::create_private_directory(&root).unwrap();
            Self(root)
        }
        fn stage(&self, operation: &OperationId) -> PathBuf {
            let directory = full_directory(&self.0, operation);
            sandsurf_native::local::create_private_directory(directory.parent().unwrap()).unwrap();
            sandsurf_native::local::create_private_directory(&directory).unwrap();
            directory
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn capture_release_uses_native_power_not_a_prior_resume_response() {
        let mut boundary = CaptureBoundary {
            operation_id: "capture".try_into().unwrap(),
            generation: Counter::ONE,
            preserve_pause: false,
        };
        assert!(boundary.needs_resume(MachineState::Paused).unwrap());
        for state in [
            MachineState::Running,
            MachineState::Stopped,
            MachineState::Failed,
        ] {
            assert!(!boundary.needs_resume(state).unwrap());
        }
        assert!(boundary.needs_resume(MachineState::Starting).is_err());
        boundary.preserve_pause = true;
        assert!(!boundary.needs_resume(MachineState::Paused).unwrap());
    }

    #[test]
    fn interrupted_full_capture_reclaims_all_partial_bytes_without_losing_ownership() {
        let root = Temp::new();
        let operation: OperationId = "capture".try_into().unwrap();
        let boundary = CaptureBoundary::begin(
            &root.0,
            operation.clone(),
            Counter::ONE,
            MachineState::Running,
        )
        .unwrap();
        let directory = root.stage(&operation);
        for name in ["reconnect.json", "snapshot.vmstate", "memory"] {
            fs::write(directory.join(name), b"incomplete").unwrap();
        }
        sandsurf_native::local::create_private_directory(&directory.join("boot")).unwrap();
        fs::write(
            directory.join("boot/.publication.tmp"),
            b"incomplete kernel",
        )
        .unwrap();
        reset_unpublished_full(&root.0, &operation).unwrap();
        assert!(!directory.exists());
        assert_eq!(CaptureBoundary::read(&root.0).unwrap(), Some(boundary));
        reset_unpublished_full(&root.0, &operation).unwrap();
        assert!(
            CaptureBoundary::require(&root.0, &operation)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn full_capture_cleanup_rejects_other_owners_and_keeps_committed_bytes() {
        let root = Temp::new();
        let operation: OperationId = "capture".try_into().unwrap();
        CaptureBoundary::begin(
            &root.0,
            operation.clone(),
            Counter::ONE,
            MachineState::Paused,
        )
        .unwrap();
        let directory = root.stage(&operation);
        sandsurf_native::local::create_private_file(&directory.join("capture.json"))
            .unwrap()
            .write_all(b"committed")
            .unwrap();
        assert!(reset_unpublished_full(&root.0, &operation).is_err());
        assert!(reset_unpublished_full(&root.0, &"different".try_into().unwrap()).is_err());
        assert_eq!(
            fs::read(directory.join("capture.json")).unwrap(),
            b"committed"
        );
        fs::create_dir(root.0.join("snapshot-store")).unwrap();
        fs::write(root.0.join("snapshot-store/receipt"), b"published").unwrap();
        CaptureBoundary::clear(&root.0).unwrap();
        assert!(reset_unpublished_full(&root.0, &operation).is_err());
        remove_full(&root.0, &operation).unwrap();
        remove_full(&root.0, &operation).unwrap();
        assert_eq!(
            fs::read(root.0.join("snapshot-store/receipt")).unwrap(),
            b"published"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_cleanup_never_follows_a_stage_symlink() {
        let root = Temp::new();
        let operation: OperationId = "capture".try_into().unwrap();
        CaptureBoundary::begin(
            &root.0,
            operation.clone(),
            Counter::ONE,
            MachineState::Paused,
        )
        .unwrap();
        let directory = root.stage(&operation);
        fs::remove_dir(&directory).unwrap();
        fs::create_dir(root.0.join("external")).unwrap();
        fs::write(root.0.join("external/data"), b"keep").unwrap();
        std::os::unix::fs::symlink(root.0.join("external"), directory).unwrap();
        assert!(remove_full(&root.0, &operation).is_err());
        assert_eq!(fs::read(root.0.join("external/data")).unwrap(), b"keep");
    }

    #[test]
    fn interrupted_capture_retains_exact_operation_and_public_pause() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-capture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        }
        #[cfg(windows)]
        sandsurf_native::local::create_private_directory(&root).unwrap();
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
        assert_eq!(
            original,
            CaptureBoundary::begin(
                &root,
                operation.clone(),
                Counter::ONE,
                MachineState::Running
            )
            .unwrap(),
            "retry must preserve the recorded pause owner, not reinterpret a later observation"
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
        let record = root.join("guardian/capture-boundary.json");
        let mut file = sandsurf_native::local::create_private_file(&record).unwrap();
        file.write_all(b"damaged ownership record").unwrap();
        drop(file);
        assert!(CaptureBoundary::read(&root).is_err());
        CaptureBoundary::clear(&root).unwrap();
        CaptureBoundary::clear(&root).unwrap();
        let mut file = sandsurf_native::local::create_private_file(&record).unwrap();
        file.write_all(b"aliased record must remain untouched")
            .unwrap();
        drop(file);
        fs::hard_link(&record, root.join("record-alias")).unwrap();
        assert!(CaptureBoundary::read(&root).is_err());
        assert!(CaptureBoundary::clear(&root).is_err());
        assert_eq!(
            fs::read(&record).unwrap(),
            b"aliased record must remain untouched"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
