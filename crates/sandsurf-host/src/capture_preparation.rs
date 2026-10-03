//! Native save and large artifact I/O have no journal or machine kill handle.
//! Original snapshot custody spans admission, I/O, and fenced publication.
use crate::guardian::{Error, Result};
use crate::restore::ReconnectState;
use sandsurf_machine::capture::{CaptureCompletion, CaptureTask, SnapshotFiles};
use sandsurf_protocol::{
    CapturedExecution, Counter, Digest, Domain, NativeFullCapture, OperationId, SnapshotArtifact,
    VmEngine, digest,
};
use std::fs::File;
use std::path::PathBuf;

pub enum CaptureAdmission {
    Ready(Box<NativeFullCapture>),
    Queued(Box<CapturePreparation>),
}

pub struct CapturePreparation {
    pub(crate) machine_root: PathBuf,
    pub(crate) operation: OperationId,
    pub(crate) boot_directory: PathBuf,
    pub(crate) reconnect: ReconnectState,
    pub(crate) engine: VmEngine,
    pub(crate) engine_version: String,
    pub(crate) architecture: String,
    pub(crate) configuration_digest: Digest,
    pub(crate) executions: Vec<CapturedExecution>,
    pub(crate) state_bound: u64,
    pub(crate) memory_bound: u64,
    pub(crate) native: Option<CaptureTask>,
    pub(crate) custody: File,
}

pub struct PreparedCapture {
    pub(crate) machine_root: PathBuf,
    pub(crate) operation: OperationId,
    pub(crate) native: Option<CaptureCompletion>,
    pub(crate) capture: Result<NativeFullCapture>,
    _custody: File,
}

impl CapturePreparation {
    pub(crate) fn execute(mut self: Box<Self>) -> Result<Box<PreparedCapture>> {
        let native = self
            .native
            .take()
            .ok_or(Error::Protocol("native save task already consumed"))?
            .execute();
        let capture = match &native.files {
            Ok(files) => self.materialize(files),
            Err(error) => Err(Error::Rejected {
                category: "snapshot".into(),
                message: error.to_string(),
            }),
        };
        Ok(Box::new(PreparedCapture {
            machine_root: self.machine_root,
            operation: self.operation,
            native: Some(native),
            capture,
            _custody: self.custody,
        }))
    }

    fn materialize(&self, files: &SnapshotFiles) -> Result<NativeFullCapture> {
        if files.state_bytes == 0
            || files.state_bytes > self.state_bound
            || files
                .memory
                .as_ref()
                .is_some_and(|(_, bytes)| *bytes == 0 || *bytes > self.memory_bound)
            || (self.engine == VmEngine::Firecracker) != files.memory.is_some()
        {
            return Err(Error::Protocol(
                "native saved state exceeds its declared shape or bound",
            ));
        }
        let directory = crate::capture::full_directory(&self.machine_root, &self.operation);
        let state = directory.join("snapshot.vmstate");
        let state_digest = if files.state == state {
            crate::snapshots::file_digest(&state, files.state_bytes)?
        } else {
            crate::snapshots::copy_and_verify(&files.state, &state, files.state_bytes, None)?
        };
        let memory = files
            .memory
            .as_ref()
            .map(|(path, bytes)| -> Result<SnapshotArtifact> {
                Ok(SnapshotArtifact {
                    digest: crate::snapshots::copy_and_verify(
                        path,
                        &directory.join("memory"),
                        *bytes,
                        None,
                    )?,
                    bytes: Counter::try_from(*bytes)
                        .map_err(|_| Error::Protocol("saved RAM length overflow"))?,
                })
            })
            .transpose()?;
        let mut reconnect = self.reconnect.clone();
        reconnect.boot = crate::storage::copy_boot(&self.boot_directory, &directory.join("boot"))?;
        let reconnect_path = directory.join("reconnect.json");
        crate::image_records::publish(&reconnect_path, &reconnect)?;
        let reconnect_bytes = reconnect_path.metadata()?.len();
        let reconnect_digest = crate::snapshots::file_digest(&reconnect_path, reconnect_bytes)?;
        let generation = digest(
            Domain::Snapshot,
            &(
                "sandsurf-full-capture-generation-v1",
                &reconnect.snapshot_id,
                &self.operation,
                &state_digest,
                &memory,
                &reconnect_digest,
            ),
        )
        .map_err(|_| Error::Protocol("full capture identity failed"))?;
        Ok(NativeFullCapture {
            engine: self.engine.clone(),
            engine_version: self.engine_version.clone(),
            architecture: self.architecture.clone(),
            configuration_digest: self.configuration_digest.clone(),
            executions: self.executions.clone(),
            snapshot_state: SnapshotArtifact {
                digest: state_digest,
                bytes: Counter::try_from(files.state_bytes)
                    .map_err(|_| Error::Protocol("saved state length overflow"))?,
            },
            memory,
            reconnect_state: SnapshotArtifact {
                digest: reconnect_digest,
                bytes: Counter::try_from(reconnect_bytes)
                    .map_err(|_| Error::Protocol("reconnect length overflow"))?,
            },
            generation,
        })
    }
}

/// Only the serialized control owner calls this, after native and authority
/// fencing. Worker completion never independently publishes a capture.
pub(crate) fn publish(prepared: &PreparedCapture) -> Result<NativeFullCapture> {
    let capture = prepared.capture.as_ref().map_err(|error| Error::Rejected {
        category: "snapshot".into(),
        message: error.to_string(),
    })?;
    let directory = crate::capture::full_directory(&prepared.machine_root, &prepared.operation);
    crate::image_records::publish(&directory.join("capture.json"), capture)?;
    Ok(capture.clone())
}

#[cfg(test)]
pub(crate) fn completion_fixture(root: &std::path::Path) -> Box<PreparedCapture> {
    Box::new(PreparedCapture {
        machine_root: root.to_owned(),
        operation: "capture".try_into().unwrap(),
        native: None,
        capture: Err(Error::Protocol("fixture is not captured native evidence")),
        _custody: sandsurf_native::local::create_private_file(&root.join("capture-custody"))
            .unwrap(),
    })
}
