//! Offline boot interpretation has no native machine or journal authority.
//! The guardian installs its result only after its durable dispatch fence.

use crate::guardian::{Error, Result};
use sandsurf_protocol::{
    Counter, DesiredState, Digest, LifecycleCommand, MachineId, MachineObservation, MachineState,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootPreparation {
    pub machine_root: PathBuf,
    pub machine_id: MachineId,
    pub generation: Counter,
    pub image_digest: Digest,
    pub disk_bytes: u64,
}

pub struct PreparedBoot {
    pub(crate) input: BootPreparation,
    pub(crate) directory: PathBuf,
    pub(crate) boot: sandsurf_image::boot::FrozenBoot,
}

impl BootPreparation {
    pub(crate) fn cold(
        machine_root: &Path,
        image_digest: &Digest,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> Result<Option<Self>> {
        if command.desired != DesiredState::Running
            || current.is_some_and(|value| {
                !matches!(value.state, MachineState::Stopped | MachineState::Failed)
            })
        {
            return Ok(None);
        }
        Ok(Some(Self {
            machine_root: machine_root.to_path_buf(),
            machine_id: command.machine_id.clone(),
            generation: match current {
                Some(value) => value
                    .generation
                    .next()
                    .map_err(|_| Error::Protocol("boot generation overflow"))?,
                None => Counter::ONE,
            },
            image_digest: image_digest.clone(),
            disk_bytes: command.configuration.resources.disk_bytes.get(),
        }))
    }
    pub(crate) fn execute(self) -> Result<PreparedBoot> {
        let (directory, boot) = crate::image_worker::prepare_boot(
            &self.machine_root,
            &self.machine_id,
            self.generation,
            &self.image_digest,
            self.disk_bytes,
        )
        .map_err(|error| Error::Rejected {
            category: "boot-preparation".into(),
            message: error.to_string(),
        })?;
        Ok(PreparedBoot {
            input: self,
            directory,
            boot,
        })
    }
}

impl PreparedBoot {
    pub(crate) fn consume(
        self,
        machine_root: &Path,
        machine_id: &MachineId,
        generation: Counter,
        image_digest: &Digest,
        disk_bytes: u64,
    ) -> std::result::Result<(PathBuf, sandsurf_image::boot::FrozenBoot), Digest> {
        if self.input.machine_root != machine_root
            || self.input.machine_id != *machine_id
            || self.input.generation != generation
            || self.input.image_digest != *image_digest
            || self.input.disk_bytes != disk_bytes
        {
            return Err(sandsurf_protocol::bytes_digest(
                b"offline-boot-preparation-binding-mismatch",
            ));
        }
        Ok((self.directory, self.boot))
    }
}
