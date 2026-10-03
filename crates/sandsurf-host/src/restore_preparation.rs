//! Offline full-state verification has storage custody, not native machine or
//! journal authority. The control owner fences its completion before staging.
use crate::guardian::{Error, Result};
use sandsurf_protocol::{Digest, FullSnapshotMetadata, SnapshotArtifact, SnapshotId, VmEngine};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePreparation {
    pub machine_root: PathBuf,
    pub snapshot_id: SnapshotId,
    pub manifest_digest: Digest,
    pub system_disk: SnapshotArtifact,
    pub expected: FullSnapshotMetadata,
}

pub struct PreparedRestore {
    pub(crate) input: RestorePreparation,
    pub(crate) reconnect: Box<crate::restore::ReconnectState>,
    pub(crate) disk_custody: Arc<File>,
    pub(crate) snapshot_custody: Arc<File>,
}

impl RestorePreparation {
    pub(crate) fn directory(&self) -> PathBuf {
        self.machine_root
            .join("snapshots")
            .join(sandsurf_native::storage::object_name(
                self.snapshot_id.as_str(),
            ))
    }
    pub(crate) fn staged_state_path(&self) -> Option<PathBuf> {
        (self.expected.engine != VmEngine::Firecracker).then(|| {
            self.machine_root
                .join("guardian/restores")
                .join(format!("{}.vmstate", self.manifest_digest.as_str()))
        })
    }
    pub(crate) fn binding(&self) -> Result<Digest> {
        sandsurf_protocol::digest(
            sandsurf_protocol::Domain::Snapshot,
            &(
                "sandsurf-restore-preparation-v1",
                &self.machine_root,
                &self.snapshot_id,
                &self.manifest_digest,
                &self.system_disk,
                &self.expected,
            ),
        )
        .map_err(|_| Error::Protocol("restore preparation digest failed"))
    }
    pub(crate) fn evidence(&self) -> Result<sandsurf_protocol::NativeSnapshotResponse> {
        Ok(sandsurf_protocol::NativeSnapshotResponse::Complete {
            evidence: sandsurf_protocol::digest(
                sandsurf_protocol::Domain::Snapshot,
                &(
                    if self.expected.engine == VmEngine::Firecracker {
                        "sandsurf-firecracker-restore-staged-v1"
                    } else {
                        "sandsurf-qemu-restore-staged-v1"
                    },
                    &self.snapshot_id,
                    &self.manifest_digest,
                    &self.expected.generation,
                ),
            )
            .map_err(|_| Error::Protocol("restore stage evidence digest failed"))?,
        })
    }
    pub(crate) fn execute(self) -> Result<PreparedRestore> {
        let snapshots = self.machine_root.join("snapshots");
        let snapshot_custody = Arc::new(
            crate::snapshots::retain_input(&snapshots, &self.snapshot_id).map_err(|_| {
                Error::Unsupported("full snapshot inputs are retired or unavailable")
            })?,
        );
        let disk = self.machine_root.join("disks/system.ext4");
        // Original attachment custody excludes a running VMM, replacement,
        // destruction and another preparation. Keep this same description
        // through installation and the actual VMM, never release/reacquire it.
        let disk_custody = crate::storage::attach(&disk)?;
        let directory = self.directory();
        for (name, artifact) in [
            ("system.ext4", &self.system_disk),
            ("snapshot.vmstate", &self.expected.snapshot_state),
            ("reconnect.json", &self.expected.reconnect_state),
        ]
        .into_iter()
        .chain(self.expected.memory.iter().map(|memory| ("memory", memory)))
        {
            if crate::snapshots::file_digest(&directory.join(name), artifact.bytes.get())
                .map_err(|_| Error::Protocol("full snapshot artifact is corrupt"))?
                != artifact.digest
            {
                return Err(Error::Protocol("full snapshot artifact digest mismatch"));
            }
        }
        if crate::snapshots::file_digest(&disk, self.system_disk.bytes.get())
            .map_err(|_| Error::Protocol("restore disk is unavailable"))?
            != self.system_disk.digest
        {
            return Err(Error::Unsupported(
                "mutable disks no longer match the suspended full snapshot",
            ));
        }
        let mut reconnect = Vec::new();
        sandsurf_native::local::open_private_file(
            &directory.join("reconnect.json"),
            sandsurf_native::PrivateFileAccess::ReadOnly,
        )?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut reconnect)?;
        if reconnect.len() > 1024 * 1024 {
            return Err(Error::Protocol("restore reconnect state exceeds its bound"));
        }
        let reconnect: crate::restore::ReconnectState = serde_json::from_slice(&reconnect)?;
        if reconnect.format_version != 1
            || reconnect.snapshot_id != self.snapshot_id
            || reconnect.generation == sandsurf_protocol::Counter::ZERO
            || match reconnect.boot.architecture {
                sandsurf_image::Architecture::X64 => "amd64",
                sandsurf_image::Architecture::Arm64 => "arm64",
            } != self.expected.architecture
        {
            return Err(Error::Protocol(
                "restore channel or boot input identity changed",
            ));
        }
        if crate::storage::read_boot(&directory.join("boot"))? != reconnect.boot {
            return Err(Error::Protocol(
                "saved running boot differs from its captured channel",
            ));
        }
        if let Some(staged) = self.staged_state_path() {
            crate::snapshots::private_directory(
                staged
                    .parent()
                    .ok_or(Error::Protocol("native state copy has no owner"))?,
            )
            .map_err(|_| Error::Protocol("restore staging root is not private"))?;
            crate::snapshots::copy_and_verify(
                &directory.join("snapshot.vmstate"),
                &staged,
                self.expected.snapshot_state.bytes.get(),
                Some(&self.expected.snapshot_state.digest),
            )
            .map_err(|_| Error::Protocol("saved machine state could not be staged"))?;
        }
        Ok(PreparedRestore {
            input: self,
            reconnect: Box::new(reconnect),
            disk_custody,
            snapshot_custody,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sandsurf_native::local::{create_private_file, ensure_private_directory};
    use sandsurf_protocol::{Counter, bytes_digest};
    use std::{io::Write, path::Path};

    pub(crate) fn fixture(root: &Path, engine: VmEngine) -> RestorePreparation {
        ensure_private_directory(&root.join("disks")).unwrap();
        ensure_private_directory(&root.join("guardian")).unwrap();
        let disk = vec![7; 4096];
        crate::storage::publish_disk(&root.join("disks/system.ext4"), 4096, |stage| {
            create_private_file(stage)?.write_all(&disk)
        })
        .unwrap();
        ensure_private_directory(&root.join("snapshots")).unwrap();
        let snapshot_id: SnapshotId = "full-state".try_into().unwrap();
        let directory = root
            .join("snapshots")
            .join(sandsurf_native::storage::object_name(snapshot_id.as_str()));
        ensure_private_directory(&directory).unwrap();
        let artifact = |name: &str, bytes: &[u8]| {
            create_private_file(&directory.join(name))
                .unwrap()
                .write_all(bytes)
                .unwrap();
            SnapshotArtifact {
                digest: bytes_digest(bytes),
                bytes: (bytes.len() as u64).try_into().unwrap(),
            }
        };
        let system_disk = artifact("system.ext4", &disk);
        let snapshot_state = artifact("snapshot.vmstate", b"native saved state");
        let mut kernel = vec![0; 4096];
        kernel[0x202..0x206].copy_from_slice(b"HdrS");
        kernel[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        kernel[0x236] = 1;
        kernel[0x206..0x208].copy_from_slice(&0x020c_u16.to_le_bytes());
        create_private_file(&root.join("fixture-kernel"))
            .unwrap()
            .write_all(&kernel)
            .unwrap();
        let boot = crate::storage::pin_boot(
            &root.join("fixture-kernel"),
            None,
            sandsurf_image::Architecture::X64,
            &directory.join("boot"),
        )
        .unwrap();
        let reconnect_state = artifact(
            "reconnect.json",
            &serde_json::to_vec(&crate::restore::ReconnectState {
                format_version: 1,
                snapshot_id: snapshot_id.clone(),
                capture_operation_id: "capture".try_into().unwrap(),
                machine_id: "computer".try_into().unwrap(),
                generation: Counter::ONE,
                boot_identity: bytes_digest(b"running boot"),
                capability: [7; 32],
                boot,
            })
            .unwrap(),
        );
        let memory =
            (engine == VmEngine::Firecracker).then(|| artifact("memory", b"native memory"));
        RestorePreparation {
            machine_root: root.to_path_buf(),
            snapshot_id,
            manifest_digest: bytes_digest(b"manifest"),
            system_disk,
            expected: FullSnapshotMetadata {
                engine,
                engine_version: "fixture".into(),
                architecture: "amd64".into(),
                configuration_digest: bytes_digest(b"configuration"),
                snapshot_state,
                memory,
                reconnect_state,
                executions: Vec::new(),
                generation: bytes_digest(b"generation"),
                fork_safe: false,
            },
        }
    }

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "ssrestore-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            sandsurf_native::local::create_private_directory(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn prepared_restore_keeps_original_disk_and_snapshot_custody_through_native_consumption() {
        let root = Root::new();
        let input = fixture(&root.0, VmEngine::Firecracker);
        let expected = input.clone();
        let prepared = input.execute().unwrap();
        assert_eq!(prepared.input, expected);
        assert!(prepared.input.staged_state_path().is_none());
        let disk = root.0.join("disks/system.ext4");
        assert!(crate::storage::attach(&disk).is_err());
        let original_native_description = prepared.disk_custody.try_clone().unwrap();
        drop(prepared);
        assert!(crate::storage::attach(&disk).is_err());
        drop(original_native_description);
        assert!(crate::storage::attach(&disk).is_ok());
        assert_eq!(
            std::fs::read(
                root.0
                    .join("snapshots")
                    .join(sandsurf_native::storage::object_name(
                        expected.snapshot_id.as_str()
                    ))
                    .join("memory")
            )
            .unwrap(),
            b"native memory"
        );
    }

    #[test]
    fn preparation_excludes_active_attachment_and_rejects_corruption_without_native_staging() {
        let root = Root::new();
        let input = fixture(&root.0, VmEngine::QemuWhpx);
        let disk = root.0.join("disks/system.ext4");
        let native = crate::storage::attach(&disk).unwrap();
        assert!(input.clone().execute().is_err());
        assert!(!root.0.join("guardian/restores").exists());
        drop(native);
        let mut changed = input.clone();
        changed.expected.snapshot_state.digest = bytes_digest(b"wrong");
        assert!(changed.execute().is_err());
        assert!(!root.0.join("guardian/restores").exists());
        let prepared = input.execute().unwrap();
        let copy = prepared.input.staged_state_path().unwrap();
        assert_eq!(std::fs::read(&copy).unwrap(), b"native saved state");
        assert_ne!(copy.parent(), Some(prepared.input.directory().as_path()));
        assert_eq!(
            std::fs::read(prepared.input.directory().join("snapshot.vmstate")).unwrap(),
            b"native saved state"
        );
        assert_eq!(prepared.reconnect.snapshot_id, prepared.input.snapshot_id);
        assert_eq!(prepared.reconnect.generation, Counter::ONE);
        drop(prepared);
        assert!(crate::storage::attach(&disk).is_ok());
    }

    #[test]
    fn restore_worker_rejects_missing_changed_or_substituted_running_boot_before_installation() {
        for mutation in 0..3 {
            let root = Root::new();
            let input = fixture(&root.0, VmEngine::Firecracker);
            let boot = input.directory().join("boot");
            let kernel = boot.join("kernel");
            match mutation {
                0 => std::fs::remove_file(&kernel).unwrap(),
                1 => {
                    let mut file = sandsurf_native::local::open_private_file(
                        &kernel,
                        sandsurf_native::PrivateFileAccess::ReadWrite,
                    );
                    // Unix pin_boot removes write bits. Windows uses a private
                    // DACL and digest-bound publication, not a readonly attribute.
                    // Fault injection explicitly simulates damaged host media.
                    if file.is_err() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(
                                &kernel,
                                std::fs::Permissions::from_mode(0o600),
                            )
                            .unwrap();
                        }
                        file = sandsurf_native::local::open_private_file(
                            &kernel,
                            sandsurf_native::PrivateFileAccess::ReadWrite,
                        );
                    }
                    file.unwrap().write_all(b"damaged").unwrap();
                }
                _ => {
                    let changed = sandsurf_image::boot::FrozenBoot {
                        architecture: sandsurf_image::Architecture::X64,
                        kernel: sandsurf_image::ImageArtifact {
                            path: "kernel".into(),
                            sha256: "f".repeat(64),
                        },
                        initramfs: None,
                    };
                    let mut file = sandsurf_native::local::open_private_file(
                        &boot.join("boot.json"),
                        sandsurf_native::PrivateFileAccess::ReadWrite,
                    )
                    .unwrap();
                    file.set_len(0).unwrap();
                    file.write_all(&serde_json::to_vec(&changed).unwrap())
                        .unwrap();
                }
            }
            assert!(input.execute().is_err());
            assert!(!root.0.join("guardian/restore-integration.json").exists());
        }
    }

    #[test]
    fn prepared_binding_covers_every_native_input_and_never_creates_authority() {
        let root = Root::new();
        let input = fixture(&root.0, VmEngine::Firecracker);
        let binding = input.binding().unwrap();
        for field in 0..5 {
            let mut changed = input.clone();
            match field {
                0 => changed.snapshot_id = "other".try_into().unwrap(),
                1 => changed.system_disk.bytes = Counter::ONE,
                2 => changed.expected.generation = bytes_digest(b"other"),
                3 => changed.manifest_digest = bytes_digest(b"other"),
                _ => changed.machine_root = root.0.join("other"),
            }
            assert_ne!(changed.binding().unwrap(), binding);
        }
        assert!(!root.0.join("guardian/restore-integration.json").exists());
    }
}
