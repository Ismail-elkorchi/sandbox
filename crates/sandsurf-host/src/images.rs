//! Native complete-machine image publication and OCI-to-VM conversion. No
//! source tree or generated filesystem is mounted in the host kernel.

#[cfg(all(test, target_os = "linux"))]
use sandsurf_image::ext4::materialize_tar;
use sandsurf_image::{
    Architecture, ImageProvenance, ImageTrust, VerifiedImage, install_image, verify_image,
};
#[cfg(test)]
use sandsurf_image::{
    ImageDefaults, ImageManifest, RootfsArtifact, RootfsFormat, SystemDiskManifest,
};
use sandsurf_native::local::{
    create_private_file, ensure_private_directory as prepare_private_directory,
};
use sandsurf_native::storage::object_name;
use sandsurf_protocol::{
    Counter, Digest, Domain, OperationId, Qualification, Snapshot, SnapshotPhase, digest,
};
use sandsurf_state::ImageRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub(crate) mod oci;

const MAX_ROOTFS_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const BUNDLED_IMAGE_MANIFEST_DIGEST: Option<&str> =
    option_env!("SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST");

pub fn bundled_image_digest() -> Option<Digest> {
    BUNDLED_IMAGE_MANIFEST_DIGEST.and_then(|value| value.to_owned().try_into().ok())
}

#[derive(Debug)]
pub enum ImageBuildError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandsurf_image::ImageError),
    Invalid(String),
}

impl fmt::Display for ImageBuildError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "image builder I/O: {error}"),
            Self::Json(error) => write!(output, "image builder document: {error}"),
            Self::Image(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}

impl std::error::Error for ImageBuildError {}
impl From<io::Error> for ImageBuildError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for ImageBuildError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_image::ImageError> for ImageBuildError {
    fn from(value: sandsurf_image::ImageError) -> Self {
        Self::Image(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportResult {
    request_digest: Digest,
    image: ImageRecord,
}

pub fn qualification() -> Qualification {
    Qualification::Unqualified {
        reasons: vec!["machine-image boot, administration and native publication have no retained hardware qualification for this exact build/profile".into()],
    }
}

pub(crate) fn import_native(
    host_root: &Path,
    manifest_path: &Path,
    manifest_digest: &Digest,
    operation: &OperationId,
    request_digest: &Digest,
) -> Result<ImageRecord, ImageBuildError> {
    if !manifest_path.is_absolute() {
        return Err(ImageBuildError::Invalid(
            "native image manifest path must be absolute".into(),
        ));
    }
    let _custody = image_custody(host_root, manifest_digest)?;
    let (stage, old) = prepare_import(host_root, operation, request_digest)?;
    if let Some(image) = old {
        return Ok(image);
    }
    let store = host_root.join("images");
    let installed_manifest = store.join(manifest_digest.as_str()).join("manifest.json");
    // After publication, recovery needs only the immutable host-owned bundle,
    // never the caller's possibly deleted or changed source directory.
    let verified = if installed_manifest.exists() {
        verify_image(
            &installed_manifest,
            ImageTrust::Pinned {
                manifest_digest: manifest_digest.as_str(),
            },
        )?
    } else {
        sandsurf_image::distribution::install(
            &store,
            manifest_path,
            ImageTrust::Pinned {
                manifest_digest: manifest_digest.as_str(),
            },
        )?
    };
    let expected = match crate::service::native_guest_architecture() {
        sandsurf_machine::GuestArchitecture::Amd64 => Architecture::X64,
        sandsurf_machine::GuestArchitecture::Arm64 => Architecture::Arm64,
    };
    if verified.manifest.architecture != expected {
        return Err(ImageBuildError::Invalid(
            "native image architecture differs from the native Linux machine".into(),
        ));
    }
    let (published, verified) = publish_image(host_root, &verified)?;
    let image = image_record(&published, &verified)?;
    finish_import(&stage, request_digest, &image)?;
    Ok(image)
}

fn publish_image(
    host_root: &Path,
    image: &VerifiedImage,
) -> Result<(PathBuf, VerifiedImage), ImageBuildError> {
    let published = install_image(&host_root.join("images"), image)?;
    // Record only the host-owned immutable copy, never caller/build paths.
    let verified = verify_image(
        &published.join("manifest.json"),
        ImageTrust::Pinned {
            manifest_digest: &image.manifest_digest,
        },
    )?;
    Ok((published, verified))
}

fn prepare_import(
    host_root: &Path,
    operation: &OperationId,
    request_digest: &Digest,
) -> Result<(PathBuf, Option<ImageRecord>), ImageBuildError> {
    prepare_private_directory(&host_root.join("images"))?;
    let imports = host_root.join("images/imports");
    prepare_private_directory(&imports)?;
    let stage = imports.join(object_name(operation.as_str()));
    if let Some(image) = completed(host_root, operation, request_digest)? {
        return Ok((stage, Some(image)));
    }
    if stage.exists() {
        let quarantine = imports.join(format!(
            "quarantine-{}-{}",
            object_name(operation.as_str()),
            short_nonce()?
        ));
        fs::rename(&stage, quarantine)?;
    }
    prepare_private_directory(&stage)?;
    Ok((stage, None))
}

/// The sole durable materialization outcome. The worker and API read this same
/// record; it is evidence for the catalog owner, never a second image catalog.
pub(crate) fn completed(
    root: &Path,
    operation: &OperationId,
    request_digest: &Digest,
) -> Result<Option<ImageRecord>, ImageBuildError> {
    let path = root
        .join("images/imports")
        .join(object_name(operation.as_str()))
        .join("result.json");
    let result = match crate::image_records::read::<ImportResult>(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if result.request_digest != *request_digest {
        return Err(ImageBuildError::Invalid(
            "image operation result binding changed".into(),
        ));
    }
    verify_published(root, &result.image)?;
    Ok(Some(result.image))
}

fn finish_import(
    stage: &Path,
    request_digest: &Digest,
    image: &ImageRecord,
) -> Result<(), ImageBuildError> {
    crate::image_records::publish(
        &stage.join("result.json"),
        &ImportResult {
            request_digest: request_digest.clone(),
            image: image.clone(),
        },
    )?;
    sandsurf_native::storage::sync_directory(stage)?;
    Ok(())
}

/// One canonical catalog representation regardless of the publication source.
/// Provenance and sensitivity are declarations bound to the verified image,
/// not attestations that the disk is safe or that the running guest is intact.
fn image_record(root: &Path, image: &VerifiedImage) -> Result<ImageRecord, ImageBuildError> {
    let manifest = &image.manifest;
    let as_digest = |value: &str| {
        Digest::try_from(bare_digest(value)?.to_owned())
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))
    };
    let (source_digest, provenance_digest, sensitive) = match &manifest.system.provenance {
        ImageProvenance::SourceBuilt { source_digest, .. } => (
            as_digest(source_digest)?,
            digest(Domain::Image, &manifest.system.provenance)
                .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
            false,
        ),
        ImageProvenance::Oci {
            manifest_digest,
            conversion_digest,
            ..
        } => (
            as_digest(manifest_digest)?,
            as_digest(conversion_digest)?,
            false,
        ),
        ImageProvenance::Derived {
            source_image_digest,
            snapshot_manifest_digest,
            sensitive,
        } => {
            let disk_digest = as_digest(&manifest.system.rootfs.sha256)?;
            let provenance = digest(
                Domain::Image,
                &(
                    "sandsurf-derived-image-v1",
                    as_digest(source_image_digest)?,
                    as_digest(snapshot_manifest_digest)?,
                    &disk_digest,
                    sensitive,
                ),
            )
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
            (disk_digest, provenance, *sensitive)
        }
    };
    Ok(ImageRecord {
        digest: as_digest(&image.manifest_digest)?,
        source_digest,
        platform: "linux".into(),
        architecture: match manifest.architecture {
            Architecture::X64 => "amd64",
            Architecture::Arm64 => "arm64",
        }
        .into(),
        logical_bytes: Counter::try_from(fs::metadata(&image.system_path)?.len())
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        storage_bytes: Counter::try_from(artifact_storage_bytes(root)?)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        provenance_digest,
        sensitive,
    })
}

pub fn publish_snapshot(
    host_root: &Path,
    snapshot: &Snapshot,
    allow_sensitive: bool,
    operation: &OperationId,
    request_digest: &Digest,
) -> Result<ImageRecord, ImageBuildError> {
    if snapshot.phase != SnapshotPhase::Ready
        || snapshot.system_disk_digest.is_none()
        || snapshot.manifest_digest.is_none()
    {
        return Err(ImageBuildError::Invalid(
            "derived image requires a ready filesystem snapshot".into(),
        ));
    }
    if snapshot.sensitive && !allow_sensitive {
        return Err(ImageBuildError::Invalid(
            "publishing this complete system disk requires explicit sensitive publication authority".into(),
        ));
    }

    let (stage, old) = prepare_import(host_root, operation, request_digest)?;
    if let Some(image) = old {
        return Ok(image);
    }

    let source_root = host_root
        .join("images")
        .join(snapshot.image_digest.as_str());
    let source = verify_image(
        &source_root.join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if source.manifest_digest != snapshot.image_digest.as_str() {
        return Err(ImageBuildError::Invalid(
            "snapshot source image identity changed".into(),
        ));
    }
    let artifact = stage.join("artifact");
    prepare_private_directory(&artifact)?;
    let kernel = artifact.join("boot-kernel");
    let template = artifact.join("derived-system.ext4");
    let (snapshot_boot_directory, snapshot_boot) =
        crate::snapshots::boot_artifacts(&crate::snapshots::root(host_root, snapshot), snapshot)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    copy_regular(
        &snapshot_boot_directory.join(&snapshot_boot.kernel.path),
        &kernel,
    )?;
    if let Some(initramfs) = &snapshot_boot.initramfs {
        copy_regular(
            &snapshot_boot_directory.join(&initramfs.path),
            &artifact.join("boot-initramfs"),
        )?;
    }
    crate::snapshots::materialize_image_template(
        &crate::snapshots::root(host_root, snapshot),
        snapshot,
        &template,
    )
    .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;

    let snapshot_manifest = snapshot
        .manifest_digest
        .as_ref()
        .expect("ready snapshot manifest was checked");
    let provenance_digest = digest(
        Domain::Image,
        &(
            "sandsurf-derived-image-v1",
            &snapshot.image_digest,
            snapshot_manifest,
            snapshot
                .system_disk_digest
                .as_ref()
                .expect("ready snapshot disk was checked"),
            snapshot.sensitive,
        ),
    )
    .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let mut manifest = source.manifest;
    manifest.id = format!("derived-{}", &provenance_digest.as_str()[..16]);
    manifest.version = snapshot_manifest.as_str()[..16].to_owned();
    manifest.boot_bundle.kernel.path = "boot-kernel".into();
    manifest.boot_bundle.kernel.sha256 = sha256_file(&kernel, MAX_ROOTFS_BYTES)?;
    manifest.boot_bundle.initramfs = snapshot_boot.initramfs.map(|mut value| {
        value.path = "boot-initramfs".into();
        value
    });
    manifest.system.rootfs.path = "derived-system.ext4".into();
    manifest.system.rootfs.sha256 = sha256_file(&template, MAX_ROOTFS_BYTES)?;
    manifest.system.provenance = ImageProvenance::Derived {
        source_image_digest: snapshot.image_digest.as_str().to_owned(),
        snapshot_manifest_digest: snapshot_manifest.as_str().to_owned(),
        sensitive: snapshot.sensitive,
    };
    manifest.signature = None;
    let manifest_path = artifact.join("manifest.json");
    let mut manifest_file = create_private_file(&manifest_path)?;
    manifest_file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    manifest_file.write_all(b"\n")?;
    manifest_file.sync_all()?;
    let verified = verify_image(&manifest_path, ImageTrust::ExplicitLocal)?;
    let (final_root, verified) = publish_image(host_root, &verified)?;
    fs::remove_dir_all(&artifact)?;
    let image = image_record(&final_root, &verified)?;
    finish_import(&stage, request_digest, &image)?;
    Ok(image)
}

fn verify_published(host_root: &Path, image: &ImageRecord) -> Result<(), ImageBuildError> {
    let verified = verify_image(
        &host_root
            .join("images")
            .join(image.digest.as_str())
            .join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if verified.manifest_digest != image.digest.as_str() {
        return Err(ImageBuildError::Invalid(
            "published image failed identity verification".into(),
        ));
    }
    Ok(())
}

pub(crate) fn resolve_native_image(
    host_root: &Path,
    expected: &Digest,
) -> Result<VerifiedImage, ImageBuildError> {
    sandsurf_native::volume::inspect(host_root)?;
    let installed = host_root.join("images").join(expected.as_str());
    match fs::symlink_metadata(&installed) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Ok(verify_image(
                &installed.join("manifest.json"),
                ImageTrust::Pinned {
                    manifest_digest: expected.as_str(),
                },
            )?)
        }
        Ok(_) => Err(ImageBuildError::Invalid(
            "image is not a host-owned directory".into(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(ImageBuildError::Invalid(
            "admitted image has no published host-owned bundle".into(),
        )),
        Err(error) => Err(error.into()),
    }
}

fn copy_regular(source: &Path, destination: &Path) -> Result<(), ImageBuildError> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ImageBuildError::Invalid(
            "image input is not a regular file".into(),
        ));
    }
    let mut input = File::open(source)?;
    let mut output = create_private_file(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

/// A publication/read lease, not another image-authority database. The host
/// catalog may retire an image while a worker reads it, but byte reclamation
/// and quota release must wait for custody to drain. Kernel locks disappear
/// on worker failure; lock files retain stable identities for later owners.
fn image_custody(host_root: &Path, digest: &Digest) -> Result<File, ImageBuildError> {
    let directory = host_root.join("images/custody");
    prepare_private_directory(&host_root.join("images"))?;
    prepare_private_directory(&directory)?;
    let path = directory.join(digest.as_str());
    let held = match create_private_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            sandsurf_native::local::open_private_file(
                &path,
                sandsurf_native::PrivateFileAccess::ReadWrite,
            )?
        }
        Err(error) => return Err(error.into()),
    };
    held.try_lock()
        .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error.to_string()))?;
    Ok(held)
}

pub fn cleanup(host_root: &Path, digest: &Digest) -> Result<(), ImageBuildError> {
    let _custody = image_custody(host_root, digest)?;
    let images = host_root.join("images");
    let target = images.join(digest.as_str());
    match fs::symlink_metadata(&target) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ImageBuildError::Invalid(
                    "retired image target is not an owned directory".into(),
                ));
            }
            fs::remove_dir_all(&target)?;
            sandsurf_native::storage::sync_directory(&images)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn artifact_storage_bytes(root: &Path) -> Result<u64, ImageBuildError> {
    Ok(sandsurf_native::storage_usage::tree_usage(root)?.allocated_bytes)
}

fn bare_digest(value: &str) -> Result<&str, ImageBuildError> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ImageBuildError::Invalid("OCI digest is malformed".into()));
    }
    Ok(value)
}

fn sha256_file(path: &Path, maximum: u64) -> Result<String, ImageBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(ImageBuildError::Invalid(
            "image artifact is not a bounded regular file".into(),
        ));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn short_nonce() -> Result<String, ImageBuildError> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| ImageBuildError::Invalid("host entropy unavailable".into()))?;
    use std::fmt::Write as _;
    let mut output = String::with_capacity(16);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("string formatting cannot fail");
    }
    Ok(output)
}

#[cfg(test)]
mod native_import_tests {
    use super::*;
    use sandsurf_image::{BootBundleManifest, ImageArtifact, ImageCapabilities};

    struct Fixture {
        root: PathBuf,
        manifest: PathBuf,
        digest: Digest,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "sandsurf-native-image-{}-{}",
                std::process::id(),
                short_nonce().unwrap()
            ));
            prepare_private_directory(&root).unwrap();
            let source = root.join("source");
            prepare_private_directory(&source).unwrap();
            fs::write(source.join("kernel"), b"native-kernel").unwrap();
            fs::write(source.join("system.ext4"), b"opaque-system-seed").unwrap();
            let manifest = ImageManifest {
                format_version: 1,
                id: "native-image-test".into(),
                version: "1".into(),
                architecture: match crate::service::native_guest_architecture() {
                    sandsurf_machine::GuestArchitecture::Amd64 => Architecture::X64,
                    sandsurf_machine::GuestArchitecture::Arm64 => Architecture::Arm64,
                },
                boot_bundle: BootBundleManifest {
                    initramfs: None,
                    profile: sandsurf_image::boot::BootProfile::Pinned,
                    kernel: ImageArtifact {
                        path: "kernel".into(),
                        sha256: sha256_file(&source.join("kernel"), MAX_ROOTFS_BYTES).unwrap(),
                    },
                    guest_agent: None,
                    capabilities: ImageCapabilities {
                        overlayfs: false,
                        vsock: false,
                        seccomp: false,
                        cgroup_v2: false,
                        devpts: false,
                    },
                },
                system: SystemDiskManifest {
                    clone_profile: sandsurf_image::identity::CloneProfile::Preserve,
                    rootfs: RootfsArtifact {
                        path: "system.ext4".into(),
                        sha256: sha256_file(&source.join("system.ext4"), MAX_ROOTFS_BYTES).unwrap(),
                        format: RootfsFormat::Ext4,
                    },
                    defaults: ImageDefaults::default(),
                    provenance: ImageProvenance::SourceBuilt {
                        source_digest: "a".repeat(64),
                        materials: BTreeMap::from([("source".into(), "b".repeat(64))]),
                    },
                },
                signature: None,
            };
            let path = source.join("manifest.json");
            crate::image_records::publish(&path, &manifest).unwrap();
            let mut compressed = flate2::write::GzEncoder::new(
                fs::File::create(source.join("system.ext4.gz")).unwrap(),
                flate2::Compression::default(),
            );
            std::io::copy(
                &mut fs::File::open(source.join("system.ext4")).unwrap(),
                &mut compressed,
            )
            .unwrap();
            compressed.finish().unwrap();
            let digest = Digest::try_from(
                verify_image(&path, ImageTrust::ExplicitLocal)
                    .unwrap()
                    .manifest_digest,
            )
            .unwrap();
            Self {
                root,
                manifest: path,
                digest,
            }
        }
        fn import(&self, operation: &str, request: &str) -> Result<ImageRecord, ImageBuildError> {
            import_native(
                &self.root,
                &self.manifest,
                &self.digest,
                &OperationId::try_from(operation.to_owned()).unwrap(),
                &Digest::try_from(request.repeat(64)).unwrap(),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn image_cleanup_waits_for_worker_custody_and_preserves_original_bytes() {
        let fixture = Fixture::new();
        fixture.import("pinned-import", "c").unwrap();
        let held = image_custody(&fixture.root, &fixture.digest).unwrap();
        let path = fixture.root.join("images").join(fixture.digest.as_str());
        let before = fs::read(path.join("system.ext4")).unwrap();
        assert!(
            matches!(cleanup(&fixture.root, &fixture.digest), Err(ImageBuildError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(fs::read(path.join("system.ext4")).unwrap(), before);
        drop(held);
        cleanup(&fixture.root, &fixture.digest).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn native_import_reconnects_after_source_deletion_and_recovers_before_result_commit() {
        let fixture = Fixture::new();
        let image = fixture.import("first-import", "c").unwrap();
        assert_eq!(image.digest, fixture.digest);
        assert_eq!(
            image.logical_bytes.get(),
            b"opaque-system-seed".len() as u64
        );
        assert!(!image.sensitive);
        fs::remove_dir_all(fixture.manifest.parent().unwrap()).unwrap();
        assert_eq!(fixture.import("first-import", "c").unwrap(), image);
        assert!(fixture.import("first-import", "d").is_err());
        // Interrupt after artifact publication but before the result/journal
        // commit. Recovery uses only the exact host-owned image digest.
        fs::remove_file(
            fixture
                .root
                .join("images/imports")
                .join(object_name("first-import"))
                .join("result.json"),
        )
        .unwrap();
        assert_eq!(fixture.import("first-import", "c").unwrap(), image);
        assert_eq!(fixture.import("another-import", "e").unwrap(), image);
        fs::set_permissions(
            fixture
                .root
                .join("images")
                .join(image.digest.as_str())
                .join("kernel"),
            fs::metadata(&fixture.root).unwrap().permissions(),
        )
        .unwrap();
        fs::write(
            fixture
                .root
                .join("images")
                .join(image.digest.as_str())
                .join("kernel"),
            b"corrupt-owned-kernel",
        )
        .unwrap();
        assert!(fixture.import("first-import", "c").is_err());
    }

    #[test]
    fn worker_and_materializer_share_one_complete_verified_result() {
        let fixture = Fixture::new();
        let image = fixture.import("worker-operation", "c").unwrap();
        let operation: OperationId = "worker-operation".try_into().unwrap();
        let binding: Digest = "c".repeat(64).try_into().unwrap();
        assert_eq!(
            completed(&fixture.root, &operation, &binding).unwrap(),
            Some(image.clone())
        );
        assert!(
            !fixture.root.join("image-workers").exists(),
            "completion must not create a duplicate outcome"
        );
        fs::remove_dir_all(fixture.manifest.parent().unwrap()).unwrap();
        assert_eq!(
            completed(&fixture.root, &operation, &binding).unwrap(),
            Some(image)
        );
        assert!(
            completed(
                &fixture.root,
                &operation,
                &"d".repeat(64).try_into().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn native_import_rejects_unpinned_or_modified_input_before_publication() {
        let fixture = Fixture::new();
        let wrong = Digest::try_from("d".repeat(64)).unwrap();
        let operation = OperationId::try_from("wrong-input".to_owned()).unwrap();
        let request = Digest::try_from("e".repeat(64)).unwrap();
        assert!(
            import_native(
                &fixture.root,
                &fixture.manifest,
                &wrong,
                &operation,
                &request
            )
            .is_err()
        );
        assert!(!fixture.root.join("images").join(wrong.as_str()).exists());
        fs::write(
            fixture.manifest.parent().unwrap().join("system.ext4.gz"),
            b"modified-system",
        )
        .unwrap();
        assert!(fixture.import("modified-input", "f").is_err());
        assert!(
            !fixture
                .root
                .join("images")
                .join(fixture.digest.as_str())
                .exists()
        );
    }

    #[test]
    fn every_image_source_uses_one_canonical_record_and_preserves_sensitive_provenance() {
        let fixture = Fixture::new();
        let mut manifest: ImageManifest = crate::image_records::read(&fixture.manifest).unwrap();
        for provenance in [
            ImageProvenance::Oci {
                index_digest: "a".repeat(64),
                manifest_digest: "b".repeat(64),
                config_digest: "c".repeat(64),
                conversion_digest: "d".repeat(64),
            },
            ImageProvenance::Derived {
                source_image_digest: "a".repeat(64),
                snapshot_manifest_digest: "b".repeat(64),
                sensitive: true,
            },
        ] {
            manifest.system.provenance = provenance;
            fs::write(&fixture.manifest, serde_json::to_vec(&manifest).unwrap()).unwrap();
            let verified = verify_image(&fixture.manifest, ImageTrust::ExplicitLocal).unwrap();
            let expected = image_record(fixture.manifest.parent().unwrap(), &verified).unwrap();
            let digest = Digest::try_from(verified.manifest_digest).unwrap();
            let imported = import_native(
                &fixture.root,
                &fixture.manifest,
                &digest,
                &OperationId::try_from(format!("canonical-{}", expected.sensitive)).unwrap(),
                &Digest::try_from("e".repeat(64)).unwrap(),
            )
            .unwrap();
            assert_eq!(imported.digest, expected.digest);
            assert_eq!(imported.source_digest, expected.source_digest);
            assert_eq!(imported.provenance_digest, expected.provenance_digest);
            assert_eq!(imported.sensitive, expected.sensitive);
            assert_eq!(
                imported.sensitive,
                matches!(
                    manifest.system.provenance,
                    ImageProvenance::Derived {
                        sensitive: true,
                        ..
                    }
                )
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    #[ignore = "native KVM/libguestfs image qualification; run explicitly with --ignored"]
    fn converted_machine_seed_has_a_verified_internal_journal() {
        let root = Path::new("/var/tmp").join(format!(
            "sandsurf-oci-journal-{}-{}",
            std::process::id(),
            short_nonce().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let archive_path = root.join("root.tar");
        let mut archive = tar::Builder::new(File::create_new(&archive_path).unwrap());
        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_mode(0o755);
        directory.set_uid(0);
        directory.set_gid(0);
        directory.set_mtime(0);
        directory.set_size(0);
        directory.set_cksum();
        archive
            .append_data(&mut directory, "etc", io::empty())
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_path("etc/identity").unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(8);
        header.set_cksum();
        archive.append(&header, &b"sandsurf"[..]).unwrap();
        archive.finish().unwrap();
        drop(archive);
        let image = root.join("system.ext4");
        materialize_tar(&archive_path, &image, 128 * 1024 * 1024).unwrap();
        let mut file = File::open(&image).unwrap();
        let mut superblock = [0u8; 1024];
        file.seek(SeekFrom::Start(1024)).unwrap();
        file.read_exact(&mut superblock).unwrap();
        assert_ne!(
            u32::from_le_bytes(superblock[92..96].try_into().unwrap()) & 0x0004,
            0
        );
        assert_eq!(
            u32::from_le_bytes(superblock[224..228].try_into().unwrap()),
            8
        );
        fs::remove_file(image).unwrap();
        fs::remove_file(archive_path).unwrap();
        fs::remove_dir_all(root.join(".appliance")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
