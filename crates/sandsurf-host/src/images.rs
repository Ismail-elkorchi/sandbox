//! Cross-platform OCI-to-VM image publication. The conversion never mounts
//! the source tree or generated filesystem in the host kernel.

use crate::api::{MachineImageRecipe, OciSource};
use sandsurf_image::ext4::materialize_tar;
use sandsurf_image::oci::{
    ConversionLimits, ConvertedTree, GuestPlatform, OciLayout, TreeEntryKind,
    unpack_layout_archive, write_filesystem_tar,
};
use sandsurf_image::{
    Architecture, ImageDefaults, ImageManifest, ImageProvenance, ImageTrust, PlatformArtifacts,
    RootfsArtifact, RootfsFormat, SystemDiskManifest, VerifiedImage, verify_image,
};
#[cfg(target_os = "windows")]
use sandsurf_image::{ImageArtifact, WindowsArtifacts};
use sandsurf_protocol::{
    Counter, Digest, Domain, OperationId, Qualification, Snapshot, SnapshotPhase, digest,
};
use sandsurf_state::ImageRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

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

pub(crate) struct OciBuildInput<'a> {
    pub source: &'a OciSource,
    pub recipe: &'a MachineImageRecipe,
    pub platform: &'a str,
}

pub(crate) fn import_oci(
    host_root: &Path,
    executable: &Path,
    input: OciBuildInput<'_>,
    operation: &OperationId,
    request_digest: &Digest,
    registry_credential: Option<&[u8]>,
) -> Result<ImageRecord, ImageBuildError> {
    let OciBuildInput {
        source,
        recipe,
        platform,
    } = input;
    let requested = parse_platform(platform)?;
    let expected_architecture = match crate::service::native_guest_architecture() {
        sandsurf_machine::GuestArchitecture::Amd64 => "amd64",
        sandsurf_machine::GuestArchitecture::Arm64 => "arm64",
    };
    if requested.os != "linux" || requested.architecture != expected_architecture {
        return Err(ImageBuildError::Invalid(
            "OCI platform must exactly match the native Linux guest architecture".into(),
        ));
    }
    let base = resolve_recipe_boot_image(host_root, executable, &recipe.boot_image_digest)?;
    let architecture = match requested.architecture.as_str() {
        "amd64" => Architecture::X64,
        "arm64" => Architecture::Arm64,
        _ => {
            return Err(ImageBuildError::Invalid(
                "unsupported OCI architecture".into(),
            ));
        }
    };
    if base.manifest.architecture != architecture {
        return Err(ImageBuildError::Invalid(
            "recipe boot image architecture differs from the OCI filesystem".into(),
        ));
    }
    let imports = host_root.join("images/imports");
    prepare_private_directory(&imports)?;
    let stage = imports.join(operation.as_str());
    let result_path = stage.join("result.json");
    if result_path.exists() {
        let old: ImportResult = read_json(&result_path, 1024 * 1024)?;
        if old.request_digest != *request_digest {
            return Err(ImageBuildError::Invalid(
                "image import staging identity conflicts with the request".into(),
            ));
        }
        verify_published(host_root, &old.image)?;
        return Ok(old.image);
    }
    if stage.exists() {
        let quarantine = imports.join(format!(
            "quarantine-{}-{}",
            operation.as_str(),
            short_nonce()?
        ));
        fs::rename(&stage, quarantine)?;
    }
    prepare_private_directory(&stage)?;
    let layout_path = match source {
        OciSource::Layout { path } => {
            if !path.is_absolute() {
                return Err(ImageBuildError::Invalid(
                    "OCI layout path must be absolute".into(),
                ));
            }
            path.clone()
        }
        OciSource::Archive { path } => {
            let layout = stage.join("layout");
            unpack_layout_archive(path, &layout, ConversionLimits::default())
                .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
            layout
        }
        OciSource::Registry { reference, .. } => {
            let layout = stage.join("layout");
            crate::registry::fetch_layout(
                &host_root.join("images/blobs"),
                &layout,
                reference,
                &requested,
                registry_credential,
                ConversionLimits::default(),
            )
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
            layout
        }
    };
    let layout = OciLayout::open(&layout_path, ConversionLimits::default())
        .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let resolved = layout
        .resolve(&requested)
        .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let tree_root = stage.join("tree");
    let tree = layout
        .convert(resolved, &tree_root)
        .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    require_os_init(&tree)?;
    let filesystem_tar = stage.join("rootfs.tar");
    write_filesystem_tar(&tree_root, &tree, &filesystem_tar)
        .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let rootfs_bytes = rootfs_size(&tree)?;
    let artifact = stage.join("artifact");
    prepare_private_directory(&artifact)?;
    let system_path = artifact.join("oci-system.ext4");
    let builder = materialize_tar(&filesystem_tar, &system_path, rootfs_bytes)
        .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let kernel_name = "boot-kernel";
    copy_regular(&base.kernel_path, &artifact.join(kernel_name))?;
    let platform_artifacts =
        materialize_platform_artifacts(&base, &system_path, &artifact, rootfs_bytes)?;
    let mut environment = BTreeMap::new();
    for assignment in &tree.source.defaults.environment {
        let (name, value) = assignment
            .split_once('=')
            .ok_or_else(|| ImageBuildError::Invalid("validated OCI environment changed".into()))?;
        environment.insert(name.to_owned(), value.to_owned());
    }
    let conversion_digest = digest(
        Domain::Image,
        &(
            "sandsurf-oci-machine-v2",
            &tree.manifest_digest,
            recipe,
            &builder,
            rootfs_bytes,
        ),
    )
    .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let mut manifest = ImageManifest {
        format_version: 3,
        id: format!("oci-{}", short_digest(&tree.source.manifest_digest)?),
        version: short_digest(&tree.source.config_digest)?.to_owned(),
        architecture,
        boot_bundle: base.manifest.boot_bundle.clone(),
        system: SystemDiskManifest {
            rootfs: RootfsArtifact {
                path: "oci-system.ext4".into(),
                sha256: sha256_file(&system_path, MAX_ROOTFS_BYTES)?,
                format: RootfsFormat::Ext4,
            },
            defaults: ImageDefaults {
                environment,
                user: tree.source.defaults.user.clone(),
                working_directory: tree.source.defaults.working_directory.clone(),
            },
            provenance: ImageProvenance::Oci {
                index_digest: bare_digest(&tree.source.source_index_digest)?.to_owned(),
                manifest_digest: bare_digest(&tree.source.manifest_digest)?.to_owned(),
                config_digest: bare_digest(&tree.source.config_digest)?.to_owned(),
                conversion_digest: conversion_digest.as_str().to_owned(),
            },
        },
        platform_artifacts,
        signature: None,
    };
    manifest.boot_bundle.kernel.path = kernel_name.into();
    manifest.boot_bundle.guest_agent = None;
    let manifest_path = artifact.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let mut manifest_file = create_private_file(&manifest_path)?;
    manifest_file.write_all(&manifest_bytes)?;
    manifest_file.write_all(b"\n")?;
    manifest_file.sync_all()?;
    let verified = verify_image(&manifest_path, ImageTrust::ExplicitLocal)?;
    let final_root = host_root.join("images").join(&verified.manifest_digest);
    if final_root.exists() {
        let existing = verify_image(&final_root.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if existing.manifest_digest != verified.manifest_digest {
            return Err(ImageBuildError::Invalid(
                "published image directory conflicts with its digest".into(),
            ));
        }
    } else {
        File::open(&artifact)?.sync_all()?;
        fs::rename(&artifact, &final_root)?;
        File::open(host_root.join("images"))?.sync_all()?;
    }
    let source_digest = Digest::try_from(bare_digest(&tree.source.manifest_digest)?.to_owned())
        .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let image = ImageRecord {
        digest: Digest::try_from(verified.manifest_digest)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        source_digest,
        platform: requested.os,
        architecture: requested.architecture,
        logical_bytes: Counter::try_from(rootfs_bytes)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        storage_bytes: Counter::try_from(artifact_storage_bytes(&final_root)?)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        provenance_digest: conversion_digest,
        sensitive: false,
    };
    let result = ImportResult {
        request_digest: request_digest.clone(),
        image: image.clone(),
    };
    write_json(&result_path, &result)?;
    File::open(&stage)?.sync_all()?;
    Ok(image)
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

    let imports = host_root.join("images/imports");
    prepare_private_directory(&imports)?;
    let stage = imports.join(operation.as_str());
    let result_path = stage.join("result.json");
    if result_path.exists() {
        let old: ImportResult = read_json(&result_path, 1024 * 1024)?;
        if old.request_digest != *request_digest {
            return Err(ImageBuildError::Invalid(
                "derived image staging identity conflicts with the request".into(),
            ));
        }
        verify_published(host_root, &old.image)?;
        return Ok(old.image);
    }
    if stage.exists() {
        let quarantine = imports.join(format!(
            "quarantine-{}-{}",
            operation.as_str(),
            short_nonce()?
        ));
        fs::rename(&stage, quarantine)?;
    }
    prepare_private_directory(&stage)?;

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
    copy_regular(&source.kernel_path, &kernel)?;
    crate::snapshots::materialize_image_template(&host_root.join("snapshots"), snapshot, &template)
        .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;

    let snapshot_manifest = snapshot
        .manifest_digest
        .as_ref()
        .expect("ready snapshot manifest was checked");
    let provenance_digest = digest(
        Domain::Image,
        &(
            "sandsurf-derived-image-v2",
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
    let platform_artifacts = materialize_derived_platform_artifacts(
        &source,
        &template,
        &artifact,
        snapshot.system_disk_bytes.get(),
    )?;
    let mut manifest = source.manifest;
    manifest.id = format!("derived-{}", &provenance_digest.as_str()[..16]);
    manifest.version = snapshot_manifest.as_str()[..16].to_owned();
    manifest.boot_bundle.kernel.path = "boot-kernel".into();
    manifest.boot_bundle.kernel.sha256 = sha256_file(&kernel, MAX_ROOTFS_BYTES)?;
    manifest.system.rootfs.path = "derived-system.ext4".into();
    manifest.system.rootfs.sha256 = sha256_file(&template, MAX_ROOTFS_BYTES)?;
    manifest.platform_artifacts = platform_artifacts;
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
    let final_root = host_root.join("images").join(&verified.manifest_digest);
    if final_root.exists() {
        let existing = verify_image(&final_root.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if existing.manifest_digest != verified.manifest_digest {
            return Err(ImageBuildError::Invalid(
                "derived image directory conflicts with its digest".into(),
            ));
        }
        remove_derived_artifact(&artifact)?;
    } else {
        File::open(&artifact)?.sync_all()?;
        fs::rename(&artifact, &final_root)?;
        File::open(host_root.join("images"))?.sync_all()?;
    }
    let architecture = match manifest.architecture {
        Architecture::X64 => "amd64",
        Architecture::Arm64 => "arm64",
    };
    let logical_bytes = snapshot.system_disk_bytes.get();
    let image = ImageRecord {
        digest: Digest::try_from(verified.manifest_digest)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        source_digest: snapshot
            .system_disk_digest
            .as_ref()
            .expect("ready snapshot disk was checked")
            .clone(),
        platform: "linux".into(),
        architecture: architecture.into(),
        logical_bytes: Counter::try_from(logical_bytes)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        storage_bytes: Counter::try_from(artifact_storage_bytes(&final_root)?)
            .map_err(|error| ImageBuildError::Invalid(error.to_string()))?,
        provenance_digest,
        sensitive: snapshot.sensitive,
    };
    write_json(
        &result_path,
        &ImportResult {
            request_digest: request_digest.clone(),
            image: image.clone(),
        },
    )?;
    File::open(&stage)?.sync_all()?;
    Ok(image)
}

fn remove_derived_artifact(path: &Path) -> Result<(), ImageBuildError> {
    for name in [
        "manifest.json",
        "derived-system.ext4",
        "boot-kernel",
        "windows-kernel",
        "windows-system.vhdx",
    ] {
        match fs::remove_file(path.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::remove_dir(path)?;
    Ok(())
}

fn parse_platform(value: &str) -> Result<GuestPlatform, ImageBuildError> {
    let mut components = value.split('/');
    let os = components.next().unwrap_or_default();
    let architecture = components.next().unwrap_or_default();
    let variant = components.next().map(str::to_owned);
    if os.is_empty() || architecture.is_empty() || components.next().is_some() || value.len() > 128
    {
        return Err(ImageBuildError::Invalid(
            "OCI platform must be os/architecture[/variant]".into(),
        ));
    }
    Ok(GuestPlatform {
        architecture: architecture.into(),
        os: os.into(),
        variant,
    })
}

fn resolve_recipe_boot_image(
    host_root: &Path,
    executable: &Path,
    expected: &Digest,
) -> Result<VerifiedImage, ImageBuildError> {
    let installed = host_root.join("images").join(expected.as_str());
    let image = match fs::symlink_metadata(&installed) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => verify_image(
            &installed.join("manifest.json"),
            ImageTrust::Pinned {
                manifest_digest: expected.as_str(),
            },
        )?,
        Ok(_) => {
            return Err(ImageBuildError::Invalid(
                "recipe boot image is not an owned image directory".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (image, _) = resolve_source_bundle(executable)?;
            if image.manifest_digest != expected.as_str() {
                return Err(ImageBuildError::Invalid(
                    "recipe boot image is unavailable".into(),
                ));
            }
            image
        }
        Err(error) => return Err(error.into()),
    };
    Ok(image)
}

/// Container roots without an OS init require an isolated build recipe. They
/// must not be silently booted as a chroot under a protected supervisor.
fn require_os_init(tree: &ConvertedTree) -> Result<(), ImageBuildError> {
    let mut path = "sbin/init".to_owned();
    for _ in 0..32 {
        let entry = tree
            .entries
            .iter()
            .find(|entry| entry.path.trim_start_matches('/') == path)
            .ok_or_else(|| {
                ImageBuildError::Invalid(
                    "OCI input has no bootable /sbin/init; an isolated OS build recipe is required"
                        .into(),
                )
            })?;
        match entry.kind {
            TreeEntryKind::Regular if entry.mode & 0o111 != 0 && entry.size > 0 => return Ok(()),
            TreeEntryKind::Symlink | TreeEntryKind::Hardlink => {
                let target = entry
                    .link_target
                    .as_ref()
                    .ok_or_else(|| ImageBuildError::Invalid("OS init link has no target".into()))?;
                let joined = if target.starts_with('/') || entry.kind == TreeEntryKind::Hardlink {
                    PathBuf::from(target.trim_start_matches('/'))
                } else {
                    Path::new(&path)
                        .parent()
                        .unwrap_or(Path::new(""))
                        .join(target)
                };
                let mut components = Vec::new();
                for component in joined.components() {
                    match component {
                        std::path::Component::Normal(value) => components.push(value.to_owned()),
                        std::path::Component::CurDir => {}
                        std::path::Component::ParentDir if !components.is_empty() => {
                            components.pop();
                        }
                        _ => {
                            return Err(ImageBuildError::Invalid(
                                "OS init link escapes the machine root".into(),
                            ));
                        }
                    }
                }
                path = components
                    .into_iter()
                    .collect::<PathBuf>()
                    .to_string_lossy()
                    .into_owned();
            }
            _ => {
                return Err(ImageBuildError::Invalid(
                    "OCI OS init is not executable".into(),
                ));
            }
        }
    }
    Err(ImageBuildError::Invalid(
        "OCI OS init link resolution exceeds its bound".into(),
    ))
}

fn rootfs_size(tree: &ConvertedTree) -> Result<u64, ImageBuildError> {
    let payload = tree.entries.iter().try_fold(0u64, |total, entry| {
        if entry.kind == TreeEntryKind::Regular {
            total.checked_add(entry.size)
        } else {
            Some(total)
        }
        .ok_or_else(|| ImageBuildError::Invalid("OCI tree size overflow".into()))
    })?;
    let metadata = u64::try_from(tree.entries.len())
        .ok()
        .and_then(|count| count.checked_mul(16 * 1024))
        .ok_or_else(|| ImageBuildError::Invalid("OCI tree metadata size overflow".into()))?;
    let required = payload
        .checked_add(payload / 2)
        .and_then(|value| value.checked_add(metadata))
        .and_then(|value| value.checked_add(128 * 1024 * 1024))
        .ok_or_else(|| ImageBuildError::Invalid("OCI root filesystem size overflow".into()))?;
    let bytes = required
        .max(256 * 1024 * 1024)
        .next_multiple_of(1024 * 1024);
    if bytes > MAX_ROOTFS_BYTES {
        return Err(ImageBuildError::Invalid(
            "OCI root filesystem exceeds the VM image bound".into(),
        ));
    }
    Ok(bytes)
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageIndex {
    #[serde(rename = "formatVersion")]
    _format_version: u16,
    #[serde(rename = "buildId")]
    _build_id: String,
    files: BTreeMap<String, String>,
}

fn resolve_source_bundle(executable: &Path) -> Result<(VerifiedImage, PathBuf), ImageBuildError> {
    if let Some(path) = std::env::var_os("SANDSURF_LOCAL_IMAGE_MANIFEST").map(PathBuf::from) {
        if !path.is_absolute() {
            return Err(ImageBuildError::Invalid(
                "SANDSURF_LOCAL_IMAGE_MANIFEST must be absolute".into(),
            ));
        }
        let image = verify_image(&path, ImageTrust::ExplicitLocal)?;
        let template = image.system_path.clone();
        return Ok((image, template));
    }
    let package = executable
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| ImageBuildError::Invalid("native package layout is invalid".into()))?;
    let architecture = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let relative = format!("development-{architecture}/manifest.json");
    let index: ImageIndex = read_json(&package.join("images/manifest.json"), 1024 * 1024)?;
    let indexed = index
        .files
        .get(&relative)
        .ok_or_else(|| ImageBuildError::Invalid("packaged image manifest is absent".into()))?;
    let pinned = BUNDLED_IMAGE_MANIFEST_DIGEST.ok_or_else(|| {
        ImageBuildError::Invalid("native host has no bundled image trust identity".into())
    })?;
    if indexed != pinned {
        return Err(ImageBuildError::Invalid(
            "packaged image index differs from the native trust identity".into(),
        ));
    }
    let image = verify_image(
        &package.join("images").join(relative),
        ImageTrust::Pinned {
            manifest_digest: pinned,
        },
    )?;
    let template = image.system_path.clone();
    Ok((image, template))
}

#[cfg(target_os = "windows")]
fn materialize_platform_artifacts(
    base: &VerifiedImage,
    defaults: &Path,
    destination: &Path,
    bytes: u64,
) -> Result<PlatformArtifacts, ImageBuildError> {
    let windows = base.windows_x64.as_ref().ok_or_else(|| {
        ImageBuildError::Invalid("packaged boot bundle has no Windows artifacts".into())
    })?;
    let kernel = destination.join("windows-kernel");
    let workload_vhdx = destination.join("windows-system.vhdx");
    copy_regular(&windows.kernel_path, &kernel)?;
    sandsurf_native::virtual_disk::import_raw(defaults, &workload_vhdx, bytes)?;
    Ok(PlatformArtifacts {
        windows_x64: Some(WindowsArtifacts {
            kernel: image_artifact(&kernel, "windows-kernel")?,
            system: image_artifact(&workload_vhdx, "windows-system.vhdx")?,
        }),
    })
}

#[cfg(not(target_os = "windows"))]
fn materialize_platform_artifacts(
    _base: &VerifiedImage,
    _workload: &Path,
    _destination: &Path,
    _bytes: u64,
) -> Result<PlatformArtifacts, ImageBuildError> {
    Ok(PlatformArtifacts::default())
}

fn materialize_derived_platform_artifacts(
    source: &VerifiedImage,
    system: &Path,
    destination: &Path,
    bytes: u64,
) -> Result<PlatformArtifacts, ImageBuildError> {
    materialize_platform_artifacts(source, system, destination, bytes)
}

#[cfg(target_os = "windows")]
fn image_artifact(path: &Path, name: &str) -> Result<ImageArtifact, ImageBuildError> {
    Ok(ImageArtifact {
        path: name.into(),
        sha256: sha256_file(path, MAX_ROOTFS_BYTES)?,
    })
}

fn prepare_private_directory(path: &Path) -> Result<(), ImageBuildError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => return Ok(()),
        Ok(_) => {
            return Err(ImageBuildError::Invalid(
                "image staging path is not a directory".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    fs::DirBuilder::new().mode(0o700).create(path)?;
    #[cfg(target_os = "windows")]
    sandsurf_native::local::create_private_directory(path)?;
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File, ImageBuildError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    Ok(options.open(path)?)
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

pub fn cleanup(host_root: &Path, digest: &Digest) -> Result<(), ImageBuildError> {
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
            File::open(images)?.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn artifact_storage_bytes(root: &Path) -> Result<u64, ImageBuildError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ImageBuildError::Invalid(
            "image artifact root is not a directory".into(),
        ));
    }
    let mut total = allocated_bytes(&metadata)?;
    let mut entries = 0_usize;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            entries = entries
                .checked_add(1)
                .ok_or_else(|| ImageBuildError::Invalid("image artifact count overflow".into()))?;
            if entries > 1_000_000 {
                return Err(ImageBuildError::Invalid(
                    "image artifact count exceeds its bound".into(),
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(ImageBuildError::Invalid(
                    "image artifact contains a symbolic link".into(),
                ));
            }
            total = total
                .checked_add(allocated_bytes(&metadata)?)
                .ok_or_else(|| ImageBuildError::Invalid("image storage size overflow".into()))?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if !metadata.is_file() {
                return Err(ImageBuildError::Invalid(
                    "image artifact contains a special file".into(),
                ));
            }
        }
    }
    Ok(total)
}

#[cfg(unix)]
fn allocated_bytes(metadata: &fs::Metadata) -> Result<u64, ImageBuildError> {
    metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| ImageBuildError::Invalid("image allocated size overflow".into()))
}

#[cfg(not(unix))]
fn allocated_bytes(metadata: &fs::Metadata) -> Result<u64, ImageBuildError> {
    // The Windows artifacts are dynamic VHDX files; their file length is the
    // portable lower bound available without opening another authority-bearing
    // filesystem handle. Quota admission remains conservative for ordinary
    // files and is reconciled from the artifact tree at publication.
    Ok(metadata.len())
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

fn short_digest(value: &str) -> Result<&str, ImageBuildError> {
    Ok(&bare_digest(value)?[..16])
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

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ImageBuildError> {
    let bytes = serde_json::to_vec(value)?;
    let mut file = create_private_file(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum: u64,
) -> Result<T, ImageBuildError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(ImageBuildError::Invalid(
            "image import result is malformed".into(),
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
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
        fs::remove_dir(root).unwrap();
    }
}
