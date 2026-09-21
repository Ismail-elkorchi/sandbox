//! Linux OCI-to-VM image publication. The conversion never mounts the source
//! tree or generated filesystem in the host kernel.

use crate::api::{DerivedImageInclusion, OciSource};
use crate::linux::{LinuxError, resolve_source_bundle};
use sandbox_image::oci::{
    ConversionLimits, ConvertedTree, GuestPlatform, OciLayout, TreeEntryKind,
    unpack_layout_archive, write_filesystem_tar,
};
use sandbox_image::{
    Architecture, ImageManifest, ImageTrust, RootfsArtifact, RootfsFormat, WorkloadDefaults,
    WorkloadImageManifest, WorkloadProvenance, verify_image,
};
use sandsurf_protocol::{
    Checkpoint, CheckpointPhase, Counter, Digest, Domain, OperationId, Qualification, digest,
};
use sandsurf_state::ImageRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_ROOTFS_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportResult {
    request_digest: Digest,
    image: ImageRecord,
}

pub fn qualification() -> Qualification {
    let result = find_builder().and_then(|path| {
        let tool = sha256_file(&path, 128 * 1024 * 1024)?;
        digest(Domain::Image, &("sandsurf-linux-oci-builder-v1", tool))
            .map_err(|error| LinuxError::Invalid(error.to_string()))
    });
    match result {
        Ok(evidence) => Qualification::Qualified { evidence },
        Err(error) => Qualification::Unqualified {
            reasons: vec![error.to_string()],
        },
    }
}

pub fn import_oci(
    host_root: &Path,
    executable: &Path,
    source: &OciSource,
    platform: &str,
    operation: &OperationId,
    request_digest: &Digest,
    registry_credential: Option<&[u8]>,
) -> Result<ImageRecord, LinuxError> {
    let requested = parse_platform(platform)?;
    let expected_architecture = match crate::service::native_guest_architecture() {
        sandsurf_machine::GuestArchitecture::Amd64 => "amd64",
        sandsurf_machine::GuestArchitecture::Arm64 => "arm64",
    };
    if requested.os != "linux" || requested.architecture != expected_architecture {
        return Err(LinuxError::Invalid(
            "OCI platform must exactly match the native Linux guest architecture".into(),
        ));
    }
    let imports = host_root.join("images/imports");
    fs::create_dir_all(&imports)?;
    fs::set_permissions(&imports, fs::Permissions::from_mode(0o700))?;
    let stage = imports.join(operation.as_str());
    let result_path = stage.join("result.json");
    if result_path.exists() {
        let old: ImportResult = read_json(&result_path, 1024 * 1024)?;
        if old.request_digest != *request_digest {
            return Err(LinuxError::Invalid(
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
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    let layout_path = match source {
        OciSource::Layout { path } => {
            if !path.is_absolute() {
                return Err(LinuxError::Invalid(
                    "OCI layout path must be absolute".into(),
                ));
            }
            path.clone()
        }
        OciSource::Archive { path } => {
            let layout = stage.join("layout");
            unpack_layout_archive(path, &layout, ConversionLimits::default())
                .map_err(|error| LinuxError::Invalid(error.to_string()))?;
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
            .map_err(|error| LinuxError::Invalid(error.to_string()))?;
            layout
        }
    };
    let layout = OciLayout::open(&layout_path, ConversionLimits::default())
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let resolved = layout
        .resolve(&requested)
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let tree_root = stage.join("tree");
    let tree = layout
        .convert(resolved, &tree_root)
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let filesystem_tar = stage.join("rootfs.tar");
    write_filesystem_tar(&tree_root, &tree, &filesystem_tar)
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let rootfs_bytes = rootfs_size(&tree)?;
    let artifact = stage.join("artifact");
    fs::DirBuilder::new().mode(0o700).create(&artifact)?;
    let workload_path = artifact.join("oci-workload.ext4");
    let builder = materialize_ext4(&filesystem_tar, &workload_path, rootfs_bytes)?;
    let (base, template) = resolve_source_bundle(executable)?;
    let kernel_name = "boot-kernel";
    let bootstrap_name = "trusted-bootstrap.ext4";
    copy_regular(&base.kernel_path, &artifact.join(kernel_name))?;
    copy_regular(&base.bootstrap_path, &artifact.join(bootstrap_name))?;
    copy_regular(&template, &artifact.join("empty-workspace.ext4"))?;
    let mut environment = BTreeMap::new();
    for assignment in &tree.source.defaults.environment {
        let (name, value) = assignment
            .split_once('=')
            .ok_or_else(|| LinuxError::Invalid("validated OCI environment changed".into()))?;
        environment.insert(name.to_owned(), value.to_owned());
    }
    let conversion_digest = digest(
        Domain::Image,
        &(
            "sandsurf-oci-ext4-v1",
            &tree.manifest_digest,
            &builder,
            rootfs_bytes,
        ),
    )
    .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let mut manifest = ImageManifest {
        format_version: 2,
        id: format!("oci-{}", short_digest(&tree.source.manifest_digest)?),
        version: short_digest(&tree.source.config_digest)?.to_owned(),
        architecture: match requested.architecture.as_str() {
            "amd64" => Architecture::X64,
            "arm64" => Architecture::Arm64,
            _ => return Err(LinuxError::Invalid("unsupported OCI architecture".into())),
        },
        boot_bundle: base.manifest.boot_bundle.clone(),
        workload: WorkloadImageManifest {
            rootfs: RootfsArtifact {
                path: "oci-workload.ext4".into(),
                sha256: sha256_file(&workload_path, MAX_ROOTFS_BYTES)?,
                format: RootfsFormat::Ext4,
            },
            state_template: Some(RootfsArtifact {
                path: "empty-workspace.ext4".into(),
                sha256: sha256_file(&artifact.join("empty-workspace.ext4"), MAX_ROOTFS_BYTES)?,
                format: RootfsFormat::Ext4,
            }),
            defaults: WorkloadDefaults {
                environment,
                user: tree.source.defaults.user.clone(),
                working_directory: tree.source.defaults.working_directory.clone(),
                entrypoint: tree.source.defaults.entrypoint.clone(),
                command: tree.source.defaults.command.clone(),
            },
            provenance: WorkloadProvenance::Oci {
                index_digest: bare_digest(&tree.source.source_index_digest)?.to_owned(),
                manifest_digest: bare_digest(&tree.source.manifest_digest)?.to_owned(),
                config_digest: bare_digest(&tree.source.config_digest)?.to_owned(),
                conversion_digest: conversion_digest.as_str().to_owned(),
            },
            compatible_protocol_major: base.manifest.workload.compatible_protocol_major,
        },
        signature: None,
    };
    manifest.boot_bundle.kernel.path = kernel_name.into();
    manifest.boot_bundle.bootstrap.path = bootstrap_name.into();
    let manifest_path = artifact.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let mut manifest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&manifest_path)?;
    manifest_file.write_all(&manifest_bytes)?;
    manifest_file.write_all(b"\n")?;
    manifest_file.sync_all()?;
    let verified = verify_image(&manifest_path, ImageTrust::ExplicitLocal)?;
    let final_root = host_root.join("images").join(&verified.manifest_digest);
    if final_root.exists() {
        let existing = verify_image(&final_root.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if existing.manifest_digest != verified.manifest_digest {
            return Err(LinuxError::Invalid(
                "published image directory conflicts with its digest".into(),
            ));
        }
    } else {
        File::open(&artifact)?.sync_all()?;
        fs::rename(&artifact, &final_root)?;
        File::open(host_root.join("images"))?.sync_all()?;
    }
    let source_digest = Digest::try_from(bare_digest(&tree.source.manifest_digest)?.to_owned())
        .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let image = ImageRecord {
        digest: Digest::try_from(verified.manifest_digest)
            .map_err(|error| LinuxError::Invalid(error.to_string()))?,
        source_digest,
        platform: requested.os,
        architecture: requested.architecture,
        logical_bytes: Counter::try_from(rootfs_bytes)
            .map_err(|error| LinuxError::Invalid(error.to_string()))?,
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

pub fn publish_checkpoint(
    host_root: &Path,
    checkpoint: &Checkpoint,
    inclusion: DerivedImageInclusion,
    operation: &OperationId,
    request_digest: &Digest,
) -> Result<ImageRecord, LinuxError> {
    if checkpoint.phase != CheckpointPhase::Ready
        || checkpoint.workload_disk_digest.is_none()
        || checkpoint.manifest_digest.is_none()
    {
        return Err(LinuxError::Invalid(
            "derived image requires a ready filesystem checkpoint".into(),
        ));
    }
    if !inclusion.workspace || !inclusion.home {
        return Err(LinuxError::Invalid(
            "the current VM-native publisher requires explicit workspace and home inclusion".into(),
        ));
    }
    if checkpoint.sensitive && !inclusion.secrets {
        return Err(LinuxError::Invalid(
            "a secret-tainted checkpoint requires explicit secret inclusion".into(),
        ));
    }

    let imports = host_root.join("images/imports");
    fs::create_dir_all(&imports)?;
    fs::set_permissions(&imports, fs::Permissions::from_mode(0o700))?;
    let stage = imports.join(operation.as_str());
    let result_path = stage.join("result.json");
    if result_path.exists() {
        let old: ImportResult = read_json(&result_path, 1024 * 1024)?;
        if old.request_digest != *request_digest {
            return Err(LinuxError::Invalid(
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
    fs::DirBuilder::new().mode(0o700).create(&stage)?;

    let source_root = host_root
        .join("images")
        .join(checkpoint.image_digest.as_str());
    let source = verify_image(
        &source_root.join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if source.manifest_digest != checkpoint.image_digest.as_str() {
        return Err(LinuxError::Invalid(
            "checkpoint source image identity changed".into(),
        ));
    }
    let artifact = stage.join("artifact");
    fs::DirBuilder::new().mode(0o700).create(&artifact)?;
    let kernel = artifact.join("boot-kernel");
    let bootstrap = artifact.join("trusted-bootstrap.ext4");
    let workload = artifact.join("derived-workload.ext4");
    let template = artifact.join("empty-workspace.ext4");
    copy_regular(&source.kernel_path, &kernel)?;
    copy_regular(&source.bootstrap_path, &bootstrap)?;
    copy_regular(&source.workload_path, &workload)?;
    crate::checkpoints::materialize_image_template(
        &host_root.join("checkpoints"),
        checkpoint,
        &template,
    )
    .map_err(|error| LinuxError::Invalid(error.to_string()))?;

    let checkpoint_manifest = checkpoint
        .manifest_digest
        .as_ref()
        .expect("ready checkpoint manifest was checked");
    let provenance_digest = digest(
        Domain::Image,
        &(
            "sandsurf-derived-image-v1",
            &checkpoint.image_digest,
            checkpoint_manifest,
            checkpoint
                .workload_disk_digest
                .as_ref()
                .expect("ready checkpoint disk was checked"),
            inclusion.workspace,
            inclusion.home,
            inclusion.secrets,
        ),
    )
    .map_err(|error| LinuxError::Invalid(error.to_string()))?;
    let mut manifest = source.manifest;
    manifest.id = format!("derived-{}", &provenance_digest.as_str()[..16]);
    manifest.version = checkpoint_manifest.as_str()[..16].to_owned();
    manifest.boot_bundle.kernel.path = "boot-kernel".into();
    manifest.boot_bundle.kernel.sha256 = sha256_file(&kernel, MAX_ROOTFS_BYTES)?;
    manifest.boot_bundle.bootstrap.path = "trusted-bootstrap.ext4".into();
    manifest.boot_bundle.bootstrap.sha256 = sha256_file(&bootstrap, MAX_ROOTFS_BYTES)?;
    manifest.workload.rootfs.path = "derived-workload.ext4".into();
    manifest.workload.rootfs.sha256 = sha256_file(&workload, MAX_ROOTFS_BYTES)?;
    manifest.workload.state_template = Some(RootfsArtifact {
        path: "empty-workspace.ext4".into(),
        sha256: sha256_file(&template, MAX_ROOTFS_BYTES)?,
        format: RootfsFormat::Ext4,
    });
    manifest.workload.provenance = WorkloadProvenance::Derived {
        source_image_digest: checkpoint.image_digest.as_str().to_owned(),
        checkpoint_manifest_digest: checkpoint_manifest.as_str().to_owned(),
        include_workspace: inclusion.workspace,
        include_home: inclusion.home,
        include_secrets: inclusion.secrets,
    };
    manifest.signature = None;
    let manifest_path = artifact.join("manifest.json");
    let mut manifest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&manifest_path)?;
    manifest_file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    manifest_file.write_all(b"\n")?;
    manifest_file.sync_all()?;
    let verified = verify_image(&manifest_path, ImageTrust::ExplicitLocal)?;
    let workload_bytes = fs::metadata(&workload)?.len();
    let final_root = host_root.join("images").join(&verified.manifest_digest);
    if final_root.exists() {
        let existing = verify_image(&final_root.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if existing.manifest_digest != verified.manifest_digest {
            return Err(LinuxError::Invalid(
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
    let logical_bytes = checkpoint
        .workload_disk_bytes
        .get()
        .checked_add(workload_bytes)
        .ok_or_else(|| LinuxError::Invalid("derived image size overflow".into()))?;
    let image = ImageRecord {
        digest: Digest::try_from(verified.manifest_digest)
            .map_err(|error| LinuxError::Invalid(error.to_string()))?,
        source_digest: checkpoint
            .workload_disk_digest
            .as_ref()
            .expect("ready checkpoint disk was checked")
            .clone(),
        platform: "linux".into(),
        architecture: architecture.into(),
        logical_bytes: Counter::try_from(logical_bytes)
            .map_err(|error| LinuxError::Invalid(error.to_string()))?,
        provenance_digest,
        sensitive: checkpoint.sensitive,
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

fn remove_derived_artifact(path: &Path) -> Result<(), LinuxError> {
    for name in [
        "manifest.json",
        "empty-workspace.ext4",
        "derived-workload.ext4",
        "trusted-bootstrap.ext4",
        "boot-kernel",
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

fn parse_platform(value: &str) -> Result<GuestPlatform, LinuxError> {
    let mut components = value.split('/');
    let os = components.next().unwrap_or_default();
    let architecture = components.next().unwrap_or_default();
    let variant = components.next().map(str::to_owned);
    if os.is_empty() || architecture.is_empty() || components.next().is_some() || value.len() > 128
    {
        return Err(LinuxError::Invalid(
            "OCI platform must be os/architecture[/variant]".into(),
        ));
    }
    Ok(GuestPlatform {
        architecture: architecture.into(),
        os: os.into(),
        variant,
    })
}

fn rootfs_size(tree: &ConvertedTree) -> Result<u64, LinuxError> {
    let payload = tree.entries.iter().try_fold(0u64, |total, entry| {
        if entry.kind == TreeEntryKind::Regular {
            total.checked_add(entry.size)
        } else {
            Some(total)
        }
        .ok_or_else(|| LinuxError::Invalid("OCI tree size overflow".into()))
    })?;
    let metadata = u64::try_from(tree.entries.len())
        .ok()
        .and_then(|count| count.checked_mul(16 * 1024))
        .ok_or_else(|| LinuxError::Invalid("OCI tree metadata size overflow".into()))?;
    let required = payload
        .checked_add(payload / 2)
        .and_then(|value| value.checked_add(metadata))
        .and_then(|value| value.checked_add(128 * 1024 * 1024))
        .ok_or_else(|| LinuxError::Invalid("OCI root filesystem size overflow".into()))?;
    let bytes = required
        .max(256 * 1024 * 1024)
        .next_multiple_of(1024 * 1024);
    if bytes > MAX_ROOTFS_BYTES {
        return Err(LinuxError::Invalid(
            "OCI root filesystem exceeds the VM image bound".into(),
        ));
    }
    Ok(bytes)
}

fn materialize_ext4(tar: &Path, output: &Path, bytes: u64) -> Result<String, LinuxError> {
    let builder = find_builder()?;
    let builder_digest = sha256_file(&builder, 128 * 1024 * 1024)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    file.set_len(bytes)?;
    file.sync_all()?;
    let status = Command::new(&builder)
        .args([
            "-F",
            "-q",
            "-O",
            "^has_journal",
            "-U",
            "00000000-0000-4000-8000-000000000001",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            "-d",
        ])
        .arg(tar)
        .arg(output)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(LinuxError::Invalid(
            "the qualified ext4 builder rejected the converted OCI tree".into(),
        ));
    }
    File::open(output)?.sync_all()?;
    Ok(builder_digest)
}

fn find_builder() -> Result<PathBuf, LinuxError> {
    for candidate in ["/usr/sbin/mke2fs", "/sbin/mke2fs"] {
        let path = PathBuf::from(candidate);
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o022 == 0
        {
            return Ok(path);
        }
    }
    Err(LinuxError::Invalid(
        "a protected mke2fs image builder is unavailable".into(),
    ))
}

fn verify_published(host_root: &Path, image: &ImageRecord) -> Result<(), LinuxError> {
    let verified = verify_image(
        &host_root
            .join("images")
            .join(image.digest.as_str())
            .join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if verified.manifest_digest != image.digest.as_str() {
        return Err(LinuxError::Invalid(
            "published image failed identity verification".into(),
        ));
    }
    Ok(())
}

fn copy_regular(source: &Path, destination: &Path) -> Result<(), LinuxError> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(LinuxError::Invalid(
            "image input is not a regular file".into(),
        ));
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn bare_digest(value: &str) -> Result<&str, LinuxError> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LinuxError::Invalid("OCI digest is malformed".into()));
    }
    Ok(value)
}

fn short_digest(value: &str) -> Result<&str, LinuxError> {
    Ok(&bare_digest(value)?[..16])
}

fn sha256_file(path: &Path, maximum: u64) -> Result<String, LinuxError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(LinuxError::Invalid(
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

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), LinuxError> {
    let bytes = serde_json::to_vec(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, LinuxError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(LinuxError::Invalid(
            "image import result is malformed".into(),
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn short_nonce() -> Result<String, LinuxError> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| LinuxError::Invalid("host entropy unavailable".into()))?;
    use std::fmt::Write as _;
    let mut output = String::with_capacity(16);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("string formatting cannot fail");
    }
    Ok(output)
}
