//! Portable OCI metadata/content conversion; Linux filesystem construction
//! runs in the native offline hardware VM, never on the host filesystem.
use super::*;
use sandsurf_image::ext4::materialize_tar;
use sandsurf_image::oci::{
    ConversionLimits, ConvertedTree, GuestPlatform, OciLayout, TreeEntryKind,
    unpack_layout_archive, write_filesystem_tar,
};
use sandsurf_image::{
    ImageDefaults, ImageManifest, RootfsArtifact, RootfsFormat, SystemDiskManifest,
};
use sandsurf_state::{MachineImageRecipe, OciSource};
use std::collections::BTreeMap;

pub(crate) struct BuildInput<'a> {
    pub source: &'a OciSource,
    pub recipe: &'a MachineImageRecipe,
    pub platform: &'a str,
}

pub(crate) fn import(
    executor: &mut dyn sandsurf_image::appliance::Executor,
    host_root: &Path,
    input: BuildInput<'_>,
    operation: &OperationId,
    request_digest: &Digest,
    registry_credential: Option<&[u8]>,
) -> Result<ImageRecord, ImageBuildError> {
    let BuildInput {
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
    let custody = std::sync::Arc::new(image_custody(host_root, &recipe.boot_image_digest)?);
    let base = resolve_native_image(host_root, &recipe.boot_image_digest)?;
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
    let (stage, old, operation_custody) = prepare_import(host_root, operation, request_digest)?;
    let operation_custody = std::sync::Arc::new(operation_custody);
    if let Some(image) = old {
        return Ok(image);
    }
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
            sandsurf_image::registry::fetch_layout(
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
    let builder = materialize_tar(
        executor,
        vec![custody, operation_custody],
        &filesystem_tar,
        &system_path,
        rootfs_bytes,
    )
    .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let kernel_name = "boot-kernel";
    copy_regular(&base.kernel_path, &artifact.join(kernel_name))?;
    if let Some(initramfs) = &base.initramfs_path {
        copy_regular(initramfs, &artifact.join("boot-initramfs"))?;
    }
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
            "sandsurf-oci-machine-v1",
            &tree.manifest_digest,
            recipe,
            &builder,
            rootfs_bytes,
        ),
    )
    .map_err(|error| ImageBuildError::Invalid(error.to_string()))?;
    let mut manifest = ImageManifest {
        format_version: 1,
        id: format!("oci-{}", short_digest(&tree.source.manifest_digest)?),
        version: short_digest(&tree.source.config_digest)?.to_owned(),
        architecture,
        boot_bundle: base.manifest.boot_bundle.clone(),
        system: SystemDiskManifest {
            clone_profile: sandsurf_image::identity::CloneProfile::Preserve,
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
        signature: None,
    };
    manifest.boot_bundle.kernel.path = kernel_name.into();
    if let Some(initramfs) = &mut manifest.boot_bundle.initramfs {
        initramfs.path = "boot-initramfs".into();
    }
    // OCI conversion does not install distribution hooks. The selected recipe
    // explicitly pins boot inputs and preserves custom OS clone identities.
    manifest.boot_bundle.profile = sandsurf_image::boot::BootProfile::Pinned;
    manifest.boot_bundle.guest_agent = None;
    let manifest_path = artifact.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let mut manifest_file = create_private_file(&manifest_path)?;
    manifest_file.write_all(&manifest_bytes)?;
    manifest_file.write_all(b"\n")?;
    manifest_file.sync_all()?;
    let verified = verify_image(&manifest_path, ImageTrust::ExplicitLocal)?;
    let (final_root, verified) = publish_image(&stage, &verified)?;
    fs::remove_dir_all(&artifact)?;
    let image = image_record(&final_root, &verified)?;
    finish_import(&stage, request_digest, &image)?;
    Ok(image)
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
                // Linux path resolution must not inherit Windows drive,
                // backslash or case-folding rules from the host.
                let joined = if target.starts_with('/') || entry.kind == TreeEntryKind::Hardlink {
                    target.trim_start_matches('/').to_owned()
                } else {
                    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
                    if parent.is_empty() {
                        target.clone()
                    } else {
                        format!("{parent}/{target}")
                    }
                };
                let mut components = Vec::new();
                for component in joined.split('/') {
                    match component {
                        "" | "." => {}
                        ".." if !components.is_empty() => {
                            components.pop();
                        }
                        ".." => {
                            return Err(ImageBuildError::Invalid(
                                "OS init link escapes the machine root".into(),
                            ));
                        }
                        value => components.push(value),
                    }
                }
                path = components.join("/");
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

fn short_digest(value: &str) -> Result<&str, ImageBuildError> {
    Ok(&bare_digest(value)?[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_image::oci::{ImageDefaults, ResolvedOciImage, TreeEntry};

    fn tree(target: &str, executable: &str) -> ConvertedTree {
        ConvertedTree {
            source: ResolvedOciImage {
                source_index_digest: "unused".into(),
                manifest_digest: "unused".into(),
                config_digest: "unused".into(),
                layer_digests: vec![],
                diff_ids: vec![],
                defaults: ImageDefaults {
                    environment: vec![],
                    user: None,
                    working_directory: None,
                    entrypoint: vec![],
                    command: vec![],
                },
                architecture: "amd64".into(),
                os: "linux".into(),
                variant: None,
            },
            manifest_digest: "unused".into(),
            entries: vec![
                TreeEntry {
                    path: "sbin/init".into(),
                    kind: TreeEntryKind::Symlink,
                    mode: 0o777,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    digest: None,
                    link_target: Some(target.into()),
                },
                TreeEntry {
                    path: executable.into(),
                    kind: TreeEntryKind::Regular,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    size: 1,
                    digest: Some("unused".into()),
                    link_target: None,
                },
            ],
        }
    }

    #[test]
    fn os_init_resolution_uses_linux_identity_and_never_host_path_rules() {
        for (target, executable) in [
            ("../bin/init", "bin/init"),
            ("/bin/init", "bin/init"),
            ("C:drive\\init", "sbin/C:drive\\init"),
            ("../CON", "CON"),
        ] {
            assert!(require_os_init(&tree(target, executable)).is_ok());
        }
        assert!(require_os_init(&tree("../../outside", "outside")).is_err());
        assert!(require_os_init(&tree("../CON", "con")).is_err());
        assert!(require_os_init(&tree("init", "other")).is_err());
        let mut value = tree("/bin/init", "bin/init");
        value.entries[1].mode = 0o644;
        assert!(require_os_init(&value).is_err());
    }
}
