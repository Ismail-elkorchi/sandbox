//! Bounded OCI-layout resolution and layer application for the unprivileged
//! Sandsurf image builder. The output is a VM-image input tree, not a container
//! runtime root and no OCI entrypoint is executed here.

use flate2::read::MultiGzDecoder;
use ruzstd::decoding::{FrameDecoder, StreamingDecoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const OCI_INDEX_MEDIA: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG_MEDIA: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const DOCKER_INDEX_MEDIA: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const DOCKER_MANIFEST_MEDIA: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_CONFIG_MEDIA: &str = "application/vnd.docker.container.image.v1+json";
const DOCKER_LAYER_TAR: &str = "application/vnd.docker.image.rootfs.diff.tar";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionLimits {
    pub descriptors: usize,
    pub layers: usize,
    pub entries: usize,
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub file_bytes: u64,
    pub path_bytes: usize,
    pub json_bytes: u64,
}

impl Default for ConversionLimits {
    fn default() -> Self {
        Self {
            descriptors: 1024,
            layers: 256,
            entries: 1_000_000,
            compressed_bytes: 16 * 1024 * 1024 * 1024,
            expanded_bytes: 64 * 1024 * 1024 * 1024,
            file_bytes: 16 * 1024 * 1024 * 1024,
            path_bytes: 4096,
            json_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPlatform {
    pub architecture: String,
    pub os: String,
    pub variant: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageDefaults {
    pub environment: Vec<String>,
    pub user: Option<String>,
    pub working_directory: Option<String>,
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedOciImage {
    pub source_index_digest: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub layer_digests: Vec<String>,
    pub diff_ids: Vec<String>,
    pub defaults: ImageDefaults,
    pub architecture: String,
    pub os: String,
    pub variant: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TreeEntry {
    pub path: String,
    pub kind: TreeEntryKind,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub size: u64,
    pub digest: Option<String>,
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TreeEntryKind {
    Directory,
    Regular,
    Symlink,
    Hardlink,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConvertedTree {
    pub source: ResolvedOciImage,
    pub entries: Vec<TreeEntry>,
    pub manifest_digest: String,
}

#[derive(Debug)]
pub enum OciError {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(String),
    Limit(&'static str),
    DigestMismatch(String),
    Unsupported(String),
}

impl fmt::Display for OciError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "OCI I/O: {error}"),
            Self::Json(error) => write!(output, "OCI JSON: {error}"),
            Self::Invalid(message) => write!(output, "invalid OCI image: {message}"),
            Self::Limit(name) => write!(output, "OCI image exceeds {name} limit"),
            Self::DigestMismatch(digest) => write!(output, "OCI blob digest mismatch: {digest}"),
            Self::Unsupported(message) => write!(output, "unsupported OCI image: {message}"),
        }
    }
}

impl std::error::Error for OciError {}
impl From<io::Error> for OciError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for OciError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub struct OciLayout {
    root: PathBuf,
    limits: ConversionLimits,
}

/// Unpack the narrow OCI image-layout archive vocabulary into a fresh private
/// staging directory. Archive links and arbitrary top-level files are refused;
/// layer archive parsing remains a separate, independently bounded step.
pub fn unpack_layout_archive(
    archive_path: &Path,
    destination: &Path,
    limits: ConversionLimits,
) -> Result<(), OciError> {
    if !archive_path.is_absolute() || !destination.is_absolute() {
        return Err(OciError::Invalid(
            "OCI archive and destination paths must be absolute".into(),
        ));
    }
    let metadata = fs::symlink_metadata(archive_path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > limits.compressed_bytes
    {
        return Err(OciError::Limit("OCI archive byte count"));
    }
    prepare_empty_destination(destination)?;
    let file = File::open(archive_path)?;
    let mut archive = sandsurf_format::archive::Archive::new(
        file,
        sandsurf_format::archive::Limits {
            headers: limits.entries,
            bytes: limits.compressed_bytes,
            file_bytes: limits.compressed_bytes,
            path_bytes: limits.path_bytes,
        },
    );
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some(mut item) = archive.next_entry()? {
        entries = entries
            .checked_add(1)
            .ok_or(OciError::Limit("OCI archive entry count"))?;
        if entries > limits.entries {
            return Err(OciError::Limit("OCI archive entry count"));
        }
        let relative = normalize_layer_path(item.path(), limits.path_bytes)?;
        if relative.is_empty() {
            continue;
        }
        if !is_layout_archive_path(&relative) {
            return Err(OciError::Invalid(format!(
                "OCI archive contains an unexpected path {}",
                relative
            )));
        }
        let kind = item.header().entry_type();
        let output = destination.join(&relative);
        if kind.is_dir() {
            fs::create_dir_all(&output)?;
            continue;
        }
        if !kind.is_file() {
            return Err(OciError::Unsupported(
                "OCI layout archive links and special files".into(),
            ));
        }
        let declared = item.size();
        bytes = bytes
            .checked_add(declared)
            .ok_or(OciError::Limit("OCI archive expanded byte count"))?;
        if bytes > limits.compressed_bytes {
            return Err(OciError::Limit("OCI archive expanded byte count"));
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        let copied = io::copy(&mut item.by_ref().take(declared + 1), &mut target)?;
        if copied != declared {
            return Err(OciError::Invalid(
                "OCI archive entry length differs from its header".into(),
            ));
        }
        target.sync_all()?;
    }
    OciLayout::open(destination, limits)?;
    Ok(())
}

/// Write a canonical uncompressed tar stream whose headers preserve the OCI
/// UID/GID/mode/link metadata. The isolated appliance consumes this stream
/// without the host mounting or chowning the untrusted tree.
pub fn write_filesystem_tar(
    tree_root: &Path,
    tree: &ConvertedTree,
    destination: &Path,
) -> Result<(), OciError> {
    if !tree_root.is_absolute() || !destination.is_absolute() {
        return Err(OciError::Invalid(
            "converted tree and tar paths must be absolute".into(),
        ));
    }
    let ordered = filesystem_archive_order(&tree.entries)?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut archive = tar::Builder::new(output);
    archive.mode(tar::HeaderMode::Deterministic);
    for entry in ordered {
        let relative = normalize_layer_path(Path::new(&entry.path), 4096)?;
        if relative.is_empty() {
            continue;
        }
        let mut header = tar::Header::new_gnu();
        header.set_uid(entry.uid);
        header.set_gid(entry.gid);
        header.set_mode(entry.mode);
        header.set_mtime(0);
        match entry.kind {
            TreeEntryKind::Directory => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                guest_header(&mut archive, &mut header, &relative, None)?;
                archive.append(&header, io::empty())?;
            }
            TreeEntryKind::Regular => {
                let digest = entry.digest.as_deref().ok_or_else(|| {
                    OciError::Invalid("regular inode has no content identity".into())
                })?;
                parse_digest(&format!("sha256:{digest}"))?;
                let source = tree_root.join(digest);
                let metadata = fs::symlink_metadata(&source)?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() != entry.size
                {
                    return Err(OciError::Invalid(
                        "converted regular file changed before materialization".into(),
                    ));
                }
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(entry.size);
                guest_header(&mut archive, &mut header, &relative, None)?;
                let mut input = HashingReader::new(File::open(source)?, entry.size);
                archive.append(&header, &mut input)?;
                if input.bytes != entry.size || format!("{:x}", input.hasher.finalize()) != digest {
                    return Err(OciError::DigestMismatch(digest.into()));
                }
            }
            TreeEntryKind::Symlink | TreeEntryKind::Hardlink => {
                let target = entry
                    .link_target
                    .as_ref()
                    .ok_or_else(|| OciError::Invalid("converted link target is absent".into()))?;
                header.set_entry_type(if entry.kind == TreeEntryKind::Symlink {
                    tar::EntryType::Symlink
                } else {
                    tar::EntryType::Link
                });
                header.set_size(0);
                guest_header(&mut archive, &mut header, &relative, Some(target))?;
                archive.append(&header, io::empty())?;
            }
        }
    }
    archive.finish()?;
    let output = archive.into_inner()?;
    output.sync_all()?;
    Ok(())
}

/// Guest Linux names never pass through a host Path interpretation. In
/// particular Windows drive prefixes, backslashes and reserved device names
/// remain literal tar bytes, never host filenames. GNU extensions carry the
/// complete bounded UTF-8 name rather than a host-normalized alias.
fn guest_header<W: Write>(
    archive: &mut tar::Builder<W>,
    header: &mut tar::Header,
    path: &str,
    link: Option<&str>,
) -> io::Result<()> {
    for (text, kind, offset) in [
        (Some(path), tar::EntryType::GNULongName, 0),
        (link, tar::EntryType::GNULongLink, 157),
    ] {
        let Some(text) = text else { continue };
        if text.len() > 4096 || text.contains('\0') {
            return Err(io::Error::other("invalid guest tar name"));
        }
        if text.len() > 100 {
            let mut extension = tar::Header::new_gnu();
            extension.set_entry_type(kind);
            extension.set_size(text.len() as u64 + 1);
            extension.set_mode(0o644);
            let name = b"././@LongLink\0";
            extension.as_mut_bytes()[..name.len()].copy_from_slice(name);
            extension.set_cksum();
            archive.append(&extension, text.as_bytes().chain(&b"\0"[..]))?;
        }
        let bytes = &mut header.as_mut_bytes()[offset..offset + 100];
        bytes.fill(0);
        let count = text.len().min(100);
        bytes[..count].copy_from_slice(&text.as_bytes()[..count]);
    }
    header.set_cksum();
    Ok(())
}

/// Directory/file order is canonical; hardlinks follow their inode source,
/// even when their names sort before it. Reject cycles before creating a tar.
fn filesystem_archive_order(entries: &[TreeEntry]) -> Result<Vec<&TreeEntry>, OciError> {
    let by_path: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    if by_path.len() != entries.len() {
        return Err(OciError::Invalid(
            "duplicate filesystem archive entry".into(),
        ));
    }
    let mut ordered = Vec::with_capacity(entries.len());
    let mut waiting: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut ready = BTreeSet::new();
    for entry in by_path.values() {
        if entry.kind != TreeEntryKind::Hardlink {
            ordered.push(*entry);
            continue;
        }
        let target = entry
            .link_target
            .as_deref()
            .and_then(|path| by_path.get(path))
            .ok_or_else(|| OciError::Invalid("filesystem hardlink target missing".into()))?;
        match target.kind {
            TreeEntryKind::Regular => {
                ready.insert(entry.path.as_str());
            }
            TreeEntryKind::Hardlink => {
                waiting
                    .entry(target.path.as_str())
                    .or_default()
                    .push(entry.path.as_str());
            }
            _ => {
                return Err(OciError::Invalid(
                    "filesystem hardlink target is not an inode source".into(),
                ));
            }
        }
    }
    while let Some(path) = ready.pop_first() {
        ordered.push(by_path[path]);
        if let Some(children) = waiting.remove(path) {
            ready.extend(children);
        }
    }
    if ordered.len() != entries.len() {
        return Err(OciError::Invalid(
            "filesystem hardlink dependency cycle".into(),
        ));
    }
    Ok(ordered)
}

fn is_layout_archive_path(path: &str) -> bool {
    if matches!(path, "oci-layout" | "index.json" | "blobs" | "blobs/sha256") {
        return true;
    }
    path.strip_prefix("blobs/sha256/")
        .is_some_and(|value| parse_digest(&format!("sha256:{value}")).is_ok())
}

impl OciLayout {
    pub fn open(root: &Path, limits: ConversionLimits) -> Result<Self, OciError> {
        if !root.is_absolute() {
            return Err(OciError::Invalid("OCI layout path must be absolute".into()));
        }
        let root = fs::canonicalize(root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(OciError::Invalid("OCI layout is not a directory".into()));
        }
        let layout: LayoutVersion = read_json(&root.join("oci-layout"), limits.json_bytes)?;
        if layout.image_layout_version != "1.0.0" {
            return Err(OciError::Unsupported(format!(
                "OCI layout version {}",
                layout.image_layout_version
            )));
        }
        Ok(Self { root, limits })
    }

    pub fn resolve(&self, platform: &GuestPlatform) -> Result<ResolvedOciImage, OciError> {
        if platform.os != "linux" || !matches!(platform.architecture.as_str(), "amd64" | "arm64") {
            return Err(OciError::Unsupported(format!(
                "platform {}/{}",
                platform.os, platform.architecture
            )));
        }
        let index_bytes = read_bounded(&self.root.join("index.json"), self.limits.json_bytes)?;
        let source_index_digest = sha256_hex(&index_bytes);
        let index: Index = serde_json::from_slice(&index_bytes)?;
        validate_schema(index.schema_version, "index")?;
        if index.manifests.is_empty() || index.manifests.len() > self.limits.descriptors {
            return Err(OciError::Limit("descriptor count"));
        }
        let descriptor = select_platform(&index.manifests, platform)?;
        let manifest_descriptor = if is_index_media(&descriptor.media_type) {
            let nested: Index = self.read_descriptor_json(descriptor)?;
            validate_schema(nested.schema_version, "nested index")?;
            if nested.manifests.is_empty() || nested.manifests.len() > self.limits.descriptors {
                return Err(OciError::Limit("nested descriptor count"));
            }
            select_platform(&nested.manifests, platform)?.clone()
        } else {
            descriptor.clone()
        };
        require_media_one_of(
            &manifest_descriptor,
            &[OCI_MANIFEST_MEDIA, DOCKER_MANIFEST_MEDIA],
        )?;
        let manifest: Manifest = self.read_descriptor_json(&manifest_descriptor)?;
        validate_schema(manifest.schema_version, "manifest")?;
        require_media_one_of(&manifest.config, &[OCI_CONFIG_MEDIA, DOCKER_CONFIG_MEDIA])?;
        if manifest.layers.is_empty() || manifest.layers.len() > self.limits.layers {
            return Err(OciError::Limit("layer count"));
        }
        let compressed_total = manifest.layers.iter().try_fold(0u64, |total, layer| {
            total
                .checked_add(layer.size)
                .ok_or(OciError::Limit("aggregate compressed byte count"))
        })?;
        if compressed_total > self.limits.compressed_bytes {
            return Err(OciError::Limit("aggregate compressed byte count"));
        }
        let config: ImageConfiguration = self.read_descriptor_json(&manifest.config)?;
        if config.os != platform.os || config.architecture != platform.architecture {
            return Err(OciError::Invalid(
                "selected manifest configuration has the wrong platform".into(),
            ));
        }
        if config.rootfs.kind != "layers" || config.rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(OciError::Invalid(
                "rootfs diff IDs do not match image layers".into(),
            ));
        }
        for value in &config.rootfs.diff_ids {
            parse_digest(value)?;
        }
        for layer in &manifest.layers {
            if !matches!(
                layer.media_type.as_str(),
                OCI_LAYER_TAR
                    | OCI_LAYER_GZIP
                    | OCI_LAYER_ZSTD
                    | DOCKER_LAYER_TAR
                    | DOCKER_LAYER_GZIP
            ) {
                return Err(OciError::Unsupported(format!(
                    "layer media type {}",
                    layer.media_type
                )));
            }
            self.validate_descriptor(layer)?;
        }
        validate_defaults(&config.config)?;
        Ok(ResolvedOciImage {
            source_index_digest,
            manifest_digest: manifest_descriptor.digest.clone(),
            config_digest: manifest.config.digest,
            layer_digests: manifest
                .layers
                .into_iter()
                .map(|value| value.digest)
                .collect(),
            diff_ids: config.rootfs.diff_ids,
            defaults: ImageDefaults {
                environment: config.config.env,
                user: nonempty(config.config.user),
                working_directory: nonempty(config.config.working_dir),
                entrypoint: config.config.entrypoint,
                command: config.config.cmd,
            },
            architecture: config.architecture,
            os: config.os,
            variant: config.variant,
        })
    }

    pub fn convert(
        &self,
        source: ResolvedOciImage,
        destination: &Path,
    ) -> Result<ConvertedTree, OciError> {
        let current = self.resolve(&GuestPlatform {
            architecture: source.architecture.clone(),
            os: source.os.clone(),
            variant: source.variant.clone(),
        })?;
        if current != source {
            return Err(OciError::Invalid(
                "resolved OCI identities changed before conversion".into(),
            ));
        }
        let manifest_descriptor = self.find_manifest_descriptor(&source.manifest_digest)?;
        let manifest: Manifest = self.read_descriptor_json(&manifest_descriptor)?;
        prepare_empty_destination(destination)?;
        let mut metadata = VirtualTree::default();
        let mut total_entries = 0usize;
        let mut total_expanded = 0u64;
        for (index, descriptor) in manifest.layers.iter().enumerate() {
            let actual_diff = self.apply_layer(
                descriptor,
                destination,
                &mut metadata,
                &mut total_entries,
                &mut total_expanded,
            )?;
            if actual_diff != source.diff_ids[index] {
                return Err(OciError::DigestMismatch(source.diff_ids[index].clone()));
            }
        }
        let entries = collect_tree(&metadata);
        let manifest_bytes = serde_json::to_vec(&("sandsurf-oci-tree-v1", &source, &entries))?;
        let manifest_digest = sha256_hex(&manifest_bytes);
        Ok(ConvertedTree {
            source,
            entries,
            manifest_digest,
        })
    }

    fn find_manifest_descriptor(&self, digest: &str) -> Result<Descriptor, OciError> {
        let index: Index = read_json(&self.root.join("index.json"), self.limits.json_bytes)?;
        for descriptor in index.manifests {
            if is_manifest_media(&descriptor.media_type) && descriptor.digest == digest {
                return Ok(descriptor);
            } else if is_index_media(&descriptor.media_type) {
                let nested: Index = self.read_descriptor_json(&descriptor)?;
                for candidate in nested.manifests {
                    if is_manifest_media(&candidate.media_type) && candidate.digest == digest {
                        return Ok(candidate);
                    }
                }
            }
        }
        Err(OciError::Invalid(
            "resolved manifest no longer exists".into(),
        ))
    }

    fn apply_layer(
        &self,
        descriptor: &Descriptor,
        root: &Path,
        metadata: &mut VirtualTree,
        total_entries: &mut usize,
        total_expanded: &mut u64,
    ) -> Result<String, OciError> {
        self.validate_descriptor(descriptor)?;
        let file = File::open(self.blob_path(&descriptor.digest)?)?;
        let remaining_expanded = self.limits.expanded_bytes.saturating_sub(*total_expanded);
        let decoder = layer_decoder(file, &descriptor.media_type, remaining_expanded)?;
        let mut hashing = HashingReader::new(decoder, remaining_expanded);
        // OCI whiteouts delete lower-layer entries regardless of archive
        // ordering. Validate/hash a bounded first pass, applying only deletes;
        // then replay this exact layer's additions, never guest commands.
        let initial_headers = *total_entries;
        {
            let mut archive = sandsurf_format::archive::Archive::new(
                &mut hashing,
                sandsurf_format::archive::Limits {
                    headers: self.limits.entries.saturating_sub(*total_entries),
                    bytes: remaining_expanded,
                    file_bytes: self.limits.file_bytes,
                    path_bytes: self.limits.path_bytes,
                },
            );
            while let Some(entry) = archive.next_entry()? {
                let path = normalize_layer_path(entry.path(), self.limits.path_bytes)?;
                if whiteout(&path)?.is_some() {
                    if !entry.header().entry_type().is_file() || entry.size() != 0 {
                        return Err(OciError::Invalid(
                            "OCI whiteout must be an empty regular entry".into(),
                        ));
                    }
                    apply_whiteout(&path, metadata)?;
                }
            }
            *total_entries += archive.headers_read();
        }
        *total_expanded = total_expanded
            .checked_add(hashing.bytes)
            .ok_or(OciError::Limit("expanded byte count"))?;
        if *total_expanded > self.limits.expanded_bytes {
            return Err(OciError::Limit("expanded byte count"));
        }
        let first = format!("sha256:{:x}", hashing.hasher.finalize());
        let decoder = layer_decoder(
            File::open(self.blob_path(&descriptor.digest)?)?,
            &descriptor.media_type,
            remaining_expanded,
        )?;
        let mut hashing = HashingReader::new(decoder, remaining_expanded);
        {
            let mut archive = sandsurf_format::archive::Archive::new(
                &mut hashing,
                sandsurf_format::archive::Limits {
                    headers: self.limits.entries.saturating_sub(initial_headers),
                    bytes: remaining_expanded,
                    file_bytes: self.limits.file_bytes,
                    path_bytes: self.limits.path_bytes,
                },
            );
            while let Some(entry) = archive.next_entry()? {
                apply_entry(entry, root, metadata, &self.limits)?;
            }
        }
        let second = format!("sha256:{:x}", hashing.hasher.finalize());
        if first != second {
            return Err(OciError::DigestMismatch(first));
        }
        Ok(second)
    }

    fn read_descriptor_json<T: for<'de> Deserialize<'de>>(
        &self,
        descriptor: &Descriptor,
    ) -> Result<T, OciError> {
        self.validate_descriptor(descriptor)?;
        read_json(&self.blob_path(&descriptor.digest)?, self.limits.json_bytes)
    }

    fn validate_descriptor(&self, descriptor: &Descriptor) -> Result<(), OciError> {
        if descriptor.size == 0 || descriptor.size > self.limits.compressed_bytes {
            return Err(OciError::Limit("compressed blob size"));
        }
        let path = self.blob_path(&descriptor.digest)?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != descriptor.size
        {
            return Err(OciError::Invalid(format!(
                "blob {} size or type differs from descriptor",
                descriptor.digest
            )));
        }
        let mut file = File::open(path)?;
        let actual = format!("sha256:{}", sha256_reader(&mut file)?);
        if actual != descriptor.digest {
            return Err(OciError::DigestMismatch(descriptor.digest.clone()));
        }
        Ok(())
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf, OciError> {
        let hexadecimal = parse_digest(digest)?;
        Ok(self.root.join("blobs").join("sha256").join(hexadecimal))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LayoutVersion {
    image_layout_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    schema_version: u32,
    #[serde(default)]
    #[serde(rename = "mediaType")]
    _media_type: Option<String>,
    manifests: Vec<Descriptor>,
    #[serde(default)]
    #[serde(rename = "annotations")]
    _annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
    #[serde(default)]
    #[serde(rename = "annotations")]
    _annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    #[serde(rename = "os.version")]
    _os_version: Option<String>,
    #[serde(default)]
    #[serde(rename = "os.features")]
    _os_features: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    #[serde(default)]
    #[serde(rename = "mediaType")]
    _media_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    #[serde(rename = "annotations")]
    _annotations: BTreeMap<String, String>,
    #[serde(default)]
    #[serde(rename = "subject")]
    _subject: Option<Descriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageConfiguration {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default)]
    #[serde(rename = "os.version")]
    _os_version: Option<String>,
    #[serde(default)]
    #[serde(rename = "os.features")]
    _os_features: Vec<String>,
    #[serde(default)]
    config: OciDefaults,
    rootfs: Rootfs,
    #[serde(default)]
    #[serde(rename = "history")]
    _history: Vec<serde_json::Value>,
    #[serde(default)]
    #[serde(rename = "created")]
    _created: Option<String>,
    #[serde(default)]
    #[serde(rename = "author")]
    _author: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct OciDefaults {
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    user: String,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    entrypoint: Vec<String>,
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    #[serde(rename = "ExposedPorts")]
    _exposed_ports: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    #[serde(rename = "Volumes")]
    _volumes: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    #[serde(rename = "Labels")]
    _labels: BTreeMap<String, String>,
    #[serde(default)]
    #[serde(rename = "StopSignal")]
    _stop_signal: Option<String>,
    #[serde(default)]
    #[serde(rename = "ArgsEscaped")]
    _args_escaped: Option<bool>,
    #[serde(default)]
    #[serde(rename = "OnBuild")]
    _on_build: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Rootfs {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "diff_ids")]
    diff_ids: Vec<String>,
}

#[derive(Default)]
struct VirtualTree {
    entries: BTreeMap<String, EntryMetadata>,
    next_inode: usize,
}

#[derive(Debug, Clone)]
enum EntryMetadata {
    Directory {
        mode: u32,
        uid: u64,
        gid: u64,
    },
    Symlink {
        mode: u32,
        uid: u64,
        gid: u64,
        target: String,
    },
    File(Rc<RefCell<FileInode>>),
}

#[derive(Debug)]
struct FileInode {
    identity: usize,
    digest: String,
    size: u64,
    mode: u32,
    uid: u64,
    gid: u64,
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
    maximum: u64,
}

fn layer_decoder(file: File, media: &str, maximum: u64) -> Result<Box<dyn Read>, OciError> {
    match media {
        OCI_LAYER_TAR | DOCKER_LAYER_TAR => Ok(Box::new(file)),
        OCI_LAYER_GZIP | DOCKER_LAYER_GZIP => Ok(Box::new(MultiGzDecoder::new(file))),
        OCI_LAYER_ZSTD => Ok(Box::new(ZstdReader::new(file, maximum)?)),
        value => Err(OciError::Unsupported(format!("layer media type {value}"))),
    }
}

/// Every compressed frame contributes to the OCI diff ID. Never silently
/// finish after the first frame and ignore verified, but uninterpreted, input.
struct ZstdReader<R: Read> {
    frame: Option<StreamingDecoder<BufReader<R>, FrameDecoder>>,
}

impl<R: Read> ZstdReader<R> {
    fn new(source: R, expanded_limit: u64) -> io::Result<Self> {
        // The output envelope and compression history are different resources.
        // Bound history before the decoder allocates it, independently of a
        // potentially multi-gigabyte machine filesystem.
        let frame = StreamingDecoder::new_with_max_window_size(
            BufReader::new(source),
            expanded_limit.min(64 * 1024 * 1024),
        )
        .map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("zstd layer: {error}"))
        })?;
        Ok(Self { frame: Some(frame) })
    }
}

impl<R: Read> Read for ZstdReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            let Some(frame) = self.frame.as_mut() else {
                return Ok(0);
            };
            let count = frame.read(output)?;
            if count != 0 {
                return Ok(count);
            }
            let (mut source, decoder) =
                self.frame.take().expect("frame checked above").into_parts();
            if source.fill_buf()?.is_empty() {
                return Ok(0);
            }
            self.frame = Some(StreamingDecoder::new_with_decoder(source, decoder).map_err(
                |error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("zstd layer frame: {error}"),
                    )
                },
            )?);
        }
    }
}

impl<R> HashingReader<R> {
    fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
            maximum,
        }
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(output)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("expanded layer byte count overflow"))?;
        if self.bytes > self.maximum {
            return Err(io::Error::other("expanded layer exceeds bound"));
        }
        self.hasher.update(&output[..count]);
        Ok(count)
    }
}

fn select_platform<'a>(
    descriptors: &'a [Descriptor],
    requested: &GuestPlatform,
) -> Result<&'a Descriptor, OciError> {
    let matching: Vec<_> = descriptors
        .iter()
        .filter(|descriptor| {
            descriptor.platform.as_ref().is_some_and(|platform| {
                platform.os == requested.os
                    && platform.architecture == requested.architecture
                    && platform.variant == requested.variant
            })
        })
        .collect();
    match matching.as_slice() {
        [value] => Ok(*value),
        [] if descriptors.len() == 1 && descriptors[0].platform.is_none() => Ok(&descriptors[0]),
        [] => Err(OciError::Invalid("requested platform is absent".into())),
        _ => Err(OciError::Invalid(
            "requested platform resolves to multiple descriptors".into(),
        )),
    }
}

fn require_media_one_of(descriptor: &Descriptor, expected: &[&str]) -> Result<(), OciError> {
    if !expected.contains(&descriptor.media_type.as_str()) {
        return Err(OciError::Invalid(format!(
            "unexpected media type {}",
            descriptor.media_type
        )));
    }
    Ok(())
}

fn is_index_media(value: &str) -> bool {
    matches!(value, OCI_INDEX_MEDIA | DOCKER_INDEX_MEDIA)
}

fn is_manifest_media(value: &str) -> bool {
    matches!(value, OCI_MANIFEST_MEDIA | DOCKER_MANIFEST_MEDIA)
}

fn validate_schema(value: u32, name: &str) -> Result<(), OciError> {
    if value != 2 {
        return Err(OciError::Unsupported(format!(
            "{name} schema version {value}"
        )));
    }
    Ok(())
}

fn validate_defaults(value: &OciDefaults) -> Result<(), OciError> {
    if value.env.len() > 4096
        || value.entrypoint.len() > 4096
        || value.cmd.len() > 4096
        || value
            .env
            .iter()
            .chain(value.entrypoint.iter())
            .chain(value.cmd.iter())
            .any(|item| item.len() > 64 * 1024 || item.contains('\0'))
        || value.user.len() > 4096
        || value.working_dir.len() > 4096
        || value.user.contains('\0')
        || value.working_dir.contains('\0')
    {
        return Err(OciError::Limit("image configuration"));
    }
    if !value.working_dir.is_empty() && !value.working_dir.starts_with('/') {
        return Err(OciError::Invalid(
            "OCI WorkingDir must be an absolute guest path".into(),
        ));
    }
    let mut names = BTreeSet::new();
    for assignment in &value.env {
        let Some((name, _)) = assignment.split_once('=') else {
            return Err(OciError::Invalid("OCI Env entry has no equals sign".into()));
        };
        if name.is_empty() || name.contains('\0') || !names.insert(name) {
            return Err(OciError::Invalid(
                "OCI Env names must be nonempty and unique".into(),
            ));
        }
    }
    Ok(())
}

/// Linux inode identity is metadata; only opaque digest-named content reaches
/// the host filesystem. Replacing an inode never changes surviving aliases.
fn apply_entry<R: Read>(
    mut entry: sandsurf_format::archive::Entry<'_, R>,
    root: &Path,
    tree: &mut VirtualTree,
    limits: &ConversionLimits,
) -> Result<(), OciError> {
    let path = normalize_layer_path(entry.path(), limits.path_bytes)?;
    if path.is_empty() {
        // The canonical filesystem profile leaves the mkfs-owned root inode
        // intact. Admit only its exact semantics, never silently discard an
        // attempted root replacement or different administration metadata.
        if !entry.header().entry_type().is_dir()
            || entry.size() != 0
            || entry.header().mode()? != 0o755
            || entry.header().uid()? != 0
            || entry.header().gid()? != 0
        {
            return Err(OciError::Unsupported(
                "OCI root must be an empty root-owned 0755 directory".into(),
            ));
        }
        return Ok(());
    }
    if whiteout(&path)?.is_some() {
        return Ok(());
    }
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    register_implicit_directories(parent, tree, limits.entries)?;
    let mode = entry.header().mode()?;
    let uid = entry.header().uid()?;
    let gid = entry.header().gid()?;
    let kind = entry.header().entry_type();
    if mode > 0o7777 || uid > u32::MAX as u64 || gid > u32::MAX as u64 {
        return Err(OciError::Unsupported(
            "inode metadata exceeds the guest Linux profile".into(),
        ));
    }
    if !kind.is_file() && entry.size() != 0 {
        return Err(OciError::Invalid(
            "non-file layer member carries payload".into(),
        ));
    }
    let value = if kind.is_dir() {
        if !matches!(
            tree.entries.get(&path),
            Some(EntryMetadata::Directory { .. })
        ) {
            remove_metadata_subtree(tree, &path);
        }
        EntryMetadata::Directory { mode, uid, gid }
    } else if kind.is_file() {
        let declared = entry.size();
        if declared > limits.file_bytes {
            return Err(OciError::Limit("individual file size"));
        }
        let identity = tree.next_inode;
        tree.next_inode = identity
            .checked_add(1)
            .ok_or(OciError::Limit("inode identity count"))?;
        let temporary = root.join(format!(".content-{identity}"));
        let mut output = sandsurf_native::local::create_private_file(&temporary)?;
        let mut reader = HashingReader::new(&mut entry, declared);
        if io::copy(&mut reader, &mut output)? != declared {
            return Err(OciError::Invalid(
                "layer file size differs from header".into(),
            ));
        }
        output.sync_all()?;
        drop(output);
        let digest = format!("{:x}", reader.hasher.finalize());
        let content = root.join(&digest);
        match fs::symlink_metadata(&content) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() == declared =>
            {
                if sha256_reader(&mut File::open(&content)?)? != digest {
                    return Err(OciError::DigestMismatch(digest));
                }
                fs::remove_file(temporary)?;
            }
            Ok(_) => {
                return Err(OciError::Invalid(
                    "opaque content identity is not a regular blob".into(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::rename(temporary, content)?
            }
            Err(error) => return Err(error.into()),
        }
        remove_metadata_subtree(tree, &path);
        EntryMetadata::File(Rc::new(RefCell::new(FileInode {
            identity,
            digest,
            size: declared,
            mode,
            uid,
            gid,
        })))
    } else if kind.is_symlink() {
        let target = normalized_link(&entry, limits.path_bytes)?;
        remove_metadata_subtree(tree, &path);
        EntryMetadata::Symlink {
            mode,
            uid,
            gid,
            target,
        }
    } else if kind.is_hard_link() {
        let target = normalize_layer_path(
            entry
                .link_name()
                .ok_or_else(|| OciError::Invalid("hardlink target is absent".into()))?,
            limits.path_bytes,
        )?;
        if path == target {
            return Err(OciError::Invalid(
                "hardlink cannot replace its own target".into(),
            ));
        }
        let Some(EntryMetadata::File(inode)) = tree.entries.get(&target) else {
            return Err(OciError::Invalid(
                "hardlink target is not an existing regular inode".into(),
            ));
        };
        let inode = Rc::clone(inode);
        // Tar metadata applies to the inode, not one directory-entry alias.
        {
            let mut value = inode.borrow_mut();
            value.mode = mode;
            value.uid = uid;
            value.gid = gid;
        }
        remove_metadata_subtree(tree, &path);
        EntryMetadata::File(inode)
    } else {
        return Err(OciError::Unsupported(format!(
            "tar entry type {:?}",
            kind.as_byte()
        )));
    };
    tree.entries.insert(path, value);
    if tree.entries.len() > limits.entries {
        return Err(OciError::Limit("final tree entry count"));
    }
    Ok(())
}

/// Interpret '/' only. Host drive, case-folding and backslash semantics are
/// irrelevant because no guest pathname will ever be opened on the host.
fn normalize_layer_path(path: &Path, maximum: usize) -> Result<String, OciError> {
    let text = path
        .to_str()
        .ok_or_else(|| OciError::Unsupported("non-UTF-8 layer path".into()))?;
    if text.len() > maximum || text.contains('\0') {
        return Err(OciError::Limit("layer path length"));
    }
    if text.starts_with('/') || text.split('/').any(|part| part == "..") {
        return Err(OciError::Invalid("layer path escapes root".into()));
    }
    Ok(text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/"))
}

fn normalized_link<R: Read>(
    entry: &sandsurf_format::archive::Entry<'_, R>,
    maximum: usize,
) -> Result<String, OciError> {
    let value = entry
        .link_name()
        .and_then(Path::to_str)
        .ok_or_else(|| OciError::Unsupported("missing or non-UTF-8 symlink target".into()))?;
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(OciError::Limit("symlink target length"));
    }
    Ok(value.into())
}

fn whiteout(path: &str) -> Result<Option<(&str, bool)>, OciError> {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name == ".wh..wh..opq" {
        return Ok(Some((parent, true)));
    }
    if let Some(target) = name.strip_prefix(".wh.") {
        if target.is_empty() || matches!(target, "." | "..") {
            return Err(OciError::Invalid("invalid OCI whiteout target".into()));
        }
        // The caller constructs the normalized target under this parent.
        return Ok(Some((target, false)));
    }
    Ok(None)
}

fn apply_whiteout(path: &str, tree: &mut VirtualTree) -> Result<(), OciError> {
    if let Some((target, opaque)) = whiteout(path)? {
        if opaque {
            tree.entries
                .retain(|candidate, _| !target.is_empty() && !is_descendant(candidate, target));
        } else {
            let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            let target = if parent.is_empty() {
                target.to_owned()
            } else {
                format!("{parent}/{target}")
            };
            remove_metadata_subtree(tree, &target);
        }
    }
    Ok(())
}

fn collect_tree(tree: &VirtualTree) -> Vec<TreeEntry> {
    let mut representatives = BTreeMap::<usize, &str>::new();
    tree.entries
        .iter()
        .map(|(path, value)| {
            let (kind, mode, uid, gid, size, digest, link_target) = match value {
                EntryMetadata::Directory { mode, uid, gid } => {
                    (TreeEntryKind::Directory, *mode, *uid, *gid, 0, None, None)
                }
                EntryMetadata::Symlink {
                    mode,
                    uid,
                    gid,
                    target,
                } => (
                    TreeEntryKind::Symlink,
                    *mode,
                    *uid,
                    *gid,
                    0,
                    None,
                    Some(target.clone()),
                ),
                EntryMetadata::File(value) => {
                    let inode = value.borrow();
                    let representative = representatives.entry(inode.identity).or_insert(path);
                    let kind = if *representative == path {
                        TreeEntryKind::Regular
                    } else {
                        TreeEntryKind::Hardlink
                    };
                    (
                        kind,
                        inode.mode,
                        inode.uid,
                        inode.gid,
                        inode.size,
                        Some(inode.digest.clone()),
                        (kind == TreeEntryKind::Hardlink).then(|| (*representative).to_owned()),
                    )
                }
            };
            TreeEntry {
                path: path.clone(),
                kind,
                mode,
                uid,
                gid,
                size,
                digest,
                link_target,
            }
        })
        .collect()
}

fn prepare_empty_destination(path: &Path) -> Result<(), OciError> {
    if !path.is_absolute() {
        return Err(OciError::Invalid(
            "conversion destination must be absolute".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && fs::read_dir(path)?.next().is_none() =>
        {
            sandsurf_native::local::canonical_private_directory(path)?;
            Ok(())
        }
        Ok(_) => Err(OciError::Invalid(
            "conversion destination must be a new empty directory".into(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            sandsurf_native::local::create_private_directory(path)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn parse_digest(value: &str) -> Result<&str, OciError> {
    let Some(hexadecimal) = value.strip_prefix("sha256:") else {
        return Err(OciError::Unsupported("non-SHA-256 OCI digest".into()));
    };
    if hexadecimal.len() != 64
        || !hexadecimal
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OciError::Invalid("malformed SHA-256 OCI digest".into()));
    }
    Ok(hexadecimal)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, OciError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(OciError::Limit("JSON byte count"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(OciError::Limit("JSON byte count"));
    }
    Ok(bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, OciError> {
    Ok(serde_json::from_slice(&read_bounded(path, maximum)?)?)
}

fn sha256_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_descendant(candidate: &str, parent: &str) -> bool {
    !parent.is_empty()
        && candidate
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn register_implicit_directories(
    path: &str,
    tree: &mut VirtualTree,
    maximum: usize,
) -> Result<(), OciError> {
    let mut current = String::new();
    for component in path.split('/').filter(|part| !part.is_empty()) {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        match tree.entries.get(&current) {
            Some(EntryMetadata::Directory { .. }) => {}
            Some(_) => {
                return Err(OciError::Invalid(
                    "layer path traverses a non-directory or symlink".into(),
                ));
            }
            None => {
                if tree.entries.len() >= maximum {
                    return Err(OciError::Limit("implicit directory count"));
                }
                tree.entries.insert(
                    current.clone(),
                    EntryMetadata::Directory {
                        mode: 0o755,
                        uid: 0,
                        gid: 0,
                    },
                );
            }
        }
    }
    Ok(())
}

fn remove_metadata_subtree(tree: &mut VirtualTree, path: &str) {
    tree.entries
        .retain(|candidate, _| candidate != path && !is_descendant(candidate, path));
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn root_members_cannot_silently_replace_the_filesystem_root() {
        let temp = Temp::new();
        for (kind, mode, uid, size, accepted) in [
            (tar::EntryType::Directory, 0o755, 0, 0, true),
            (tar::EntryType::Directory, 0o777, 0, 0, false),
            (tar::EntryType::Directory, 0o755, 42, 0, false),
            (tar::EntryType::Regular, 0o755, 0, 0, false),
            (tar::EntryType::Directory, 0o755, 0, 1, false),
        ] {
            let mut writer = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(mode);
            header.set_uid(uid);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(size);
            writer
                .append_data(&mut header, ".", &b"x"[..size as usize])
                .unwrap();
            let bytes = writer.into_inner().unwrap();
            let mut archive = sandsurf_format::archive::Archive::new(
                &bytes[..],
                sandsurf_format::archive::Limits {
                    headers: 1,
                    bytes: 4096,
                    file_bytes: 1,
                    path_bytes: 4096,
                },
            );
            let result = archive
                .next_entry()
                .map_err(OciError::from)
                .and_then(|entry| {
                    apply_entry(
                        entry.unwrap(),
                        &temp.0,
                        &mut VirtualTree::default(),
                        &ConversionLimits::default(),
                    )
                });
            assert_eq!(result.is_ok(), accepted);
        }
    }

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-oci-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            sandsurf_native::local::create_private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn compressed_layers_account_for_every_member_and_reject_uninterpreted_tails() {
        fn gzip(data: &[u8]) -> Vec<u8> {
            let mut writer =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(data).unwrap();
            writer.finish().unwrap()
        }
        fn zstd(data: &[u8]) -> Vec<u8> {
            assert!(data.len() < 256);
            let mut encoded = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, data.len() as u8];
            let block = ((data.len() as u32) << 3) | 1;
            encoded.extend_from_slice(&block.to_le_bytes()[..3]);
            encoded.extend_from_slice(data);
            encoded
        }
        let mut compressed = [gzip(b"first"), gzip(b"second")].concat();
        let mut decoded = Vec::new();
        MultiGzDecoder::new(&compressed[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"firstsecond");
        compressed.extend_from_slice(b"uninterpreted");
        assert!(
            MultiGzDecoder::new(&compressed[..])
                .read_to_end(&mut Vec::new())
                .is_err()
        );
        let mut compressed = [zstd(b"first"), zstd(b"second")].concat();
        let mut decoded = Vec::new();
        ZstdReader::new(&compressed[..], 4096)
            .unwrap()
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"firstsecond");
        compressed.extend_from_slice(b"uninterpreted");
        assert!(
            ZstdReader::new(&compressed[..], 4096)
                .unwrap()
                .read_to_end(&mut Vec::new())
                .is_err()
        );
        // A 128 MiB history window must fail before allocating its buffer.
        let oversized_window = [0x28, 0xb5, 0x2f, 0xfd, 0, 0x88];
        assert!(ZstdReader::new(&oversized_window[..], u64::MAX).is_err());
    }

    #[test]
    fn paths_never_escape_the_builder_root() {
        for value in ["../escape", "/absolute", "a/../../escape"] {
            assert!(normalize_layer_path(Path::new(value), 4096).is_err());
        }
        assert_eq!(
            normalize_layer_path(Path::new("./usr/bin/tool"), 4096).unwrap(),
            "usr/bin/tool"
        );
    }

    #[test]
    fn parent_symlinks_are_never_followed() {
        let mut tree = VirtualTree::default();
        tree.entries.insert(
            "link".into(),
            EntryMetadata::Symlink {
                mode: 0o777,
                uid: 0,
                gid: 0,
                target: "/outside".into(),
            },
        );
        assert!(register_implicit_directories("link/child", &mut tree, 32).is_err());
    }

    #[test]
    fn digests_are_strictly_sha256() {
        assert!(parse_digest(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(parse_digest(&format!("sha512:{}", "a".repeat(64))).is_err());
        assert!(parse_digest(&format!("sha256:{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn duplicate_environment_names_are_rejected() {
        let value = OciDefaults {
            env: vec!["A=1".into(), "A=2".into()],
            ..OciDefaults::default()
        };
        assert!(validate_defaults(&value).is_err());
    }

    #[test]
    fn destination_must_be_empty() {
        let root = Temp::new();
        fs::write(root.0.join("existing"), b"x").unwrap();
        assert!(prepare_empty_destination(&root.0).is_err());
    }

    fn apply_test_layer(
        layout: &Temp,
        tree: &mut VirtualTree,
        bytes: &[u8],
        entries: &mut usize,
        expanded: &mut u64,
    ) {
        fs::create_dir_all(layout.0.join("blobs/sha256")).unwrap();
        let descriptor: Descriptor =
            serde_json::from_value(write_blob(&layout.0, bytes, OCI_LAYER_TAR)).unwrap();
        let blobs = layout.0.join("content");
        if !blobs.exists() {
            sandsurf_native::local::create_private_directory(&blobs).unwrap();
        }
        let owner = OciLayout {
            root: layout.0.clone(),
            limits: ConversionLimits::default(),
        };
        assert_eq!(
            owner
                .apply_layer(&descriptor, &blobs, tree, entries, expanded)
                .unwrap(),
            format!("sha256:{}", sha256_hex(bytes))
        );
    }

    #[test]
    fn opaque_content_preserves_linux_names_and_distinct_equal_inodes_on_every_host() {
        let layout = Temp::new();
        let mut tree = VirtualTree::default();
        let mut archive = tar::Builder::new(Vec::new());
        let long = format!("{}λ", "very-long".repeat(30));
        let names = [
            "CON",
            "con",
            "C:drive\\tool",
            "a:b",
            "trailing.",
            "back\\slash",
            long.as_str(),
        ];
        for path in names {
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o4755);
            header.set_uid(42);
            header.set_gid(43);
            guest_header(&mut archive, &mut header, path, None).unwrap();
            archive.append(&header, &b"same"[..]).unwrap();
        }
        archive.finish().unwrap();
        apply_test_layer(
            &layout,
            &mut tree,
            &archive.into_inner().unwrap(),
            &mut 0,
            &mut 0,
        );
        let entries = collect_tree(&tree);
        assert_eq!(entries.len(), names.len());
        assert!(
            entries
                .iter()
                .all(|entry| entry.kind == TreeEntryKind::Regular
                    && entry.mode == 0o4755
                    && entry.uid == 42
                    && entry.gid == 43)
        );
        assert_eq!(fs::read_dir(layout.0.join("content")).unwrap().count(), 1);
        let source = ResolvedOciImage {
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
        };
        let converted = ConvertedTree {
            source,
            entries,
            manifest_digest: "unused".into(),
        };
        let output = layout.0.join("filesystem.tar");
        write_filesystem_tar(&layout.0.join("content"), &converted, &output).unwrap();
        let mut archive = sandsurf_format::archive::CanonicalArchive::new(
            File::open(output).unwrap(),
            sandsurf_format::archive::Limits {
                headers: 32,
                bytes: 65536,
                file_bytes: 16,
                path_bytes: 4096,
            },
            names.len() as u64 * 4,
        );
        let mut actual = BTreeSet::new();
        while let Some(mut entry) = archive.next_entry().unwrap() {
            actual.insert(entry.path().to_str().unwrap().to_owned());
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"same");
        }
        assert_eq!(actual, names.into_iter().map(str::to_owned).collect());
        fs::write(layout.0.join("content").join(sha256_hex(b"same")), b"evil").unwrap();
        assert!(
            write_filesystem_tar(
                &layout.0.join("content"),
                &converted,
                &layout.0.join("tampered.tar")
            )
            .is_err()
        );
    }

    #[test]
    fn replacement_and_whiteouts_preserve_surviving_hardlink_inodes_not_target_names() {
        let layout = Temp::new();
        let mut tree = VirtualTree::default();
        let mut entries = 0;
        let mut expanded = 0;
        let mut first = tar::Builder::new(Vec::new());
        let mut file = tar::Header::new_gnu();
        file.set_size(3);
        file.set_mode(0o755);
        file.set_uid(0);
        file.set_gid(0);
        guest_header(&mut first, &mut file, "z-source", None).unwrap();
        first.append(&file, &b"old"[..]).unwrap();
        for path in ["a-alias", "b-alias"] {
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Link);
            link.set_size(0);
            link.set_mode(0o4755);
            link.set_uid(42);
            link.set_gid(43);
            guest_header(&mut first, &mut link, path, Some("z-source")).unwrap();
            first.append(&link, io::empty()).unwrap();
        }
        first.finish().unwrap();
        apply_test_layer(
            &layout,
            &mut tree,
            &first.into_inner().unwrap(),
            &mut entries,
            &mut expanded,
        );
        apply_test_layer(
            &layout,
            &mut tree,
            &tar_layer(&[("z-source", b"new")]),
            &mut entries,
            &mut expanded,
        );
        let current = collect_tree(&tree);
        let a = current
            .iter()
            .find(|entry| entry.path == "a-alias")
            .unwrap();
        assert_eq!(a.kind, TreeEntryKind::Regular);
        assert_eq!(a.mode, 0o4755);
        assert_eq!((a.uid, a.gid), (42, 43));
        assert_eq!(a.digest, Some(sha256_hex(b"old")));
        let b = current
            .iter()
            .find(|entry| entry.path == "b-alias")
            .unwrap();
        assert_eq!(b.kind, TreeEntryKind::Hardlink);
        assert_eq!(b.link_target.as_deref(), Some("a-alias"));
        assert_eq!(
            current
                .iter()
                .find(|entry| entry.path == "z-source")
                .unwrap()
                .digest,
            Some(sha256_hex(b"new"))
        );
        apply_test_layer(
            &layout,
            &mut tree,
            &tar_layer(&[(".wh.a-alias", b"")]),
            &mut entries,
            &mut expanded,
        );
        let current = collect_tree(&tree);
        assert!(!current.iter().any(|entry| entry.path == "a-alias"));
        assert_eq!(
            current
                .iter()
                .find(|entry| entry.path == "b-alias")
                .unwrap()
                .kind,
            TreeEntryKind::Regular
        );
    }

    #[test]
    fn whiteouts_are_lower_layer_deletions_even_when_tar_members_follow_additions() {
        let layout = Temp::new();
        let mut tree = VirtualTree::default();
        let mut entries = 0;
        let mut expanded = 0;
        apply_test_layer(
            &layout,
            &mut tree,
            &tar_layer(&[("dir/old", b"old"), ("replace", b"old")]),
            &mut entries,
            &mut expanded,
        );
        apply_test_layer(
            &layout,
            &mut tree,
            &tar_layer(&[
                ("dir/new", b"new"),
                ("replace", b"new"),
                ("dir/.wh..wh..opq", b""),
                (".wh.replace", b""),
            ]),
            &mut entries,
            &mut expanded,
        );
        let current = collect_tree(&tree);
        assert!(current.iter().any(|entry| entry.path == "dir/new"));
        assert!(!current.iter().any(|entry| entry.path == "dir/old"));
        assert_eq!(
            current
                .iter()
                .find(|entry| entry.path == "replace")
                .unwrap()
                .digest,
            Some(sha256_hex(b"new"))
        );
        assert!(current.iter().all(|entry| !entry.path.contains(".wh.")));
    }

    #[test]
    fn resolves_and_applies_layers_with_whiteouts_and_implicit_directories() {
        let layout = Temp::new();
        fs::create_dir_all(layout.0.join("blobs/sha256")).unwrap();
        fs::write(
            layout.0.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();

        let first = tar_layer(&[("usr/bin/old", b"old"), ("usr/bin/tool", b"v1")]);
        let second = tar_layer(&[("usr/bin/.wh.old", b""), ("usr/bin/tool", b"v2")]);
        let first_descriptor = write_blob(&layout.0, &first, OCI_LAYER_TAR);
        let second_descriptor = write_blob(&layout.0, &second, OCI_LAYER_TAR);
        let config = serde_json::to_vec(&json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/bin"],
                "User": "1000:1000",
                "WorkingDir": "/workspace",
                "Entrypoint": ["/bin/sh"],
                "Cmd": ["-l"]
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": [
                    format!("sha256:{}", sha256_hex(&first)),
                    format!("sha256:{}", sha256_hex(&second))
                ]
            }
        }))
        .unwrap();
        let config_descriptor = write_blob(&layout.0, &config, OCI_CONFIG_MEDIA);
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA,
            "config": config_descriptor,
            "layers": [first_descriptor, second_descriptor]
        }))
        .unwrap();
        let manifest_descriptor = write_blob(&layout.0, &manifest, OCI_MANIFEST_MEDIA);
        fs::write(
            layout.0.join("index.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "mediaType": OCI_INDEX_MEDIA,
                "manifests": [{
                    "mediaType": manifest_descriptor["mediaType"],
                    "digest": manifest_descriptor["digest"],
                    "size": manifest_descriptor["size"],
                    "platform": { "architecture": "amd64", "os": "linux" }
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let source = OciLayout::open(&layout.0, ConversionLimits::default())
            .unwrap()
            .resolve(&GuestPlatform {
                architecture: "amd64".into(),
                os: "linux".into(),
                variant: None,
            })
            .unwrap();
        assert_eq!(
            source.defaults.working_directory.as_deref(),
            Some("/workspace")
        );
        let destination = layout.0.join("tree");
        let conversion = OciLayout::open(&layout.0, ConversionLimits::default())
            .unwrap()
            .convert(source.clone(), &destination);
        let converted = conversion.unwrap();
        let tool_entry = converted
            .entries
            .iter()
            .find(|entry| entry.path == "usr/bin/tool")
            .unwrap();
        assert_eq!(
            fs::read(destination.join(tool_entry.digest.as_ref().unwrap())).unwrap(),
            b"v2"
        );
        assert!(
            !converted
                .entries
                .iter()
                .any(|entry| entry.path == "usr/bin/old")
        );
        assert!(
            !destination.join("usr").exists(),
            "Linux paths never become host paths"
        );
        assert!(
            converted
                .entries
                .iter()
                .any(|entry| entry.path == "usr" && entry.kind == TreeEntryKind::Directory)
        );
        let filesystem_tar = layout.0.join("filesystem.tar");
        write_filesystem_tar(&destination, &converted, &filesystem_tar).unwrap();
        let mut archive = tar::Archive::new(File::open(&filesystem_tar).unwrap());
        let tool = archive
            .entries()
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.path().unwrap() == Path::new("usr/bin/tool"))
            .unwrap();
        assert_eq!(tool.header().uid().unwrap(), 0);
        assert_eq!(tool.header().gid().unwrap(), 0);
        assert_eq!(tool.header().mode().unwrap(), 0o755);
        let mut forged = source;
        forged.config_digest = format!("sha256:{}", "0".repeat(64));
        assert!(
            OciLayout::open(&layout.0, ConversionLimits::default())
                .unwrap()
                .convert(forged, &layout.0.join("forged"))
                .is_err()
        );
    }

    #[test]
    fn filesystem_archive_preserves_hardlinks_without_forward_references() {
        let entry = |path: &str, kind, target: Option<&str>| TreeEntry {
            path: path.into(),
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            digest: None,
            link_target: target.map(str::to_owned),
        };
        let entries = vec![
            entry("a", TreeEntryKind::Hardlink, Some("b")),
            entry("b", TreeEntryKind::Hardlink, Some("z")),
            entry("z", TreeEntryKind::Regular, None),
        ];
        let ordered = filesystem_archive_order(&entries).unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["z", "b", "a"]
        );
        let cycle = vec![
            entry("a", TreeEntryKind::Hardlink, Some("b")),
            entry("b", TreeEntryKind::Hardlink, Some("a")),
        ];
        assert!(filesystem_archive_order(&cycle).is_err());
        let absent = vec![entry("a", TreeEntryKind::Hardlink, Some("missing"))];
        assert!(filesystem_archive_order(&absent).is_err());
    }

    #[test]
    fn layout_archive_rejects_links_and_unrelated_paths() {
        let root = Temp::new();
        let archive_path = root.0.join("bad.tar");
        let output = File::create(&archive_path).unwrap();
        let mut builder = tar::Builder::new(output);
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "unexpected", &b"x"[..])
            .unwrap();
        builder.finish().unwrap();
        assert!(
            unpack_layout_archive(
                &archive_path,
                &root.0.join("layout"),
                ConversionLimits::default()
            )
            .is_err()
        );
        assert!(!root.0.join("layout/unexpected").exists());
    }

    fn tar_layer(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    }

    fn write_blob(root: &Path, bytes: &[u8], media_type: &str) -> serde_json::Value {
        let digest = sha256_hex(bytes);
        fs::write(root.join("blobs/sha256").join(&digest), bytes).unwrap();
        json!({
            "mediaType": media_type,
            "digest": format!("sha256:{digest}"),
            "size": bytes.len()
        })
    }
}
