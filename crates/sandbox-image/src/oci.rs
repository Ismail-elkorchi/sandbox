//! Bounded OCI-layout resolution and layer application for the unprivileged
//! Sandsurf image builder. The output is a VM-image input tree, not a container
//! runtime root and no OCI entrypoint is executed here.

use flate2::read::GzDecoder;
use ruzstd::decoding::StreamingDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

const OCI_INDEX_MEDIA: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG_MEDIA: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

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
pub struct WorkloadDefaults {
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
    pub defaults: WorkloadDefaults,
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
        let manifest_descriptor = if descriptor.media_type == OCI_INDEX_MEDIA {
            let nested: Index = self.read_descriptor_json(descriptor)?;
            validate_schema(nested.schema_version, "nested index")?;
            if nested.manifests.is_empty() || nested.manifests.len() > self.limits.descriptors {
                return Err(OciError::Limit("nested descriptor count"));
            }
            select_platform(&nested.manifests, platform)?.clone()
        } else {
            descriptor.clone()
        };
        require_media(&manifest_descriptor, OCI_MANIFEST_MEDIA)?;
        let manifest: Manifest = self.read_descriptor_json(&manifest_descriptor)?;
        validate_schema(manifest.schema_version, "manifest")?;
        require_media(&manifest.config, OCI_CONFIG_MEDIA)?;
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
                OCI_LAYER_TAR | OCI_LAYER_GZIP | OCI_LAYER_ZSTD
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
            defaults: WorkloadDefaults {
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
        let mut metadata = BTreeMap::new();
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
        let entries = collect_tree(destination, &metadata, self.limits.entries)?;
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
            if descriptor.media_type == OCI_MANIFEST_MEDIA && descriptor.digest == digest {
                return Ok(descriptor);
            } else if descriptor.media_type == OCI_INDEX_MEDIA {
                let nested: Index = self.read_descriptor_json(&descriptor)?;
                for candidate in nested.manifests {
                    if candidate.media_type == OCI_MANIFEST_MEDIA && candidate.digest == digest {
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
        metadata: &mut BTreeMap<String, EntryMetadata>,
        total_entries: &mut usize,
        total_expanded: &mut u64,
    ) -> Result<String, OciError> {
        self.validate_descriptor(descriptor)?;
        let file = File::open(self.blob_path(&descriptor.digest)?)?;
        let decoder: Box<dyn Read> = match descriptor.media_type.as_str() {
            OCI_LAYER_TAR => Box::new(file),
            OCI_LAYER_GZIP => Box::new(GzDecoder::new(file)),
            OCI_LAYER_ZSTD => Box::new(
                StreamingDecoder::new(file)
                    .map_err(|error| OciError::Invalid(format!("zstd layer: {error}")))?,
            ),
            value => return Err(OciError::Unsupported(format!("layer media type {value}"))),
        };
        let mut hashing = HashingReader::new(decoder, self.limits.expanded_bytes);
        {
            let mut archive = tar::Archive::new(&mut hashing);
            for entry in archive.entries()? {
                *total_entries = total_entries
                    .checked_add(1)
                    .ok_or(OciError::Limit("entry count"))?;
                if *total_entries > self.limits.entries {
                    return Err(OciError::Limit("entry count"));
                }
                apply_entry(entry?, root, metadata, &self.limits)?;
            }
        }
        io::copy(&mut hashing, &mut io::sink())?;
        *total_expanded = total_expanded
            .checked_add(hashing.bytes)
            .ok_or(OciError::Limit("expanded byte count"))?;
        if *total_expanded > self.limits.expanded_bytes {
            return Err(OciError::Limit("expanded byte count"));
        }
        Ok(format!("sha256:{:x}", hashing.hasher.finalize()))
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

#[derive(Debug, Clone)]
struct EntryMetadata {
    kind: TreeEntryKind,
    mode: u32,
    uid: u64,
    gid: u64,
    link_target: Option<String>,
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
    maximum: u64,
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

fn require_media(descriptor: &Descriptor, expected: &str) -> Result<(), OciError> {
    if descriptor.media_type != expected {
        return Err(OciError::Invalid(format!(
            "expected media type {expected}, got {}",
            descriptor.media_type
        )));
    }
    Ok(())
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

fn apply_entry<R: Read>(
    mut entry: tar::Entry<'_, R>,
    root: &Path,
    metadata: &mut BTreeMap<String, EntryMetadata>,
    limits: &ConversionLimits,
) -> Result<(), OciError> {
    let path = normalize_layer_path(&entry.path()?, limits.path_bytes)?;
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| OciError::Invalid("layer path has no UTF-8 basename".into()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    register_implicit_directories(parent, metadata);
    if name == ".wh..wh..opq" {
        let directory = resolve_directory(root, parent, true)?;
        for child in fs::read_dir(&directory)? {
            remove_path(&child?.path())?;
        }
        let prefix = path_key(parent);
        if prefix.is_empty() {
            metadata.clear();
        } else {
            metadata.retain(|candidate, _| !is_descendant(candidate, &prefix));
        }
        return Ok(());
    }
    if let Some(target) = name.strip_prefix(".wh.") {
        if target.is_empty() {
            return Err(OciError::Invalid("empty OCI whiteout target".into()));
        }
        let directory = resolve_directory(root, parent, true)?;
        remove_path(&directory.join(target))?;
        let target_path = parent.join(target);
        let key = path_key(&target_path);
        metadata.retain(|candidate, _| candidate != &key && !is_descendant(candidate, &key));
        return Ok(());
    }

    let parent_path = resolve_directory(root, parent, true)?;
    let destination = parent_path.join(name);
    let mode = entry.header().mode().map_err(OciError::Io)? & 0o7777;
    let uid = entry.header().uid().map_err(OciError::Io)?;
    let gid = entry.header().gid().map_err(OciError::Io)?;
    let kind = entry.header().entry_type();
    let key = path_key(&path);
    if kind.is_dir() {
        if destination.exists() {
            let current = fs::symlink_metadata(&destination)?;
            if !current.is_dir() || current.file_type().is_symlink() {
                remove_path(&destination)?;
                fs::create_dir(&destination)?;
            }
        } else {
            fs::create_dir(&destination)?;
        }
        set_mode(&destination, mode)?;
        metadata.insert(
            key,
            EntryMetadata {
                kind: TreeEntryKind::Directory,
                mode,
                uid,
                gid,
                link_target: None,
            },
        );
    } else if kind.is_file() {
        remove_metadata_subtree(metadata, &key);
        let declared = entry.size();
        if declared > limits.file_bytes {
            return Err(OciError::Limit("individual file size"));
        }
        remove_path(&destination)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        let copied = io::copy(&mut entry.by_ref().take(limits.file_bytes + 1), &mut output)?;
        if copied != declared || copied > limits.file_bytes {
            return Err(OciError::Invalid(
                "layer file size differs from header or exceeds bound".into(),
            ));
        }
        output.flush()?;
        set_mode(&destination, mode)?;
        metadata.insert(
            key,
            EntryMetadata {
                kind: TreeEntryKind::Regular,
                mode,
                uid,
                gid,
                link_target: None,
            },
        );
    } else if kind.is_symlink() {
        remove_metadata_subtree(metadata, &key);
        let target = normalized_link(&entry, limits.path_bytes)?;
        remove_path(&destination)?;
        create_symlink(&target, &destination)?;
        metadata.insert(
            key,
            EntryMetadata {
                kind: TreeEntryKind::Symlink,
                mode,
                uid,
                gid,
                link_target: Some(target),
            },
        );
    } else if kind.is_hard_link() {
        remove_metadata_subtree(metadata, &key);
        let target = entry
            .link_name()?
            .ok_or_else(|| OciError::Invalid("hardlink target is absent".into()))?;
        let target = normalize_layer_path(&target, limits.path_bytes)?;
        let target_path = resolve_existing_regular(root, &target)?;
        remove_path(&destination)?;
        fs::hard_link(target_path, &destination)?;
        metadata.insert(
            key,
            EntryMetadata {
                kind: TreeEntryKind::Hardlink,
                mode,
                uid,
                gid,
                link_target: Some(path_key(&target)),
            },
        );
    } else {
        return Err(OciError::Unsupported(format!(
            "tar entry type {:?}",
            kind.as_byte()
        )));
    }
    Ok(())
}

fn normalize_layer_path(path: &Path, maximum: usize) -> Result<PathBuf, OciError> {
    let text = path
        .to_str()
        .ok_or_else(|| OciError::Unsupported("non-UTF-8 layer path".into()))?;
    if text.len() > maximum || text.contains('\0') {
        return Err(OciError::Limit("layer path length"));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            _ => return Err(OciError::Invalid("layer path escapes root".into())),
        }
    }
    Ok(normalized)
}

fn resolve_directory(root: &Path, relative: &Path, create: bool) -> Result<PathBuf, OciError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(OciError::Invalid("directory path is not normalized".into()));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(OciError::Invalid(
                    "layer path traverses a non-directory or symlink".into(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                fs::create_dir(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(current)
}

fn resolve_existing_regular(root: &Path, relative: &Path) -> Result<PathBuf, OciError> {
    let parent = resolve_directory(
        root,
        relative.parent().unwrap_or_else(|| Path::new("")),
        false,
    )?;
    let path = parent.join(
        relative
            .file_name()
            .ok_or_else(|| OciError::Invalid("hardlink target has no basename".into()))?,
    );
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(OciError::Invalid(
            "hardlink target is not an existing regular file".into(),
        ));
    }
    Ok(path)
}

fn normalized_link<R: Read>(entry: &tar::Entry<'_, R>, maximum: usize) -> Result<String, OciError> {
    let target = entry
        .link_name()?
        .ok_or_else(|| OciError::Invalid("symlink target is absent".into()))?;
    let value = target
        .to_str()
        .ok_or_else(|| OciError::Unsupported("non-UTF-8 symlink target".into()))?;
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(OciError::Limit("symlink target length"));
    }
    Ok(value.to_owned())
}

fn remove_path(path: &Path) -> Result<(), OciError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)?
        }
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn collect_tree(
    root: &Path,
    metadata: &BTreeMap<String, EntryMetadata>,
    maximum: usize,
) -> Result<Vec<TreeEntry>, OciError> {
    let mut paths = Vec::new();
    collect_paths(root, Path::new(""), &mut paths, maximum)?;
    paths.sort();
    let mut entries = Vec::with_capacity(paths.len());
    for relative in paths {
        let key = path_key(&relative);
        let value = metadata.get(&key).ok_or_else(|| {
            OciError::Invalid(format!("tree metadata missing for implicit path {key}"))
        })?;
        let path = root.join(&relative);
        let filesystem = fs::symlink_metadata(&path)?;
        let (size, digest) = if filesystem.is_file() && !filesystem.file_type().is_symlink() {
            let mut file = File::open(&path)?;
            (filesystem.len(), Some(sha256_reader(&mut file)?))
        } else {
            (0, None)
        };
        entries.push(TreeEntry {
            path: key,
            kind: value.kind,
            mode: value.mode,
            uid: value.uid,
            gid: value.gid,
            size,
            digest,
            link_target: value.link_target.clone(),
        });
    }
    Ok(entries)
}

fn collect_paths(
    root: &Path,
    relative: &Path,
    paths: &mut Vec<PathBuf>,
    maximum: usize,
) -> Result<(), OciError> {
    for item in fs::read_dir(root.join(relative))? {
        let item = item?;
        let child = relative.join(item.file_name());
        paths.push(child.clone());
        if paths.len() > maximum {
            return Err(OciError::Limit("final tree entry count"));
        }
        let metadata = fs::symlink_metadata(item.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            collect_paths(root, &child, paths, maximum)?;
        }
    }
    Ok(())
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
            Ok(())
        }
        Ok(_) => Err(OciError::Invalid(
            "conversion destination must be a new empty directory".into(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
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

fn path_key(path: &Path) -> String {
    path.components()
        .filter_map(|value| match value {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_descendant(candidate: &str, parent: &str) -> bool {
    !parent.is_empty()
        && candidate
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn register_implicit_directories(path: &Path, metadata: &mut BTreeMap<String, EntryMetadata>) {
    let mut current = PathBuf::new();
    for component in path.components() {
        if let Component::Normal(value) = component {
            current.push(value);
            metadata.entry(path_key(&current)).or_insert(EntryMetadata {
                kind: TreeEntryKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                link_target: None,
            });
        }
    }
}

fn remove_metadata_subtree(metadata: &mut BTreeMap<String, EntryMetadata>, path: &str) {
    metadata.retain(|candidate, _| candidate != path && !is_descendant(candidate, path));
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[cfg(unix)]
fn create_symlink(target: &str, destination: &Path) -> Result<(), OciError> {
    std::os::unix::fs::symlink(target, destination)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, _destination: &Path) -> Result<(), OciError> {
    Err(OciError::Unsupported(
        "OCI conversion requires the Linux builder appliance".into(),
    ))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), OciError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), OciError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-oci-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn paths_never_escape_the_builder_root() {
        for value in ["../escape", "/absolute", "a/../../escape"] {
            assert!(normalize_layer_path(Path::new(value), 4096).is_err());
        }
        assert_eq!(
            normalize_layer_path(Path::new("./usr/bin/tool"), 4096).unwrap(),
            PathBuf::from("usr/bin/tool")
        );
    }

    #[test]
    fn parent_symlinks_are_never_followed() {
        let root = Temp::new();
        let outside = Temp::new();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside.0, root.0.join("link")).unwrap();
        #[cfg(unix)]
        assert!(resolve_directory(&root.0, Path::new("link/child"), true).is_err());
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
        let converted = OciLayout::open(&layout.0, ConversionLimits::default())
            .unwrap()
            .convert(source.clone(), &destination)
            .unwrap();
        assert_eq!(fs::read(destination.join("usr/bin/tool")).unwrap(), b"v2");
        assert!(!destination.join("usr/bin/old").exists());
        assert!(
            converted
                .entries
                .iter()
                .any(|entry| { entry.path == "usr" && entry.kind == TreeEntryKind::Directory })
        );
        assert!(
            converted.entries.iter().any(|entry| {
                entry.path == "usr/bin/tool" && entry.kind == TreeEntryKind::Regular
            })
        );

        let mut forged = source;
        forged.config_digest = format!("sha256:{}", "0".repeat(64));
        let other = layout.0.join("forged");
        assert!(
            OciLayout::open(&layout.0, ConversionLimits::default())
                .unwrap()
                .convert(forged, &other)
                .is_err()
        );
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
