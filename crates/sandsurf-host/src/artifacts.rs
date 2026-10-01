//! Native host-file authority and bounded content-addressed transfer storage.
//!
//! Host paths enter Sandsurf only through this module. A capture is published
//! after every source file has been copied and content-verified; callers page
//! immutable metadata and blobs rather than retaining ambient path authority.

use crate::api::{
    HostApplyReport, HostChangeSet, HostTreeCapture, HostTreeChange, HostTreeEntry,
    HostTreeEntryKind,
};
#[cfg(unix)]
use cap_std::fs::Permissions as CapPermissions;
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapOpenOptions},
};
use sandsurf_native::storage::object_name;
use sandsurf_protocol::{
    CommitmentId, Counter, Digest, Domain, FileKind, FilesystemRequest, FilesystemResponse,
    GuestPath, MachineId, OperationId, bytes_digest, digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use unicode_normalization::UnicodeNormalization;

const MAX_ENTRIES: usize = 100_000;
const MAX_CAPTURE_DEPTH: usize = 256;
const MAX_BLOB_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_CHUNK_BYTES: usize = sandsurf_protocol::MAX_STREAM_BYTES;
const CONTROL_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum ArtifactError {
    Io(io::Error),
    Json(serde_json::Error),
    Contract(sandsurf_protocol::Invalid),
    State(sandsurf_state::Error),
    Invalid(&'static str),
    Conflict(&'static str),
    Capacity(&'static str),
    Guest(String),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "host artifact I/O: {error}"),
            Self::Json(error) => write!(output, "host artifact metadata: {error}"),
            Self::Contract(error) => write!(output, "host artifact contract: {error}"),
            Self::State(error) => write!(output, "host artifact storage: {error}"),
            Self::Invalid(message) => write!(output, "invalid host artifact request: {message}"),
            Self::Conflict(message) => write!(output, "host artifact conflict: {message}"),
            Self::Capacity(message) => write!(output, "host artifact capacity: {message}"),
            Self::Guest(message) => write!(output, "guest artifact capture: {message}"),
        }
    }
}
impl std::error::Error for ArtifactError {}
impl From<io::Error> for ArtifactError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for ArtifactError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_protocol::Invalid> for ArtifactError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}
impl From<sandsurf_state::Error> for ArtifactError {
    fn from(value: sandsurf_state::Error) -> Self {
        Self::State(value)
    }
}

pub type Result<T> = std::result::Result<T, ArtifactError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaptureRecord {
    capture: HostTreeCapture,
    approval_id: Option<CommitmentId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ApplyPhase {
    Applying,
    Committed,
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplyRecord {
    machine_id: MachineId,
    artifact_id: OperationId,
    operation_id: OperationId,
    destination: PathBuf,
    destination_identity: NativeIdentity,
    request_digest: Digest,
    approval_id: CommitmentId,
    change_set: HostChangeSet,
    original: Vec<Option<HostTreeEntry>>,
    completed: usize,
    active: Option<usize>,
    recovered: bool,
    phase: ApplyPhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeIdentity {
    first: u64,
    second: u64,
}

pub struct ArtifactStore {
    root: PathBuf,
    capture_index: Mutex<Option<Arc<CaptureIndex>>>,
}

struct CaptureIndex {
    capture: HostTreeCapture,
    entries: Vec<HostTreeEntry>,
    file_digests: BTreeSet<String>,
}

impl ArtifactStore {
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return Err(ArtifactError::Invalid("transfer root must be absolute"));
        }
        create_private_directory(root)?;
        create_private_directory(&root.join("blobs"))?;
        Ok(Self {
            root: root.into(),
            capture_index: Mutex::new(None),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        &self,
        machine_id: MachineId,
        operation_id: OperationId,
        source: &Path,
        exclusions: &[String],
        maximum_bytes: Counter,
        approval_id: CommitmentId,
    ) -> Result<HostTreeCapture> {
        let _lease = self.capture_lease(&operation_id)?;
        if !source.is_absolute() || maximum_bytes == Counter::ZERO {
            return Err(ArtifactError::Invalid(
                "capture source and byte bound are invalid",
            ));
        }
        let exclusions = validate_exclusions(exclusions)?;
        let request_digest = digest(
            Domain::Transfer,
            &(
                "sandsurf-host-tree-capture-v1",
                &machine_id,
                &operation_id,
                source,
                exclusions.iter().collect::<Vec<_>>(),
                maximum_bytes,
            ),
        )?;
        let published = self.capture_directory(&operation_id);
        if published.exists() {
            let record = read_json::<CaptureRecord>(&published.join("record.json"))?;
            if record.capture.request_digest != request_digest
                || record.capture.machine_id != machine_id
            {
                return Err(ArtifactError::Conflict(
                    "capture operation identity is already bound",
                ));
            }
            return Ok(record.capture);
        }

        let stage = self.capture_stage(&operation_id);
        if stage.exists() {
            fs::remove_dir_all(&stage)?;
        }
        create_private_directory(&stage)?;
        let result = (|| {
            let source_metadata = fs::symlink_metadata(source)?;
            if !source_metadata.is_dir() || source_metadata.file_type().is_symlink() {
                return Err(ArtifactError::Invalid(
                    "capture source must be a directory, not a link",
                ));
            }
            let source_identity = native_identity(source, &source_metadata)?;
            let canonical = fs::canonicalize(source)?;
            if source_identity != native_identity(&canonical, &fs::symlink_metadata(&canonical)?)? {
                return Err(ArtifactError::Conflict(
                    "capture source changed during admission",
                ));
            }
            let directory = Dir::open_ambient_dir(&canonical, ambient_authority())?;
            let mut entries = Vec::new();
            let mut bytes = 0_u64;
            let mut portable_names = BTreeSet::new();
            self.walk_capture(
                &directory,
                Path::new("."),
                "",
                &exclusions,
                maximum_bytes.get(),
                &mut bytes,
                &mut entries,
                &mut portable_names,
            )?;
            let manifest_digest = manifest_digest(&entries)?;
            let capture = HostTreeCapture {
                operation_id,
                machine_id,
                request_digest,
                manifest_digest,
                entries: Counter::try_from(entries.len() as u64)?,
                bytes: Counter::try_from(bytes)?,
            };
            write_json(&stage.join("entries.json"), &entries)?;
            write_json(
                &stage.join("record.json"),
                &CaptureRecord {
                    capture: capture.clone(),
                    approval_id: Some(approval_id),
                },
            )?;
            sync_directory(&stage)?;
            fs::rename(&stage, &published)?;
            sync_directory(&self.root)?;
            Ok(capture)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&stage);
        }
        result
    }

    pub fn capture_guest<F>(
        &self,
        machine_id: MachineId,
        operation_id: OperationId,
        request_digest: Digest,
        source: GuestPath,
        maximum_bytes: Counter,
        mut query: F,
    ) -> Result<HostTreeCapture>
    where
        F: FnMut(FilesystemRequest) -> Result<FilesystemResponse>,
    {
        let _lease = self.capture_lease(&operation_id)?;
        if maximum_bytes == Counter::ZERO || maximum_bytes.get() > MAX_BLOB_BYTES {
            return Err(ArtifactError::Capacity(
                "guest capture byte bound is invalid",
            ));
        }
        if let Some(capture) =
            self.existing_guest_capture(&machine_id, &operation_id, &request_digest)?
        {
            return Ok(capture);
        }
        let published = self.capture_directory(&operation_id);
        let stage = self.capture_stage(&operation_id);
        if stage.exists() {
            fs::remove_dir_all(&stage)?;
        }
        create_private_directory(&stage)?;
        let result = (|| {
            let mut entries = Vec::new();
            let mut bytes = 0_u64;
            let mut portable_names = BTreeSet::new();
            self.walk_guest_capture(
                &mut query,
                source,
                "",
                0,
                maximum_bytes.get(),
                &mut bytes,
                &mut entries,
                &mut portable_names,
            )?;
            let manifest_digest = manifest_digest(&entries)?;
            let capture = HostTreeCapture {
                operation_id,
                machine_id,
                request_digest,
                manifest_digest,
                entries: Counter::try_from(entries.len() as u64)?,
                bytes: Counter::try_from(bytes)?,
            };
            write_json(&stage.join("entries.json"), &entries)?;
            write_json(
                &stage.join("record.json"),
                &CaptureRecord {
                    capture: capture.clone(),
                    approval_id: None,
                },
            )?;
            sync_directory(&stage)?;
            fs::rename(&stage, &published)?;
            sync_directory(&self.root)?;
            Ok(capture)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&stage);
        }
        result
    }

    pub fn existing_guest_capture(
        &self,
        machine_id: &MachineId,
        operation_id: &OperationId,
        request_digest: &Digest,
    ) -> Result<Option<HostTreeCapture>> {
        let published = self.capture_directory(operation_id);
        if !published.exists() {
            return Ok(None);
        }
        let record = read_json::<CaptureRecord>(&published.join("record.json"))?;
        if &record.capture.machine_id != machine_id
            || &record.capture.request_digest != request_digest
            || record.approval_id.is_some()
        {
            return Err(ArtifactError::Conflict(
                "guest capture operation identity is already bound",
            ));
        }
        self.load_capture_index(machine_id, operation_id)?;
        Ok(Some(record.capture))
    }

    fn load_capture_index(
        &self,
        machine_id: &MachineId,
        operation_id: &OperationId,
    ) -> Result<Arc<CaptureIndex>> {
        let mut cache = self
            .capture_index
            .lock()
            .map_err(|_| ArtifactError::Conflict("capture index is unavailable"))?;
        if let Some(index) = cache.as_ref()
            && &index.capture.operation_id == operation_id
        {
            if &index.capture.machine_id != machine_id {
                return Err(ArtifactError::Conflict(
                    "capture belongs to another machine",
                ));
            }
            return Ok(index.clone());
        }
        let directory = self.capture_directory(operation_id);
        let record = read_json::<CaptureRecord>(&directory.join("record.json"))?;
        if &record.capture.machine_id != machine_id || &record.capture.operation_id != operation_id
        {
            return Err(ArtifactError::Conflict(
                "capture belongs to another machine",
            ));
        }
        let entries = read_json::<Vec<HostTreeEntry>>(&directory.join("entries.json"))?;
        if manifest_digest(&entries)? != record.capture.manifest_digest
            || entries.len() as u64 != record.capture.entries.get()
        {
            return Err(ArtifactError::Conflict("capture manifest is corrupt"));
        }
        let file_digests = entries
            .iter()
            .filter(|entry| entry.kind == HostTreeEntryKind::File)
            .filter_map(|entry| entry.digest.as_ref().map(|value| value.as_str().to_owned()))
            .collect();
        let index = Arc::new(CaptureIndex {
            capture: record.capture,
            entries,
            file_digests,
        });
        *cache = Some(index.clone());
        Ok(index)
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_guest_capture<F>(
        &self,
        query: &mut F,
        directory: GuestPath,
        parent: &str,
        depth: usize,
        maximum_bytes: u64,
        bytes: &mut u64,
        entries: &mut Vec<HostTreeEntry>,
        portable_names: &mut BTreeSet<String>,
    ) -> Result<()>
    where
        F: FnMut(FilesystemRequest) -> Result<FilesystemResponse>,
    {
        if depth > MAX_CAPTURE_DEPTH {
            return Err(ArtifactError::Capacity(
                "guest capture directory depth exceeds its bound",
            ));
        }
        let mut after = None;
        loop {
            let page = match query(FilesystemRequest::List {
                path: directory.clone(),
                after: after.clone(),
                maximum: 1024,
            })? {
                FilesystemResponse::List { page } => page,
                _ => {
                    return Err(ArtifactError::Invalid(
                        "guest directory query was not a page",
                    ));
                }
            };
            for child in page.entries {
                let name = std::str::from_utf8(&child.name)
                    .map_err(|_| ArtifactError::Invalid("guest path is not portable UTF-8"))?;
                if name.contains('/') || name.contains('\\') {
                    return Err(ArtifactError::Invalid("guest entry name is malformed"));
                }
                let portable = if parent.is_empty() {
                    name.to_owned()
                } else {
                    format!("{parent}/{name}")
                };
                validate_relative(&portable)?;
                let collision = portable
                    .split('/')
                    .map(str::to_lowercase)
                    .collect::<Vec<_>>()
                    .join("/");
                if !portable_names.insert(collision) {
                    return Err(ArtifactError::Invalid(
                        "guest capture has a case-folding path collision",
                    ));
                }
                if entries.len() >= MAX_ENTRIES {
                    return Err(ArtifactError::Capacity(
                        "guest capture has too many entries",
                    ));
                }
                let mut path = directory.as_bytes().to_vec();
                path.push(b'/');
                path.extend_from_slice(&child.name);
                let path = GuestPath::try_from(path)?;
                let mode = child.stat.mode;
                match child.stat.kind {
                    FileKind::Directory => {
                        entries.push(HostTreeEntry {
                            path: portable.clone(),
                            kind: HostTreeEntryKind::Directory,
                            mode,
                            size: Counter::ZERO,
                            digest: None,
                            target: None,
                        });
                        self.walk_guest_capture(
                            query,
                            path,
                            &portable,
                            depth + 1,
                            maximum_bytes,
                            bytes,
                            entries,
                            portable_names,
                        )?;
                    }
                    FileKind::Symlink => {
                        let target = match query(FilesystemRequest::Readlink { path })? {
                            FilesystemResponse::Link { target } => target,
                            _ => return Err(ArtifactError::Invalid("guest symlink query failed")),
                        };
                        if target.is_empty() || target.len() > 4096 || target.contains(&0) {
                            return Err(ArtifactError::Invalid(
                                "guest symlink target is malformed",
                            ));
                        }
                        entries.push(HostTreeEntry {
                            path: portable,
                            kind: HostTreeEntryKind::Symlink,
                            mode,
                            size: Counter::try_from(target.len() as u64)?,
                            digest: Some(bytes_digest(&target)),
                            target: Some(target),
                        });
                    }
                    FileKind::Regular => {
                        let length = child.stat.size;
                        if length > MAX_BLOB_BYTES {
                            return Err(ArtifactError::Capacity("guest file is too large"));
                        }
                        *bytes = bytes
                            .checked_add(length)
                            .filter(|value| *value <= maximum_bytes)
                            .ok_or(ArtifactError::Capacity(
                                "guest capture exceeds its byte bound",
                            ))?;
                        let digest = self.publish_guest_blob(query, path, length)?;
                        entries.push(HostTreeEntry {
                            path: portable,
                            kind: HostTreeEntryKind::File,
                            mode,
                            size: Counter::try_from(length)?,
                            digest: Some(digest),
                            target: None,
                        });
                    }
                    FileKind::Other => {
                        return Err(ArtifactError::Invalid(
                            "guest capture contains an unsupported filesystem object",
                        ));
                    }
                }
            }
            match page.next {
                Some(next)
                    if !next.is_empty()
                        && after
                            .as_ref()
                            .is_none_or(|old| next.as_slice() > old.as_slice()) =>
                {
                    after = Some(next);
                }
                Some(_) => return Err(ArtifactError::Invalid("guest directory cursor is empty")),
                None => return Ok(()),
            }
        }
    }

    fn publish_guest_blob<F>(&self, query: &mut F, path: GuestPath, length: u64) -> Result<Digest>
    where
        F: FnMut(FilesystemRequest) -> Result<FilesystemResponse>,
    {
        let temporary = self.root.join("blobs").join(format!(
            "guest-{}-{}.tmp",
            std::process::id(),
            random_suffix()?
        ));
        let result = (|| {
            let mut output = private_file(&temporary, true)?;
            let mut hasher = Sha256::new();
            let mut offset = 0_u64;
            loop {
                let range = match query(FilesystemRequest::Read {
                    path: path.clone(),
                    offset,
                    maximum: sandsurf_protocol::MAX_STREAM_BYTES as u32,
                })? {
                    FilesystemResponse::Read { range } => range,
                    _ => return Err(ArtifactError::Invalid("guest read returned wrong response")),
                };
                if range.offset != offset || range.bytes.len() > sandsurf_protocol::MAX_STREAM_BYTES
                {
                    return Err(ArtifactError::Invalid("guest file page is malformed"));
                }
                if range.bytes.is_empty() && !range.eof {
                    return Err(ArtifactError::Invalid("guest file page is empty"));
                }
                offset = offset
                    .checked_add(range.bytes.len() as u64)
                    .filter(|value| *value <= length)
                    .ok_or(ArtifactError::Conflict("guest file grew during capture"))?;
                if sandsurf_native::capacity::available_storage_bytes(&self.root)?
                    < CONTROL_HEADROOM_BYTES + range.bytes.len() as u64
                {
                    return Err(ArtifactError::Capacity(
                        "guest capture would consume host control headroom",
                    ));
                }
                output.write_all(&range.bytes)?;
                hasher.update(&range.bytes);
                if range.eof {
                    break;
                }
            }
            if offset != length {
                return Err(ArtifactError::Conflict("guest file length changed"));
            }
            let digest: Digest = format!("{:x}", hasher.finalize()).try_into()?;
            self.publish_completed_blob(&temporary, output, &digest, length)?;
            Ok(digest)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_capture(
        &self,
        root: &Dir,
        relative: &Path,
        portable_parent: &str,
        exclusions: &BTreeSet<String>,
        maximum_bytes: u64,
        bytes: &mut u64,
        entries: &mut Vec<HostTreeEntry>,
        portable_names: &mut BTreeSet<String>,
    ) -> Result<()> {
        let mut children = root
            .read_dir(relative)?
            .map(|value| value.map(|entry| entry.file_name()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        children.sort_by_key(|left| os_bytes(left));
        for name in children {
            let name = portable_component(&name)?;
            let portable = if portable_parent.is_empty() {
                name.clone()
            } else {
                format!("{portable_parent}/{name}")
            };
            if is_excluded(&portable, exclusions) {
                continue;
            }
            let collision = portable
                .split('/')
                .map(|part| part.to_lowercase())
                .collect::<Vec<_>>()
                .join("/");
            if !portable_names.insert(collision) {
                return Err(ArtifactError::Invalid(
                    "capture contains a case-folding path collision",
                ));
            }
            if entries.len() >= MAX_ENTRIES {
                return Err(ArtifactError::Capacity("capture has too many entries"));
            }
            let child = relative.join(&name);
            let metadata = root.symlink_metadata(&child)?;
            let mode = native_mode(&metadata);
            if metadata.is_dir() && !metadata.is_symlink() {
                entries.push(HostTreeEntry {
                    path: portable.clone(),
                    kind: HostTreeEntryKind::Directory,
                    mode,
                    size: Counter::ZERO,
                    digest: None,
                    target: None,
                });
                self.walk_capture(
                    root,
                    &child,
                    &portable,
                    exclusions,
                    maximum_bytes,
                    bytes,
                    entries,
                    portable_names,
                )?;
            } else if metadata.is_symlink() {
                let target = path_bytes(&root.read_link_contents(&child)?)?;
                if target.is_empty() || target.len() > 4096 || target.contains(&0) {
                    return Err(ArtifactError::Invalid("symlink target is malformed"));
                }
                entries.push(HostTreeEntry {
                    path: portable,
                    kind: HostTreeEntryKind::Symlink,
                    mode,
                    size: Counter::try_from(target.len() as u64)?,
                    digest: Some(bytes_digest(&target)),
                    target: Some(target),
                });
            } else if metadata.is_file() {
                if metadata.len() > MAX_BLOB_BYTES || native_link_count(&metadata) > 1 {
                    return Err(ArtifactError::Invalid(
                        "regular files must be singly linked and within the file bound",
                    ));
                }
                *bytes = bytes
                    .checked_add(metadata.len())
                    .filter(|value| *value <= maximum_bytes)
                    .ok_or(ArtifactError::Capacity(
                        "capture exceeds its byte reservation",
                    ))?;
                let mut file = root.open(&child)?;
                if !same_cap_identity(&metadata, &file.metadata()?) {
                    return Err(ArtifactError::Conflict(
                        "capture file changed before it was opened",
                    ));
                }
                let content_digest = self.publish_blob(&mut file, metadata.len())?;
                if !same_cap_identity(&metadata, &file.metadata()?)
                    || !same_cap_identity(&metadata, &root.symlink_metadata(&child)?)
                {
                    return Err(ArtifactError::Conflict(
                        "capture file changed while it was copied",
                    ));
                }
                entries.push(HostTreeEntry {
                    path: portable,
                    kind: HostTreeEntryKind::File,
                    mode,
                    size: Counter::try_from(metadata.len())?,
                    digest: Some(content_digest),
                    target: None,
                });
            } else {
                return Err(ArtifactError::Invalid(
                    "capture contains an unsupported filesystem object",
                ));
            }
        }
        Ok(())
    }

    fn publish_blob(&self, source: &mut impl Read, length: u64) -> Result<Digest> {
        let temporary = self.root.join("blobs").join(format!(
            "capture-{}-{}.tmp",
            std::process::id(),
            random_suffix()?
        ));
        let result = (|| {
            let mut output = private_file(&temporary, true)?;
            let mut hasher = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                copied = copied
                    .checked_add(count as u64)
                    .filter(|value| *value <= length)
                    .ok_or(ArtifactError::Conflict("capture file grew while copying"))?;
                output.write_all(&buffer[..count])?;
                hasher.update(&buffer[..count]);
            }
            if copied != length {
                return Err(ArtifactError::Conflict(
                    "capture file length changed while copying",
                ));
            }
            let digest: Digest = format!("{:x}", hasher.finalize()).try_into()?;
            self.publish_completed_blob(&temporary, output, &digest, length)?;
            Ok(digest)
        })();
        // The producer is closed before reclaiming any incomplete stage,
        // including read/write failures and oversized or shortened sources.
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn publish_completed_blob(
        &self,
        temporary: &Path,
        output: File,
        digest: &Digest,
        length: u64,
    ) -> Result<()> {
        // A protected writer fences rename/delete while producing bytes. End
        // that ownership before the storage publisher flushes and transfers
        // the completed object to its immutable content-addressed name.
        drop(output);
        // Content-addressed publication has one owner across threads and
        // worker processes. In particular, deduplication cannot open a newly
        // named Windows object until its publisher has closed DELETE custody.
        // This waits for ownership only; it never retries the storage effect.
        let _publication = self.operation_lease_with_wait(
            "blob",
            digest.as_str(),
            std::time::Duration::from_secs(5),
        )?;
        let destination = self.blob_path(digest);
        match verify_blob(&destination, digest, length) {
            Ok(()) => {
                fs::remove_file(temporary)?;
                sync_directory(&self.root.join("blobs"))?;
                return Ok(());
            }
            Err(ArtifactError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match sandsurf_native::storage::publish_new_file(temporary, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_blob(&destination, digest, length)?;
                fs::remove_file(temporary)?;
                sync_directory(&self.root.join("blobs"))?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn capture_entries(
        &self,
        machine_id: &MachineId,
        operation_id: &OperationId,
        after: Counter,
        maximum: Counter,
    ) -> Result<(HostTreeCapture, Vec<HostTreeEntry>, Option<Counter>)> {
        if maximum == Counter::ZERO || maximum.get() > 4096 {
            return Err(ArtifactError::Capacity(
                "capture page bound must be in 1..=4096",
            ));
        }
        let index = self.load_capture_index(machine_id, operation_id)?;
        let entries = &index.entries;
        let start = usize::try_from(after.get())
            .map_err(|_| ArtifactError::Capacity("capture cursor is invalid"))?;
        if start > entries.len() {
            return Err(ArtifactError::Conflict("capture cursor is past the end"));
        }
        let limit = start
            .saturating_add(maximum.get() as usize)
            .min(entries.len());
        let mut end = start;
        let mut metadata_bytes = 2usize;
        for entry in &entries[start..limit] {
            let length = serde_json::to_vec(entry)?.len() + 1;
            if metadata_bytes + length > sandsurf_protocol::MAX_CONTROL_BYTES / 2 {
                break;
            }
            metadata_bytes += length;
            end += 1;
        }
        if end == start && start < entries.len() {
            return Err(ArtifactError::Capacity(
                "one artifact entry exceeds its metadata page bound",
            ));
        }
        let next = (end < entries.len())
            .then(|| Counter::try_from(end as u64))
            .transpose()?;
        Ok((index.capture.clone(), entries[start..end].to_vec(), next))
    }

    pub fn read_capture_blob(
        &self,
        machine_id: &MachineId,
        operation_id: &OperationId,
        requested: &Digest,
        offset: Counter,
        maximum: u32,
    ) -> Result<(Vec<u8>, bool)> {
        if maximum == 0 || maximum as usize > MAX_CHUNK_BYTES {
            return Err(ArtifactError::Capacity("blob page bound is invalid"));
        }
        let index = self.load_capture_index(machine_id, operation_id)?;
        if !index.file_digests.contains(requested.as_str()) {
            return Err(ArtifactError::Conflict(
                "blob is not referenced by this capture",
            ));
        }
        read_blob(
            &self.blob_path(requested),
            requested,
            offset,
            maximum.min(sandsurf_protocol::MAX_STREAM_BYTES as u32),
        )
    }

    pub fn apply(
        &self,
        machine_id: MachineId,
        artifact_id: OperationId,
        operation_id: OperationId,
        destination: &Path,
        change_set: HostChangeSet,
        approval_id: CommitmentId,
    ) -> Result<HostApplyReport> {
        let _operation_lease = self.operation_lease("apply", operation_id.as_str())?;
        validate_change_set(&change_set)?;
        let artifact = self.load_capture_index(&machine_id, &artifact_id)?;
        let retained = artifact
            .entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<std::collections::BTreeMap<_, _>>();
        for change in &change_set.changes {
            if let HostTreeChange::Upsert { entry } = change
                && retained.get(entry.path.as_str()).copied() != Some(entry)
            {
                return Err(ArtifactError::Conflict(
                    "change is not retained by the source artifact",
                ));
            }
        }
        if !destination.is_absolute() {
            return Err(ArtifactError::Invalid(
                "host apply destination must be absolute",
            ));
        }
        let supplied_metadata = fs::symlink_metadata(destination)?;
        if !supplied_metadata.is_dir() || supplied_metadata.file_type().is_symlink() {
            return Err(ArtifactError::Invalid(
                "host apply destination must be a directory, not a link",
            ));
        }
        let supplied_identity = native_identity(destination, &supplied_metadata)?;
        let destination = fs::canonicalize(destination)?;
        let actual_metadata = fs::symlink_metadata(&destination)?;
        let destination_identity = native_identity(&destination, &actual_metadata)?;
        if supplied_identity != destination_identity {
            return Err(ArtifactError::Conflict(
                "host apply destination changed during admission",
            ));
        }
        let request_digest = digest(
            Domain::Transfer,
            &(
                "sandsurf-artifact-apply-v1",
                &machine_id,
                &artifact_id,
                &operation_id,
                destination.to_string_lossy().as_ref(),
                &destination_identity,
                &change_set.digest,
            ),
        )?;
        let destination_key = digest(Domain::Transfer, &destination_identity)?;
        let _destination_lease = self.operation_lease("destination", destination_key.as_str())?;
        let journal_path = self.apply_record_path(&operation_id);
        let root = Dir::open_ambient_dir(&destination, ambient_authority())?;
        let mut record = if journal_path.exists() {
            let mut existing = read_json::<ApplyRecord>(&journal_path)?;
            if existing.machine_id != machine_id
                || existing.artifact_id != artifact_id
                || existing.approval_id != approval_id
                || existing.operation_id != operation_id
                || existing.destination != destination
                || existing.destination_identity != destination_identity
                || existing.request_digest != request_digest
                || existing.change_set != change_set
            {
                return Err(ArtifactError::Conflict(
                    "host apply operation identity is already bound",
                ));
            }
            if existing.phase == ApplyPhase::Committed {
                return apply_report(&existing);
            }
            if existing.phase == ApplyPhase::Conflicted {
                return Err(ArtifactError::Conflict(
                    "interrupted host apply requires external conflict resolution",
                ));
            }
            if existing.completed != 0 || existing.active.is_some() {
                match self.rollback_apply(&root, &mut existing) {
                    Ok(()) => {
                        existing.recovered = true;
                        persist_replace(&journal_path, &existing)?;
                    }
                    Err(error) => {
                        existing.phase = ApplyPhase::Conflicted;
                        let _ = persist_replace(&journal_path, &existing);
                        return Err(error);
                    }
                }
            }
            existing
        } else {
            let base = change_set
                .base
                .iter()
                .map(|entry| (entry.path.as_str(), entry))
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut original = Vec::with_capacity(change_set.changes.len());
            for change in &change_set.changes {
                let path = change_path(change);
                let observed = self.capture_destination_entry(&root, path)?;
                match base.get(path) {
                    Some(expected) if observed.as_ref() == Some(*expected) => {}
                    Some(_) => {
                        return Err(ArtifactError::Conflict(
                            "host destination differs from the change-set base",
                        ));
                    }
                    None if observed.is_none() => {}
                    None => {
                        return Err(ArtifactError::Conflict(
                            "host destination contains a conflicting addition",
                        ));
                    }
                }
                original.push(observed);
            }
            let record = ApplyRecord {
                machine_id,
                artifact_id,
                operation_id,
                destination,
                destination_identity,
                request_digest,
                approval_id,
                change_set,
                original,
                completed: 0,
                active: None,
                recovered: false,
                phase: ApplyPhase::Applying,
            };
            write_json(&journal_path, &record)?;
            sync_directory(&self.root)?;
            record
        };

        for index in record.completed..record.change_set.changes.len() {
            record.active = Some(index);
            persist_replace(&journal_path, &record)?;
            let path = change_path(&record.change_set.changes[index]);
            if self.capture_destination_entry(&root, path)? != record.original[index] {
                record.phase = ApplyPhase::Conflicted;
                persist_replace(&journal_path, &record)?;
                return Err(ArtifactError::Conflict(
                    "host destination changed during apply",
                ));
            }
            if let Err(error) = self.apply_change(
                &root,
                &record.operation_id,
                index,
                &record.change_set.changes[index],
            ) {
                return match self.rollback_apply(&root, &mut record) {
                    Ok(()) => {
                        persist_replace(&journal_path, &record)?;
                        Err(error)
                    }
                    Err(rollback) => {
                        record.phase = ApplyPhase::Conflicted;
                        let _ = persist_replace(&journal_path, &record);
                        Err(rollback)
                    }
                };
            }
            let installed = installed_entry(&record.change_set.changes[index]);
            if self.capture_destination_entry(&root, path)? != installed {
                record.phase = ApplyPhase::Conflicted;
                persist_replace(&journal_path, &record)?;
                return Err(ArtifactError::Conflict(
                    "host destination changed before apply evidence committed",
                ));
            }
            record.completed = index + 1;
            record.active = None;
            persist_replace(&journal_path, &record)?;
        }
        record.phase = ApplyPhase::Committed;
        persist_replace(&journal_path, &record)?;
        apply_report(&record)
    }

    fn rollback_apply(&self, root: &Dir, record: &mut ApplyRecord) -> Result<()> {
        let count = record
            .active
            .map_or(record.completed, |active| record.completed.max(active + 1));
        for index in (0..count).rev() {
            let change = &record.change_set.changes[index];
            let path = change_path(change);
            let current = self.capture_destination_entry(root, path)?;
            let installed = installed_entry(change);
            if current == record.original[index] {
                continue;
            }
            if current != installed {
                return Err(ArtifactError::Conflict(
                    "external edit prevents safe host-apply recovery",
                ));
            }
            match &record.original[index] {
                Some(entry) => self.install_entry(root, &record.operation_id, index, entry)?,
                None => remove_entry(root, path)?,
            }
        }
        record.completed = 0;
        record.active = None;
        Ok(())
    }

    fn apply_change(
        &self,
        root: &Dir,
        operation: &OperationId,
        index: usize,
        change: &HostTreeChange,
    ) -> Result<()> {
        match change {
            HostTreeChange::Upsert { entry } => self.install_entry(root, operation, index, entry),
            HostTreeChange::Delete { path } => remove_entry(root, path),
        }
    }

    fn install_entry(
        &self,
        root: &Dir,
        operation: &OperationId,
        index: usize,
        entry: &HostTreeEntry,
    ) -> Result<()> {
        validate_relative(&entry.path)?;
        validate_parent_chain(root, &entry.path)?;
        match entry.kind {
            HostTreeEntryKind::Directory => {
                match root.create_dir(&entry.path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let metadata = root.symlink_metadata(&entry.path)?;
                        if !metadata.is_dir() || metadata.is_symlink() {
                            return Err(ArtifactError::Conflict(
                                "directory destination changed type",
                            ));
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
                set_mode(root, &entry.path, entry.mode)?;
            }
            HostTreeEntryKind::File => {
                let expected = entry
                    .digest
                    .as_ref()
                    .ok_or(ArtifactError::Invalid("file entry has no digest"))?;
                verify_blob(&self.blob_path(expected), expected, entry.size.get())?;
                let temporary = sibling_temporary(&entry.path, operation, index)?;
                let mut options = CapOpenOptions::new();
                options.write(true).create_new(true);
                let mut output = root.open_with(&temporary, &options)?;
                let mut input = private_file(&self.blob_path(expected), false)?;
                let copied = io::copy(&mut input, &mut output)?;
                if copied != entry.size.get() {
                    let _ = root.remove_file(&temporary);
                    return Err(ArtifactError::Conflict("host blob length changed"));
                }
                sandsurf_native::storage::sync_file(&output.into_std())?;
                set_mode(root, &temporary, entry.mode)?;
                replace_with_temporary(root, &temporary, &entry.path)?;
                sync_cap_parent(root, &entry.path)?;
            }
            HostTreeEntryKind::Symlink => {
                let target = entry
                    .target
                    .as_deref()
                    .ok_or(ArtifactError::Invalid("symlink entry has no target"))?;
                let temporary = sibling_temporary(&entry.path, operation, index)?;
                create_symlink(root, target, &temporary)?;
                replace_with_temporary(root, &temporary, &entry.path)?;
                sync_cap_parent(root, &entry.path)?;
            }
        }
        Ok(())
    }

    fn capture_destination_entry(&self, root: &Dir, path: &str) -> Result<Option<HostTreeEntry>> {
        validate_relative(path)?;
        let metadata = match root.symlink_metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mode = native_mode(&metadata);
        if metadata.is_dir() && !metadata.is_symlink() {
            return Ok(Some(HostTreeEntry {
                path: path.into(),
                kind: HostTreeEntryKind::Directory,
                mode,
                size: Counter::ZERO,
                digest: None,
                target: None,
            }));
        }
        if metadata.is_symlink() {
            let target = path_bytes(&root.read_link_contents(path)?)?;
            return Ok(Some(HostTreeEntry {
                path: path.into(),
                kind: HostTreeEntryKind::Symlink,
                mode,
                size: Counter::try_from(target.len() as u64)?,
                digest: Some(bytes_digest(&target)),
                target: Some(target),
            }));
        }
        if !metadata.is_file() || native_link_count(&metadata) > 1 {
            return Err(ArtifactError::Invalid(
                "host apply encountered an unsupported or multiply linked object",
            ));
        }
        let mut file = root.open(path)?;
        if !same_cap_identity(&metadata, &file.metadata()?) {
            return Err(ArtifactError::Conflict(
                "host apply file changed before opening",
            ));
        }
        let content = self.publish_blob(&mut file, metadata.len())?;
        if !same_cap_identity(&metadata, &file.metadata()?)
            || !same_cap_identity(&metadata, &root.symlink_metadata(path)?)
        {
            return Err(ArtifactError::Conflict(
                "host apply file changed while hashing",
            ));
        }
        Ok(Some(HostTreeEntry {
            path: path.into(),
            kind: HostTreeEntryKind::File,
            mode,
            size: Counter::try_from(metadata.len())?,
            digest: Some(content),
            target: None,
        }))
    }

    fn capture_directory(&self, operation: &OperationId) -> PathBuf {
        self.root
            .join(format!("capture-{}", object_name(operation.as_str())))
    }
    fn capture_lease(&self, operation: &OperationId) -> Result<File> {
        self.operation_lease("capture", operation.as_str())
    }
    fn operation_lease(&self, namespace: &str, identity: &str) -> Result<File> {
        self.operation_lease_with_wait(namespace, identity, std::time::Duration::ZERO)
    }
    fn operation_lease_with_wait(
        &self,
        namespace: &str,
        identity: &str,
        wait: std::time::Duration,
    ) -> Result<File> {
        let path = self
            .root
            .join(format!("{namespace}-{}.lock", object_name(identity)));
        let file = match sandsurf_native::local::create_private_file(&path) {
            Ok(file) => {
                sandsurf_native::storage::sync_file(&file)?;
                sync_directory(&self.root)?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                sandsurf_native::local::open_private_file(
                    &path,
                    sandsurf_native::PrivateFileAccess::ReadWrite,
                )?
            }
            Err(error) => return Err(error.into()),
        };
        let deadline = std::time::Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(ArtifactError::Conflict(
                        "artifact effect already has an active worker",
                    ));
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
        Ok(file)
    }
    fn capture_stage(&self, operation: &OperationId) -> PathBuf {
        self.root
            .join(format!("capture-{}.stage", object_name(operation.as_str())))
    }
    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join(digest.as_str())
    }
    fn apply_record_path(&self, operation: &OperationId) -> PathBuf {
        self.root
            .join(format!("apply-{}.json", object_name(operation.as_str())))
    }
}

fn validate_change_set(change_set: &HostChangeSet) -> Result<()> {
    if change_set.base.len() > MAX_ENTRIES || change_set.changes.len() > MAX_ENTRIES {
        return Err(ArtifactError::Capacity("change set has too many entries"));
    }
    let mut base_paths = BTreeSet::new();
    let mut portable = BTreeSet::new();
    for entry in &change_set.base {
        validate_entry(entry)?;
        if !base_paths.insert(entry.path.clone()) || !portable.insert(entry.path.to_lowercase()) {
            return Err(ArtifactError::Invalid("change-set base paths collide"));
        }
    }
    if manifest_digest(&change_set.base)? != change_set.base_manifest_digest {
        return Err(ArtifactError::Invalid(
            "change-set base manifest digest mismatch",
        ));
    }
    let mut changed = BTreeSet::new();
    for change in &change_set.changes {
        let path = change_path(change);
        validate_relative(path)?;
        if !changed.insert(path.to_owned()) {
            return Err(ArtifactError::Invalid("change-set paths are not unique"));
        }
        if let HostTreeChange::Upsert { entry } = change {
            validate_entry(entry)?;
        }
    }
    if change_set_digest(&change_set.base_manifest_digest, &change_set.changes)?
        != change_set.digest
    {
        return Err(ArtifactError::Invalid("change-set digest mismatch"));
    }
    Ok(())
}

fn validate_entry(entry: &HostTreeEntry) -> Result<()> {
    validate_relative(&entry.path)?;
    if entry.mode & !0o7777 != 0 {
        return Err(ArtifactError::Invalid("artifact entry mode is invalid"));
    }
    match entry.kind {
        HostTreeEntryKind::Directory
            if entry.size == Counter::ZERO && entry.digest.is_none() && entry.target.is_none() => {}
        HostTreeEntryKind::File
            if entry.digest.is_some()
                && entry.target.is_none()
                && entry.size.get() <= MAX_BLOB_BYTES => {}
        HostTreeEntryKind::Symlink
            if entry.digest.is_some()
                && entry.target.as_ref().is_some_and(|target| {
                    !target.is_empty()
                        && target.len() <= 4096
                        && !target.contains(&0)
                        && target.len() as u64 == entry.size.get()
                        && entry.digest.as_ref() == Some(&bytes_digest(target))
                }) => {}
        _ => return Err(ArtifactError::Invalid("artifact entry shape is invalid")),
    }
    Ok(())
}

pub fn change_set_digest(
    base_manifest_digest: &Digest,
    changes: &[HostTreeChange],
) -> Result<Digest> {
    let mut hash = Sha256::new();
    hash.update(b"SANDSURF-TREE-CHANGES-V1\0");
    for change in changes {
        let value = digest(Domain::Transfer, &("sandsurf-tree-change-v1", change))?;
        hash.update(decode_digest(&value)?);
    }
    let changes_digest: Digest = format!("{:x}", hash.finalize()).try_into()?;
    Ok(digest(
        Domain::Transfer,
        &(
            "sandsurf-tree-change-set-v1",
            base_manifest_digest,
            changes_digest,
        ),
    )?)
}

fn decode_digest(value: &Digest) -> Result<[u8; 32]> {
    let mut raw = [0_u8; 32];
    for (index, chunk) in value.as_str().as_bytes().chunks(2).enumerate() {
        raw[index] = (hex(chunk[0])? << 4) | hex(chunk[1])?;
    }
    Ok(raw)
}

fn change_path(change: &HostTreeChange) -> &str {
    match change {
        HostTreeChange::Upsert { entry } => &entry.path,
        HostTreeChange::Delete { path } => path,
    }
}

fn installed_entry(change: &HostTreeChange) -> Option<HostTreeEntry> {
    match change {
        HostTreeChange::Upsert { entry } => Some(entry.clone()),
        HostTreeChange::Delete { .. } => None,
    }
}

fn apply_report(record: &ApplyRecord) -> Result<HostApplyReport> {
    Ok(HostApplyReport {
        operation_id: record.operation_id.clone(),
        change_set_digest: record.change_set.digest.clone(),
        applied: Counter::try_from(record.completed as u64)?,
        recovered: record.recovered,
    })
}

fn validate_parent_chain(root: &Dir, path: &str) -> Result<()> {
    let mut current = PathBuf::new();
    if let Some(parent) = Path::new(path).parent() {
        for component in parent.components() {
            let Component::Normal(name) = component else {
                return Err(ArtifactError::Invalid("artifact parent is malformed"));
            };
            current.push(name);
            let metadata = root.symlink_metadata(&current)?;
            if !metadata.is_dir() || metadata.is_symlink() {
                return Err(ArtifactError::Conflict(
                    "artifact parent is absent, linked, or not a directory",
                ));
            }
        }
    }
    Ok(())
}

fn sibling_temporary(path: &str, operation: &OperationId, index: usize) -> Result<PathBuf> {
    let path = Path::new(path);
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(ArtifactError::Invalid("artifact path has no file name"))?;
    Ok(parent.join(format!(
        ".{name}.sandsurf-{}-{index}.tmp",
        operation.as_str()
    )))
}

fn replace_with_temporary(root: &Dir, temporary: &Path, path: &str) -> Result<()> {
    if root
        .symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.is_symlink())
    {
        root.remove_dir(path)?;
    }
    match root.rename(temporary, root, path) {
        Ok(()) => Ok(()),
        #[cfg(windows)]
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            root.remove_file(path)?;
            root.rename(temporary, root, path)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn remove_entry(root: &Dir, path: &str) -> Result<()> {
    validate_parent_chain(root, path)?;
    let metadata = root.symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.is_symlink() {
        root.remove_dir(path)?;
    } else {
        root.remove_file(path)?;
    }
    sync_cap_parent(root, path)
}

#[cfg(unix)]
fn set_mode(root: &Dir, path: impl AsRef<Path>, mode: u32) -> Result<()> {
    use cap_std::fs::PermissionsExt;
    root.set_permissions(path, CapPermissions::from_mode(mode))?;
    Ok(())
}
#[cfg(windows)]
fn set_mode(root: &Dir, path: impl AsRef<Path>, mode: u32) -> Result<()> {
    if mode & 0o111 != 0 {
        return Err(ArtifactError::Invalid(
            "Windows host apply requires an explicit executable-mode conversion policy",
        ));
    }
    let mut permissions = root.metadata(path.as_ref())?.permissions();
    permissions.set_readonly(mode & 0o200 == 0);
    root.set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn create_symlink(root: &Dir, target: &[u8], path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    root.symlink_contents(Path::new(OsStr::from_bytes(target)), path)?;
    Ok(())
}
#[cfg(windows)]
fn create_symlink(root: &Dir, target: &[u8], path: &Path) -> Result<()> {
    let target = std::str::from_utf8(target)
        .map_err(|_| ArtifactError::Invalid("Windows link target is not UTF-8"))?;
    root.symlink_file(target, path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_cap_parent(root: &Dir, path: &str) -> Result<()> {
    let parent = Path::new(path)
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    root.open_dir(parent)?.open(".")?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_cap_parent(_: &Dir, _: &str) -> Result<()> {
    // FlushFileBuffers does not provide a Windows directory-flush primitive.
    // Every installed regular file is flushed before its capability-relative
    // rename and the journal remains pending until all replacements complete.
    Ok(())
}

#[cfg(unix)]
fn native_identity(_: &Path, metadata: &fs::Metadata) -> io::Result<NativeIdentity> {
    use std::os::unix::fs::MetadataExt;
    Ok(NativeIdentity {
        first: metadata.dev(),
        second: metadata.ino(),
    })
}
#[cfg(windows)]
fn native_identity(path: &Path, _: &fs::Metadata) -> io::Result<NativeIdentity> {
    let (volume, file) = sandsurf_native::local::directory_identity(path)?;
    Ok(NativeIdentity {
        first: volume,
        second: file,
    })
}

fn persist_replace<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let temporary = path.with_extension("replace");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    write_json(&temporary, value)?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn manifest_digest(entries: &[HostTreeEntry]) -> Result<Digest> {
    let mut hash = Sha256::new();
    hash.update(b"SANDSURF-TREE-MANIFEST-V1\0");
    for entry in entries {
        let entry_digest = digest(Domain::Transfer, &("sandsurf-tree-entry-v1", entry))?;
        let mut raw = [0_u8; 32];
        for (index, chunk) in entry_digest.as_str().as_bytes().chunks(2).enumerate() {
            raw[index] = (hex(chunk[0])? << 4) | hex(chunk[1])?;
        }
        hash.update(raw);
    }
    Ok(format!("{:x}", hash.finalize()).try_into()?)
}

fn hex(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ArtifactError::Invalid("digest encoding is malformed")),
    }
}

fn validate_exclusions(values: &[String]) -> Result<BTreeSet<String>> {
    if values.len() > 4096 {
        return Err(ArtifactError::Capacity("too many capture exclusions"));
    }
    let mut result = BTreeSet::new();
    for value in values {
        validate_relative(value)?;
        result.insert(value.clone());
    }
    Ok(result)
}

fn validate_relative(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\\')
        || value.ends_with('/')
        || value.nfc().collect::<String>() != value
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(ArtifactError::Invalid(
            "host transfer path is not normalized and relative",
        ));
    }
    for component in value.split('/') {
        if windows_reserved(component) {
            return Err(ArtifactError::Invalid(
                "host transfer path is not portable to Windows",
            ));
        }
    }
    Ok(())
}

fn windows_reserved(value: &str) -> bool {
    if value.ends_with([' ', '.']) || value.contains(':') {
        return true;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn portable_component(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .ok_or(ArtifactError::Invalid("host path is not valid UTF-8"))?
        .to_owned();
    validate_relative(&value)?;
    Ok(value)
}

fn is_excluded(path: &str, exclusions: &BTreeSet<String>) -> bool {
    exclusions
        .iter()
        .any(|excluded| path == excluded || path.starts_with(&format!("{excluded}/")))
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}
#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn path_bytes(value: &Path) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(value.as_os_str().as_bytes().to_vec())
}
#[cfg(not(unix))]
fn path_bytes(value: &Path) -> Result<Vec<u8>> {
    Ok(value
        .to_str()
        .ok_or(ArtifactError::Invalid("link target is not valid UTF-8"))?
        .as_bytes()
        .to_vec())
}

#[cfg(unix)]
fn native_mode(metadata: &cap_std::fs::Metadata) -> u32 {
    use cap_std::fs::MetadataExt;
    metadata.mode() & 0o7777
}
#[cfg(windows)]
fn native_mode(metadata: &cap_std::fs::Metadata) -> u32 {
    if metadata.is_dir() {
        0o755
    } else if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

#[cfg(unix)]
fn native_link_count(metadata: &cap_std::fs::Metadata) -> u64 {
    use cap_std::fs::MetadataExt;
    metadata.nlink()
}
#[cfg(not(unix))]
fn native_link_count(_: &cap_std::fs::Metadata) -> u64 {
    1
}

#[cfg(unix)]
fn same_cap_identity(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(not(unix))]
fn same_cap_identity(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn verify_blob(path: &Path, expected: &Digest, length: u64) -> Result<()> {
    let mut file = private_file(path, false)?;
    if file.metadata()?.len() != length {
        return Err(ArtifactError::Conflict("host blob length changed"));
    }
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher_writer(&mut hasher))?;
    let actual: Digest = format!("{:x}", hasher.finalize()).try_into()?;
    if &actual != expected {
        return Err(ArtifactError::Conflict("host blob digest changed"));
    }
    Ok(())
}

struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn hasher_writer(hasher: &mut Sha256) -> HashWriter<'_> {
    HashWriter(hasher)
}

fn read_blob(
    path: &Path,
    expected: &Digest,
    offset: Counter,
    maximum: u32,
) -> Result<(Vec<u8>, bool)> {
    let mut file = private_file(path, false)?;
    let length = file.metadata()?.len();
    if offset.get() > length {
        return Err(ArtifactError::Conflict("blob cursor is past the end"));
    }
    file.seek(SeekFrom::Start(offset.get()))?;
    let count = (length - offset.get()).min(maximum as u64) as usize;
    let mut bytes = vec![0; count];
    file.read_exact(&mut bytes)?;
    if offset.get() == 0 && count as u64 == length {
        let actual: Digest = format!("{:x}", Sha256::digest(&bytes)).try_into()?;
        if &actual != expected {
            return Err(ArtifactError::Conflict("host blob digest changed"));
        }
    }
    Ok((bytes, offset.get() + count as u64 == length))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let file = private_file(path, true)?;
    let mut output = BufWriter::new(file);
    serde_json::to_writer(&mut output, value)?;
    output.flush()?;
    sandsurf_native::storage::sync_file(output.get_ref())?;
    Ok(())
}
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let file = private_file(path, false)?;
    if file.metadata()?.len() > 64 * 1024 * 1024 {
        return Err(ArtifactError::Capacity("transfer metadata is oversized"));
    }
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

fn random_suffix() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| ArtifactError::Invalid("host randomness unavailable"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    sandsurf_native::local::ensure_private_directory(path)
}

fn private_file(path: &Path, create: bool) -> io::Result<File> {
    if create {
        sandsurf_native::local::create_private_file(path)
    } else {
        sandsurf_native::local::open_private_file(
            path,
            sandsurf_native::PrivateFileAccess::ReadOnly,
        )
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    sandsurf_native::storage::sync_directory(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::{DirectoryEntry, DirectoryPage, FileRange, FileStat};

    fn temporary(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("sandsurf-tree-{name}-{}", random_suffix().unwrap()));
        create_private_directory(&path).unwrap();
        path
    }

    #[test]
    fn failed_capture_closes_and_reclaims_every_unpublished_stage() {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("source disconnected"))
            }
        }
        let state = temporary("failed-blobs");
        let store = ArtifactStore::open(&state).unwrap();
        assert!(store.publish_blob(&mut FailedRead, 1).is_err());
        assert!(store.publish_blob(&mut &b"long"[..], 1).is_err());
        assert!(store.publish_blob(&mut &b"short"[..], 6).is_err());
        assert_eq!(fs::read_dir(state.join("blobs")).unwrap().count(), 0);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn concurrent_capture_publication_reuses_one_immutable_blob_without_aliases() {
        let state = temporary("concurrent-blobs");
        // Separate stores exercise OS custody rather than an in-memory mutex
        // that would not coordinate independent artifact workers.
        let stores: Vec<_> = (0..16)
            .map(|_| ArtifactStore::open(&state).unwrap())
            .collect();
        std::thread::scope(|scope| {
            let workers: Vec<_> = stores
                .iter()
                .map(|store| {
                    scope.spawn(move || {
                        store
                            .publish_blob(&mut &b"shared original bytes"[..], 21)
                            .unwrap()
                    })
                })
                .collect();
            for worker in workers {
                assert_eq!(
                    worker.join().unwrap(),
                    bytes_digest(b"shared original bytes")
                );
            }
        });
        let entries: Vec<_> = fs::read_dir(state.join("blobs"))
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        assert_eq!(entries.len(), 1);
        let blob = entries[0].path();
        assert_eq!(fs::read(&blob).unwrap(), b"shared original bytes");
        drop(
            sandsurf_native::local::open_private_file(
                &blob,
                sandsurf_native::PrivateFileAccess::ReadOnly,
            )
            .unwrap(),
        );
        fs::remove_dir_all(state).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn artifact_store_never_adopts_an_unprotected_directory() {
        let root =
            std::env::temp_dir().join(format!("sandsurf-unprotected-{}", random_suffix().unwrap()));
        fs::create_dir(&root).unwrap();
        assert!(ArtifactStore::open(&root).is_err());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn live_guest_capture_retains_immutable_bytes_without_a_guest_barrier() {
        let state = temporary("guest-capture");
        let authority = ArtifactStore::open(&state).unwrap();
        let machine: MachineId = "machine-a".try_into().unwrap();
        let operation: OperationId = "guest-capture-a".try_into().unwrap();
        let request_digest = bytes_digest(b"guest-capture-request");
        let mut content = b"original guest bytes".repeat(8192);
        let original = content.clone();
        let content_digest = bytes_digest(&content);
        let capture = authority
            .capture_guest(
                machine.clone(),
                operation.clone(),
                request_digest.clone(),
                GuestPath::try_from("/home/agent/project").unwrap(),
                Counter::try_from(1024 * 1024).unwrap(),
                |request| match request {
                    FilesystemRequest::List { path, after, .. }
                        if path.to_utf8() == Some("/home/agent/project") && after.is_none() =>
                    {
                        Ok(FilesystemResponse::List {
                            page: DirectoryPage {
                                entries: vec![DirectoryEntry {
                                    name: b"file".to_vec(),
                                    stat: FileStat {
                                        kind: FileKind::Regular,
                                        size: content.len() as u64,
                                        readonly: false,
                                        modified_millis: None,
                                        mode: 0o644,
                                        device: 1,
                                        inode: 2,
                                    },
                                }],
                                next: None,
                            },
                        })
                    }
                    FilesystemRequest::Read {
                        path,
                        offset,
                        maximum,
                    } if path.to_utf8() == Some("/home/agent/project/file") => {
                        let start = offset as usize;
                        let end = (start + maximum as usize).min(content.len());
                        Ok(FilesystemResponse::Read {
                            range: FileRange {
                                offset,
                                bytes: content[start..end].to_vec(),
                                eof: end == content.len(),
                                observation: sandsurf_protocol::FileReadObservation {
                                    size: content.len() as u64,
                                    token: content_digest.clone(),
                                },
                            },
                        })
                    }
                    _ => Err(ArtifactError::Invalid("unexpected guest query")),
                },
            )
            .unwrap();
        assert_eq!(capture.entries.get(), 1);
        let (_, entries, _) = authority
            .capture_entries(&machine, &operation, Counter::ZERO, Counter::ONE)
            .unwrap();
        assert_eq!(entries[0].digest, Some(content_digest.clone()));
        content.fill(0);
        let mut retained = Vec::new();
        loop {
            let (page, eof) = authority
                .read_capture_blob(
                    &machine,
                    &operation,
                    &content_digest,
                    Counter::try_from(retained.len() as u64).unwrap(),
                    1024,
                )
                .unwrap();
            retained.extend_from_slice(&page);
            if eof {
                break;
            }
        }
        assert_eq!(retained, original);
        assert_eq!(
            authority
                .existing_guest_capture(&machine, &operation, &request_digest)
                .unwrap(),
            Some(capture.clone())
        );
        let recovered = ArtifactStore::open(&state).unwrap();
        assert_eq!(
            recovered
                .existing_guest_capture(&machine, &operation, &request_digest)
                .unwrap(),
            Some(capture)
        );
        fs::write(
            recovered.capture_directory(&operation).join("entries.json"),
            b"[]",
        )
        .unwrap();
        assert!(matches!(
            ArtifactStore::open(&state).unwrap().existing_guest_capture(
                &machine,
                &operation,
                &request_digest
            ),
            Err(ArtifactError::Conflict("capture manifest is corrupt"))
        ));
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn duplicate_capture_cannot_remove_an_active_workers_stage() {
        let state = temporary("capture-lease");
        let store = ArtifactStore::open(&state).unwrap();
        let operation: OperationId = "capture-active".try_into().unwrap();
        let lease = store.capture_lease(&operation).unwrap();
        let stage = store.capture_stage(&operation);
        create_private_directory(&stage).unwrap();
        fs::write(stage.join("owned"), b"active worker data").unwrap();
        let second = ArtifactStore::open(&state).unwrap();
        let result = second.capture_guest(
            "machine".try_into().unwrap(),
            operation.clone(),
            bytes_digest(b"request"),
            "/home/agent".try_into().unwrap(),
            Counter::ONE,
            |_| panic!("duplicate must not issue guest queries"),
        );
        assert!(matches!(
            result,
            Err(ArtifactError::Conflict(
                "artifact effect already has an active worker"
            ))
        ));
        assert_eq!(
            fs::read(stage.join("owned")).unwrap(),
            b"active worker data"
        );
        drop(lease);
        let lease = second.capture_lease(&operation).unwrap();
        drop(lease);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn case_distinct_artifact_operations_have_independent_paths_and_worker_leases() {
        let state = temporary("artifact-addresses");
        let store = ArtifactStore::open(&state).unwrap();
        let upper: OperationId = "Capture".try_into().unwrap();
        let lower: OperationId = "capture".try_into().unwrap();
        let upper_lease = store.capture_lease(&upper).unwrap();
        let lower_lease = store.capture_lease(&lower).unwrap();
        let upper_stage = store.capture_stage(&upper);
        let lower_stage = store.capture_stage(&lower);
        assert_ne!(
            upper_stage.to_string_lossy().to_lowercase(),
            lower_stage.to_string_lossy().to_lowercase()
        );
        assert_ne!(
            store.apply_record_path(&upper),
            store.apply_record_path(&lower)
        );
        create_private_directory(&upper_stage).unwrap();
        create_private_directory(&lower_stage).unwrap();
        fs::write(upper_stage.join("owner"), b"upper").unwrap();
        fs::write(lower_stage.join("owner"), b"lower").unwrap();
        assert_eq!(fs::read(upper_stage.join("owner")).unwrap(), b"upper");
        assert_eq!(fs::read(lower_stage.join("owner")).unwrap(), b"lower");
        drop(upper_lease);
        drop(lower_lease);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn capture_is_content_bound_paginated_and_idempotent() {
        let state = temporary("state");
        let source = temporary("source");
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/file"), b"alpha\0beta").unwrap();
        let authority = ArtifactStore::open(&state).unwrap();
        let machine: MachineId = "machine-a".try_into().unwrap();
        let operation: OperationId = "capture-a".try_into().unwrap();
        let approval: CommitmentId = "approval-a".try_into().unwrap();
        let captured = authority
            .capture(
                machine.clone(),
                operation.clone(),
                &source,
                &[],
                Counter::try_from(1024).unwrap(),
                approval.clone(),
            )
            .unwrap();
        assert_eq!(captured.entries.get(), 2);
        assert_eq!(captured.bytes.get(), 10);
        assert_eq!(
            authority
                .capture(
                    machine.clone(),
                    operation.clone(),
                    &source,
                    &[],
                    Counter::try_from(1024).unwrap(),
                    approval
                )
                .unwrap(),
            captured
        );
        let (_, first, next) = authority
            .capture_entries(&machine, &operation, Counter::ZERO, Counter::ONE)
            .unwrap();
        assert_eq!(first.len(), 1);
        let (_, second, next_after) = authority
            .capture_entries(&machine, &operation, next.unwrap(), Counter::ONE)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(next_after, None);
        let file = second
            .iter()
            .find(|entry| entry.kind == HostTreeEntryKind::File)
            .unwrap();
        let (bytes, eof) = authority
            .read_capture_blob(
                &machine,
                &operation,
                file.digest.as_ref().unwrap(),
                Counter::ZERO,
                64,
            )
            .unwrap();
        assert!(eof);
        assert_eq!(bytes, b"alpha\0beta");
        fs::remove_dir_all(state).unwrap();
        fs::remove_dir_all(source).unwrap();
    }

    #[test]
    fn apply_is_base_checked_journaled_and_idempotent() {
        let state = temporary("apply-state");
        let destination = temporary("apply-destination");
        fs::write(destination.join("file"), b"base").unwrap();
        let authority = ArtifactStore::open(&state).unwrap();
        let machine: MachineId = "machine-a".try_into().unwrap();
        let capture_id: OperationId = "capture-base".try_into().unwrap();
        let capture = authority
            .capture(
                machine.clone(),
                capture_id.clone(),
                &destination,
                &[],
                Counter::try_from(1024).unwrap(),
                "capture-approval".try_into().unwrap(),
            )
            .unwrap();
        let (_, base, _) = authority
            .capture_entries(
                &machine,
                &capture_id,
                Counter::ZERO,
                Counter::try_from(100).unwrap(),
            )
            .unwrap();
        let bytes = b"changed bytes";
        let content = bytes_digest(bytes);
        let source = temporary("apply-source");
        fs::write(source.join("file"), bytes).unwrap();
        let artifact_id: OperationId = "capture-changed".try_into().unwrap();
        authority
            .capture(
                machine.clone(),
                artifact_id.clone(),
                &source,
                &[],
                Counter::try_from(1024).unwrap(),
                "source-approval".try_into().unwrap(),
            )
            .unwrap();
        let old = base.iter().find(|entry| entry.path == "file").unwrap();
        let changes = vec![HostTreeChange::Upsert {
            entry: HostTreeEntry {
                path: "file".into(),
                kind: HostTreeEntryKind::File,
                mode: old.mode,
                size: Counter::try_from(bytes.len() as u64).unwrap(),
                digest: Some(content),
                target: None,
            },
        }];
        let set_digest = change_set_digest(&capture.manifest_digest, &changes).unwrap();
        let change_set = HostChangeSet {
            base_manifest_digest: capture.manifest_digest,
            base,
            digest: set_digest,
            changes,
        };
        let operation: OperationId = "apply-one".try_into().unwrap();
        let approval: CommitmentId = "apply-approval".try_into().unwrap();
        assert!(matches!(
            authority.apply(
                machine.clone(),
                capture_id,
                operation.clone(),
                &destination,
                change_set.clone(),
                approval.clone()
            ),
            Err(ArtifactError::Conflict(
                "change is not retained by the source artifact"
            ))
        ));
        let destination_identity =
            native_identity(&destination, &fs::metadata(&destination).unwrap()).unwrap();
        let destination_key = digest(Domain::Transfer, &destination_identity).unwrap();
        let destination_lease = authority
            .operation_lease("destination", destination_key.as_str())
            .unwrap();
        let second = ArtifactStore::open(&state).unwrap();
        assert!(matches!(
            second.apply(
                machine.clone(),
                artifact_id.clone(),
                operation.clone(),
                &destination,
                change_set.clone(),
                approval.clone()
            ),
            Err(ArtifactError::Conflict(
                "artifact effect already has an active worker"
            ))
        ));
        assert_eq!(fs::read(destination.join("file")).unwrap(), b"base");
        drop(destination_lease);
        let report = authority
            .apply(
                machine.clone(),
                artifact_id.clone(),
                operation.clone(),
                &destination,
                change_set.clone(),
                approval.clone(),
            )
            .unwrap();
        assert_eq!(report.applied, Counter::ONE);
        assert_eq!(fs::read(destination.join("file")).unwrap(), bytes);
        assert!(matches!(
            authority.apply(
                machine.clone(),
                artifact_id.clone(),
                operation.clone(),
                &destination,
                change_set.clone(),
                "changed-approval".try_into().unwrap()
            ),
            Err(ArtifactError::Conflict(
                "host apply operation identity is already bound"
            ))
        ));
        assert_eq!(
            authority
                .apply(
                    machine.clone(),
                    artifact_id.clone(),
                    operation.clone(),
                    &destination,
                    change_set.clone(),
                    approval.clone(),
                )
                .unwrap(),
            report
        );
        let journal = authority.apply_record_path(&operation);
        let mut interrupted = read_json::<ApplyRecord>(&journal).unwrap();
        interrupted.phase = ApplyPhase::Applying;
        interrupted.completed = 0;
        interrupted.active = Some(0);
        interrupted.recovered = false;
        persist_replace(&journal, &interrupted).unwrap();
        let recovered = authority
            .apply(
                machine,
                artifact_id,
                operation,
                &destination,
                change_set,
                approval,
            )
            .unwrap();
        assert!(recovered.recovered);
        assert_eq!(fs::read(destination.join("file")).unwrap(), bytes);
        fs::remove_dir_all(state).unwrap();
        fs::remove_dir_all(destination).unwrap();
        fs::remove_dir_all(source).unwrap();
    }
}
