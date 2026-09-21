//! Native host-file authority and bounded content-addressed transfer storage.
//!
//! Host paths enter Sandsurf only through this module. A capture is published
//! after every source file has been copied and content-verified; callers page
//! immutable metadata and blobs rather than retaining ambient path authority.

use crate::api::{
    HostApplyReport, HostBlobTransfer, HostTreeCapture, HostTreeEntry, HostTreeEntryKind,
    HostWorkspaceChange, HostWorkspaceChangeSet,
};
#[cfg(unix)]
use cap_std::fs::Permissions as CapPermissions;
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapOpenOptions},
};
use sandsurf_protocol::{
    CommitmentId, Counter, Digest, Domain, OperationId, SandboxId, bytes_digest, digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

const MAX_ENTRIES: usize = 100_000;
const MAX_BLOB_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_CHUNK_BYTES: usize = sandsurf_protocol::MAX_STREAM_BYTES;

#[derive(Debug)]
pub enum WorkspaceError {
    Io(io::Error),
    Json(serde_json::Error),
    Contract(sandsurf_protocol::Invalid),
    Invalid(&'static str),
    Conflict(&'static str),
    Capacity(&'static str),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "host workspace I/O: {error}"),
            Self::Json(error) => write!(output, "host workspace metadata: {error}"),
            Self::Contract(error) => write!(output, "host workspace contract: {error}"),
            Self::Invalid(message) => write!(output, "invalid host workspace request: {message}"),
            Self::Conflict(message) => write!(output, "host workspace conflict: {message}"),
            Self::Capacity(message) => write!(output, "host workspace capacity: {message}"),
        }
    }
}
impl std::error::Error for WorkspaceError {}
impl From<io::Error> for WorkspaceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for WorkspaceError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_protocol::Invalid> for WorkspaceError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}

pub type Result<T> = std::result::Result<T, WorkspaceError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaptureRecord {
    capture: HostTreeCapture,
    approval_id: CommitmentId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UploadRecord {
    sandbox_id: SandboxId,
    transfer: HostBlobTransfer,
    approval_id: CommitmentId,
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
    sandbox_id: SandboxId,
    operation_id: OperationId,
    destination: PathBuf,
    destination_identity: NativeIdentity,
    request_digest: Digest,
    approval_id: CommitmentId,
    change_set: HostWorkspaceChangeSet,
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

pub struct WorkspaceAuthority {
    root: PathBuf,
}

impl WorkspaceAuthority {
    pub fn open(root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return Err(WorkspaceError::Invalid("transfer root must be absolute"));
        }
        create_private_directory(root)?;
        create_private_directory(&root.join("blobs"))?;
        Ok(Self { root: root.into() })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        &self,
        sandbox_id: SandboxId,
        operation_id: OperationId,
        source: &Path,
        exclusions: &[String],
        maximum_bytes: Counter,
        approval_id: CommitmentId,
    ) -> Result<HostTreeCapture> {
        if !source.is_absolute() || maximum_bytes == Counter::ZERO {
            return Err(WorkspaceError::Invalid(
                "capture source and byte bound are invalid",
            ));
        }
        let exclusions = validate_exclusions(exclusions)?;
        let request_digest = digest(
            Domain::Transfer,
            &(
                "sandsurf-host-tree-capture-v1",
                &sandbox_id,
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
                || record.capture.sandbox_id != sandbox_id
            {
                return Err(WorkspaceError::Conflict(
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
                return Err(WorkspaceError::Invalid(
                    "capture source must be a directory, not a link",
                ));
            }
            let canonical = fs::canonicalize(source)?;
            if !same_native_identity(&source_metadata, &fs::symlink_metadata(&canonical)?) {
                return Err(WorkspaceError::Conflict(
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
                sandbox_id,
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
                    approval_id,
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
                return Err(WorkspaceError::Invalid(
                    "capture contains a case-folding path collision",
                ));
            }
            if entries.len() >= MAX_ENTRIES {
                return Err(WorkspaceError::Capacity("capture has too many entries"));
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
                    return Err(WorkspaceError::Invalid("symlink target is malformed"));
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
                    return Err(WorkspaceError::Invalid(
                        "regular files must be singly linked and within the file bound",
                    ));
                }
                *bytes = bytes
                    .checked_add(metadata.len())
                    .filter(|value| *value <= maximum_bytes)
                    .ok_or(WorkspaceError::Capacity(
                        "capture exceeds its byte reservation",
                    ))?;
                let mut file = root.open(&child)?;
                if !same_cap_identity(&metadata, &file.metadata()?) {
                    return Err(WorkspaceError::Conflict(
                        "capture file changed before it was opened",
                    ));
                }
                let content_digest = self.publish_blob(&mut file, metadata.len())?;
                if !same_cap_identity(&metadata, &file.metadata()?)
                    || !same_cap_identity(&metadata, &root.symlink_metadata(&child)?)
                {
                    return Err(WorkspaceError::Conflict(
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
                return Err(WorkspaceError::Invalid(
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
                .ok_or(WorkspaceError::Conflict("capture file grew while copying"))?;
            output.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
        }
        if copied != length {
            let _ = fs::remove_file(&temporary);
            return Err(WorkspaceError::Conflict(
                "capture file length changed while copying",
            ));
        }
        output.sync_all()?;
        let digest: Digest = format!("{:x}", hasher.finalize()).try_into()?;
        let destination = self.blob_path(&digest);
        if destination.exists() {
            verify_blob(&destination, &digest, length)?;
            fs::remove_file(&temporary)?;
        } else {
            fs::rename(&temporary, &destination)?;
            sync_directory(&self.root.join("blobs"))?;
        }
        Ok(digest)
    }

    pub fn capture_entries(
        &self,
        sandbox_id: &SandboxId,
        operation_id: &OperationId,
        after: Counter,
        maximum: Counter,
    ) -> Result<(HostTreeCapture, Vec<HostTreeEntry>, Option<Counter>)> {
        if maximum == Counter::ZERO || maximum.get() > 4096 {
            return Err(WorkspaceError::Capacity(
                "capture page bound must be in 1..=4096",
            ));
        }
        let directory = self.capture_directory(operation_id);
        let record = read_json::<CaptureRecord>(&directory.join("record.json"))?;
        if &record.capture.sandbox_id != sandbox_id {
            return Err(WorkspaceError::Conflict(
                "capture belongs to another sandbox",
            ));
        }
        let entries = read_json::<Vec<HostTreeEntry>>(&directory.join("entries.json"))?;
        if manifest_digest(&entries)? != record.capture.manifest_digest
            || entries.len() as u64 != record.capture.entries.get()
        {
            return Err(WorkspaceError::Conflict("capture manifest is corrupt"));
        }
        let start = usize::try_from(after.get())
            .map_err(|_| WorkspaceError::Capacity("capture cursor is invalid"))?;
        if start > entries.len() {
            return Err(WorkspaceError::Conflict("capture cursor is past the end"));
        }
        let end = start
            .saturating_add(maximum.get() as usize)
            .min(entries.len());
        let next = (end < entries.len())
            .then(|| Counter::try_from(end as u64))
            .transpose()?;
        Ok((record.capture, entries[start..end].to_vec(), next))
    }

    pub fn read_capture_blob(
        &self,
        sandbox_id: &SandboxId,
        operation_id: &OperationId,
        requested: &Digest,
        offset: Counter,
        maximum: u32,
    ) -> Result<(Vec<u8>, bool)> {
        if maximum == 0 || maximum as usize > MAX_CHUNK_BYTES {
            return Err(WorkspaceError::Capacity("blob page bound is invalid"));
        }
        let (capture, entries, _) = self.capture_entries(
            sandbox_id,
            operation_id,
            Counter::ZERO,
            Counter::try_from(4096)?,
        )?;
        if capture.entries.get() > 4096 {
            let all = read_json::<Vec<HostTreeEntry>>(
                &self.capture_directory(operation_id).join("entries.json"),
            )?;
            if !all
                .iter()
                .any(|entry| entry.digest.as_ref() == Some(requested))
            {
                return Err(WorkspaceError::Conflict(
                    "blob is not referenced by this capture",
                ));
            }
        } else if !entries
            .iter()
            .any(|entry| entry.digest.as_ref() == Some(requested))
        {
            return Err(WorkspaceError::Conflict(
                "blob is not referenced by this capture",
            ));
        }
        read_blob(&self.blob_path(requested), requested, offset, maximum)
    }

    pub fn begin_upload(
        &self,
        sandbox_id: SandboxId,
        transfer: HostBlobTransfer,
        approval_id: CommitmentId,
    ) -> Result<()> {
        validate_transfer(&transfer)?;
        let destination = self.blob_path(&transfer.digest);
        if destination.exists() {
            return verify_blob(&destination, &transfer.digest, transfer.length.get());
        }
        let record = UploadRecord {
            sandbox_id,
            transfer: transfer.clone(),
            approval_id,
        };
        let metadata = self.upload_record_path(&transfer.id);
        if metadata.exists() {
            let old = read_json::<UploadRecord>(&metadata)?;
            if old.sandbox_id == record.sandbox_id && old.transfer == record.transfer {
                return Ok(());
            }
            return Err(WorkspaceError::Conflict("upload identity is already bound"));
        }
        write_json(&metadata, &record)?;
        private_file(&self.upload_data_path(&transfer.id), true)?.sync_all()?;
        sync_directory(&self.root)?;
        Ok(())
    }

    pub fn write_upload(
        &self,
        sandbox_id: &SandboxId,
        transfer: &HostBlobTransfer,
        offset: Counter,
        bytes: &[u8],
    ) -> Result<()> {
        validate_transfer(transfer)?;
        if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES {
            return Err(WorkspaceError::Capacity("upload chunk bound is invalid"));
        }
        let record = read_json::<UploadRecord>(&self.upload_record_path(&transfer.id))?;
        if &record.sandbox_id != sandbox_id || &record.transfer != transfer {
            return Err(WorkspaceError::Conflict("upload request changed"));
        }
        let mut file = private_file(&self.upload_data_path(&transfer.id), false)?;
        if file.metadata()?.len() != offset.get()
            || offset
                .get()
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > transfer.length.get())
        {
            return Err(WorkspaceError::Conflict(
                "upload chunks must be contiguous and within the declaration",
            ));
        }
        file.seek(SeekFrom::Start(offset.get()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn commit_upload(&self, sandbox_id: &SandboxId, transfer: &HostBlobTransfer) -> Result<()> {
        validate_transfer(transfer)?;
        let destination = self.blob_path(&transfer.digest);
        if destination.exists() {
            return verify_blob(&destination, &transfer.digest, transfer.length.get());
        }
        let record_path = self.upload_record_path(&transfer.id);
        let record = read_json::<UploadRecord>(&record_path)?;
        if &record.sandbox_id != sandbox_id || &record.transfer != transfer {
            return Err(WorkspaceError::Conflict("upload request changed"));
        }
        let data = self.upload_data_path(&transfer.id);
        verify_blob(&data, &transfer.digest, transfer.length.get())?;
        fs::rename(&data, &destination)?;
        sync_directory(&self.root.join("blobs"))?;
        fs::remove_file(record_path)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    pub fn apply(
        &self,
        sandbox_id: SandboxId,
        operation_id: OperationId,
        destination: &Path,
        change_set: HostWorkspaceChangeSet,
        approval_id: CommitmentId,
    ) -> Result<HostApplyReport> {
        validate_change_set(&change_set)?;
        if !destination.is_absolute() {
            return Err(WorkspaceError::Invalid(
                "host apply destination must be absolute",
            ));
        }
        let supplied_metadata = fs::symlink_metadata(destination)?;
        if !supplied_metadata.is_dir() || supplied_metadata.file_type().is_symlink() {
            return Err(WorkspaceError::Invalid(
                "host apply destination must be a directory, not a link",
            ));
        }
        let destination = fs::canonicalize(destination)?;
        let actual_metadata = fs::symlink_metadata(&destination)?;
        if !same_native_identity(&supplied_metadata, &actual_metadata) {
            return Err(WorkspaceError::Conflict(
                "host apply destination changed during admission",
            ));
        }
        let destination_identity = native_identity(&actual_metadata);
        let request_digest = digest(
            Domain::Transfer,
            &(
                "sandsurf-host-apply-v1",
                &sandbox_id,
                &operation_id,
                destination.to_string_lossy().as_ref(),
                &destination_identity,
                &change_set.digest,
            ),
        )?;
        let journal_path = self.apply_record_path(&operation_id);
        let root = Dir::open_ambient_dir(&destination, ambient_authority())?;
        let mut record = if journal_path.exists() {
            let mut existing = read_json::<ApplyRecord>(&journal_path)?;
            if existing.sandbox_id != sandbox_id
                || existing.operation_id != operation_id
                || existing.destination != destination
                || existing.destination_identity != destination_identity
                || existing.request_digest != request_digest
                || existing.change_set != change_set
            {
                return Err(WorkspaceError::Conflict(
                    "host apply operation identity is already bound",
                ));
            }
            if existing.phase == ApplyPhase::Committed {
                return apply_report(&existing);
            }
            if existing.phase == ApplyPhase::Conflicted {
                return Err(WorkspaceError::Conflict(
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
                        return Err(WorkspaceError::Conflict(
                            "host destination differs from the change-set base",
                        ));
                    }
                    None if observed.is_none() => {}
                    None => {
                        return Err(WorkspaceError::Conflict(
                            "host destination contains a conflicting addition",
                        ));
                    }
                }
                original.push(observed);
            }
            let record = ApplyRecord {
                sandbox_id,
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
                return Err(WorkspaceError::Conflict(
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
                return Err(WorkspaceError::Conflict(
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
                return Err(WorkspaceError::Conflict(
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
        change: &HostWorkspaceChange,
    ) -> Result<()> {
        match change {
            HostWorkspaceChange::Upsert { entry } => {
                self.install_entry(root, operation, index, entry)
            }
            HostWorkspaceChange::Delete { path } => remove_entry(root, path),
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
                            return Err(WorkspaceError::Conflict(
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
                    .ok_or(WorkspaceError::Invalid("file entry has no digest"))?;
                verify_blob(&self.blob_path(expected), expected, entry.size.get())?;
                let temporary = sibling_temporary(&entry.path, operation, index)?;
                let mut options = CapOpenOptions::new();
                options.write(true).create_new(true);
                let mut output = root.open_with(&temporary, &options)?;
                let mut input = private_file(&self.blob_path(expected), false)?;
                let copied = io::copy(&mut input, &mut output)?;
                if copied != entry.size.get() {
                    let _ = root.remove_file(&temporary);
                    return Err(WorkspaceError::Conflict("host blob length changed"));
                }
                output.sync_all()?;
                set_mode(root, &temporary, entry.mode)?;
                replace_with_temporary(root, &temporary, &entry.path)?;
                sync_cap_parent(root, &entry.path)?;
            }
            HostTreeEntryKind::Symlink => {
                let target = entry
                    .target
                    .as_deref()
                    .ok_or(WorkspaceError::Invalid("symlink entry has no target"))?;
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
            return Err(WorkspaceError::Invalid(
                "host apply encountered an unsupported or multiply linked object",
            ));
        }
        let mut file = root.open(path)?;
        if !same_cap_identity(&metadata, &file.metadata()?) {
            return Err(WorkspaceError::Conflict(
                "host apply file changed before opening",
            ));
        }
        let content = self.publish_blob(&mut file, metadata.len())?;
        if !same_cap_identity(&metadata, &file.metadata()?)
            || !same_cap_identity(&metadata, &root.symlink_metadata(path)?)
        {
            return Err(WorkspaceError::Conflict(
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
        self.root.join(format!("capture-{}", operation.as_str()))
    }
    fn capture_stage(&self, operation: &OperationId) -> PathBuf {
        self.root
            .join(format!("capture-{}.stage", operation.as_str()))
    }
    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join(digest.as_str())
    }
    fn upload_record_path(&self, transfer: &sandsurf_protocol::TransferId) -> PathBuf {
        self.root.join(format!("upload-{}.json", transfer.as_str()))
    }
    fn upload_data_path(&self, transfer: &sandsurf_protocol::TransferId) -> PathBuf {
        self.root.join(format!("upload-{}.part", transfer.as_str()))
    }
    fn apply_record_path(&self, operation: &OperationId) -> PathBuf {
        self.root.join(format!("apply-{}.json", operation.as_str()))
    }
}

fn validate_change_set(change_set: &HostWorkspaceChangeSet) -> Result<()> {
    if change_set.base.len() > MAX_ENTRIES || change_set.changes.len() > MAX_ENTRIES {
        return Err(WorkspaceError::Capacity("change set has too many entries"));
    }
    let mut base_paths = BTreeSet::new();
    let mut portable = BTreeSet::new();
    for entry in &change_set.base {
        validate_entry(entry)?;
        if !base_paths.insert(entry.path.clone()) || !portable.insert(entry.path.to_lowercase()) {
            return Err(WorkspaceError::Invalid("change-set base paths collide"));
        }
    }
    if manifest_digest(&change_set.base)? != change_set.base_manifest_digest {
        return Err(WorkspaceError::Invalid(
            "change-set base manifest digest mismatch",
        ));
    }
    let mut changed = BTreeSet::new();
    for change in &change_set.changes {
        let path = change_path(change);
        validate_relative(path)?;
        if !changed.insert(path.to_owned()) {
            return Err(WorkspaceError::Invalid("change-set paths are not unique"));
        }
        if let HostWorkspaceChange::Upsert { entry } = change {
            validate_entry(entry)?;
        }
    }
    if change_set_digest(&change_set.base_manifest_digest, &change_set.changes)?
        != change_set.digest
    {
        return Err(WorkspaceError::Invalid("change-set digest mismatch"));
    }
    Ok(())
}

fn validate_entry(entry: &HostTreeEntry) -> Result<()> {
    validate_relative(&entry.path)?;
    if entry.mode & !0o7777 != 0 {
        return Err(WorkspaceError::Invalid("workspace entry mode is invalid"));
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
        _ => return Err(WorkspaceError::Invalid("workspace entry shape is invalid")),
    }
    Ok(())
}

pub fn change_set_digest(
    base_manifest_digest: &Digest,
    changes: &[HostWorkspaceChange],
) -> Result<Digest> {
    let mut hash = Sha256::new();
    hash.update(b"SANDSURF-WORKSPACE-CHANGES-V1\0");
    for change in changes {
        let value = digest(Domain::Transfer, &("sandsurf-workspace-change-v1", change))?;
        hash.update(decode_digest(&value)?);
    }
    let changes_digest: Digest = format!("{:x}", hash.finalize()).try_into()?;
    Ok(digest(
        Domain::Transfer,
        &(
            "sandsurf-workspace-change-set-v1",
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

fn change_path(change: &HostWorkspaceChange) -> &str {
    match change {
        HostWorkspaceChange::Upsert { entry } => &entry.path,
        HostWorkspaceChange::Delete { path } => path,
    }
}

fn installed_entry(change: &HostWorkspaceChange) -> Option<HostTreeEntry> {
    match change {
        HostWorkspaceChange::Upsert { entry } => Some(entry.clone()),
        HostWorkspaceChange::Delete { .. } => None,
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
                return Err(WorkspaceError::Invalid("workspace parent is malformed"));
            };
            current.push(name);
            let metadata = root.symlink_metadata(&current)?;
            if !metadata.is_dir() || metadata.is_symlink() {
                return Err(WorkspaceError::Conflict(
                    "workspace parent is absent, linked, or not a directory",
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
        .ok_or(WorkspaceError::Invalid("workspace path has no file name"))?;
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
        return Err(WorkspaceError::Invalid(
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
        .map_err(|_| WorkspaceError::Invalid("Windows link target is not UTF-8"))?;
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
fn native_identity(metadata: &fs::Metadata) -> NativeIdentity {
    use std::os::unix::fs::MetadataExt;
    NativeIdentity {
        first: metadata.dev(),
        second: metadata.ino(),
    }
}
#[cfg(not(unix))]
fn native_identity(metadata: &fs::Metadata) -> NativeIdentity {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |value| value.as_nanos() as u64);
    NativeIdentity {
        first: metadata.len(),
        second: modified,
    }
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
    hash.update(b"SANDSURF-WORKSPACE-MANIFEST-V1\0");
    for entry in entries {
        let entry_digest = digest(Domain::Transfer, &("sandsurf-workspace-entry-v1", entry))?;
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
        _ => Err(WorkspaceError::Invalid("digest encoding is malformed")),
    }
}

fn validate_transfer(transfer: &HostBlobTransfer) -> Result<()> {
    if transfer.length.get() > MAX_BLOB_BYTES {
        return Err(WorkspaceError::Capacity("host blob is too large"));
    }
    Ok(())
}

fn validate_exclusions(values: &[String]) -> Result<BTreeSet<String>> {
    if values.len() > 4096 {
        return Err(WorkspaceError::Capacity("too many capture exclusions"));
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
        return Err(WorkspaceError::Invalid(
            "host transfer path is not normalized and relative",
        ));
    }
    for component in value.split('/') {
        if windows_reserved(component) {
            return Err(WorkspaceError::Invalid(
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
        .ok_or(WorkspaceError::Invalid("host path is not valid UTF-8"))?
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
        .ok_or(WorkspaceError::Invalid("link target is not valid UTF-8"))?
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

#[cfg(unix)]
fn same_native_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}
#[cfg(not(unix))]
fn same_native_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn verify_blob(path: &Path, expected: &Digest, length: u64) -> Result<()> {
    let mut file = private_file(path, false)?;
    if file.metadata()?.len() != length {
        return Err(WorkspaceError::Conflict("host blob length changed"));
    }
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher_writer(&mut hasher))?;
    let actual: Digest = format!("{:x}", hasher.finalize()).try_into()?;
    if &actual != expected {
        return Err(WorkspaceError::Conflict("host blob digest changed"));
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
        return Err(WorkspaceError::Conflict("blob cursor is past the end"));
    }
    file.seek(SeekFrom::Start(offset.get()))?;
    let count = (length - offset.get()).min(maximum as u64) as usize;
    let mut bytes = vec![0; count];
    file.read_exact(&mut bytes)?;
    if offset.get() == 0 && count as u64 == length {
        let actual: Digest = format!("{:x}", Sha256::digest(&bytes)).try_into()?;
        if &actual != expected {
            return Err(WorkspaceError::Conflict("host blob digest changed"));
        }
    }
    Ok((bytes, offset.get() + count as u64 == length))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let file = private_file(path, true)?;
    let mut output = BufWriter::new(file);
    serde_json::to_writer(&mut output, value)?;
    output.flush()?;
    output.get_ref().sync_all()?;
    Ok(())
}
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let file = private_file(path, false)?;
    if file.metadata()?.len() > 64 * 1024 * 1024 {
        return Err(WorkspaceError::Capacity("transfer metadata is oversized"));
    }
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

fn random_suffix() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| WorkspaceError::Invalid("host randomness unavailable"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "transfer directory is not private",
        ));
    }
    Ok(())
}
#[cfg(windows)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn private_file(path: &Path, create: bool) -> io::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "transfer file is not private",
        ));
    }
    Ok(file)
}
#[cfg(windows)]
fn private_file(path: &Path, create: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .open(path)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
#[cfg(windows)]
fn sync_directory(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sandsurf-workspace-{name}-{}",
            random_suffix().unwrap()
        ));
        create_private_directory(&path).unwrap();
        path
    }

    #[test]
    fn capture_is_content_bound_paginated_and_idempotent() {
        let state = temporary("state");
        let source = temporary("source");
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/file"), b"alpha\0beta").unwrap();
        let authority = WorkspaceAuthority::open(&state).unwrap();
        let sandbox: SandboxId = "sandbox-a".try_into().unwrap();
        let operation: OperationId = "capture-a".try_into().unwrap();
        let approval: CommitmentId = "approval-a".try_into().unwrap();
        let captured = authority
            .capture(
                sandbox.clone(),
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
                    sandbox.clone(),
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
            .capture_entries(&sandbox, &operation, Counter::ZERO, Counter::ONE)
            .unwrap();
        assert_eq!(first.len(), 1);
        let (_, second, next_after) = authority
            .capture_entries(&sandbox, &operation, next.unwrap(), Counter::ONE)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(next_after, None);
        let file = second
            .iter()
            .find(|entry| entry.kind == HostTreeEntryKind::File)
            .unwrap();
        let (bytes, eof) = authority
            .read_capture_blob(
                &sandbox,
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
    fn uploads_are_contiguous_and_digest_bound() {
        let state = temporary("upload");
        let authority = WorkspaceAuthority::open(&state).unwrap();
        let bytes = b"one-two-three";
        let transfer = HostBlobTransfer {
            id: "transfer-a".try_into().unwrap(),
            length: Counter::try_from(bytes.len() as u64).unwrap(),
            digest: bytes_digest(bytes),
        };
        let sandbox: SandboxId = "sandbox-a".try_into().unwrap();
        authority
            .begin_upload(
                sandbox.clone(),
                transfer.clone(),
                "approval-a".try_into().unwrap(),
            )
            .unwrap();
        authority
            .write_upload(&sandbox, &transfer, Counter::ZERO, &bytes[..4])
            .unwrap();
        assert!(
            authority
                .write_upload(&sandbox, &transfer, Counter::ZERO, &bytes[4..])
                .is_err()
        );
        authority
            .write_upload(
                &sandbox,
                &transfer,
                Counter::try_from(4).unwrap(),
                &bytes[4..],
            )
            .unwrap();
        authority.commit_upload(&sandbox, &transfer).unwrap();
        verify_blob(
            &authority.blob_path(&transfer.digest),
            &transfer.digest,
            bytes.len() as u64,
        )
        .unwrap();
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn apply_is_base_checked_journaled_and_idempotent() {
        let state = temporary("apply-state");
        let destination = temporary("apply-destination");
        fs::write(destination.join("file"), b"base").unwrap();
        let authority = WorkspaceAuthority::open(&state).unwrap();
        let sandbox: SandboxId = "sandbox-a".try_into().unwrap();
        let capture_id: OperationId = "capture-base".try_into().unwrap();
        let capture = authority
            .capture(
                sandbox.clone(),
                capture_id.clone(),
                &destination,
                &[],
                Counter::try_from(1024).unwrap(),
                "capture-approval".try_into().unwrap(),
            )
            .unwrap();
        let (_, base, _) = authority
            .capture_entries(
                &sandbox,
                &capture_id,
                Counter::ZERO,
                Counter::try_from(100).unwrap(),
            )
            .unwrap();
        let bytes = b"changed bytes";
        let content = bytes_digest(bytes);
        let transfer = HostBlobTransfer {
            id: "apply-content".try_into().unwrap(),
            length: Counter::try_from(bytes.len() as u64).unwrap(),
            digest: content.clone(),
        };
        authority
            .begin_upload(
                sandbox.clone(),
                transfer.clone(),
                "upload-approval".try_into().unwrap(),
            )
            .unwrap();
        authority
            .write_upload(&sandbox, &transfer, Counter::ZERO, bytes)
            .unwrap();
        authority.commit_upload(&sandbox, &transfer).unwrap();
        let old = base.iter().find(|entry| entry.path == "file").unwrap();
        let changes = vec![HostWorkspaceChange::Upsert {
            entry: HostTreeEntry {
                path: "file".into(),
                kind: HostTreeEntryKind::File,
                mode: old.mode,
                size: transfer.length,
                digest: Some(content),
                target: None,
            },
        }];
        let set_digest = change_set_digest(&capture.manifest_digest, &changes).unwrap();
        let change_set = HostWorkspaceChangeSet {
            base_manifest_digest: capture.manifest_digest,
            base,
            digest: set_digest,
            changes,
        };
        let operation: OperationId = "apply-one".try_into().unwrap();
        let approval: CommitmentId = "apply-approval".try_into().unwrap();
        let report = authority
            .apply(
                sandbox.clone(),
                operation.clone(),
                &destination,
                change_set.clone(),
                approval.clone(),
            )
            .unwrap();
        assert_eq!(report.applied, Counter::ONE);
        assert_eq!(fs::read(destination.join("file")).unwrap(), bytes);
        assert_eq!(
            authority
                .apply(
                    sandbox.clone(),
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
            .apply(sandbox, operation, &destination, change_set, approval)
            .unwrap();
        assert!(recovered.recovered);
        assert_eq!(fs::read(destination.join("file")).unwrap(), bytes);
        fs::remove_dir_all(state).unwrap();
        fs::remove_dir_all(destination).unwrap();
    }
}
