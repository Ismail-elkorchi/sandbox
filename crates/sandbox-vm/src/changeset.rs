use crate::artifact::{ArtifactEntry, ArtifactError, ArtifactKind, decode_hex, validate_relative};
use sandbox_digest::identity_digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NONCE: AtomicU64 = AtomicU64::new(1);
const MAX_CHANGE_SET_CONTENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECOVERY_JOURNAL_BYTES: u64 = 140 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeSet {
    pub format_version: u32,
    pub base_manifest_digest: String,
    pub base: Vec<BaseEntry>,
    pub operations: Vec<ChangeOperation>,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaseEntry {
    pub path: String,
    pub kind: ArtifactKind,
    pub sha256: Option<String>,
    pub mode: u32,
    pub modified_unix_ms: i64,
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ChangeOperation {
    Upsert { entry: ArtifactEntry },
    Delete { path: String },
    Rename { from: String, to: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApplyReport {
    pub applied: usize,
    pub recovered: bool,
    pub journal_path: PathBuf,
}

#[derive(Debug)]
pub enum ApplyError {
    Io(io::Error),
    Invalid(String),
    Conflict(String),
    Artifact(ArtifactError),
}

pub fn create_change_set(
    base_files: &[ArtifactEntry],
    current_files: &[ArtifactEntry],
) -> Result<ChangeSet, ApplyError> {
    let base = indexed_entries(base_files, false)?;
    let current = indexed_entries(current_files, true)?;
    let base_entries = base
        .values()
        .map(|entry| base_entry(entry))
        .collect::<Vec<_>>();
    let base_manifest_digest =
        identity_digest(&base_entries).map_err(|error| ApplyError::Invalid(error.to_string()))?;

    let mut removed = base
        .keys()
        .filter(|path| !current.contains_key(*path))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut added = current
        .keys()
        .filter(|path| !base.contains_key(*path))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut renames = Vec::new();

    let removed_candidates = removed.iter().cloned().collect::<Vec<_>>();
    for from in removed_candidates {
        let source = &base[&from];
        if source.kind == ArtifactKind::Directory {
            continue;
        }
        let Some(to) = added
            .iter()
            .find(|to| same_entry(source, current[*to]))
            .cloned()
        else {
            continue;
        };
        removed.remove(&from);
        added.remove(&to);
        renames.push(ChangeOperation::Rename { from, to });
    }

    // Construct destination parents before moving or writing children. A directory is emitted
    // once here for construction and once at the end so its final metadata is not changed by
    // later child creation.
    let mut constructed_directories = current
        .iter()
        .filter(|(path, entry)| {
            entry.kind == ArtifactKind::Directory
                && base
                    .get(*path)
                    .is_none_or(|previous| previous.kind != ArtifactKind::Directory)
        })
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    constructed_directories.sort_by(|left, right| {
        Path::new(left)
            .components()
            .count()
            .cmp(&Path::new(right).components().count())
            .then_with(|| left.cmp(right))
    });
    let mut operations = Vec::new();
    for path in &constructed_directories {
        operations.push(ChangeOperation::Upsert {
            entry: current[path].clone(),
        });
        added.remove(path);
    }

    operations.extend(renames);

    // Empty directories only after any renamed children have left them, and always remove
    // descendants before their parents.
    let mut removed = removed.into_iter().collect::<Vec<_>>();
    removed.sort_by(|left, right| {
        Path::new(right)
            .components()
            .count()
            .cmp(&Path::new(left).components().count())
            .then_with(|| left.cmp(right))
    });
    operations.extend(
        removed
            .into_iter()
            .map(|path| ChangeOperation::Delete { path }),
    );

    // Content-bearing entries are installed after obsolete descendants have been removed. This
    // permits a directory to be replaced by a regular file or symbolic link atomically.
    for path in added
        .iter()
        .filter(|path| current[*path].kind != ArtifactKind::Directory)
    {
        operations.push(ChangeOperation::Upsert {
            entry: current[path].clone(),
        });
    }
    for (path, entry) in &current {
        if entry.kind != ArtifactKind::Directory
            && base
                .get(path)
                .is_some_and(|previous| !same_entry(previous, entry))
        {
            operations.push(ChangeOperation::Upsert {
                entry: (*entry).clone(),
            });
        }
    }

    // Apply directory metadata last because creating or moving children changes it.
    let mut changed_directories = current
        .iter()
        .filter(|(path, entry)| {
            entry.kind == ArtifactKind::Directory
                && base
                    .get(*path)
                    .is_none_or(|previous| !same_entry(previous, entry))
        })
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    changed_directories.sort_by(|left, right| {
        Path::new(right)
            .components()
            .count()
            .cmp(&Path::new(left).components().count())
            .then_with(|| left.cmp(right))
    });
    for path in changed_directories {
        operations.push(ChangeOperation::Upsert {
            entry: current[&path].clone(),
        });
    }
    let mut change_set = ChangeSet {
        format_version: 1,
        base_manifest_digest,
        base: base_entries,
        operations,
        digest: String::new(),
    };
    change_set.digest =
        identity_digest(&change_set).map_err(|error| ApplyError::Invalid(error.to_string()))?;
    Ok(change_set)
}

fn indexed_entries(
    files: &[ArtifactEntry],
    require_content: bool,
) -> Result<BTreeMap<String, &ArtifactEntry>, ApplyError> {
    let mut indexed = BTreeMap::new();
    for entry in files {
        validate_relative(&entry.path)?;
        validate_snapshot_entry(entry, require_content)?;
        if indexed.insert(entry.path.clone(), entry).is_some() {
            return Err(ApplyError::Invalid(format!(
                "duplicate change-set path: {}",
                entry.path
            )));
        }
    }
    for (path, entry) in &indexed {
        let mut parent = Path::new(path).parent();
        while let Some(value) = parent.filter(|value| !value.as_os_str().is_empty()) {
            let text = value
                .to_str()
                .ok_or_else(|| ApplyError::Invalid("change-set path is not UTF-8".into()))?;
            if indexed
                .get(text)
                .is_none_or(|parent_entry| parent_entry.kind != ArtifactKind::Directory)
            {
                return Err(ApplyError::Invalid(format!(
                    "change-set parent is absent or not a directory: {text} (child {path}, kind {:?})",
                    entry.kind
                )));
            }
            parent = value.parent();
        }
    }
    Ok(indexed)
}

fn base_entry(entry: &ArtifactEntry) -> BaseEntry {
    BaseEntry {
        path: entry.path.clone(),
        kind: entry.kind,
        sha256: entry.sha256.clone(),
        mode: entry.mode,
        modified_unix_ms: entry.modified_unix_ms,
        link_target: entry.link_target.clone(),
    }
}

fn same_entry(left: &ArtifactEntry, right: &ArtifactEntry) -> bool {
    left.kind == right.kind
        && left.mode == right.mode
        && left.modified_unix_ms == right.modified_unix_ms
        && left.sha256 == right.sha256
        && left.link_target == right.link_target
}

impl Display for ApplyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "change-set I/O error: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid change set: {message}"),
            Self::Conflict(path) => write!(formatter, "host conflict at {path}"),
            Self::Artifact(error) => Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<io::Error> for ApplyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ArtifactError> for ApplyError {
    fn from(error: ArtifactError) -> Self {
        Self::Artifact(error)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryJournal {
    format_version: u32,
    root: PathBuf,
    root_device: u64,
    root_inode: u64,
    change_set_digest: String,
    completed_operations: usize,
    original: Vec<OriginalEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OriginalEntry {
    path: String,
    entry: Option<ArtifactEntry>,
}

struct ApplyRoot {
    #[cfg(not(target_os = "linux"))]
    path: PathBuf,
    #[cfg(target_os = "linux")]
    descriptor: File,
    device: u64,
    inode: u64,
}

impl ApplyRoot {
    fn open(path: &Path) -> Result<Self, ApplyError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

            let descriptor = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)?;
            let metadata = descriptor.metadata()?;
            if !metadata.is_dir() {
                return Err(ApplyError::Invalid(
                    "change-set root must be a directory".into(),
                ));
            }
            Ok(Self {
                descriptor,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if !path.is_dir() {
                return Err(ApplyError::Invalid(
                    "change-set root must be a directory".into(),
                ));
            }
            Ok(Self {
                path: path.to_path_buf(),
                device: 0,
                inode: 0,
            })
        }
    }

    fn verify_identity(&self) -> Result<(), ApplyError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;

            let metadata = self.descriptor.metadata()?;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(ApplyError::Conflict("workspace-root".into()));
            }
        }
        Ok(())
    }
}

pub fn apply_change_set(
    root: &Path,
    recovery_directory: &Path,
    change_set: &ChangeSet,
) -> Result<ApplyReport, ApplyError> {
    validate_change_set(change_set)?;
    let canonical_root = fs::canonicalize(root)?;
    if !recovery_directory.is_absolute() {
        return Err(ApplyError::Invalid(
            "recovery directory must be absolute".into(),
        ));
    }
    fs::create_dir_all(recovery_directory)?;
    let canonical_recovery = fs::canonicalize(recovery_directory)?;
    if canonical_recovery.starts_with(&canonical_root)
        || canonical_root.starts_with(&canonical_recovery)
    {
        return Err(ApplyError::Invalid(
            "recovery directory and workspace root must be disjoint".into(),
        ));
    }
    let root = ApplyRoot::open(&canonical_root)?;
    check_conflicts(&root, &change_set.base, &change_set.base_manifest_digest)?;
    let affected = affected_paths(&change_set.operations);
    let mut original = Vec::with_capacity(affected.len());
    let mut recovery_bytes = 0_u64;
    for path in &affected {
        let snapshot = snapshot_path(&root, path)?;
        if let Some(entry) = &snapshot.entry
            && let Some(content) = &entry.content_hex
        {
            recovery_bytes = recovery_bytes
                .checked_add((content.len() / 2) as u64)
                .ok_or_else(|| ApplyError::Invalid("recovery snapshot size overflow".into()))?;
            if recovery_bytes > MAX_CHANGE_SET_CONTENT_BYTES {
                return Err(ApplyError::Invalid(
                    "recovery snapshot exceeds the aggregate 64 MiB limit".into(),
                ));
            }
        }
        original.push(snapshot);
    }
    let journal_path = canonical_recovery.join(format!(
        "apply-{}-{}.json",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut journal = RecoveryJournal {
        format_version: 1,
        root: canonical_root.clone(),
        root_device: root.device,
        root_inode: root.inode,
        change_set_digest: change_set.digest.clone(),
        completed_operations: 0,
        original,
    };
    persist_journal(&journal_path, &journal)?;
    for operation in &change_set.operations {
        if let Err(error) = apply_operation(&root, operation) {
            return match restore_original(&root, &journal.original) {
                Ok(()) => {
                    let _ = fs::remove_file(&journal_path);
                    Err(error)
                }
                Err(rollback) => Err(ApplyError::Invalid(format!(
                    "apply failed ({error}); rollback failed ({rollback}); recovery journal remains at {}",
                    journal_path.display()
                ))),
            };
        }
        journal.completed_operations += 1;
        persist_journal(&journal_path, &journal)?;
    }
    root.verify_identity()?;
    fs::remove_file(&journal_path)?;
    Ok(ApplyReport {
        applied: change_set.operations.len(),
        recovered: false,
        journal_path,
    })
}

pub fn recover_interrupted_apply(journal_path: &Path) -> Result<ApplyReport, ApplyError> {
    let bytes = read_recovery_journal(journal_path)?;
    let journal: RecoveryJournal =
        serde_json::from_slice(&bytes).map_err(|error| ApplyError::Invalid(error.to_string()))?;
    if journal.format_version != 1 || !journal.root.is_absolute() {
        return Err(ApplyError::Invalid("invalid recovery journal".into()));
    }
    validate_recovery_journal(&journal)?;
    let root = ApplyRoot::open(&journal.root)?;
    if root.device != journal.root_device || root.inode != journal.root_inode {
        return Err(ApplyError::Conflict("workspace-root".into()));
    }
    restore_original(&root, &journal.original)?;
    fs::remove_file(journal_path)?;
    Ok(ApplyReport {
        applied: journal.completed_operations,
        recovered: true,
        journal_path: journal_path.to_path_buf(),
    })
}

fn validate_recovery_journal(journal: &RecoveryJournal) -> Result<(), ApplyError> {
    if journal.original.len() > 65_536
        || journal.completed_operations > 65_536
        || journal.change_set_digest.len() != 64
        || !journal
            .change_set_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ApplyError::Invalid(
            "recovery journal metadata is invalid".into(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut content_bytes = 0_u64;
    for original in &journal.original {
        validate_relative(&original.path)?;
        if !paths.insert(&original.path) {
            return Err(ApplyError::Invalid(
                "recovery journal paths are not unique".into(),
            ));
        }
        let Some(entry) = &original.entry else {
            continue;
        };
        if entry.path != original.path {
            return Err(ApplyError::Invalid(
                "recovery journal entry path mismatch".into(),
            ));
        }
        validate_artifact_entry(entry)?;
        match entry.kind {
            ArtifactKind::RegularFile
                if entry.content_hex.is_some()
                    && entry.sha256.is_some()
                    && entry.link_target.is_none() =>
            {
                content_bytes = content_bytes
                    .checked_add(
                        (entry.content_hex.as_deref().unwrap_or_default().len() / 2) as u64,
                    )
                    .ok_or_else(|| ApplyError::Invalid("recovery content overflow".into()))?;
            }
            ArtifactKind::Directory
                if entry.content_hex.is_none()
                    && entry.sha256.is_none()
                    && entry.link_target.is_none() => {}
            ArtifactKind::SymbolicLink
                if entry.content_hex.is_none()
                    && entry.sha256.is_none()
                    && entry.link_target.is_some() => {}
            _ => {
                return Err(ApplyError::Invalid(
                    "recovery journal entry shape is invalid".into(),
                ));
            }
        }
        if content_bytes > MAX_CHANGE_SET_CONTENT_BYTES {
            return Err(ApplyError::Invalid(
                "recovery journal content exceeds its aggregate limit".into(),
            ));
        }
    }
    Ok(())
}

/// Validates the complete, content-bound wire representation without touching the host.
pub fn validate_change_set(change_set: &ChangeSet) -> Result<(), ApplyError> {
    if change_set.format_version != 1 || change_set.operations.len() > 65_536 {
        return Err(ApplyError::Invalid(
            "unsupported version or operation count".into(),
        ));
    }
    for base in &change_set.base {
        validate_relative(&base.path)?;
        validate_base_entry(base)?;
    }
    let mut content_bytes = 0_u64;
    for operation in &change_set.operations {
        match operation {
            ChangeOperation::Upsert { entry } => {
                validate_relative(&entry.path)?;
                validate_artifact_entry(entry)?;
                if let Some(content) = &entry.content_hex {
                    content_bytes = content_bytes
                        .checked_add((content.len() / 2) as u64)
                        .ok_or_else(|| {
                            ApplyError::Invalid("change-set content size overflow".into())
                        })?;
                    if content_bytes > MAX_CHANGE_SET_CONTENT_BYTES {
                        return Err(ApplyError::Invalid(
                            "change-set content exceeds the aggregate 64 MiB limit".into(),
                        ));
                    }
                }
            }
            ChangeOperation::Delete { path } => validate_relative(path)?,
            ChangeOperation::Rename { from, to } => {
                validate_relative(from)?;
                validate_relative(to)?;
            }
        }
    }
    let actual_base = identity_digest(&change_set.base)
        .map_err(|error| ApplyError::Invalid(error.to_string()))?;
    if actual_base != change_set.base_manifest_digest {
        return Err(ApplyError::Invalid("base manifest digest mismatch".into()));
    }
    let mut unsigned = change_set.clone();
    unsigned.digest.clear();
    let actual =
        identity_digest(&unsigned).map_err(|error| ApplyError::Invalid(error.to_string()))?;
    if actual != change_set.digest {
        return Err(ApplyError::Invalid("change-set digest mismatch".into()));
    }
    validate_operation_sequence(change_set)?;
    Ok(())
}

fn validate_operation_sequence(change_set: &ChangeSet) -> Result<(), ApplyError> {
    let mut state = BTreeMap::<String, ArtifactKind>::new();
    let mut previous = None::<&str>;
    for entry in &change_set.base {
        if previous.is_some_and(|value| value >= entry.path.as_str())
            || state.insert(entry.path.clone(), entry.kind).is_some()
        {
            return Err(ApplyError::Invalid(
                "base manifest paths must be unique and sorted".into(),
            ));
        }
        require_directory_parent(&state, &entry.path)?;
        previous = Some(&entry.path);
    }
    for operation in &change_set.operations {
        match operation {
            ChangeOperation::Upsert { entry } => {
                require_directory_parent(&state, &entry.path)?;
                if state.get(&entry.path) == Some(&ArtifactKind::Directory)
                    && entry.kind != ArtifactKind::Directory
                    && has_descendant(&state, &entry.path)
                {
                    return Err(ApplyError::Invalid(format!(
                        "directory replacement still has children: {}",
                        entry.path
                    )));
                }
                state.insert(entry.path.clone(), entry.kind);
            }
            ChangeOperation::Delete { path } => {
                let Some(kind) = state.get(path).copied() else {
                    return Err(ApplyError::Invalid(format!(
                        "delete source does not exist in operation state: {path}"
                    )));
                };
                if kind == ArtifactKind::Directory && has_descendant(&state, path) {
                    return Err(ApplyError::Invalid(format!(
                        "directory delete still has children: {path}"
                    )));
                }
                state.remove(path);
            }
            ChangeOperation::Rename { from, to } => {
                let Some(kind) = state.get(from).copied() else {
                    return Err(ApplyError::Invalid(format!(
                        "rename source does not exist in operation state: {from}"
                    )));
                };
                if kind == ArtifactKind::Directory {
                    return Err(ApplyError::Invalid(
                        "directory renames are not supported by recovery format 1".into(),
                    ));
                }
                if state.contains_key(to) {
                    return Err(ApplyError::Invalid(format!(
                        "rename destination already exists in operation state: {to}"
                    )));
                }
                require_directory_parent(&state, to)?;
                state.remove(from);
                state.insert(to.clone(), kind);
            }
        }
    }
    Ok(())
}

fn require_directory_parent(
    state: &BTreeMap<String, ArtifactKind>,
    path: &str,
) -> Result<(), ApplyError> {
    let parent = Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        let parent = parent
            .to_str()
            .ok_or_else(|| ApplyError::Invalid("change-set parent is not UTF-8".into()))?;
        if state.get(parent) != Some(&ArtifactKind::Directory) {
            return Err(ApplyError::Invalid(format!(
                "change-set parent is absent or not a directory: {parent}"
            )));
        }
    }
    Ok(())
}

fn has_descendant(state: &BTreeMap<String, ArtifactKind>, path: &str) -> bool {
    let prefix = format!("{path}/");
    state
        .range(prefix.clone()..)
        .next()
        .is_some_and(|(candidate, _)| candidate.starts_with(&prefix))
}

fn check_conflicts(
    root: &ApplyRoot,
    base: &[BaseEntry],
    expected_digest: &str,
) -> Result<(), ApplyError> {
    let current = snapshot_base_manifest(root)?;
    let actual =
        identity_digest(&current).map_err(|error| ApplyError::Invalid(error.to_string()))?;
    if actual != expected_digest || current != base {
        return Err(ApplyError::Conflict(".".into()));
    }
    Ok(())
}

fn snapshot_base_manifest(root: &ApplyRoot) -> Result<Vec<BaseEntry>, ApplyError> {
    #[cfg(target_os = "linux")]
    let mut entries =
        crate::artifact::collect_open_directory(&root.descriptor, MAX_CHANGE_SET_CONTENT_BYTES)?
            .files
            .into_iter()
            .map(|entry| base_entry(&entry))
            .collect::<Vec<_>>();
    #[cfg(not(target_os = "linux"))]
    let mut entries = {
        let parent = root
            .path
            .parent()
            .ok_or_else(|| ApplyError::Invalid("filesystem root is not a workspace".into()))?;
        let name = root
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ApplyError::Invalid("workspace name is not UTF-8".into()))?;
        let bundle = crate::artifact::collect_artifacts(
            parent,
            &[name.to_owned()],
            MAX_CHANGE_SET_CONTENT_BYTES,
        )?;
        let prefix = format!("{name}/");
        bundle
            .files
            .into_iter()
            .filter_map(|mut entry| {
                let path = entry.path.strip_prefix(&prefix)?.to_owned();
                entry.path = path;
                Some(base_entry(&entry))
            })
            .collect::<Vec<_>>()
    };
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn validate_base_entry(entry: &BaseEntry) -> Result<(), ApplyError> {
    if entry.mode > 0o7777 {
        return Err(ApplyError::Invalid("base entry mode is invalid".into()));
    }
    match entry.kind {
        ArtifactKind::RegularFile => {
            validate_sha256(entry.sha256.as_deref())?;
            if entry.link_target.is_some() {
                return Err(ApplyError::Invalid(
                    "regular base entry has a link target".into(),
                ));
            }
        }
        ArtifactKind::SymbolicLink => {
            if entry.sha256.is_some()
                || entry
                    .link_target
                    .as_deref()
                    .is_none_or(|target| target.contains('\0'))
            {
                return Err(ApplyError::Invalid(
                    "symbolic-link base entry is invalid".into(),
                ));
            }
        }
        ArtifactKind::Directory => {
            if entry.sha256.is_some() || entry.link_target.is_some() {
                return Err(ApplyError::Invalid(
                    "directory base entry is invalid".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_artifact_entry(entry: &ArtifactEntry) -> Result<(), ApplyError> {
    validate_snapshot_entry(entry, true)
}

fn validate_snapshot_entry(entry: &ArtifactEntry, require_content: bool) -> Result<(), ApplyError> {
    if entry.mode > 0o7777 {
        return Err(ApplyError::Invalid("artifact mode is invalid".into()));
    }
    match entry.kind {
        ArtifactKind::RegularFile => {
            let expected = validate_sha256(entry.sha256.as_deref())?;
            if require_content && entry.content_hex.is_none() {
                return Err(ApplyError::Invalid(
                    "regular file content is missing".into(),
                ));
            }
            if let Some(content) = entry.content_hex.as_deref()
                && format!("{:x}", Sha256::digest(decode_hex(content)?)) != expected
            {
                return Err(ApplyError::Invalid(
                    "regular file content digest is invalid".into(),
                ));
            }
            if entry.link_target.is_some() {
                return Err(ApplyError::Invalid(
                    "regular file content digest is invalid".into(),
                ));
            }
        }
        ArtifactKind::SymbolicLink => {
            if entry.content_hex.is_some()
                || entry.sha256.is_some()
                || entry
                    .link_target
                    .as_deref()
                    .is_none_or(|target| target.contains('\0'))
            {
                return Err(ApplyError::Invalid(
                    "symbolic-link artifact entry is invalid".into(),
                ));
            }
        }
        ArtifactKind::Directory => {
            if entry.content_hex.is_some() || entry.sha256.is_some() || entry.link_target.is_some()
            {
                return Err(ApplyError::Invalid(
                    "directory artifact entry is invalid".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_sha256(value: Option<&str>) -> Result<&str, ApplyError> {
    value
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| ApplyError::Invalid("SHA-256 digest is invalid".into()))
}

fn affected_paths(operations: &[ChangeOperation]) -> Vec<String> {
    let mut paths = operations
        .iter()
        .flat_map(|operation| match operation {
            ChangeOperation::Upsert { entry } => vec![entry.path.clone()],
            ChangeOperation::Delete { path } => vec![path.clone()],
            ChangeOperation::Rename { from, to } => vec![from.clone(), to.clone()],
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString, OsString};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "linux")]
const CHANGESET_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[cfg(target_os = "linux")]
const CHANGESET_RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[cfg(target_os = "linux")]
const CHANGESET_RESOLVE_BENEATH: u64 = 0x08;
#[cfg(target_os = "linux")]
#[repr(C)]
struct ChangeSetOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
fn openat2_beneath(directory_fd: RawFd, relative: &CStr, flags: libc::c_int) -> io::Result<File> {
    let how = ChangeSetOpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: CHANGESET_RESOLVE_BENEATH
            | CHANGESET_RESOLVE_NO_SYMLINKS
            | CHANGESET_RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: directory_fd is retained, relative and how are initialized live buffers, and a
    // successful openat2 returns one fresh descriptor transferred to File below.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory_fd,
            relative.as_ptr(),
            &how,
            std::mem::size_of::<ChangeSetOpenHow>(),
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is a fresh successful openat2 result and is transferred exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor as RawFd) })
}

#[cfg(target_os = "linux")]
fn duplicate_descriptor(descriptor: RawFd) -> io::Result<File> {
    // SAFETY: F_DUPFD_CLOEXEC duplicates the retained descriptor into one newly owned result.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: duplicate is a fresh descriptor transferred exactly once.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

#[cfg(target_os = "linux")]
fn secure_parent(root: &ApplyRoot, relative: &str) -> Result<(File, CString), ApplyError> {
    validate_relative(relative)?;
    let path = Path::new(relative);
    let name = path
        .file_name()
        .ok_or_else(|| ApplyError::Invalid("change-set path has no final component".into()))?;
    let name = CString::new(name.as_bytes())
        .map_err(|_| ApplyError::Invalid("change-set path contains NUL".into()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let descriptor = if parent.as_os_str().is_empty() {
        duplicate_descriptor(root.descriptor.as_raw_fd())?
    } else {
        let parent = CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| ApplyError::Invalid("change-set parent contains NUL".into()))?;
        match openat2_beneath(
            root.descriptor.as_raw_fd(),
            &parent,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        ) {
            Ok(descriptor) => descriptor,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EXDEV)
                ) =>
            {
                return Err(ApplyError::Invalid(format!(
                    "change-set parent is not a real directory: {}",
                    path.parent().unwrap_or_else(|| Path::new("")).display()
                )));
            }
            Err(error) => return Err(error.into()),
        }
    };
    Ok((descriptor, name))
}

#[cfg(target_os = "linux")]
fn secure_object(root: &ApplyRoot, relative: &str) -> Result<Option<File>, ApplyError> {
    let (parent, name) = match secure_parent(root, relative) {
        Ok(value) => value,
        Err(ApplyError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    match openat2_beneath(
        parent.as_raw_fd(),
        &name,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    ) {
        Ok(object) => Ok(Some(object)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn same_linux_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.size() == right.size()
}

#[cfg(target_os = "linux")]
fn readable_descriptor(object: &File) -> io::Result<File> {
    File::open(format!("/proc/self/fd/{}", object.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn read_symlink_descriptor(object: &File) -> Result<OsString, ApplyError> {
    let mut bytes = vec![0_u8; 16 * 1024];
    // SAFETY: object is a retained O_PATH symlink descriptor; the empty path selects it directly,
    // and bytes is writable for its complete advertised length.
    let count = unsafe {
        libc::readlinkat(
            object.as_raw_fd(),
            c"".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let count = usize::try_from(count)
        .map_err(|_| ApplyError::Invalid("symbolic link target is too large".into()))?;
    if count == bytes.len() {
        return Err(ApplyError::Invalid(
            "symbolic link target is too large".into(),
        ));
    }
    bytes.truncate(count);
    Ok(OsString::from_vec(bytes))
}

#[cfg(target_os = "linux")]
fn snapshot_path(root: &ApplyRoot, relative: &str) -> Result<OriginalEntry, ApplyError> {
    let Some(object) = secure_object(root, relative)? else {
        return Ok(OriginalEntry {
            path: relative.into(),
            entry: None,
        });
    };
    let metadata = object.metadata()?;
    if metadata.dev() != root.device {
        return Err(ApplyError::Invalid(format!(
            "change-set path crosses a filesystem boundary: {relative}"
        )));
    }
    let kind = file_kind(&metadata).ok_or_else(|| ApplyError::Invalid(relative.into()))?;
    let (content_hex, sha256) = if kind == ArtifactKind::RegularFile {
        if metadata.size() > MAX_CHANGE_SET_CONTENT_BYTES {
            return Err(ApplyError::Invalid(format!(
                "recovery snapshot exceeds its per-file limit: {relative}"
            )));
        }
        let mut file = readable_descriptor(&object)?;
        let opened = file.metadata()?;
        if !same_linux_identity(&metadata, &opened) {
            return Err(ApplyError::Conflict(relative.into()));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_CHANGE_SET_CONTENT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CHANGE_SET_CONTENT_BYTES
            || !same_linux_identity(&opened, &file.metadata()?)
        {
            return Err(ApplyError::Conflict(relative.into()));
        }
        (
            Some(crate::artifact::encode_hex(&bytes)),
            Some(format!("{:x}", Sha256::digest(&bytes))),
        )
    } else {
        (None, None)
    };
    let link_target = if kind == ArtifactKind::SymbolicLink {
        Some(
            read_symlink_descriptor(&object)?
                .to_str()
                .ok_or_else(|| ApplyError::Invalid(relative.into()))?
                .to_owned(),
        )
    } else {
        None
    };
    Ok(OriginalEntry {
        path: relative.into(),
        entry: Some(ArtifactEntry {
            path: relative.into(),
            kind,
            mode: metadata.mode() & 0o7777,
            modified_unix_ms: metadata.mtime().saturating_mul(1000)
                + metadata.mtime_nsec() / 1_000_000,
            content_hex,
            link_target,
            sha256,
        }),
    })
}

#[cfg(target_os = "linux")]
fn restore_original(root: &ApplyRoot, original: &[OriginalEntry]) -> Result<(), ApplyError> {
    let mut ordered = original.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|entry| std::cmp::Reverse(Path::new(&entry.path).components().count()));
    for value in &ordered {
        remove_path(root, &value.path)?;
    }
    ordered.sort_by_key(|entry| Path::new(&entry.path).components().count());
    for value in ordered {
        if let Some(entry) = &value.entry {
            write_entry(root, entry)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_operation(root: &ApplyRoot, operation: &ChangeOperation) -> Result<(), ApplyError> {
    match operation {
        ChangeOperation::Upsert { entry } => {
            if entry.kind == ArtifactKind::Directory
                && secure_object(root, &entry.path)?
                    .is_some_and(|object| object.metadata().is_ok_and(|metadata| metadata.is_dir()))
            {
                let object = secure_object(root, &entry.path)?
                    .ok_or_else(|| ApplyError::Conflict(entry.path.clone()))?;
                return apply_descriptor_metadata(&object, entry);
            }
            remove_path(root, &entry.path)?;
            write_entry(root, entry)
        }
        ChangeOperation::Delete { path } => remove_path(root, path),
        ChangeOperation::Rename { from, to } => {
            if secure_object(root, from)?.is_none() {
                return Err(ApplyError::Conflict(from.clone()));
            }
            remove_path(root, to)?;
            let (from_parent, from_name) = secure_parent(root, from)?;
            let (to_parent, to_name) = secure_parent(root, to)?;
            // SAFETY: both parents are retained beneath root and names are single NUL-terminated
            // components; renameat cannot traverse either name.
            if unsafe {
                libc::renameat(
                    from_parent.as_raw_fd(),
                    from_name.as_ptr(),
                    to_parent.as_raw_fd(),
                    to_name.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            sync_directory(&from_parent)?;
            sync_directory(&to_parent)?;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn write_entry(root: &ApplyRoot, entry: &ArtifactEntry) -> Result<(), ApplyError> {
    let (parent, name) = secure_parent(root, &entry.path)?;
    match entry.kind {
        ArtifactKind::Directory => {
            // SAFETY: parent is retained beneath root and name is one validated component.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let object = openat2_beneath(
                parent.as_raw_fd(),
                &name,
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )?;
            apply_descriptor_metadata(&object, entry)?;
        }
        ArtifactKind::RegularFile => {
            let bytes =
                decode_hex(entry.content_hex.as_deref().ok_or_else(|| {
                    ApplyError::Invalid("regular file content is missing".into())
                })?)?;
            let temporary_name = CString::new(format!(
                ".sandbox-new-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ))
            .map_err(|_| ApplyError::Invalid("temporary name contains NUL".into()))?;
            // SAFETY: parent is retained and temporary_name is one new validated component.
            let descriptor = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    temporary_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error().into());
            }
            // SAFETY: descriptor is a fresh successful openat result transferred once.
            let mut file = unsafe { File::from_raw_fd(descriptor) };
            let result = (|| -> Result<(), ApplyError> {
                file.write_all(&bytes)?;
                file.sync_all()?;
                apply_writable_metadata(&file, entry)?;
                // SAFETY: both names are single components under the same retained parent.
                if unsafe {
                    libc::renameat(
                        parent.as_raw_fd(),
                        temporary_name.as_ptr(),
                        parent.as_raw_fd(),
                        name.as_ptr(),
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                Ok(())
            })();
            if result.is_err() {
                // SAFETY: cleanup addresses only the fixed temporary component under parent.
                unsafe { libc::unlinkat(parent.as_raw_fd(), temporary_name.as_ptr(), 0) };
            }
            result?;
        }
        ArtifactKind::SymbolicLink => {
            let target = entry
                .link_target
                .as_deref()
                .ok_or_else(|| ApplyError::Invalid("symbolic link target is missing".into()))?;
            let target = CString::new(target.as_bytes())
                .map_err(|_| ApplyError::Invalid("symbolic link target contains NUL".into()))?;
            // SAFETY: target and name are live strings and parent is retained beneath root.
            if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            apply_symlink_metadata(&parent, &name, entry)?;
        }
    }
    sync_directory(&parent)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn entry_times(entry: &ArtifactEntry) -> [libc::timespec; 2] {
    let seconds = entry.modified_unix_ms.div_euclid(1000);
    let nanoseconds = entry.modified_unix_ms.rem_euclid(1000) * 1_000_000;
    [
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds as libc::c_long,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds as libc::c_long,
        },
    ]
}

#[cfg(target_os = "linux")]
fn apply_writable_metadata(file: &File, entry: &ArtifactEntry) -> Result<(), ApplyError> {
    // SAFETY: file is live and mode is bounded by prior change-set validation.
    if unsafe { libc::fchmod(file.as_raw_fd(), entry.mode & 0o7777) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let times = entry_times(entry);
    // SAFETY: file is live and times is an initialized two-element array.
    if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_descriptor_metadata(object: &File, entry: &ArtifactEntry) -> Result<(), ApplyError> {
    let file = readable_descriptor(object)?;
    apply_writable_metadata(&file, entry)
}

#[cfg(target_os = "linux")]
fn apply_symlink_metadata(
    parent: &File,
    name: &CStr,
    entry: &ArtifactEntry,
) -> Result<(), ApplyError> {
    let times = entry_times(entry);
    // SAFETY: parent is retained, name is one component, and NOFOLLOW prevents target traversal.
    if unsafe {
        libc::utimensat(
            parent.as_raw_fd(),
            name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_path(root: &ApplyRoot, relative: &str) -> Result<(), ApplyError> {
    let Some(object) = secure_object(root, relative)? else {
        return Ok(());
    };
    let expected = object.metadata()?;
    let (parent, name) = secure_parent(root, relative)?;
    let staging_name = CString::new(format!(
        ".sandbox-remove-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| ApplyError::Invalid("staging name contains NUL".into()))?;
    // SAFETY: both names are single components under the retained parent.
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            name.as_ptr(),
            parent.as_raw_fd(),
            staging_name.as_ptr(),
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Err(ApplyError::Conflict(relative.into()));
        }
        return Err(error.into());
    }
    let staged = openat2_beneath(
        parent.as_raw_fd(),
        &staging_name,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    if !same_linux_identity(&expected, &staged.metadata()?) {
        // SAFETY: best-effort restoration uses only retained parent and fixed component names.
        unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                staging_name.as_ptr(),
                parent.as_raw_fd(),
                name.as_ptr(),
            )
        };
        return Err(ApplyError::Conflict(relative.into()));
    }
    let flags = if expected.is_dir() {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    // SAFETY: staging_name is one component under retained parent; flags matches its opened type.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), staging_name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    sync_directory(&parent)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_directory(directory: &File) -> Result<(), ApplyError> {
    let readable = readable_descriptor(directory)?;
    readable.sync_all()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn snapshot_path(root: &ApplyRoot, relative: &str) -> Result<OriginalEntry, ApplyError> {
    let root = &root.path;
    if !safe_parent_exists(root, relative)? {
        return Ok(OriginalEntry {
            path: relative.into(),
            entry: None,
        });
    }
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(OriginalEntry {
                path: relative.into(),
                entry: None,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let kind = file_kind(&metadata).ok_or_else(|| ApplyError::Invalid(relative.into()))?;
    if kind == ArtifactKind::RegularFile && metadata.len() > MAX_CHANGE_SET_CONTENT_BYTES {
        return Err(ApplyError::Invalid(format!(
            "recovery snapshot exceeds its per-file limit: {relative}"
        )));
    }
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let entry = ArtifactEntry {
        path: relative.into(),
        kind,
        #[cfg(unix)]
        mode: metadata.mode() & 0o7777,
        #[cfg(not(unix))]
        mode: 0o644,
        #[cfg(unix)]
        modified_unix_ms: metadata.mtime().saturating_mul(1000) + metadata.mtime_nsec() / 1_000_000,
        #[cfg(not(unix))]
        modified_unix_ms: 0,
        content_hex: if kind == ArtifactKind::RegularFile {
            use std::io::Read as _;
            let mut bytes = Vec::new();
            fs::File::open(&path)?
                .take(MAX_CHANGE_SET_CONTENT_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_CHANGE_SET_CONTENT_BYTES {
                return Err(ApplyError::Invalid(format!(
                    "recovery snapshot exceeds its per-file limit: {relative}"
                )));
            }
            Some(crate::artifact::encode_hex(&bytes))
        } else {
            None
        },
        link_target: (kind == ArtifactKind::SymbolicLink)
            .then(|| fs::read_link(&path).map(|target| target.to_string_lossy().into_owned()))
            .transpose()?,
        sha256: None,
    };
    Ok(OriginalEntry {
        path: relative.into(),
        entry: Some(entry),
    })
}

#[cfg(not(target_os = "linux"))]
fn restore_original(root: &ApplyRoot, original: &[OriginalEntry]) -> Result<(), ApplyError> {
    let mut ordered = original.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|entry| std::cmp::Reverse(Path::new(&entry.path).components().count()));
    for value in &ordered {
        remove_path(root, &value.path)?;
    }
    ordered.sort_by_key(|entry| Path::new(&entry.path).components().count());
    for value in ordered {
        if let Some(entry) = &value.entry {
            write_entry(root, entry)?;
            if entry.kind == ArtifactKind::Directory {
                apply_entry_metadata(&root.path.join(&entry.path), entry)?;
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_operation(root: &ApplyRoot, operation: &ChangeOperation) -> Result<(), ApplyError> {
    let path = &root.path;
    match operation {
        ChangeOperation::Upsert { entry } => {
            if entry.kind == ArtifactKind::Directory
                && fs::symlink_metadata(path.join(&entry.path))
                    .is_ok_and(|metadata| metadata.is_dir())
            {
                return apply_entry_metadata(&path.join(&entry.path), entry);
            }
            remove_path(root, &entry.path)?;
            write_entry(root, entry)
        }
        ChangeOperation::Delete { path } => remove_path(root, path),
        ChangeOperation::Rename { from, to } => {
            ensure_safe_parent(root, from)?;
            ensure_safe_parent(root, to)?;
            if path.join(to).exists() {
                remove_path(root, to)?;
            }
            fs::rename(path.join(from), path.join(to)).map_err(Into::into)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn write_entry(root: &ApplyRoot, entry: &ArtifactEntry) -> Result<(), ApplyError> {
    ensure_safe_parent(root, &entry.path)?;
    let path = root.path.join(&entry.path);
    match entry.kind {
        ArtifactKind::Directory => {
            fs::create_dir(&path)?;
            return Ok(());
        }
        ArtifactKind::RegularFile => {
            let bytes =
                decode_hex(entry.content_hex.as_deref().ok_or_else(|| {
                    ApplyError::Invalid("regular file content is missing".into())
                })?)?;
            let temporary = path.with_extension(format!(
                "sandbox-new-{}",
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            use std::io::Write as _;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(temporary, &path)?;
        }
        ArtifactKind::SymbolicLink => {
            let target = entry
                .link_target
                .as_deref()
                .ok_or_else(|| ApplyError::Invalid("symbolic link target is missing".into()))?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &path)?;
            #[cfg(not(unix))]
            return Err(ApplyError::Invalid(
                "symbolic links are unsupported on this host".into(),
            ));
        }
    }
    #[cfg(unix)]
    if entry.kind != ArtifactKind::SymbolicLink {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(entry.mode & 0o7777))?;
    }
    apply_entry_metadata(&path, entry)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_entry_metadata(path: &Path, entry: &ArtifactEntry) -> Result<(), ApplyError> {
    #[cfg(unix)]
    {
        if entry.kind != ArtifactKind::SymbolicLink {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(entry.mode & 0o7777))?;
        }
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ApplyError::Invalid("metadata path contains NUL".into()))?;
        let seconds = entry.modified_unix_ms.div_euclid(1000);
        let nanoseconds = entry.modified_unix_ms.rem_euclid(1000) * 1_000_000;
        let times = [
            libc::timespec {
                tv_sec: seconds,
                tv_nsec: nanoseconds as libc::c_long,
            },
            libc::timespec {
                tv_sec: seconds,
                tv_nsec: nanoseconds as libc::c_long,
            },
        ];
        // SAFETY: path and times remain live; symlink behavior is selected explicitly by kind.
        if unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path.as_ptr(),
                times.as_ptr(),
                if entry.kind == ArtifactKind::SymbolicLink {
                    libc::AT_SYMLINK_NOFOLLOW
                } else {
                    0
                },
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    #[cfg(not(unix))]
    if entry.kind != ArtifactKind::SymbolicLink {
        fs::set_permissions(
            path,
            fs::Permissions::from_readonly(entry.mode & 0o222 == 0),
        )?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn remove_path(root: &ApplyRoot, relative: &str) -> Result<(), ApplyError> {
    ensure_safe_parent(root, relative)?;
    let path = root.path.join(relative);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir(&path)?,
        Ok(_) => fs::remove_file(&path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_safe_parent(root: &ApplyRoot, relative: &str) -> Result<(), ApplyError> {
    if !safe_parent_exists(root, relative)? {
        return Err(
            io::Error::new(io::ErrorKind::NotFound, "change-set parent does not exist").into(),
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn safe_parent_exists(root: &ApplyRoot, relative: &str) -> Result<bool, ApplyError> {
    validate_relative(relative)?;
    let parent = Path::new(relative)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let mut current = root.path.clone();
    for component in parent.components() {
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ApplyError::Invalid(format!(
                "change-set parent is not a real directory: {}",
                current.display()
            )));
        }
    }
    Ok(true)
}

fn persist_journal(path: &Path, journal: &RecoveryJournal) -> Result<(), ApplyError> {
    let temporary = path.with_extension("json.new");
    let bytes =
        serde_json::to_vec(journal).map_err(|error| ApplyError::Invalid(error.to_string()))?;
    if bytes.len() as u64 > MAX_RECOVERY_JOURNAL_BYTES {
        return Err(ApplyError::Invalid(
            "recovery journal exceeds its byte limit".into(),
        ));
    }
    use std::io::Write as _;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let result = (|| -> Result<(), ApplyError> {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        fs::File::open(
            path.parent()
                .ok_or_else(|| ApplyError::Invalid("journal has no parent".into()))?,
        )?
        .sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_recovery_journal(path: &Path) -> Result<Vec<u8>, ApplyError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_RECOVERY_JOURNAL_BYTES {
        return Err(ApplyError::Invalid(
            "recovery journal is not a bounded regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // A recovery journal is trusted mutation authority. Require the same ownership and
        // privacy properties used when it is created, and reject hard-link aliases.
        // SAFETY: geteuid has no pointer arguments or preconditions.
        if before.uid() != unsafe { libc::geteuid() }
            || before.mode() & 0o077 != 0
            || before.nlink() != 1
        {
            return Err(ApplyError::Invalid(
                "recovery journal ownership or permissions are unsafe".into(),
            ));
        }
    }
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_RECOVERY_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 > MAX_RECOVERY_JOURNAL_BYTES
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(ApplyError::Conflict("recovery-journal".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
            || before.uid() != after.uid()
        {
            return Err(ApplyError::Conflict("recovery-journal".into()));
        }
    }
    Ok(bytes)
}

fn file_kind(metadata: &fs::Metadata) -> Option<ArtifactKind> {
    if metadata.is_dir() {
        Some(ArtifactKind::Directory)
    } else if metadata.is_file() {
        Some(ArtifactKind::RegularFile)
    } else if metadata.file_type().is_symlink() {
        Some(ArtifactKind::SymbolicLink)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandbox-changeset-test-{name}-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temporary directory");
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn invalid_digest_is_rejected_before_apply() {
        let change = ChangeSet {
            format_version: 1,
            base_manifest_digest: "0".repeat(64),
            base: Vec::new(),
            operations: Vec::new(),
            digest: "0".repeat(64),
        };
        assert!(validate_change_set(&change).is_err());
    }

    #[test]
    fn generated_change_set_applies_only_to_an_unchanged_base() {
        let workspace = TemporaryDirectory::new("apply");
        let recovery = TemporaryDirectory::new("recovery");
        fs::write(workspace.0.join("file"), b"old").expect("write base");
        let base = artifact_snapshot(&workspace.0);
        let mut current = base.clone();
        let file = current
            .iter_mut()
            .find(|entry| entry.path == "file")
            .expect("file entry");
        file.content_hex = Some(crate::artifact::encode_hex(b"new"));
        file.sha256 = Some(format!("{:x}", Sha256::digest(b"new")));
        file.modified_unix_ms += 1;
        let change_set = create_change_set(&base, &current).expect("create change set");
        let report = apply_change_set(&workspace.0, &recovery.0, &change_set).expect("apply");
        assert_eq!(report.applied, 1);
        assert_eq!(fs::read(workspace.0.join("file")).expect("read"), b"new");
        assert!(matches!(
            apply_change_set(&workspace.0, &recovery.0, &change_set),
            Err(ApplyError::Conflict(_))
        ));
    }

    #[test]
    fn generated_change_set_can_create_a_directory_tree() {
        let workspace = TemporaryDirectory::new("nested-apply");
        let recovery = TemporaryDirectory::new("nested-recovery");
        let base = artifact_snapshot(&workspace.0);
        let directory = ArtifactEntry {
            path: "created".into(),
            kind: ArtifactKind::Directory,
            mode: 0o750,
            modified_unix_ms: 1_700_000_000_000,
            content_hex: None,
            link_target: None,
            sha256: None,
        };
        let content = b"nested";
        let nested = ArtifactEntry {
            path: "created/file".into(),
            kind: ArtifactKind::RegularFile,
            mode: 0o640,
            modified_unix_ms: 1_700_000_000_000,
            content_hex: Some(crate::artifact::encode_hex(content)),
            link_target: None,
            sha256: Some(format!("{:x}", Sha256::digest(content))),
        };
        let change_set = create_change_set(&base, &[directory, nested]).expect("create");
        apply_change_set(&workspace.0, &recovery.0, &change_set).expect("apply");
        assert_eq!(
            fs::read(workspace.0.join("created/file")).expect("read"),
            content
        );
    }

    #[test]
    fn generated_change_set_creates_a_rename_destination_parent_first() {
        let workspace = TemporaryDirectory::new("rename-parent");
        let recovery = TemporaryDirectory::new("rename-parent-recovery");
        fs::write(workspace.0.join("source"), b"moved").expect("write source");
        let base = artifact_snapshot(&workspace.0);
        let mut moved = base
            .iter()
            .find(|entry| entry.path == "source")
            .expect("source entry")
            .clone();
        moved.path = "created/destination".into();
        let directory = ArtifactEntry {
            path: "created".into(),
            kind: ArtifactKind::Directory,
            mode: 0o750,
            modified_unix_ms: 1_700_000_000_000,
            content_hex: None,
            link_target: None,
            sha256: None,
        };
        let change_set = create_change_set(&base, &[directory, moved]).expect("create");
        assert!(matches!(
            change_set.operations.first(),
            Some(ChangeOperation::Upsert { entry }) if entry.path == "created"
        ));
        apply_change_set(&workspace.0, &recovery.0, &change_set).expect("apply");
        assert_eq!(
            fs::read(workspace.0.join("created/destination")).expect("read"),
            b"moved"
        );
        assert!(!workspace.0.join("source").exists());
    }

    #[test]
    fn generated_change_set_deletes_children_before_replacing_a_directory() {
        let workspace = TemporaryDirectory::new("directory-replacement");
        let recovery = TemporaryDirectory::new("directory-replacement-recovery");
        fs::create_dir(workspace.0.join("node")).expect("create directory");
        fs::write(workspace.0.join("node/child"), b"obsolete").expect("write child");
        let base = artifact_snapshot(&workspace.0);
        let content = b"replacement";
        let replacement = ArtifactEntry {
            path: "node".into(),
            kind: ArtifactKind::RegularFile,
            mode: 0o640,
            modified_unix_ms: 1_700_000_000_000,
            content_hex: Some(crate::artifact::encode_hex(content)),
            link_target: None,
            sha256: Some(format!("{:x}", Sha256::digest(content))),
        };
        let change_set = create_change_set(&base, &[replacement]).expect("create");
        apply_change_set(&workspace.0, &recovery.0, &change_set).expect("apply");
        assert_eq!(fs::read(workspace.0.join("node")).expect("read"), content);
    }

    #[test]
    fn interrupted_apply_is_rolled_back_from_its_journal() {
        let workspace = TemporaryDirectory::new("interrupted");
        let recovery = TemporaryDirectory::new("interrupted-recovery");
        fs::write(workspace.0.join("file"), b"old").expect("write base");
        let root = ApplyRoot::open(&workspace.0).expect("open root");
        let original = vec![snapshot_path(&root, "file").expect("snapshot")];
        let journal_path = recovery.0.join("apply-1-1.json");
        let journal = RecoveryJournal {
            format_version: 1,
            root: fs::canonicalize(&workspace.0).expect("canonical root"),
            root_device: root.device,
            root_inode: root.inode,
            change_set_digest: "0".repeat(64),
            completed_operations: 1,
            original,
        };
        persist_journal(&journal_path, &journal).expect("persist journal");
        fs::write(workspace.0.join("file"), b"partial").expect("partial apply");
        let report = recover_interrupted_apply(&journal_path).expect("recover");
        assert!(report.recovered);
        assert_eq!(fs::read(workspace.0.join("file")).expect("read"), b"old");
        assert!(!journal_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_rejects_a_journal_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let recovery = TemporaryDirectory::new("unsafe-journal");
        let journal_path = recovery.0.join("apply.json");
        fs::write(&journal_path, b"{}").expect("write journal");
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o644))
            .expect("set permissions");
        let error = recover_interrupted_apply(&journal_path).expect_err("must reject");
        assert!(matches!(error, ApplyError::Invalid(_)));
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_parent_is_rejected_before_snapshotting() {
        let workspace = TemporaryDirectory::new("symlink");
        let outside = TemporaryDirectory::new("outside");
        fs::write(outside.0.join("secret"), b"outside").expect("outside file");
        std::os::unix::fs::symlink(&outside.0, workspace.0.join("link")).expect("symlink");
        let root = ApplyRoot::open(&workspace.0).expect("open root");
        let error = snapshot_path(&root, "link/secret").expect_err("must reject");
        assert!(matches!(error, ApplyError::Invalid(_)));
        assert_eq!(
            fs::read(outside.0.join("secret")).expect("read"),
            b"outside"
        );
    }

    fn artifact_snapshot(root: &Path) -> Vec<ArtifactEntry> {
        let parent = root.parent().expect("parent");
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .expect("name");
        let prefix = format!("{name}/");
        crate::artifact::collect_artifacts(parent, &[name.into()], 1024 * 1024)
            .expect("collect")
            .files
            .into_iter()
            .filter_map(|mut entry| {
                entry.path = entry.path.strip_prefix(&prefix)?.into();
                Some(entry)
            })
            .collect()
    }
}
