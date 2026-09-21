use cap_std::ambient_authority;
use cap_std::fs::{Dir, MetadataExt, OpenOptions, OpenOptionsExt, Permissions, PermissionsExt};
use cap_std::time::SystemClock;
use sandsurf_protocol::{
    Counter, Digest, DirectoryEntry, DirectoryPage, FileExpectation, FileKind, FileMutation,
    FileRange, FileRevision, FileStat, FileTransaction, FileTransfer, GuestPath, OperationId,
    WatchEvent, WatchEventKind, WatcherId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt as StdOpenOptionsExt, PermissionsExt as StdPermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_IN_MEMORY_READ: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_PAGE_ENTRIES: usize = 4096;
const MAX_WATCHERS: usize = 1024;
const MAX_WATCH_EVENTS: usize = 4096;
const TRANSACTION_JOURNAL_VERSION: u16 = 1;
const MAX_TRANSACTION_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum FilesystemError {
    Io(io::Error),
    Invalid(&'static str),
    Conflict,
    Capacity,
    Barrier,
}

impl fmt::Display for FilesystemError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "filesystem I/O: {error}"),
            Self::Invalid(message) => write!(output, "invalid filesystem request: {message}"),
            Self::Conflict => output.write_str("filesystem revision conflict"),
            Self::Capacity => output.write_str("filesystem response exceeds its bound"),
            Self::Barrier => output.write_str("workload writer barrier is unavailable"),
        }
    }
}

impl std::error::Error for FilesystemError {}
impl From<io::Error> for FilesystemError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedRevision {
    Any,
    Absent,
    Matches(FileRevision),
}

#[derive(Debug, Clone, Copy)]
pub struct WriteOptions<'a> {
    pub maximum: u64,
    pub mode: u32,
    pub operation_id: &'a OperationId,
    pub expected: &'a ExpectedRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WatchFingerprint {
    kind: u8,
    size: u64,
    mode: u32,
    modified_nanos: i128,
}

struct Watcher {
    epoch: Counter,
    root: GuestPath,
    recursive: bool,
    sequence: Counter,
    snapshot: BTreeMap<Vec<u8>, WatchFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TransactionPhase {
    Staging,
    Prepared,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransactionJournal {
    version: u16,
    id: OperationId,
    phase: TransactionPhase,
    entries: Vec<TransactionJournalEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransactionJournalEntry {
    path: GuestPath,
    temporary: Option<String>,
    backup: String,
    original_present: bool,
}

/// A real implementation freezes or fences workload writers for the duration
/// of a multi-step conditional mutation. A mutex that only covers API calls is
/// not a sufficient implementation while workload processes can write.
pub trait WriterBarrier {
    type Guard;
    fn acquire(&self) -> Result<Self::Guard, FilesystemError>;
}

pub struct FilesystemService {
    root: Dir,
    guest_scope: String,
    transactions: Mutex<()>,
    watchers: Mutex<BTreeMap<WatcherId, Watcher>>,
}

impl FilesystemService {
    /// `root` is opened once by trusted guest bootstrap. `guest_scope` is the
    /// corresponding absolute Linux path exposed by this capability.
    pub fn open(root: &Path, guest_scope: &str) -> Result<Self, FilesystemError> {
        if !root.is_absolute() {
            return Err(FilesystemError::Invalid("service root must be absolute"));
        }
        validate_scope(guest_scope)?;
        let root = Dir::open_ambient_dir(root, ambient_authority())?;
        Ok(Self {
            root,
            guest_scope: if guest_scope == "/" {
                "/".to_owned()
            } else {
                guest_scope.trim_end_matches('/').to_owned()
            },
            transactions: Mutex::new(()),
            watchers: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn stat(&self, guest_path: &str) -> Result<FileStat, FilesystemError> {
        self.stat_path(
            &GuestPath::try_from(guest_path)
                .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?,
        )
    }

    pub fn stat_path(&self, guest_path: &GuestPath) -> Result<FileStat, FilesystemError> {
        let relative = self.relative_path(guest_path, true)?;
        Ok(file_stat(self.root.metadata(relative)?))
    }

    pub fn lstat(&self, guest_path: &str) -> Result<FileStat, FilesystemError> {
        self.lstat_path(
            &GuestPath::try_from(guest_path)
                .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?,
        )
    }

    pub fn lstat_path(&self, guest_path: &GuestPath) -> Result<FileStat, FilesystemError> {
        let relative = self.relative_path(guest_path, true)?;
        Ok(file_stat(self.root.symlink_metadata(relative)?))
    }

    pub fn list(&self, guest_path: &str) -> Result<Vec<DirectoryEntry>, FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        let mut result = Vec::new();
        let mut cursor = None;
        loop {
            let page = self.list_page(&path, cursor.as_deref(), MAX_PAGE_ENTRIES)?;
            result.extend(page.entries);
            if result.len() > MAX_DIRECTORY_ENTRIES {
                return Err(FilesystemError::Capacity);
            }
            let Some(next) = page.next else {
                return Ok(result);
            };
            cursor = Some(next);
        }
    }

    pub fn list_page(
        &self,
        guest_path: &GuestPath,
        after: Option<&[u8]>,
        maximum: usize,
    ) -> Result<DirectoryPage, FilesystemError> {
        if maximum == 0 || maximum > MAX_PAGE_ENTRIES {
            return Err(FilesystemError::Invalid(
                "directory page bound must be 1..4096",
            ));
        }
        if after.is_some_and(|value| value.is_empty() || value.len() > 255 || value.contains(&0)) {
            return Err(FilesystemError::Invalid("directory cursor is malformed"));
        }
        let relative = self.relative_path(guest_path, true)?;
        let mut values = Vec::new();
        for entry in self.root.read_dir(&relative)? {
            let entry = entry?;
            if values.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(FilesystemError::Capacity);
            }
            let name = entry.file_name().as_bytes().to_vec();
            let entry_path = relative.join(OsStr::from_bytes(&name));
            values.push(DirectoryEntry {
                name,
                stat: file_stat(self.root.symlink_metadata(entry_path)?),
            });
        }
        values.sort_by(|left, right| left.name.cmp(&right.name));
        let mut selected = values
            .into_iter()
            .filter(|entry| after.is_none_or(|cursor| entry.name.as_slice() > cursor));
        let entries: Vec<_> = selected.by_ref().take(maximum).collect();
        let next = if selected.next().is_some() {
            entries.last().map(|entry| entry.name.clone())
        } else {
            None
        };
        Ok(DirectoryPage { entries, next })
    }

    pub fn read_file(&self, guest_path: &str, maximum: u64) -> Result<Vec<u8>, FilesystemError> {
        if maximum == 0 || maximum > MAX_IN_MEMORY_READ {
            return Err(FilesystemError::Invalid("read bound must be 1..64 MiB"));
        }
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        let relative = self.relative_path(&path, false)?;
        let metadata = self.root.metadata(&relative)?;
        if !metadata.is_file() || metadata.len() > maximum {
            return Err(FilesystemError::Capacity);
        }
        let range = self.read_range(&path, 0, maximum as usize)?;
        if !range.eof || range.offset != 0 {
            return Err(FilesystemError::Capacity);
        }
        Ok(range.bytes)
    }

    pub fn read_range(
        &self,
        guest_path: &GuestPath,
        offset: u64,
        maximum: usize,
    ) -> Result<FileRange, FilesystemError> {
        if maximum == 0 || maximum as u64 > MAX_FILE_BYTES {
            return Err(FilesystemError::Invalid("read bound must be 1..64 MiB"));
        }
        let relative = self.relative_path(guest_path, false)?;
        let mut file = self.root.open(&relative)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES || offset > metadata.len() {
            return Err(FilesystemError::Capacity);
        }
        let revision = revision_at(&self.root, &relative)?.ok_or(FilesystemError::Conflict)?;
        file.seek(SeekFrom::Start(offset))?;
        let available = metadata.len() - offset;
        let length = available.min(maximum as u64) as usize;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        let after = revision_at(&self.root, &relative)?.ok_or(FilesystemError::Conflict)?;
        if after != revision {
            return Err(FilesystemError::Conflict);
        }
        Ok(FileRange {
            offset,
            bytes,
            eof: length as u64 == available,
            revision,
        })
    }

    pub fn revision(&self, guest_path: &str) -> Result<Option<FileRevision>, FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        let relative = self.relative_path(&path, false)?;
        revision_at(&self.root, &relative)
    }

    pub fn write_file<B: WriterBarrier>(
        &self,
        guest_path: &str,
        bytes: &[u8],
        mode: u32,
        operation_id: &OperationId,
        expected: &ExpectedRevision,
        barrier: &B,
    ) -> Result<FileRevision, FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        self.write_file_from(
            &path,
            &mut &bytes[..],
            WriteOptions {
                maximum: bytes.len() as u64,
                mode,
                operation_id,
                expected,
            },
            barrier,
        )
    }

    /// Stream a file into a staged sibling, then hold the workload writer
    /// barrier only while checking the precondition and installing it.
    pub fn write_file_from<B: WriterBarrier>(
        &self,
        guest_path: &GuestPath,
        reader: &mut impl Read,
        options: WriteOptions<'_>,
        barrier: &B,
    ) -> Result<FileRevision, FilesystemError> {
        if options.maximum > MAX_FILE_BYTES || options.mode & !0o7777 != 0 {
            return Err(FilesystemError::Capacity);
        }
        let relative = self.relative_path(guest_path, false)?;
        let (parent_path, name) = split_parent(&relative)?;
        let parent = self.root.open_dir(parent_path)?;
        let temporary = format!(".sandsurf-{}.tmp", options.operation_id.as_str());
        if temporary.as_bytes() == name.as_bytes() {
            return Err(FilesystemError::Invalid(
                "temporary name aliases destination",
            ));
        }
        let mut open_options = OpenOptions::new();
        open_options.write(true).create_new(true);
        let mut file = match parent.open_with(&temporary, &open_options) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(FilesystemError::Conflict);
            }
            Err(error) => return Err(error.into()),
        };
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut written = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                written = written
                    .checked_add(read as u64)
                    .filter(|value| *value <= options.maximum && *value <= MAX_FILE_BYTES)
                    .ok_or(FilesystemError::Capacity)?;
                file.write_all(&buffer[..read])?;
                hasher.update(&buffer[..read]);
            }
            file.set_permissions(Permissions::from_mode(options.mode))?;
            file.sync_all()?;
            let _transaction = self
                .transactions
                .lock()
                .map_err(|_| FilesystemError::Barrier)?;
            let _writer_barrier = barrier.acquire()?;
            check_expected(&parent, Path::new(&name), options.expected)?;
            parent.rename(&temporary, &parent, Path::new(&name))?;
            let mut sync_options = OpenOptions::new();
            sync_options.read(true);
            parent.open_with(".", &sync_options)?.sync_all()?;
            Ok(FileRevision {
                size: written,
                digest: Digest::try_from(format!("{:x}", hasher.finalize()))
                    .map_err(|_| FilesystemError::Invalid("digest encoding failed"))?,
            })
        })();
        if result.is_err() {
            let _ = parent.remove_file(&temporary);
        }
        result
    }

    pub fn begin_write_transfer(&self, transfer: &FileTransfer) -> Result<(), FilesystemError> {
        transfer
            .validate()
            .map_err(|_| FilesystemError::Invalid("transfer is malformed"))?;
        let (parent, temporary, _) = self.transfer_paths(transfer)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let file = parent.open_with(&temporary, &options).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                FilesystemError::Conflict
            } else {
                error.into()
            }
        })?;
        file.sync_all()?;
        sync_cap_directory(&parent)?;
        Ok(())
    }

    pub fn write_transfer_chunk(
        &self,
        transfer: &FileTransfer,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u64, FilesystemError> {
        transfer
            .validate()
            .map_err(|_| FilesystemError::Invalid("transfer is malformed"))?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| !bytes.is_empty() && *end <= transfer.length)
            .ok_or(FilesystemError::Capacity)?;
        let (parent, temporary, _) = self.transfer_paths(transfer)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW);
        let mut file = parent.open_with(&temporary, &options)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != offset {
            return Err(FilesystemError::Conflict);
        }
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(end)
    }

    pub fn commit_write_transfer<B: WriterBarrier>(
        &self,
        transfer: &FileTransfer,
        barrier: &B,
    ) -> Result<FileRevision, FilesystemError> {
        transfer
            .validate()
            .map_err(|_| FilesystemError::Invalid("transfer is malformed"))?;
        let (parent, temporary, destination) = self.transfer_paths(transfer)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW);
        let mut file = parent.open_with(&temporary, &options)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != transfer.length {
            return Err(FilesystemError::Conflict);
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual = Digest::try_from(format!("{:x}", hasher.finalize()))
            .map_err(|_| FilesystemError::Invalid("digest encoding failed"))?;
        if actual != transfer.digest {
            return Err(FilesystemError::Conflict);
        }
        file.set_permissions(Permissions::from_mode(transfer.mode))?;
        file.sync_all()?;
        let expected = protocol_expectation(&transfer.expected);
        let _transaction = self
            .transactions
            .lock()
            .map_err(|_| FilesystemError::Barrier)?;
        let _writer_barrier = barrier.acquire()?;
        check_expected(&parent, &destination, &expected)?;
        parent.rename(&temporary, &parent, &destination)?;
        sync_cap_directory(&parent)?;
        Ok(FileRevision {
            size: transfer.length,
            digest: actual,
        })
    }

    pub fn abort_write_transfer(&self, transfer: &FileTransfer) -> Result<(), FilesystemError> {
        transfer
            .validate()
            .map_err(|_| FilesystemError::Invalid("transfer is malformed"))?;
        let (parent, temporary, _) = self.transfer_paths(transfer)?;
        match parent.remove_file(&temporary) {
            Ok(()) => sync_cap_directory(&parent),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Install a bounded set of file replacements/removals behind one writer
    /// barrier. A control-state journal is committed before workload paths are
    /// changed, allowing cold-start recovery to roll an interrupted install
    /// back or finish cleanup after commitment.
    pub fn apply_transaction<B: WriterBarrier>(
        &self,
        transaction: &FileTransaction,
        operation_id: &OperationId,
        journal_root: &Path,
        barrier: &B,
    ) -> Result<(), FilesystemError> {
        transaction
            .validate()
            .map_err(|_| FilesystemError::Invalid("transaction is malformed"))?;
        if transaction.id != *operation_id || !journal_root.is_absolute() {
            return Err(FilesystemError::Invalid(
                "transaction identity or journal root is invalid",
            ));
        }
        ensure_journal_root(journal_root)?;
        let _transaction = self
            .transactions
            .lock()
            .map_err(|_| FilesystemError::Barrier)?;
        let journal_path = transaction_journal_path(journal_root, &transaction.id);
        if journal_path.exists() {
            return Err(FilesystemError::Conflict);
        }
        let mut journal = TransactionJournal {
            version: TRANSACTION_JOURNAL_VERSION,
            id: transaction.id.clone(),
            phase: TransactionPhase::Staging,
            entries: transaction
                .mutations
                .iter()
                .enumerate()
                .map(|(index, mutation)| {
                    let path = match mutation {
                        FileMutation::Write { path, .. } | FileMutation::Remove { path, .. } => {
                            path.clone()
                        }
                    };
                    TransactionJournalEntry {
                        path,
                        temporary: matches!(mutation, FileMutation::Write { .. }).then(|| {
                            format!(
                                ".sandsurf-transaction-{}-{index}.new",
                                transaction.id.as_str()
                            )
                        }),
                        backup: format!(
                            ".sandsurf-transaction-{}-{index}.old",
                            transaction.id.as_str()
                        ),
                        original_present: false,
                    }
                })
                .collect(),
        };
        persist_transaction_journal(&journal_path, &journal)?;

        let staged = (|| {
            for (mutation, entry) in transaction.mutations.iter().zip(&journal.entries) {
                let FileMutation::Write {
                    bytes, mode, path, ..
                } = mutation
                else {
                    continue;
                };
                let relative = self.relative_path(path, false)?;
                let (parent_path, _) = split_parent(&relative)?;
                let parent = self.root.open_dir(parent_path)?;
                let temporary = entry
                    .temporary
                    .as_deref()
                    .ok_or(FilesystemError::Invalid("write staging name is absent"))?;
                ensure_cap_absent(&parent, temporary)?;
                ensure_cap_absent(&parent, &entry.backup)?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true).mode(*mode);
                let mut file = parent.open_with(temporary, &options)?;
                file.write_all(bytes)?;
                file.set_permissions(Permissions::from_mode(*mode))?;
                file.sync_all()?;
                sync_cap_directory(&parent)?;
            }
            Ok::<(), FilesystemError>(())
        })();
        if let Err(error) = staged {
            let _ = self.cleanup_staging(&journal);
            let _ = remove_transaction_journal(&journal_path);
            return Err(error);
        }

        let _writer_barrier = match barrier.acquire() {
            Ok(value) => value,
            Err(error) => {
                let _ = self.cleanup_staging(&journal);
                let _ = remove_transaction_journal(&journal_path);
                return Err(error);
            }
        };
        let validated = (|| {
            for ((mutation, entry), index) in transaction
                .mutations
                .iter()
                .zip(journal.entries.iter_mut())
                .zip(0_usize..)
            {
                let (path, expected) = match mutation {
                    FileMutation::Write { path, expected, .. }
                    | FileMutation::Remove { path, expected } => (path, expected),
                };
                let relative = self.relative_path(path, false)?;
                let (parent_path, destination) = split_parent(&relative)?;
                let parent = self.root.open_dir(parent_path)?;
                ensure_cap_absent(&parent, &entry.backup)?;
                entry.original_present = cap_entry_exists(&parent, Path::new(&destination))?;
                check_expected(
                    &parent,
                    Path::new(&destination),
                    &protocol_expectation(expected),
                )?;
                if matches!(mutation, FileMutation::Remove { .. }) && !entry.original_present {
                    return Err(FilesystemError::Conflict);
                }
                if let Some(temporary) = &entry.temporary
                    && !cap_entry_exists(&parent, Path::new(temporary))?
                {
                    return Err(FilesystemError::Conflict);
                }
                if index >= 1024 {
                    return Err(FilesystemError::Capacity);
                }
            }
            Ok::<(), FilesystemError>(())
        })();
        if let Err(error) = validated {
            let _ = self.cleanup_staging(&journal);
            let _ = remove_transaction_journal(&journal_path);
            return Err(error);
        }
        journal.phase = TransactionPhase::Prepared;
        persist_transaction_journal(&journal_path, &journal)?;

        let installed = (|| {
            for entry in &journal.entries {
                let relative = self.relative_path(&entry.path, false)?;
                let (parent_path, destination) = split_parent(&relative)?;
                let parent = self.root.open_dir(parent_path)?;
                if entry.original_present {
                    parent.rename(&destination, &parent, &entry.backup)?;
                    sync_cap_directory(&parent)?;
                }
                if let Some(temporary) = &entry.temporary {
                    parent.rename(temporary, &parent, &destination)?;
                    sync_cap_directory(&parent)?;
                }
            }
            Ok::<(), FilesystemError>(())
        })();
        if let Err(error) = installed {
            if self.rollback_transaction(&journal).is_ok() {
                let _ = remove_transaction_journal(&journal_path);
                return Err(error);
            }
            return Err(FilesystemError::Barrier);
        }
        journal.phase = TransactionPhase::Committed;
        if let Err(error) = persist_transaction_journal(&journal_path, &journal) {
            if self.rollback_transaction(&journal).is_ok() {
                let _ = remove_transaction_journal(&journal_path);
                return Err(error);
            }
            return Err(FilesystemError::Barrier);
        }
        self.cleanup_committed(&journal)?;
        remove_transaction_journal(&journal_path)
    }

    pub fn recover_transactions(&self, journal_root: &Path) -> Result<(), FilesystemError> {
        if !journal_root.is_absolute() {
            return Err(FilesystemError::Invalid(
                "transaction journal root is invalid",
            ));
        }
        ensure_journal_root(journal_root)?;
        let mut entries = std::fs::read_dir(journal_root)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        if entries.len() > 2048 {
            return Err(FilesystemError::Capacity);
        }
        for entry in entries {
            let metadata = entry.file_type()?;
            let path = entry.path();
            if !metadata.is_file() || metadata.is_symlink() {
                return Err(FilesystemError::Invalid(
                    "transaction journal contains a non-file",
                ));
            }
            if path.extension().and_then(|value| value.to_str()) == Some("new") {
                std::fs::remove_file(path)?;
                continue;
            }
            let journal = read_transaction_journal(&path)?;
            let expected = transaction_journal_path(journal_root, &journal.id);
            if path != expected || journal.version != TRANSACTION_JOURNAL_VERSION {
                return Err(FilesystemError::Invalid(
                    "transaction journal identity is invalid",
                ));
            }
            match journal.phase {
                TransactionPhase::Staging => self.cleanup_staging(&journal)?,
                TransactionPhase::Prepared => self.rollback_transaction(&journal)?,
                TransactionPhase::Committed => self.cleanup_committed(&journal)?,
            }
            remove_transaction_journal(&path)?;
        }
        sync_std_directory(journal_root)
    }

    fn cleanup_staging(&self, journal: &TransactionJournal) -> Result<(), FilesystemError> {
        for entry in &journal.entries {
            let relative = self.relative_path(&entry.path, false)?;
            let (parent_path, _) = split_parent(&relative)?;
            let parent = self.root.open_dir(parent_path)?;
            if let Some(temporary) = &entry.temporary {
                remove_cap_entry_if_present(&parent, temporary)?;
            }
            remove_cap_entry_if_present(&parent, &entry.backup)?;
            sync_cap_directory(&parent)?;
        }
        Ok(())
    }

    fn rollback_transaction(&self, journal: &TransactionJournal) -> Result<(), FilesystemError> {
        for entry in journal.entries.iter().rev() {
            let relative = self.relative_path(&entry.path, false)?;
            let (parent_path, destination) = split_parent(&relative)?;
            let parent = self.root.open_dir(parent_path)?;
            let backup_present = cap_entry_exists(&parent, Path::new(&entry.backup))?;
            let installed_new = match &entry.temporary {
                Some(temporary) => !cap_entry_exists(&parent, Path::new(temporary))?,
                None => false,
            };
            if backup_present {
                remove_cap_entry_if_present(&parent, &destination)?;
                parent.rename(&entry.backup, &parent, &destination)?;
            } else if !entry.original_present && installed_new {
                remove_cap_entry_if_present(&parent, &destination)?;
            }
            if let Some(temporary) = &entry.temporary {
                remove_cap_entry_if_present(&parent, temporary)?;
            }
            sync_cap_directory(&parent)?;
        }
        Ok(())
    }

    fn cleanup_committed(&self, journal: &TransactionJournal) -> Result<(), FilesystemError> {
        for entry in &journal.entries {
            let relative = self.relative_path(&entry.path, false)?;
            let (parent_path, _) = split_parent(&relative)?;
            let parent = self.root.open_dir(parent_path)?;
            remove_cap_entry_if_present(&parent, &entry.backup)?;
            if let Some(temporary) = &entry.temporary {
                remove_cap_entry_if_present(&parent, temporary)?;
            }
            sync_cap_directory(&parent)?;
        }
        Ok(())
    }

    fn transfer_paths(
        &self,
        transfer: &FileTransfer,
    ) -> Result<(Dir, String, PathBuf), FilesystemError> {
        let relative = self.relative_path(&transfer.path, false)?;
        let (parent_path, destination) = split_parent(&relative)?;
        let parent = self.root.open_dir(parent_path)?;
        let temporary = format!(".sandsurf-transfer-{}.tmp", transfer.id.as_str());
        if temporary.as_bytes() == destination.as_bytes() {
            return Err(FilesystemError::Invalid(
                "transfer name aliases destination",
            ));
        }
        Ok((parent, temporary, PathBuf::from(destination)))
    }

    pub fn mkdir(&self, guest_path: &str, recursive: bool) -> Result<(), FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        self.mkdir_path(&path, recursive)
    }

    pub fn mkdir_path(
        &self,
        guest_path: &GuestPath,
        recursive: bool,
    ) -> Result<(), FilesystemError> {
        let relative = self.relative_path(guest_path, false)?;
        if recursive {
            self.root.create_dir_all(relative)?;
        } else {
            self.root.create_dir(relative)?;
        }
        Ok(())
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), FilesystemError> {
        let from = GuestPath::try_from(from)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        let to = GuestPath::try_from(to)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        self.rename_path(&from, &to)
    }

    pub fn rename_path(&self, from: &GuestPath, to: &GuestPath) -> Result<(), FilesystemError> {
        let from = self.relative_path(from, false)?;
        let to = self.relative_path(to, false)?;
        self.root.rename(from, &self.root, to)?;
        Ok(())
    }

    pub fn remove(&self, guest_path: &str, recursive: bool) -> Result<(), FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        self.remove_path(&path, recursive)
    }

    pub fn remove_path(
        &self,
        guest_path: &GuestPath,
        recursive: bool,
    ) -> Result<(), FilesystemError> {
        let relative = self.relative_path(guest_path, false)?;
        let metadata = self.root.symlink_metadata(&relative)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if recursive {
                self.root.remove_dir_all(relative)?;
            } else {
                self.root.remove_dir(relative)?;
            }
        } else {
            self.root.remove_file(relative)?;
        }
        Ok(())
    }

    pub fn read_link(&self, guest_path: &str) -> Result<String, FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        String::from_utf8(self.read_link_path(&path)?)
            .map_err(|_| FilesystemError::Invalid("symlink target is not UTF-8"))
    }

    pub fn read_link_path(&self, guest_path: &GuestPath) -> Result<Vec<u8>, FilesystemError> {
        let relative = self.relative_path(guest_path, false)?;
        Ok(self
            .root
            .read_link_contents(relative)?
            .into_os_string()
            .into_vec())
    }

    pub fn symlink(&self, target: &str, guest_path: &str) -> Result<(), FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        self.symlink_path(target.as_bytes(), &path)
    }

    pub fn symlink_path(
        &self,
        target: &[u8],
        guest_path: &GuestPath,
    ) -> Result<(), FilesystemError> {
        if target.is_empty() || target.len() > 4096 || target.contains(&0) {
            return Err(FilesystemError::Invalid("symlink target is malformed"));
        }
        let relative = self.relative_path(guest_path, false)?;
        self.root
            .symlink_contents(OsStr::from_bytes(target), relative)?;
        Ok(())
    }

    pub fn chmod(&self, guest_path: &GuestPath, mode: u32) -> Result<(), FilesystemError> {
        if mode & !0o7777 != 0 {
            return Err(FilesystemError::Invalid("file mode is malformed"));
        }
        let relative = self.relative_path(guest_path, false)?;
        let file = self.root.open(relative)?;
        file.set_permissions(Permissions::from_mode(mode))?;
        file.sync_all()?;
        Ok(())
    }

    pub fn watch(
        &self,
        watcher_id: WatcherId,
        epoch: Counter,
        guest_path: GuestPath,
        recursive: bool,
    ) -> Result<(), FilesystemError> {
        if epoch == Counter::ZERO {
            return Err(FilesystemError::Invalid("watcher epoch must be positive"));
        }
        let relative = self.relative_path(&guest_path, true)?;
        let snapshot = scan_watch(&self.root, &relative, &guest_path, recursive)?;
        let mut watchers = self.watchers.lock().map_err(|_| FilesystemError::Barrier)?;
        if watchers.len() >= MAX_WATCHERS {
            return Err(FilesystemError::Capacity);
        }
        if watchers.contains_key(&watcher_id) {
            return Err(FilesystemError::Conflict);
        }
        watchers.insert(
            watcher_id,
            Watcher {
                epoch,
                root: guest_path,
                recursive,
                sequence: Counter::ZERO,
                snapshot,
            },
        );
        Ok(())
    }

    pub fn poll_watcher(
        &self,
        watcher_id: &WatcherId,
        epoch: Counter,
        maximum: usize,
    ) -> Result<Vec<WatchEvent>, FilesystemError> {
        if maximum == 0 || maximum > MAX_WATCH_EVENTS {
            return Err(FilesystemError::Invalid(
                "watch event bound must be 1..4096",
            ));
        }
        let mut watchers = self.watchers.lock().map_err(|_| FilesystemError::Barrier)?;
        let watcher = watchers
            .get_mut(watcher_id)
            .ok_or(FilesystemError::Invalid("watcher does not exist"))?;
        if watcher.epoch != epoch {
            return Err(FilesystemError::Conflict);
        }
        let relative = self.relative_path(&watcher.root, true)?;
        let current = scan_watch(&self.root, &relative, &watcher.root, watcher.recursive)?;
        let keys: BTreeSet<_> = watcher
            .snapshot
            .keys()
            .chain(current.keys())
            .cloned()
            .collect();
        let mut changes = Vec::new();
        for path in keys {
            let kind = match (watcher.snapshot.get(&path), current.get(&path)) {
                (None, Some(_)) => Some(WatchEventKind::Created),
                (Some(_), None) => Some(WatchEventKind::Removed),
                (Some(before), Some(after)) if before != after => Some(WatchEventKind::Modified),
                _ => None,
            };
            if let Some(kind) = kind {
                changes.push((kind, path));
            }
        }
        watcher.snapshot = current;
        if changes.len() > maximum {
            watcher.sequence = watcher
                .sequence
                .next()
                .map_err(|_| FilesystemError::Capacity)?;
            return Ok(vec![WatchEvent {
                watcher_id: watcher_id.clone(),
                epoch,
                sequence: watcher.sequence,
                kind: WatchEventKind::Overflow,
                path: None,
            }]);
        }
        let mut events = Vec::with_capacity(changes.len());
        for (kind, path) in changes {
            watcher.sequence = watcher
                .sequence
                .next()
                .map_err(|_| FilesystemError::Capacity)?;
            events.push(WatchEvent {
                watcher_id: watcher_id.clone(),
                epoch,
                sequence: watcher.sequence,
                kind,
                path: Some(
                    GuestPath::try_from(path)
                        .map_err(|_| FilesystemError::Invalid("watched path is malformed"))?,
                ),
            });
        }
        Ok(events)
    }

    pub fn unwatch(&self, watcher_id: &WatcherId, epoch: Counter) -> Result<(), FilesystemError> {
        let mut watchers = self.watchers.lock().map_err(|_| FilesystemError::Barrier)?;
        let watcher = watchers
            .get(watcher_id)
            .ok_or(FilesystemError::Invalid("watcher does not exist"))?;
        if watcher.epoch != epoch {
            return Err(FilesystemError::Conflict);
        }
        watchers.remove(watcher_id);
        Ok(())
    }

    fn relative_path(
        &self,
        value: &GuestPath,
        allow_scope: bool,
    ) -> Result<PathBuf, FilesystemError> {
        let bytes = value.as_bytes();
        let scope = self.guest_scope.as_bytes();
        let suffix = if scope == b"/" {
            &bytes[1..]
        } else if bytes == scope {
            &[][..]
        } else if bytes.starts_with(scope) && bytes.get(scope.len()) == Some(&b'/') {
            &bytes[scope.len() + 1..]
        } else {
            return Err(FilesystemError::Invalid(
                "guest path is outside capability scope",
            ));
        };
        if suffix.is_empty() && !allow_scope {
            return Err(FilesystemError::Invalid(
                "operation cannot target scope root",
            ));
        }
        if suffix.is_empty() {
            Ok(PathBuf::from("."))
        } else {
            Ok(PathBuf::from(OsString::from_vec(suffix.to_vec())))
        }
    }
}

fn ensure_cap_absent(parent: &Dir, name: &str) -> Result<(), FilesystemError> {
    if cap_entry_exists(parent, Path::new(name))? {
        Err(FilesystemError::Conflict)
    } else {
        Ok(())
    }
}

fn cap_entry_exists(parent: &Dir, name: &Path) -> Result<bool, FilesystemError> {
    match parent.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn remove_cap_entry_if_present(
    parent: &Dir,
    name: impl AsRef<Path>,
) -> Result<(), FilesystemError> {
    let name = name.as_ref();
    let metadata = match parent.symlink_metadata(name) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        parent.remove_dir_all(name)?;
    } else {
        parent.remove_file(name)?;
    }
    Ok(())
}

fn ensure_journal_root(root: &Path) -> Result<(), FilesystemError> {
    std::fs::create_dir_all(root)?;
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FilesystemError::Invalid(
            "transaction journal root is not a directory",
        ));
    }
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn transaction_journal_path(root: &Path, id: &OperationId) -> PathBuf {
    root.join(format!("{}.json", id.as_str()))
}

fn persist_transaction_journal(
    path: &Path,
    journal: &TransactionJournal,
) -> Result<(), FilesystemError> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|_| FilesystemError::Invalid("transaction journal cannot be encoded"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_TRANSACTION_JOURNAL_BYTES {
        return Err(FilesystemError::Capacity);
    }
    let temporary = path.with_extension("json.new");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    sync_std_directory(path.parent().ok_or(FilesystemError::Invalid(
        "transaction journal has no parent",
    ))?)
}

fn read_transaction_journal(path: &Path) -> Result<TransactionJournal, FilesystemError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_TRANSACTION_JOURNAL_BYTES
    {
        return Err(FilesystemError::Invalid(
            "transaction journal is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_TRANSACTION_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let value: TransactionJournal = serde_json::from_slice(&bytes)
        .map_err(|_| FilesystemError::Invalid("transaction journal is malformed"))?;
    if value.entries.is_empty() || value.entries.len() > 1024 {
        return Err(FilesystemError::Invalid(
            "transaction journal entry count is invalid",
        ));
    }
    Ok(value)
}

fn remove_transaction_journal(path: &Path) -> Result<(), FilesystemError> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    sync_std_directory(path.parent().ok_or(FilesystemError::Invalid(
        "transaction journal has no parent",
    ))?)
}

fn sync_std_directory(path: &Path) -> Result<(), FilesystemError> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn scan_watch(
    root: &Dir,
    relative: &Path,
    guest_path: &GuestPath,
    recursive: bool,
) -> Result<BTreeMap<Vec<u8>, WatchFingerprint>, FilesystemError> {
    let mut result = BTreeMap::new();
    let mut pending = vec![(relative.to_path_buf(), guest_path.as_bytes().to_vec())];
    while let Some((directory, guest_directory)) = pending.pop() {
        for entry in root.read_dir(&directory)? {
            let entry = entry?;
            if result.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(FilesystemError::Capacity);
            }
            let name = entry.file_name().as_bytes().to_vec();
            let child = directory.join(OsStr::from_bytes(&name));
            let metadata = root.symlink_metadata(&child)?;
            let mut guest_child = guest_directory.clone();
            if guest_child != b"/" {
                guest_child.push(b'/');
            }
            guest_child.extend_from_slice(&name);
            let kind = if metadata.is_file() {
                1
            } else if metadata.is_dir() {
                2
            } else if metadata.file_type().is_symlink() {
                3
            } else {
                4
            };
            result.insert(
                guest_child.clone(),
                WatchFingerprint {
                    kind,
                    size: metadata.len(),
                    mode: metadata.mode(),
                    modified_nanos: i128::from(metadata.mtime()) * 1_000_000_000
                        + i128::from(metadata.mtime_nsec()),
                },
            );
            if recursive && metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push((child, guest_child));
            }
        }
    }
    Ok(result)
}

fn validate_scope(value: &str) -> Result<(), FilesystemError> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\0')
        || !value.starts_with('/')
        || value.split('/').any(|part| part == "..")
    {
        return Err(FilesystemError::Invalid("guest scope is malformed"));
    }
    Ok(())
}

fn split_parent(path: &Path) -> Result<(PathBuf, OsString), FilesystemError> {
    let name = path
        .file_name()
        .ok_or(FilesystemError::Invalid("path has no basename"))?
        .to_os_string();
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty());
    Ok((parent.unwrap_or_else(|| Path::new(".")).to_path_buf(), name))
}

fn sync_cap_directory(directory: &Dir) -> Result<(), FilesystemError> {
    let mut options = OpenOptions::new();
    options.read(true);
    directory.open_with(".", &options)?.sync_all()?;
    Ok(())
}

fn protocol_expectation(value: &FileExpectation) -> ExpectedRevision {
    match value {
        FileExpectation::Any => ExpectedRevision::Any,
        FileExpectation::Absent => ExpectedRevision::Absent,
        FileExpectation::Matches { size, digest } => ExpectedRevision::Matches(FileRevision {
            size: *size,
            digest: digest.clone(),
        }),
    }
}

fn revision_at(root: &Dir, relative: &Path) -> Result<Option<FileRevision>, FilesystemError> {
    let mut file = match root.open(relative) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(FilesystemError::Invalid(
            "revision target is not a bounded regular file",
        ));
    }
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(FilesystemError::Capacity)?;
        if copied > MAX_FILE_BYTES {
            return Err(FilesystemError::Capacity);
        }
        hasher.update(&buffer[..read]);
    }
    if copied != metadata.len() {
        return Err(FilesystemError::Conflict);
    }
    Ok(Some(FileRevision {
        size: metadata.len(),
        digest: Digest::try_from(format!("{:x}", hasher.finalize()))
            .map_err(|_| FilesystemError::Invalid("digest encoding failed"))?,
    }))
}

fn check_expected(
    root: &Dir,
    relative: &Path,
    expected: &ExpectedRevision,
) -> Result<(), FilesystemError> {
    let current = revision_at(root, relative)?;
    let matches = match expected {
        ExpectedRevision::Any => true,
        ExpectedRevision::Absent => current.is_none(),
        ExpectedRevision::Matches(value) => current.as_ref() == Some(value),
    };
    if matches {
        Ok(())
    } else {
        Err(FilesystemError::Conflict)
    }
}

fn file_stat(metadata: cap_std::fs::Metadata) -> FileStat {
    let kind = if metadata.is_file() {
        FileKind::Regular
    } else if metadata.is_dir() {
        FileKind::Directory
    } else if metadata.file_type().is_symlink() {
        FileKind::Symlink
    } else {
        FileKind::Other
    };
    let modified_millis = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(SystemClock::UNIX_EPOCH).ok())
        .and_then(|value| u64::try_from(value.as_millis()).ok());
    FileStat {
        kind,
        size: metadata.len(),
        readonly: metadata.permissions().readonly(),
        modified_millis,
        mode: metadata.mode() & 0o7777,
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-fs-{}-{}",
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

    struct Barrier;
    impl WriterBarrier for Barrier {
        type Guard = std::sync::MutexGuard<'static, ()>;

        fn acquire(&self) -> Result<Self::Guard, FilesystemError> {
            // The test barrier is process-global only to make its guard lifetime
            // nameable; production uses the workload cgroup writer barrier.
            static VALUE: Mutex<()> = Mutex::new(());
            VALUE.lock().map_err(|_| FilesystemError::Barrier)
        }
    }

    #[test]
    fn file_operations_are_scoped_and_conditionally_atomic() {
        let root = Temp::new();
        let service = FilesystemService::open(&root.0, "/workspace").unwrap();
        let barrier = Barrier;
        service.mkdir("/workspace/src", true).unwrap();
        let first = service
            .write_file(
                "/workspace/src/file",
                b"one",
                0o644,
                &OperationId::try_from("write-one").unwrap(),
                &ExpectedRevision::Absent,
                &barrier,
            )
            .unwrap();
        assert_eq!(
            service.read_file("/workspace/src/file", 1024).unwrap(),
            b"one"
        );
        assert!(matches!(
            service.write_file(
                "/workspace/src/file",
                b"conflict",
                0o644,
                &OperationId::try_from("write-conflict").unwrap(),
                &ExpectedRevision::Absent,
                &barrier,
            ),
            Err(FilesystemError::Conflict)
        ));
        service
            .write_file(
                "/workspace/src/file",
                b"two",
                0o644,
                &OperationId::try_from("write-two").unwrap(),
                &ExpectedRevision::Matches(first),
                &barrier,
            )
            .unwrap();
        assert_eq!(service.list("/workspace/src").unwrap()[0].name, b"file");
    }

    #[test]
    fn streamed_write_is_contiguous_digest_bound_and_atomically_published() {
        let root = Temp::new();
        let service = FilesystemService::open(&root.0, "/workspace").unwrap();
        let bytes = b"streamed-binary\0content";
        let transfer = FileTransfer {
            id: "transfer".try_into().unwrap(),
            path: GuestPath::try_from("/workspace/result").unwrap(),
            length: bytes.len() as u64,
            digest: Digest::try_from(format!("{:x}", Sha256::digest(bytes))).unwrap(),
            mode: 0o640,
            expected: FileExpectation::Absent,
        };
        service.begin_write_transfer(&transfer).unwrap();
        assert!(matches!(
            service.write_transfer_chunk(&transfer, 1, &bytes[..4]),
            Err(FilesystemError::Conflict)
        ));
        service
            .write_transfer_chunk(&transfer, 0, &bytes[..8])
            .unwrap();
        service
            .write_transfer_chunk(&transfer, 8, &bytes[8..])
            .unwrap();
        assert!(!root.0.join("result").exists());
        let revision = service.commit_write_transfer(&transfer, &Barrier).unwrap();
        assert_eq!(revision.size, bytes.len() as u64);
        assert_eq!(fs::read(root.0.join("result")).unwrap(), bytes);
    }

    #[test]
    fn traversal_and_out_of_scope_paths_are_rejected() {
        let root = Temp::new();
        let service = FilesystemService::open(&root.0, "/workspace").unwrap();
        for path in ["/other/file", "/workspace/../secret", "relative"] {
            assert!(service.lstat(path).is_err());
        }
    }

    #[test]
    fn symlink_operations_do_not_grant_an_ambient_host_path() {
        let root = Temp::new();
        let outside = Temp::new();
        fs::write(outside.0.join("secret"), b"secret").unwrap();
        let service = FilesystemService::open(&root.0, "/workspace").unwrap();
        service
            .symlink(outside.0.to_str().unwrap(), "/workspace/link")
            .unwrap();
        assert_eq!(
            service.read_link("/workspace/link").unwrap(),
            outside.0.to_str().unwrap()
        );
        assert!(service.read_file("/workspace/link/secret", 1024).is_err());
    }

    #[test]
    fn byte_paths_ranges_pagination_and_watch_overflow_are_explicit() {
        let root = Temp::new();
        let service = FilesystemService::open(&root.0, "/workspace").unwrap();
        let non_utf8 = OsString::from_vec(vec![b'n', 0xff]);
        fs::write(root.0.join(&non_utf8), b"0123456789").unwrap();
        fs::write(root.0.join("z"), b"z").unwrap();
        fs::write(root.0.join("a"), b"a").unwrap();
        let scope = GuestPath::try_from("/workspace").unwrap();
        let first = service.list_page(&scope, None, 2).unwrap();
        assert_eq!(first.entries.len(), 2);
        let second = service.list_page(&scope, first.next.as_deref(), 2).unwrap();
        assert_eq!(first.entries.len() + second.entries.len(), 3);
        assert!(
            service
                .list(scope.to_utf8().unwrap())
                .unwrap()
                .iter()
                .any(|entry| entry.name == non_utf8.as_bytes())
        );

        let byte_path = GuestPath::try_from({
            let mut value = b"/workspace/".to_vec();
            value.extend_from_slice(non_utf8.as_bytes());
            value
        })
        .unwrap();
        let range = service.read_range(&byte_path, 3, 4).unwrap();
        assert_eq!(range.bytes, b"3456");
        assert!(!range.eof);

        let watcher: WatcherId = "watch".try_into().unwrap();
        service
            .watch(watcher.clone(), Counter::ONE, scope, false)
            .unwrap();
        fs::write(root.0.join("new-one"), b"1").unwrap();
        fs::write(root.0.join("new-two"), b"2").unwrap();
        let events = service.poll_watcher(&watcher, Counter::ONE, 1).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, WatchEventKind::Overflow);
        assert_eq!(events[0].path, None);
        service.unwatch(&watcher, Counter::ONE).unwrap();
        assert!(service.poll_watcher(&watcher, Counter::ONE, 1).is_err());
    }

    #[test]
    fn multi_file_transaction_is_preconditioned_and_recovers_interruption() {
        let root = Temp::new();
        let files = root.0.join("files");
        let journals = root.0.join("journals");
        fs::create_dir(&files).unwrap();
        fs::write(files.join("one"), b"old-one").unwrap();
        fs::write(files.join("two"), b"old-two").unwrap();
        let service = FilesystemService::open(&files, "/workspace").unwrap();
        let one = service.revision("/workspace/one").unwrap().unwrap();
        let two = service.revision("/workspace/two").unwrap().unwrap();
        let operation_id = OperationId::try_from("transaction").unwrap();
        let transaction = FileTransaction {
            id: operation_id.clone(),
            mutations: vec![
                FileMutation::Write {
                    path: GuestPath::try_from("/workspace/one").unwrap(),
                    bytes: b"new-one".to_vec(),
                    mode: 0o640,
                    expected: FileExpectation::Matches {
                        size: one.size,
                        digest: one.digest,
                    },
                },
                FileMutation::Remove {
                    path: GuestPath::try_from("/workspace/two").unwrap(),
                    expected: FileExpectation::Matches {
                        size: two.size,
                        digest: two.digest,
                    },
                },
            ],
        };
        service
            .apply_transaction(&transaction, &operation_id, &journals, &Barrier)
            .unwrap();
        assert_eq!(fs::read(files.join("one")).unwrap(), b"new-one");
        assert!(!files.join("two").exists());
        assert!(fs::read_dir(&journals).unwrap().next().is_none());

        fs::write(files.join("recover"), b"original").unwrap();
        fs::rename(
            files.join("recover"),
            files.join(".sandsurf-transaction-recovery-0.old"),
        )
        .unwrap();
        fs::write(files.join("recover"), b"partial").unwrap();
        let recovery = TransactionJournal {
            version: TRANSACTION_JOURNAL_VERSION,
            id: OperationId::try_from("recovery").unwrap(),
            phase: TransactionPhase::Prepared,
            entries: vec![TransactionJournalEntry {
                path: GuestPath::try_from("/workspace/recover").unwrap(),
                temporary: Some(".sandsurf-transaction-recovery-0.new".into()),
                backup: ".sandsurf-transaction-recovery-0.old".into(),
                original_present: true,
            }],
        };
        persist_transaction_journal(
            &transaction_journal_path(&journals, &recovery.id),
            &recovery,
        )
        .unwrap();
        service.recover_transactions(&journals).unwrap();
        assert_eq!(fs::read(files.join("recover")).unwrap(), b"original");
        assert!(fs::read_dir(&journals).unwrap().next().is_none());
    }
}
