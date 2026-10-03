use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt, Permissions, PermissionsExt};
use sandsurf_protocol::{
    ControlPage, Counter, Digest, DirectoryEntry, DirectoryPage, FileExpectation, FileKind,
    FileRange, FileReadObservation, FileRevision, FileStat, FileTransfer, GuestPath, OperationId,
    WatchEvent, WatchEventKind, WatchPage, WatcherId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_IN_MEMORY_READ: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_PAGE_ENTRIES: usize = 4096;
const MAX_WATCHERS: usize = 1024;
const MAX_WATCH_EVENTS: usize = 4096;
const MAX_WATCH_RECORD_BYTES: usize = sandsurf_protocol::MAX_CONTROL_BYTES / 2;
const MAX_RETAINED_WATCH_EVENTS: usize = 512;

#[derive(Debug)]
pub enum FilesystemError {
    Io(io::Error),
    Invalid(&'static str),
    Conflict,
    Capacity,
    Unavailable,
}

impl fmt::Display for FilesystemError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "filesystem I/O: {error}"),
            Self::Invalid(message) => write!(output, "invalid filesystem request: {message}"),
            Self::Conflict => output.write_str("filesystem revision conflict"),
            Self::Capacity => output.write_str("filesystem response exceeds its bound"),
            Self::Unavailable => output.write_str("filesystem service lock is unavailable"),
        }
    }
}

impl std::error::Error for FilesystemError {}
impl From<io::Error> for FilesystemError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WriteOptions<'a> {
    pub maximum: u64,
    pub mode: u32,
    pub operation_id: &'a OperationId,
    pub expected: &'a FileExpectation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WatchFingerprint {
    kind: u8,
    size: u64,
    mode: u32,
    modified_nanos: i128,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WatchRecord {
    version: u16,
    id: WatcherId,
    generation: Counter,
    root: GuestPath,
    recursive: bool,
    sequence: Counter,
    closed: bool,
    events: Vec<WatchEvent>,
}

struct Watcher {
    record: WatchRecord,
    // A missing baseline means observation was interrupted, not that the VM
    // stopped. The first new sample durably records an explicit overflow.
    snapshot: Option<BTreeMap<Vec<u8>, WatchFingerprint>>,
}

struct WatchJournalLease(cap_std::fs::File);
impl Drop for WatchJournalLease {
    fn drop(&mut self) {
        // This owns a journal writer, not a VM attachment. Fork children never
        // write it. End logical ownership on an orderly service close even if
        // an unrelated child temporarily inherited its descriptor before exec.
        // Crash release still depends on final OS handle closure.
        // SAFETY: this is the exclusively held regular-file descriptor.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub struct FilesystemService {
    writes: Mutex<()>,
    watchers: Mutex<BTreeMap<WatcherId, Watcher>>,
    watcher_root: Dir,
    _watcher_lease: WatchJournalLease,
}

impl FilesystemService {
    /// The guest administrator's Linux filesystem, not a scoped workload capability.
    pub fn open(watcher_root: &Path) -> Result<Self, FilesystemError> {
        if !watcher_root.is_absolute() {
            return Err(FilesystemError::Invalid(
                "watch journal path must be absolute",
            ));
        }
        fs::create_dir_all(watcher_root)?;
        let directory = Dir::open_ambient_dir(watcher_root, ambient_authority())?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let lease = directory.open_with(".owner", &options)?;
        if !lease.metadata()?.is_file() {
            return Err(FilesystemError::Invalid("invalid watch journal lease"));
        }
        // SAFETY: the held descriptor is a regular file. Ownership lasts until
        // this filesystem service drops, independently of polling clients.
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mut watchers = BTreeMap::new();
        for entry in directory.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name == ".owner" {
                continue;
            }
            if name.as_bytes().starts_with(b".pending-") && name.as_bytes().len() <= 41 {
                directory.remove_file(&name)?;
                continue;
            }
            if watchers.len() >= MAX_WATCHERS {
                return Err(FilesystemError::Capacity);
            }
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            let file = directory.open_with(&name, &options)?;
            if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_WATCH_RECORD_BYTES as u64
            {
                return Err(FilesystemError::Invalid(
                    "watch journal record is not bounded",
                ));
            }
            let mut bytes = Vec::new();
            file.take(MAX_WATCH_RECORD_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_WATCH_RECORD_BYTES {
                return Err(FilesystemError::Capacity);
            }
            let record: WatchRecord = serde_json::from_slice(&bytes)
                .map_err(|_| FilesystemError::Invalid("watch journal is corrupt"))?;
            if record.version != 1
                || name.as_bytes() != record.id.as_str().as_bytes()
                || record.generation == Counter::ZERO
                || record.events.len() > MAX_RETAINED_WATCH_EVENTS
            {
                return Err(FilesystemError::Invalid(
                    "watch journal identity is invalid",
                ));
            }
            let mut sequence = Counter::ZERO;
            for event in &record.events {
                if event.watcher_id != record.id
                    || event.generation != record.generation
                    || event.sequence <= sequence
                    || event.sequence > record.sequence
                    || (event.kind == WatchEventKind::Overflow) != event.path.is_none()
                {
                    return Err(FilesystemError::Invalid(
                        "watch journal event identity is invalid",
                    ));
                }
                sequence = event.sequence;
            }
            watchers.insert(
                record.id.clone(),
                Watcher {
                    record,
                    snapshot: None,
                },
            );
        }
        Ok(Self {
            writes: Mutex::new(()),
            watchers: Mutex::new(watchers),
            watcher_root: directory,
            _watcher_lease: WatchJournalLease(lease),
        })
    }

    fn publish_watcher(&self, record: &WatchRecord) -> Result<(), FilesystemError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|_| FilesystemError::Invalid("watch record encoding failed"))?;
        if bytes.len() > MAX_WATCH_RECORD_BYTES {
            return Err(FilesystemError::Capacity);
        }
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| FilesystemError::Unavailable)?;
        let staged = format!(".pending-{:x}", u128::from_le_bytes(nonce));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let publication = (|| -> Result<(), FilesystemError> {
            let mut file = self.watcher_root.open_with(&staged, &options)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            self.watcher_root
                .rename(&staged, &self.watcher_root, record.id.as_str())?;
            sync_cap_directory(&self.watcher_root)?;
            Ok(())
        })();
        if publication.is_err() {
            let _ = self.watcher_root.remove_file(&staged);
        }
        publication
    }

    pub fn stat(&self, guest_path: &str) -> Result<FileStat, FilesystemError> {
        self.stat_path(
            &GuestPath::try_from(guest_path)
                .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?,
        )
    }

    pub fn stat_path(&self, guest_path: &GuestPath) -> Result<FileStat, FilesystemError> {
        let relative = linux_path(guest_path);
        Ok(file_stat(fs::metadata(relative)?))
    }

    pub fn lstat(&self, guest_path: &str) -> Result<FileStat, FilesystemError> {
        self.lstat_path(
            &GuestPath::try_from(guest_path)
                .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?,
        )
    }

    pub fn lstat_path(&self, guest_path: &GuestPath) -> Result<FileStat, FilesystemError> {
        let relative = linux_path(guest_path);
        Ok(file_stat(fs::symlink_metadata(relative)?))
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
        let relative = linux_path(guest_path);
        // Keep only the next bounded name window. Directory size is not a
        // management-service allocation permission; do not stat/copy the
        // whole directory merely to return one lexical page.
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(&relative)? {
            let entry = entry?;
            let name = entry.file_name().as_bytes().to_vec();
            if after.is_none_or(|cursor| name.as_slice() > cursor) {
                names.insert(name);
                if names.len() > maximum + 1 {
                    names.pop_last();
                }
            }
        }
        let mut more = names.len() > maximum;
        if more {
            names.pop_last();
        }
        let mut page = ControlPage::default();
        for name in names {
            let entry_path = relative.join(OsStr::from_bytes(&name));
            if !page
                .push(DirectoryEntry {
                    name,
                    stat: file_stat(fs::symlink_metadata(entry_path)?),
                })
                .map_err(|_| FilesystemError::Capacity)?
            {
                more = true;
                break;
            }
        }
        let entries = page.into_values();
        let next = if more {
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
        let relative = linux_path(&path);
        let metadata = fs::metadata(&relative)?;
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
        if maximum == 0 || maximum as u64 > MAX_IN_MEMORY_READ {
            return Err(FilesystemError::Invalid("read bound must be 1..64 MiB"));
        }
        let relative = linux_path(guest_path);
        let mut file = File::open(&relative)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES || offset > metadata.len() {
            return Err(FilesystemError::Capacity);
        }
        let observation = read_observation(&metadata)?;
        file.seek(SeekFrom::Start(offset))?;
        let available = metadata.len() - offset;
        let length = available.min(maximum as u64) as usize;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        if read_observation(&file.metadata()?)? != observation
            || read_observation(&fs::metadata(&relative)?)? != observation
        {
            return Err(FilesystemError::Conflict);
        }
        Ok(FileRange {
            offset,
            bytes,
            eof: length as u64 == available,
            observation,
        })
    }

    pub fn revision(&self, guest_path: &str) -> Result<Option<FileRevision>, FilesystemError> {
        let path = GuestPath::try_from(guest_path)
            .map_err(|_| FilesystemError::Invalid("guest path is malformed"))?;
        let relative = linux_path(&path);
        revision_at(&relative)
    }

    pub fn write_file(
        &self,
        guest_path: &str,
        bytes: &[u8],
        mode: u32,
        operation_id: &OperationId,
        expected: &FileExpectation,
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
        )
    }

    /// Publish a staged sibling atomically. Absent uses kernel no-replace,
    /// including when arbitrary Linux processes are writing concurrently.
    pub fn write_file_from(
        &self,
        guest_path: &GuestPath,
        reader: &mut impl Read,
        options: WriteOptions<'_>,
    ) -> Result<FileRevision, FilesystemError> {
        if options.maximum > MAX_FILE_BYTES || options.mode & !0o7777 != 0 {
            return Err(FilesystemError::Capacity);
        }
        let relative = linux_path(guest_path);
        let (parent_path, name) = split_parent(&relative)?;
        let parent = Dir::open_ambient_dir(parent_path, ambient_authority())?;
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
            let _write = self
                .writes
                .lock()
                .map_err(|_| FilesystemError::Unavailable)?;
            publish_file(
                &parent,
                Path::new(&temporary),
                Path::new(&name),
                options.expected,
            )?;
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

    pub fn commit_write_transfer(
        &self,
        transfer: &FileTransfer,
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
        let _write = self
            .writes
            .lock()
            .map_err(|_| FilesystemError::Unavailable)?;
        publish_file(
            &parent,
            Path::new(&temporary),
            &destination,
            &transfer.expected,
        )?;
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

    fn transfer_paths(
        &self,
        transfer: &FileTransfer,
    ) -> Result<(Dir, String, PathBuf), FilesystemError> {
        let relative = linux_path(&transfer.path);
        let (parent_path, destination) = split_parent(&relative)?;
        let parent = Dir::open_ambient_dir(parent_path, ambient_authority())?;
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
        let relative = linux_path(guest_path);
        if recursive {
            fs::create_dir_all(relative)?;
        } else {
            fs::create_dir(relative)?;
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
        let from = linux_path(from);
        let to = linux_path(to);
        fs::rename(from, to)?;
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
        let relative = linux_path(guest_path);
        let metadata = fs::symlink_metadata(&relative)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if recursive {
                fs::remove_dir_all(relative)?;
            } else {
                fs::remove_dir(relative)?;
            }
        } else {
            fs::remove_file(relative)?;
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
        let relative = linux_path(guest_path);
        Ok(fs::read_link(relative)?.into_os_string().into_vec())
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
        let relative = linux_path(guest_path);
        std::os::unix::fs::symlink(OsStr::from_bytes(target), relative)?;
        Ok(())
    }

    pub fn chmod(&self, guest_path: &GuestPath, mode: u32) -> Result<(), FilesystemError> {
        if mode & !0o7777 != 0 {
            return Err(FilesystemError::Invalid("file mode is malformed"));
        }
        let relative = linux_path(guest_path);
        let file = File::open(relative)?;
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))?;
        file.sync_all()?;
        Ok(())
    }

    pub fn watch(
        &self,
        watcher_id: WatcherId,
        generation: Counter,
        guest_path: GuestPath,
        recursive: bool,
    ) -> Result<(), FilesystemError> {
        if generation == Counter::ZERO {
            return Err(FilesystemError::Invalid(
                "watcher generation must be positive",
            ));
        }
        let mut watchers = self
            .watchers
            .lock()
            .map_err(|_| FilesystemError::Unavailable)?;
        if let Some(watcher) = watchers.get(&watcher_id) {
            return if !watcher.record.closed
                && watcher.record.generation == generation
                && watcher.record.root == guest_path
                && watcher.record.recursive == recursive
            {
                Ok(())
            } else {
                Err(FilesystemError::Conflict)
            };
        }
        if watchers.len() >= MAX_WATCHERS {
            return Err(FilesystemError::Capacity);
        }
        let available = MAX_DIRECTORY_ENTRIES.saturating_sub(
            watchers
                .values()
                .map(|watcher| watcher.snapshot.as_ref().map_or(0, BTreeMap::len))
                .sum::<usize>(),
        );
        let snapshot = scan_watch(&linux_path(&guest_path), &guest_path, recursive, available)?;
        let record = WatchRecord {
            version: 1,
            id: watcher_id.clone(),
            generation,
            root: guest_path,
            recursive,
            sequence: Counter::ZERO,
            closed: false,
            events: Vec::new(),
        };
        self.publish_watcher(&record)?;
        watchers.insert(
            watcher_id,
            Watcher {
                record,
                snapshot: Some(snapshot),
            },
        );
        Ok(())
    }

    pub fn poll_watcher(
        &self,
        watcher_id: &WatcherId,
        generation: Counter,
        after: Counter,
        maximum: usize,
    ) -> Result<WatchPage, FilesystemError> {
        if maximum == 0 || maximum > MAX_WATCH_EVENTS {
            return Err(FilesystemError::Invalid(
                "watch event bound must be 1..4096",
            ));
        }
        let mut watchers = self
            .watchers
            .lock()
            .map_err(|_| FilesystemError::Unavailable)?;
        let other_entries: usize = watchers
            .iter()
            .filter(|(id, _)| *id != watcher_id)
            .map(|(_, watcher)| watcher.snapshot.as_ref().map_or(0, BTreeMap::len))
            .sum();
        let watcher = watchers
            .get_mut(watcher_id)
            .ok_or(FilesystemError::Invalid("watcher does not exist"))?;
        if watcher.record.generation != generation
            || watcher.record.closed
            || after > watcher.record.sequence
        {
            return Err(FilesystemError::Conflict);
        }
        let relative = linux_path(&watcher.record.root);
        let current = scan_watch(
            &relative,
            &watcher.record.root,
            watcher.record.recursive,
            MAX_DIRECTORY_ENTRIES.saturating_sub(other_entries),
        )?;
        let mut changes = Vec::new();
        if let Some(before) = &watcher.snapshot {
            let keys: BTreeSet<_> = before.keys().chain(current.keys()).cloned().collect();
            for path in keys {
                let kind = match (before.get(&path), current.get(&path)) {
                    (None, Some(_)) => Some(WatchEventKind::Created),
                    (Some(_), None) => Some(WatchEventKind::Removed),
                    (Some(before), Some(after)) if before != after => {
                        Some(WatchEventKind::Modified)
                    }
                    _ => None,
                };
                if let Some(kind) = kind {
                    changes.push((kind, path));
                    if changes.len() > MAX_RETAINED_WATCH_EVENTS {
                        break;
                    }
                }
            }
        }
        let mut record = watcher.record.clone();
        if watcher.snapshot.is_none() {
            push_watch_overflow(&mut record, false)?;
        } else if changes.len() > MAX_RETAINED_WATCH_EVENTS {
            push_watch_overflow(&mut record, true)?;
        } else {
            for (kind, path) in changes {
                record.sequence = record
                    .sequence
                    .next()
                    .map_err(|_| FilesystemError::Capacity)?;
                record.events.push(WatchEvent {
                    watcher_id: watcher_id.clone(),
                    generation,
                    sequence: record.sequence,
                    kind,
                    path: Some(
                        GuestPath::try_from(path)
                            .map_err(|_| FilesystemError::Invalid("watched path is malformed"))?,
                    ),
                });
            }
        }
        if record.events.len() > MAX_RETAINED_WATCH_EVENTS
            || serde_json::to_vec(&record)
                .map_err(|_| FilesystemError::Capacity)?
                .len()
                > MAX_WATCH_RECORD_BYTES
        {
            push_watch_overflow(&mut record, true)?;
        }
        // Publish before advancing the in-memory baseline or replying. Lost
        // responses can be retried with the same cursor without consuming data.
        if record.sequence != watcher.record.sequence {
            self.publish_watcher(&record)?;
        }
        watcher.record = record;
        watcher.snapshot = Some(current);
        let events: Vec<_> = watcher
            .record
            .events
            .iter()
            .filter(|event| event.sequence > after)
            .take(maximum)
            .cloned()
            .collect();
        let cursor = events.last().map_or(after, |event| event.sequence);
        Ok(WatchPage { events, cursor })
    }

    pub fn unwatch(
        &self,
        watcher_id: &WatcherId,
        generation: Counter,
    ) -> Result<(), FilesystemError> {
        let mut watchers = self
            .watchers
            .lock()
            .map_err(|_| FilesystemError::Unavailable)?;
        let watcher = watchers
            .get_mut(watcher_id)
            .ok_or(FilesystemError::Invalid("watcher does not exist"))?;
        if watcher.record.generation != generation {
            return Err(FilesystemError::Conflict);
        }
        let mut record = watcher.record.clone();
        record.closed = true;
        record.events.clear();
        self.publish_watcher(&record)?;
        watcher.record = record;
        watcher.snapshot = None;
        Ok(())
    }
}

fn push_watch_overflow(record: &mut WatchRecord, discard: bool) -> Result<(), FilesystemError> {
    record.sequence = record
        .sequence
        .next()
        .map_err(|_| FilesystemError::Capacity)?;
    if discard {
        record.events.clear();
    }
    record.events.push(WatchEvent {
        watcher_id: record.id.clone(),
        generation: record.generation,
        sequence: record.sequence,
        kind: WatchEventKind::Overflow,
        path: None,
    });
    Ok(())
}

fn linux_path(value: &GuestPath) -> PathBuf {
    PathBuf::from(OsString::from_vec(value.as_bytes().to_vec()))
}

fn scan_watch(
    relative: &Path,
    guest_path: &GuestPath,
    recursive: bool,
    maximum: usize,
) -> Result<BTreeMap<Vec<u8>, WatchFingerprint>, FilesystemError> {
    let mut result = BTreeMap::new();
    let mut pending = vec![(relative.to_path_buf(), guest_path.as_bytes().to_vec())];
    while let Some((directory, guest_directory)) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if result.len() >= maximum {
                return Err(FilesystemError::Capacity);
            }
            let name = entry.file_name().as_bytes().to_vec();
            let child = directory.join(OsStr::from_bytes(&name));
            let metadata = fs::symlink_metadata(&child)?;
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

fn read_observation(metadata: &std::fs::Metadata) -> Result<FileReadObservation, FilesystemError> {
    Ok(FileReadObservation {
        size: metadata.len(),
        token: sandsurf_protocol::digest(
            sandsurf_protocol::Domain::Transfer,
            &(
                "sandsurf-guest-live-file-observation-v1",
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        )
        .map_err(|_| FilesystemError::Invalid("file observation encoding failed"))?,
    })
}

fn revision_at(relative: &Path) -> Result<Option<FileRevision>, FilesystemError> {
    let mut file = match File::open(relative) {
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

fn file_stat(metadata: std::fs::Metadata) -> FileStat {
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
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
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

fn publish_file(
    parent: &Dir,
    temporary: &Path,
    destination: &Path,
    expected: &FileExpectation,
) -> Result<(), FilesystemError> {
    match expected {
        FileExpectation::Any => parent.rename(temporary, parent, destination)?,
        FileExpectation::Absent => {
            let temporary = std::ffi::CString::new(temporary.as_os_str().as_bytes())
                .map_err(|_| FilesystemError::Invalid("temporary path contains NUL"))?;
            let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
                .map_err(|_| FilesystemError::Invalid("destination contains NUL"))?;
            // SAFETY: both names are single components, the directory is held
            // open, and both C string buffers live through the syscall.
            if unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    parent.as_raw_fd(),
                    temporary.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                let error = io::Error::last_os_error();
                return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                    FilesystemError::Conflict
                } else {
                    error.into()
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn path(&self, suffix: &str) -> String {
            self.0.join(suffix).to_str().unwrap().to_owned()
        }
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

    #[test]
    fn file_publication_is_conditionally_atomic() {
        let root = Temp::new();
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        service.mkdir(root.path("src").as_str(), true).unwrap();
        service
            .write_file(
                root.path("src/file").as_str(),
                b"one",
                0o644,
                &OperationId::try_from("write-one").unwrap(),
                &FileExpectation::Absent,
            )
            .unwrap();
        assert_eq!(
            service
                .read_file(root.path("src/file").as_str(), 1024)
                .unwrap(),
            b"one"
        );
        assert!(matches!(
            service.write_file(
                root.path("src/file").as_str(),
                b"conflict",
                0o644,
                &OperationId::try_from("write-conflict").unwrap(),
                &FileExpectation::Absent,
            ),
            Err(FilesystemError::Conflict)
        ));
        service
            .write_file(
                root.path("src/file").as_str(),
                b"two",
                0o644,
                &OperationId::try_from("write-two").unwrap(),
                &FileExpectation::Any,
            )
            .unwrap();
        assert_eq!(
            service.list(root.path("src").as_str()).unwrap()[0].name,
            b"file"
        );
    }

    #[test]
    fn streamed_write_is_contiguous_digest_bound_and_atomically_published() {
        let root = Temp::new();
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        let bytes = b"streamed-binary\0content";
        let transfer = FileTransfer {
            id: "transfer".try_into().unwrap(),
            path: GuestPath::try_from(root.path("result").as_str()).unwrap(),
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
        let revision = service.commit_write_transfer(&transfer).unwrap();
        assert_eq!(revision.size, bytes.len() as u64);
        assert_eq!(fs::read(root.0.join("result")).unwrap(), bytes);
    }

    #[test]
    fn relative_and_nul_paths_are_rejected() {
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        for path in ["relative", "/contains\0nul"] {
            assert!(service.lstat(path).is_err());
        }
    }

    #[test]
    fn absolute_linux_symlinks_are_followed_and_lstat_observes_the_link() {
        let root = Temp::new();
        let outside = Temp::new();
        fs::write(outside.0.join("secret"), b"secret").unwrap();
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        service
            .symlink(outside.0.to_str().unwrap(), root.path("link").as_str())
            .unwrap();
        assert_eq!(
            service.read_link(root.path("link").as_str()).unwrap(),
            outside.0.to_str().unwrap()
        );
        assert_eq!(
            service
                .read_file(root.path("link/secret").as_str(), 1024)
                .unwrap(),
            b"secret"
        );
        assert_eq!(
            service.lstat(root.path("link").as_str()).unwrap().kind,
            FileKind::Symlink
        );
    }

    #[test]
    fn range_reads_are_bounded_and_observe_metadata_changes() {
        let root = Temp::new();
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        let path = root.0.join("sparse");
        let mut file = File::create(&path).unwrap();
        file.set_len(64 * 1024 * 1024 * 1024).unwrap();
        file.write_all(b"first").unwrap();
        let guest_path = GuestPath::try_from(path.to_str().unwrap()).unwrap();
        let first = service.read_range(&guest_path, 0, 5).unwrap();
        assert_eq!(first.bytes, b"first");
        assert_eq!(first.observation.size, 64 * 1024 * 1024 * 1024);
        assert!(!first.eof);
        file.set_len(63 * 1024 * 1024 * 1024).unwrap();
        let second = service.read_range(&guest_path, 0, 5).unwrap();
        assert_ne!(first.observation.token, second.observation.token);
        assert!(matches!(
            service.read_range(&guest_path, 0, MAX_IN_MEMORY_READ as usize + 1),
            Err(FilesystemError::Invalid(_))
        ));
    }

    #[test]
    fn watch_pages_replay_after_disconnect_and_report_service_restart() {
        let root = Temp::new();
        let ledger = Temp::new();
        let id: WatcherId = "durable-watch".try_into().unwrap();
        let path = GuestPath::try_from(root.path("").as_str()).unwrap();
        let service = FilesystemService::open(&ledger.0).unwrap();
        assert!(FilesystemService::open(&ledger.0).is_err());
        service
            .watch(id.clone(), Counter::ONE, path.clone(), false)
            .unwrap();
        fs::write(root.0.join("one"), b"1").unwrap();
        let first = service
            .poll_watcher(&id, Counter::ONE, Counter::ZERO, 1)
            .unwrap();
        assert_eq!(first.events[0].kind, WatchEventKind::Created);
        assert_eq!(
            service
                .poll_watcher(&id, Counter::ONE, Counter::ZERO, 1)
                .unwrap(),
            first
        );
        drop(service);
        fs::write(root.0.join("two"), b"2").unwrap();
        let service = FilesystemService::open(&ledger.0).unwrap();
        assert_eq!(
            service
                .poll_watcher(&id, Counter::ONE, Counter::ZERO, 1)
                .unwrap(),
            first
        );
        let gap = service
            .poll_watcher(&id, Counter::ONE, first.cursor, 1)
            .unwrap();
        assert_eq!(gap.events[0].kind, WatchEventKind::Overflow);
        assert_eq!(gap.cursor, first.cursor.next().unwrap());
        assert_eq!(
            service
                .poll_watcher(&id, Counter::ONE, first.cursor, 1)
                .unwrap(),
            gap
        );
        assert!(
            service
                .poll_watcher(&id, Counter::try_from(2).unwrap(), gap.cursor, 1)
                .is_err()
        );
        assert!(
            service
                .poll_watcher(&id, Counter::ONE, gap.cursor.next().unwrap(), 1)
                .is_err()
        );
        service.unwatch(&id, Counter::ONE).unwrap();
        drop(service);
        let service = FilesystemService::open(&ledger.0).unwrap();
        assert!(
            service
                .poll_watcher(&id, Counter::ONE, gap.cursor, 1)
                .is_err()
        );
        assert!(service.watch(id, Counter::ONE, path, false).is_err());
    }

    #[test]
    fn watch_retention_exhaustion_reports_a_gap_instead_of_silently_losing_pages() {
        let root = Temp::new();
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        let id: WatcherId = "bounded-watch".try_into().unwrap();
        service
            .watch(
                id.clone(),
                Counter::ONE,
                GuestPath::try_from(root.path("").as_str()).unwrap(),
                false,
            )
            .unwrap();
        for index in 0..=MAX_RETAINED_WATCH_EVENTS {
            fs::write(root.0.join(format!("item-{index}")), b"1").unwrap();
        }
        let gap = service
            .poll_watcher(&id, Counter::ONE, Counter::ZERO, 256)
            .unwrap();
        assert_eq!(gap.events.len(), 1);
        assert_eq!(gap.events[0].kind, WatchEventKind::Overflow);
        assert_eq!(
            service
                .poll_watcher(&id, Counter::ONE, Counter::ZERO, 256)
                .unwrap(),
            gap
        );
        assert!(
            fs::metadata(ledger.0.join(id.as_str())).unwrap().len()
                <= MAX_WATCH_RECORD_BYTES as u64
        );
        assert!(
            service
                .poll_watcher(&id, Counter::ONE, gap.cursor, 256)
                .unwrap()
                .events
                .is_empty()
        );
    }

    #[test]
    fn watch_recovery_rejects_corrupt_and_oversized_guest_records() {
        let ledger = Temp::new();
        fs::write(ledger.0.join("corrupt"), b"{}").unwrap();
        assert!(FilesystemService::open(&ledger.0).is_err());
        fs::remove_file(ledger.0.join("corrupt")).unwrap();
        File::create(ledger.0.join("oversized"))
            .unwrap()
            .set_len(MAX_WATCH_RECORD_BYTES as u64 + 1)
            .unwrap();
        assert!(FilesystemService::open(&ledger.0).is_err());
    }

    #[test]
    fn directory_pagination_bounds_encoded_metadata_and_resumes_long_names() {
        let root = Temp::new();
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        let mut expected = Vec::new();
        for index in 0..512 {
            let name = format!("{index:04}-{}", "z".repeat(245));
            fs::write(root.0.join(&name), b"file").unwrap();
            expected.push(name.into_bytes());
        }
        let scope = GuestPath::try_from(root.path("").as_str()).unwrap();
        let mut after = None;
        let mut captured = Vec::new();
        loop {
            let page = service.list_page(&scope, after.as_deref(), 4096).unwrap();
            assert!(
                serde_json::to_vec(&page).unwrap().len() <= sandsurf_protocol::MAX_CONTROL_BYTES
            );
            assert!(!page.entries.is_empty());
            assert!(page.entries.len() < 512);
            captured.extend(page.entries.into_iter().map(|entry| entry.name));
            let Some(next) = page.next else {
                break;
            };
            after = Some(next);
        }
        assert_eq!(captured, expected);
        assert_eq!(service.list(scope.to_utf8().unwrap()).unwrap().len(), 512);
    }

    #[test]
    fn byte_paths_ranges_pagination_and_watch_overflow_are_explicit() {
        let root = Temp::new();
        let ledger = Temp::new();
        let service = FilesystemService::open(&ledger.0).unwrap();
        let non_utf8 = OsString::from_vec(vec![b'n', 0xff]);
        fs::write(root.0.join(&non_utf8), b"0123456789").unwrap();
        fs::write(root.0.join("z"), b"z").unwrap();
        fs::write(root.0.join("a"), b"a").unwrap();
        let scope = GuestPath::try_from(root.path("").as_str()).unwrap();
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
            let mut value = root.0.as_os_str().as_bytes().to_vec();
            value.push(b'/');
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
        let page = service
            .poll_watcher(&watcher, Counter::ONE, Counter::ZERO, 1)
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].kind, WatchEventKind::Created);
        let events = service
            .poll_watcher(&watcher, Counter::ONE, page.cursor, 1)
            .unwrap()
            .events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, WatchEventKind::Created);
        service.unwatch(&watcher, Counter::ONE).unwrap();
        assert!(
            service
                .poll_watcher(&watcher, Counter::ONE, Counter::ZERO, 1)
                .is_err()
        );
    }
}
