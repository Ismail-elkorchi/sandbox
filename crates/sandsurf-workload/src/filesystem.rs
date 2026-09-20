use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, Permissions, PermissionsExt};
use cap_std::time::SystemClock;
use sandsurf_protocol::{Digest, OperationId, bytes_digest};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStat {
    pub kind: FileKind,
    pub size: u64,
    pub readonly: bool,
    pub modified_millis: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: String,
    pub stat: FileStat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRevision {
    pub size: u64,
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedRevision {
    Any,
    Absent,
    Matches(FileRevision),
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
        })
    }

    pub fn stat(&self, guest_path: &str) -> Result<FileStat, FilesystemError> {
        let relative = self.relative(guest_path, true)?;
        Ok(file_stat(self.root.metadata(relative)?))
    }

    pub fn lstat(&self, guest_path: &str) -> Result<FileStat, FilesystemError> {
        let relative = self.relative(guest_path, true)?;
        Ok(file_stat(self.root.symlink_metadata(relative)?))
    }

    pub fn list(&self, guest_path: &str) -> Result<Vec<DirectoryEntry>, FilesystemError> {
        let relative = self.relative(guest_path, true)?;
        let mut values = Vec::new();
        for entry in self.root.read_dir(&relative)? {
            let entry = entry?;
            if values.len() >= MAX_DIRECTORY_ENTRIES {
                return Err(FilesystemError::Capacity);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| FilesystemError::Invalid("directory name is not UTF-8"))?;
            let entry_path = relative.join(&name);
            values.push(DirectoryEntry {
                name,
                stat: file_stat(self.root.symlink_metadata(entry_path)?),
            });
        }
        values.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        Ok(values)
    }

    pub fn read_file(&self, guest_path: &str, maximum: u64) -> Result<Vec<u8>, FilesystemError> {
        if maximum == 0 || maximum > MAX_FILE_BYTES {
            return Err(FilesystemError::Invalid("read bound must be 1..64 MiB"));
        }
        let relative = self.relative(guest_path, false)?;
        let mut file = self.root.open(relative)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > maximum {
            return Err(FilesystemError::Capacity);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(FilesystemError::Capacity);
        }
        Ok(bytes)
    }

    pub fn revision(&self, guest_path: &str) -> Result<Option<FileRevision>, FilesystemError> {
        let relative = self.relative(guest_path, false)?;
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
        if bytes.len() as u64 > MAX_FILE_BYTES || mode & !0o7777 != 0 {
            return Err(FilesystemError::Capacity);
        }
        let relative = self.relative(guest_path, false)?;
        let (parent_path, name) = split_parent(&relative)?;
        let _transaction = self
            .transactions
            .lock()
            .map_err(|_| FilesystemError::Barrier)?;
        let _writer_barrier = barrier.acquire()?;
        let parent = self.root.open_dir(parent_path)?;
        check_expected(&parent, Path::new(&name), expected)?;
        let temporary = format!(".sandsurf-{}.tmp", operation_id.as_str());
        if temporary == name {
            return Err(FilesystemError::Invalid(
                "temporary name aliases destination",
            ));
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = match parent.open_with(&temporary, &options) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(FilesystemError::Conflict);
            }
            Err(error) => return Err(error.into()),
        };
        let result = (|| {
            file.write_all(bytes)?;
            file.set_permissions(Permissions::from_mode(mode))?;
            file.sync_all()?;
            check_expected(&parent, Path::new(&name), expected)?;
            parent.rename(&temporary, &parent, &name)?;
            let mut sync_options = OpenOptions::new();
            sync_options.read(true);
            parent.open_with(".", &sync_options)?.sync_all()?;
            Ok(FileRevision {
                size: bytes.len() as u64,
                digest: bytes_digest(bytes),
            })
        })();
        if result.is_err() {
            let _ = parent.remove_file(&temporary);
        }
        result
    }

    pub fn mkdir(&self, guest_path: &str, recursive: bool) -> Result<(), FilesystemError> {
        let relative = self.relative(guest_path, false)?;
        if recursive {
            self.root.create_dir_all(relative)?;
        } else {
            self.root.create_dir(relative)?;
        }
        Ok(())
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), FilesystemError> {
        let from = self.relative(from, false)?;
        let to = self.relative(to, false)?;
        self.root.rename(from, &self.root, to)?;
        Ok(())
    }

    pub fn remove(&self, guest_path: &str, recursive: bool) -> Result<(), FilesystemError> {
        let relative = self.relative(guest_path, false)?;
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
        let relative = self.relative(guest_path, false)?;
        self.root
            .read_link_contents(relative)?
            .into_os_string()
            .into_string()
            .map_err(|_| FilesystemError::Invalid("symlink target is not UTF-8"))
    }

    pub fn symlink(&self, target: &str, guest_path: &str) -> Result<(), FilesystemError> {
        if target.is_empty() || target.len() > 4096 || target.contains('\0') {
            return Err(FilesystemError::Invalid("symlink target is malformed"));
        }
        let relative = self.relative(guest_path, false)?;
        self.root.symlink_contents(target, relative)?;
        Ok(())
    }

    fn relative(&self, value: &str, allow_scope: bool) -> Result<PathBuf, FilesystemError> {
        if value.len() > 4096 || value.contains('\0') || !value.starts_with('/') {
            return Err(FilesystemError::Invalid("guest path is malformed"));
        }
        let suffix = if self.guest_scope == "/" {
            value.trim_start_matches('/')
        } else if value == self.guest_scope {
            ""
        } else {
            value
                .strip_prefix(&format!("{}/", self.guest_scope))
                .ok_or(FilesystemError::Invalid(
                    "guest path is outside capability scope",
                ))?
        };
        if suffix.is_empty() && !allow_scope {
            return Err(FilesystemError::Invalid(
                "operation cannot target scope root",
            ));
        }
        let mut relative = PathBuf::new();
        for component in Path::new(suffix).components() {
            match component {
                Component::Normal(value) => relative.push(value),
                Component::CurDir => {}
                _ => return Err(FilesystemError::Invalid("guest path is not normalized")),
            }
        }
        Ok(relative)
    }
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

fn split_parent(path: &Path) -> Result<(PathBuf, String), FilesystemError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(FilesystemError::Invalid("path has no UTF-8 basename"))?
        .to_owned();
    Ok((
        path.parent().unwrap_or_else(|| Path::new("")).to_path_buf(),
        name,
    ))
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
        assert_eq!(service.list("/workspace/src").unwrap()[0].name, "file");
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
}
