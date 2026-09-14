use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags, limits::Limit};
use std::fs::File;
#[cfg(unix)]
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

const APPLICATION_ID: i64 = 0x53534631;

pub(crate) struct Database {
    pub connection: Connection,
    pub root: PathBuf,
    _lease: File,
}

impl Database {
    pub fn create(root: &Path, role: &str, schema: &str) -> Result<Self> {
        if !root.is_absolute() {
            return Err(Error::Conflict("state root must be absolute"));
        }
        create_private_directory(root)?;
        let root = canonical_directory(root)?;
        let lease = private_file(&root.join("writer.lock"), true)?;
        lock(&lease)?;
        let database_path = root.join("authority.sqlite");
        let file = private_file(&database_path, true)?;
        file.sync_all()?;
        let mut connection = connect(&database_path)?;
        configure_durability(&connection)?;
        let tx = connection.transaction()?;
        tx.execute_batch("PRAGMA application_id = 1397966385; PRAGMA user_version = 1; CREATE TABLE identity(role TEXT NOT NULL) STRICT;")?;
        tx.execute("INSERT INTO identity VALUES (?1)", [role])?;
        tx.execute_batch(schema)?;
        tx.commit()?;
        sync_directory(&root)?;
        if let Some(parent) = root.parent() {
            sync_directory(parent)?;
        }
        Ok(Self {
            connection,
            root,
            _lease: lease,
        })
    }

    pub fn open(root: &Path, role: &str) -> Result<Self> {
        let root = canonical_directory(root)?;
        let lease = private_file(&root.join("writer.lock"), false)?;
        lock(&lease)?;
        let path = root.join("authority.sqlite");
        private_file(&path, false)?;
        let connection = connect(&path)?;
        let application: i64 = connection.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if application != APPLICATION_ID || version != 1 {
            return Err(Error::Corrupt(
                "incompatible authority catalog; preserved intact",
            ));
        }
        let actual: String = connection.query_row("SELECT role FROM identity", [], |r| r.get(0))?;
        if actual != role {
            return Err(Error::Conflict("authority writer role mismatch"));
        }
        configure_durability(&connection)?;
        Ok(Self {
            connection,
            root,
            _lease: lease,
        })
    }
}

fn connect(path: &Path) -> Result<Connection> {
    // Never recreate a missing catalog when opening an existing identity.
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024)?;
    connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 128 * 1024)?;
    connection.set_limit(Limit::SQLITE_LIMIT_COLUMN, 128)?;
    Ok(connection)
}

fn configure_durability(connection: &Connection) -> Result<()> {
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=4194304; PRAGMA max_page_count=262144;")?;
    Ok(())
}

fn lock(file: &File) -> Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(Error::Conflict("authority already has an exclusive writer"))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

#[cfg(unix)]
fn canonical_directory(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    // macOS system paths such as /var are aliases. Resolve ancestors once at
    // admission, keeping SQLite's all-components NOFOLLOW check enabled. The
    // supplied state directory itself must still be private and not a symlink.
    validate_directory(path)?;
    let before = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    validate_directory(&canonical)?;
    let after = fs::symlink_metadata(&canonical)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Error::Conflict("state directory changed during resolution"));
    }
    Ok(canonical)
}

#[cfg(unix)]
pub(crate) fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    validate_directory(path)
}

#[cfg(unix)]
fn validate_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid takes no pointers, allocates no resources, and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != uid
    {
        return Err(Error::Conflict(
            "state root must be an owned private directory, not a symlink",
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn private_file(path: &Path, create: bool) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no pointers, allocates no resources, and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != uid
    {
        return Err(Error::Conflict(
            "state file must be private, owned and singly linked",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

// Windows must receive native ACL/handle qualification before a store can be admitted.
// A POSIX mode argument on Windows would silently fail to establish this boundary.
#[cfg(not(unix))]
pub(crate) fn create_private_directory(_: &Path) -> Result<()> {
    Err(Error::Unsupported(
        "native private-state provisioning is not implemented on this host",
    ))
}
#[cfg(not(unix))]
fn canonical_directory(_: &Path) -> Result<PathBuf> {
    Err(Error::Unsupported(
        "native private-state provisioning is not implemented on this host",
    ))
}
#[cfg(not(unix))]
pub(crate) fn private_file(_: &Path, _: bool) -> Result<File> {
    Err(Error::Unsupported(
        "native private-state file handles are not implemented on this host",
    ))
}
#[cfg(not(unix))]
pub(crate) fn sync_directory(_: &Path) -> Result<()> {
    Err(Error::Unsupported(
        "native state publication is not implemented on this host",
    ))
}
