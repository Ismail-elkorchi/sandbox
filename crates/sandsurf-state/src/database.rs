use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags, limits::Limit};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

const APPLICATION_ID: i64 = 0x53534d31;

pub(crate) struct Database {
    pub connection: Connection,
    pub root: PathBuf,
    // Field order closes SQLite before releasing its exclusive writer lease.
    _lease: WriterLease,
}

struct WriterLease(File);
impl Drop for WriterLease {
    fn drop(&mut self) {
        // CLOEXEC closes inherited descriptors on exec, not at fork. Explicitly
        // unlock on an orderly writer close so an unrelated exec-in-progress
        // child cannot extend the old writer's lifetime. Never use inherited
        // SQLite connections in fork children. Crash release still relies on OS
        // handle closure; an uncertain inherited owner correctly remains busy.
        let _ = self.0.unlock();
    }
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
        sync_file(&file)?;
        let mut connection = connect(&database_path)?;
        configure_durability(&connection)?;
        let tx = connection.transaction()?;
        tx.execute_batch("PRAGMA application_id = 1397968177; PRAGMA user_version = 6; CREATE TABLE identity(role TEXT NOT NULL) STRICT;")?;
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
            _lease: WriterLease(lease),
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
        if application != APPLICATION_ID || version != 6 {
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
            _lease: WriterLease(lease),
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
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=4194304; PRAGMA max_page_count=262144;")?;
    Ok(())
}

pub(crate) fn lock(file: &File) -> Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(Error::Conflict("authority already has an exclusive writer"))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

#[cfg(any(unix, target_os = "windows"))]
fn canonical_directory(path: &Path) -> Result<PathBuf> {
    Ok(sandsurf_native::local::canonical_private_directory(path)?)
}

#[cfg(any(unix, target_os = "windows"))]
pub(crate) fn create_private_directory(path: &Path) -> Result<()> {
    sandsurf_native::local::create_private_directory(path)?;
    Ok(())
}

#[cfg(any(unix, target_os = "windows"))]
pub(crate) fn private_file(path: &Path, create: bool) -> Result<File> {
    Ok(if create {
        sandsurf_native::local::create_private_file(path)?
    } else {
        sandsurf_native::local::open_private_file(
            path,
            sandsurf_native::PrivateFileAccess::ReadWrite,
        )?
    })
}

#[cfg(any(unix, target_os = "windows"))]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    sandsurf_native::storage::sync_directory(path)?;
    Ok(())
}

pub(crate) fn sync_file(file: &File) -> Result<()> {
    sandsurf_native::storage::sync_file(file)?;
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
pub(crate) fn create_private_directory(_: &Path) -> Result<()> {
    Err(Error::Unsupported(
        "native private-state provisioning is not implemented on this host",
    ))
}
#[cfg(not(any(unix, target_os = "windows")))]
fn canonical_directory(_: &Path) -> Result<PathBuf> {
    Err(Error::Unsupported(
        "native private-state provisioning is not implemented on this host",
    ))
}
#[cfg(not(any(unix, target_os = "windows")))]
pub(crate) fn private_file(_: &Path, _: bool) -> Result<File> {
    Err(Error::Unsupported(
        "native private-state file handles are not implemented on this host",
    ))
}
#[cfg(not(any(unix, target_os = "windows")))]
pub(crate) fn sync_directory(_: &Path) -> Result<()> {
    Err(Error::Unsupported(
        "native state publication is not implemented on this host",
    ))
}
