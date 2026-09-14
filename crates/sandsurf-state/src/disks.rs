//! Guardian-owned raw backing files. No host mounting, filesystem parsing, or
//! inferred guest sync occurs here. Image provenance and native owner-death
//! containment must be established by their respective services before boot.
use crate::{
    Error, Result, RuntimeJournal,
    catalog::capacity,
    database::{lock, private_file, sync_directory, sync_file},
    decode, encode,
};
use rusqlite::{OptionalExtension, params};
use sandsurf_protocol::*;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskPurpose {
    Workload,
    Supervisor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskCopy {
    pub id: DiskId,
    pub operation_id: OperationId,
    pub source_digest: Digest,
    pub bytes: Counter,
    pub purpose: DiskPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskPhase {
    Copying,
    Ready,
    Deleting,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskRecord {
    pub request: DiskCopy,
    pub request_digest: Digest,
    pub phase: DiskPhase,
    pub cleanup_digest: Option<Digest>,
}

/// A private writable backing file plus its exclusive kernel lease. Drivers
/// must retain this handle (or a duplicate) for the entire attachment lifetime.
/// Acquiring it does not itself mean a VM is running or a disk is guest-synced.
pub struct DiskAttachment {
    file: File,
    record: DiskRecord,
}
impl DiskAttachment {
    pub fn record(&self) -> &DiskRecord {
        &self.record
    }
    pub fn duplicate_handle(&self) -> Result<File> {
        Ok(self.file.try_clone()?)
    }
    pub fn flush_host(&self) -> Result<()> {
        sync_file(&self.file)
    }
}

impl RuntimeJournal {
    pub fn disk(&self, id: &DiskId) -> Result<Option<DiskRecord>> {
        disk(&self.db.connection, id)
    }

    /// Commits copy intent and logical reservation before creating backing data.
    /// The host remains responsible for global admission; this is a local bound.
    pub fn prepare_disk_copy(&mut self, request: DiskCopy) -> Result<DiskRecord> {
        if request.bytes == Counter::ZERO || !request.bytes.get().is_multiple_of(512) {
            return Err(Error::Conflict(
                "raw disk size must be positive and sector aligned",
            ));
        }
        let identity = digest(
            Domain::Operation,
            &(&self.sandbox, "raw-disk-copy", &request),
        )?;
        let tx = self.db.connection.transaction()?;
        if let Some(old) = disk(&tx, &request.id)? {
            return if old.request_digest == identity {
                Ok(old)
            } else {
                Err(Error::Conflict("disk identity already bound"))
            };
        }
        let used: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 UNION ALL SELECT 1 FROM disks WHERE operation=?1)", [request.operation_id.as_str()], |row| row.get(0))?;
        if used {
            return Err(Error::Conflict("disk operation identity already bound"));
        }
        capacity(&tx, "disks", self.limits.disks)?;
        let mut total = request.bytes;
        {
            let mut statement =
                tx.prepare("SELECT request FROM disks WHERE phase!='\"deleted\"'")?;
            for value in statement.query_map([], |row| row.get::<_, String>(0))? {
                total = total.checked_add(decode::<DiskCopy>(&value?)?.bytes.get())?;
            }
        }
        if total > self.limits.disk_bytes {
            return Err(Error::Capacity("retained disk reservations exhausted"));
        }
        tx.execute(
            "INSERT INTO disks VALUES (?1,?2,?3,?4,?5,NULL)",
            params![
                request.id.as_str(),
                request.operation_id.as_str(),
                encode(&request)?,
                identity.as_str(),
                encode(&DiskPhase::Copying)?
            ],
        )?;
        tx.commit()?;
        Ok(DiskRecord {
            request,
            request_digest: identity,
            phase: DiskPhase::Copying,
            cleanup_digest: None,
        })
    }

    /// Bounded verified copy with physical allocation. Interrupted copies stay
    /// non-attachable and reserved; retry touches only their journal-owned file.
    pub fn materialize_disk(
        &mut self,
        id: &DiskId,
        expected: &Digest,
        source: &File,
    ) -> Result<DiskRecord> {
        let record = require_disk(&self.db.connection, id, expected)?;
        if record.phase == DiskPhase::Ready {
            return Ok(record);
        }
        if record.phase != DiskPhase::Copying {
            return Err(Error::Conflict("disk is retired"));
        }
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.len() != record.request.bytes.get() {
            return Err(Error::Conflict(
                "source must be a complete held regular disk image",
            ));
        }
        let path = self.db.root.join(format!("disk-{}.raw", id.as_str()));
        let file = match private_file(&path, true) {
            Ok(file) => file,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                private_file(&path, false)?
            }
            Err(error) => return Err(error),
        };
        lock(&file)?;
        ensure_distinct(source, &file)?;
        // No Ready disk can reach this truncation. Copying files have never been attachable.
        file.set_len(0)?;
        reserve(
            &file,
            record.request.bytes.get(),
            self.limits.disk_headroom_bytes.get(),
        )?;
        let actual = copy(source, &file, record.request.bytes.get())?;
        if actual != record.request.source_digest {
            return Err(Error::Corrupt(
                "disk copy content does not match the verified source identity",
            ));
        }
        if source.metadata()?.len() != record.request.bytes.get() {
            return Err(Error::Conflict("source image changed during copy"));
        }
        sync_file(&file)?;
        if content_digest(&file, record.request.bytes.get())? != actual {
            return Err(Error::Corrupt(
                "materialized disk readback does not match its source",
            ));
        }
        sync_directory(&self.db.root)?;
        self.db.connection.execute(
            "UPDATE disks SET phase=?2 WHERE id=?1",
            params![id.as_str(), encode(&DiskPhase::Ready)?],
        )?;
        Ok(DiskRecord {
            phase: DiskPhase::Ready,
            ..record
        })
    }

    pub fn acquire_disk(&self, id: &DiskId, expected: &Digest) -> Result<DiskAttachment> {
        let record = require_disk(&self.db.connection, id, expected)?;
        if record.phase != DiskPhase::Ready {
            return Err(Error::Conflict("disk is not committed and attachable"));
        }
        let file = private_file(
            &self.db.root.join(format!("disk-{}.raw", id.as_str())),
            false,
        )?;
        lock(&file)?;
        if file.metadata()?.len() != record.request.bytes.get() {
            return Err(Error::Corrupt("owned disk geometry changed"));
        }
        // Mutable guest disks are not rechecked against their original image hash.
        Ok(DiskAttachment { file, record })
    }

    /// Record deletion intent before unlinking. A live attachment can keep cleanup
    /// pending, but no new attachment may be acquired after this commit.
    pub fn retire_disk(&mut self, id: &DiskId, expected: &Digest) -> Result<DiskRecord> {
        let mut record = require_disk(&self.db.connection, id, expected)?;
        if matches!(record.phase, DiskPhase::Deleting | DiskPhase::Deleted) {
            return Ok(record);
        }
        self.db.connection.execute(
            "UPDATE disks SET phase=?2 WHERE id=?1",
            params![id.as_str(), encode(&DiskPhase::Deleting)?],
        )?;
        record.phase = DiskPhase::Deleting;
        Ok(record)
    }

    pub fn cleanup_disk(&mut self, id: &DiskId, expected: &Digest) -> Result<DiskRecord> {
        let mut record = require_disk(&self.db.connection, id, expected)?;
        if record.phase == DiskPhase::Deleted {
            return Ok(record);
        }
        if record.phase != DiskPhase::Deleting {
            return Err(Error::Conflict("disk deletion has not been committed"));
        }
        let path = self.db.root.join(format!("disk-{}.raw", id.as_str()));
        let held = match private_file(&path, false) {
            Ok(file) => {
                lock(&file)?;
                Some(file)
            }
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if held.is_some() {
            fs::remove_file(&path)?;
        }
        sync_directory(&self.db.root)?;
        let evidence = digest(
            Domain::Operation,
            &(&self.sandbox, id, expected, "raw-backing-removed"),
        )?;
        self.db.connection.execute(
            "UPDATE disks SET phase=?2,cleanup_digest=?3 WHERE id=?1",
            params![id.as_str(), encode(&DiskPhase::Deleted)?, evidence.as_str()],
        )?;
        record.phase = DiskPhase::Deleted;
        record.cleanup_digest = Some(evidence);
        Ok(record)
    }
}

fn disk(db: &rusqlite::Connection, id: &DiskId) -> Result<Option<DiskRecord>> {
    let row: Option<(String, String, String, Option<String>)> = db
        .query_row(
            "SELECT request,request_digest,phase,cleanup_digest FROM disks WHERE id=?1",
            [id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(request, request_digest, phase, cleanup_digest)| {
        Ok(DiskRecord {
            request: decode(&request)?,
            request_digest: request_digest.try_into()?,
            phase: decode(&phase)?,
            cleanup_digest: cleanup_digest.map(Digest::try_from).transpose()?,
        })
    })
    .transpose()
}
fn require_disk(db: &rusqlite::Connection, id: &DiskId, expected: &Digest) -> Result<DiskRecord> {
    let record = disk(db, id)?.ok_or(Error::Missing("disk identity missing"))?;
    if record.request_digest != *expected {
        return Err(Error::Conflict("disk request identity mismatch"));
    }
    Ok(record)
}

#[cfg(unix)]
fn ensure_distinct(source: &File, destination: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let a = source.metadata()?;
    let b = destination.metadata()?;
    if (a.dev(), a.ino()) == (b.dev(), b.ino()) {
        return Err(Error::Conflict("source and destination cannot alias"));
    }
    Ok(())
}

#[cfg(unix)]
fn copy(source: &File, destination: &File, length: u64) -> Result<Digest> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::FileExt;
    let mut buffer = [0u8; MAX_STREAM_BYTES];
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(buffer.len() as u64) as usize;
        source.read_exact_at(&mut buffer[..count], offset)?;
        destination.write_all_at(&buffer[..count], offset)?;
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(format!("{:x}", hash.finalize()).try_into()?)
}

#[cfg(unix)]
fn content_digest(file: &File, length: u64) -> Result<Digest> {
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::FileExt;
    let mut buffer = [0u8; MAX_STREAM_BYTES];
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(buffer.len() as u64) as usize;
        file.read_exact_at(&mut buffer[..count], offset)?;
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(format!("{:x}", hash.finalize()).try_into()?)
}

#[cfg(unix)]
fn free_bytes(file: &File) -> Result<u64> {
    use std::os::fd::AsRawFd;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: fstatvfs fills the provided structure for a live file descriptor.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful call initialized every field of this structure.
    let value = unsafe { value.assume_init() };
    (value.f_bavail as u128 * value.f_frsize as u128)
        .try_into()
        .map_err(|_| Error::Capacity("filesystem capacity exceeds accounting range"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reserve(file: &File, length: u64, headroom: u64) -> Result<()> {
    use std::os::fd::AsRawFd;
    let required = length
        .checked_add(headroom)
        .ok_or(Error::Capacity("disk reservation overflow"))?;
    if free_bytes(file)? < required {
        return Err(Error::Capacity(
            "disk copy would consume host control headroom",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: posix_fallocate receives a held regular file and bounded positive length.
        let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, length as libc::off_t) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result).into());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let mut request = libc::fstore_t {
            fst_flags: libc::F_ALLOCATEALL,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: length as libc::off_t,
            fst_bytesalloc: 0,
        };
        // SAFETY: F_PREALLOCATE reads/writes the live fstore_t for this owned regular file.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut request) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if request.fst_bytesalloc < length as libc::off_t {
            return Err(Error::Capacity("native disk reservation is incomplete"));
        }
    }
    file.set_len(length)?;
    if free_bytes(file)? < headroom {
        return Err(Error::Capacity(
            "host headroom changed during disk reservation",
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reserve(_: &File, _: u64, _: u64) -> Result<()> {
    Err(Error::Unsupported(
        "native physical raw-disk reservation is not implemented on this host",
    ))
}
#[cfg(not(unix))]
fn ensure_distinct(_: &File, _: &File) -> Result<()> {
    Err(Error::Unsupported(
        "native disk identity is not implemented on this host",
    ))
}
#[cfg(not(unix))]
fn copy(_: &File, _: &File, _: u64) -> Result<Digest> {
    Err(Error::Unsupported(
        "native disk copying is not implemented on this host",
    ))
}

#[cfg(not(unix))]
fn content_digest(_: &File, _: u64) -> Result<Digest> {
    Err(Error::Unsupported(
        "native disk readback is not implemented on this host",
    ))
}
