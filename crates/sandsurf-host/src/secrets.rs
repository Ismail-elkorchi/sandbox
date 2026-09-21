use sandsurf_protocol::{Counter, Digest, SecretId, SecretVersion, bytes_digest};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_SECRET_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum SecretError {
    Io(io::Error),
    Invalid(&'static str),
    Conflict(&'static str),
}

impl fmt::Display for SecretError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "secret store: {error}"),
            Self::Invalid(message) | Self::Conflict(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for SecretError {}
impl From<io::Error> for SecretError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct SecretAuthority {
    root: PathBuf,
}

impl SecretAuthority {
    pub fn open(root: &Path) -> Result<Self, SecretError> {
        create_private_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn put(&self, id: SecretId, bytes: &[u8]) -> Result<SecretVersion, SecretError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretError::Invalid(
                "secret must contain 1 byte through 1 MiB",
            ));
        }
        let version = bytes_digest(bytes);
        let directory = self.root.join(id.as_str());
        create_private_directory(&directory)?;
        let path = directory.join(version.as_str());
        match private_new_file(&path) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
                sync_directory(&directory)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = self.read(&id, &version)?;
                if existing != bytes {
                    return Err(SecretError::Conflict(
                        "secret version path does not contain its digest-bound bytes",
                    ));
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(SecretVersion {
            id,
            version,
            bytes: Counter::try_from(bytes.len() as u64)
                .map_err(|_| SecretError::Invalid("secret length cannot be represented"))?,
        })
    }

    pub fn read(&self, id: &SecretId, version: &Digest) -> Result<Vec<u8>, SecretError> {
        let path = self.root.join(id.as_str()).join(version.as_str());
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
            return Err(SecretError::Invalid("secret object is not a regular file"));
        }
        if metadata.len() > MAX_SECRET_BYTES as u64 {
            return Err(SecretError::Invalid("secret object exceeds its bound"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?.read_to_end(&mut bytes)?;
        if bytes_digest(&bytes) != *version {
            return Err(SecretError::Conflict("secret object digest mismatch"));
        }
        Ok(bytes)
    }
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secret store object is not a directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    fs::DirBuilder::new().mode(0o700).create(path)?;
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}

fn private_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    // Windows requires backup-semantics when opening a directory handle. A
    // successful sync is the publication barrier for the version file.
    OpenOptions::new()
        .read(true)
        .custom_flags(0x0200_0000)
        .open(path)?
        .sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn versions_are_immutable_and_digest_bound() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-secrets-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = SecretAuthority::open(&root).unwrap();
        let id: SecretId = "registry-token".try_into().unwrap();
        let first = authority.put(id.clone(), b"one").unwrap();
        let second = authority.put(id.clone(), b"two").unwrap();
        assert_ne!(first.version, second.version);
        assert_eq!(authority.read(&id, &first.version).unwrap(), b"one");
        assert_eq!(authority.read(&id, &second.version).unwrap(), b"two");
        fs::remove_dir_all(root).unwrap();
    }
}
