use hmac::{Hmac, Mac};
use sandsurf_protocol::{Counter, Digest, SecretId, SecretVersion, SecretVersionId};
use sha2::Sha256;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8; 8] = b"SSFSEC1\0";
const HEADER_BYTES: usize = 48;
type IntegrityMac = Hmac<Sha256>;

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
    integrity_key: Zeroizing<[u8; 32]>,
}

impl SecretAuthority {
    pub fn open(root: &Path) -> Result<Self, SecretError> {
        sandsurf_native::local::ensure_private_directory(root)?;
        let key_path = root.join(".integrity-key");
        let key_missing = match fs::symlink_metadata(&key_path) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        if key_missing {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(&mut *key)
                .map_err(|_| SecretError::Invalid("secret integrity entropy unavailable"))?;
            let temporary = root.join(format!(".integrity-key-{}.pending", random_nonce()?));
            let mut file = sandsurf_native::local::create_private_file(&temporary)?;
            file.write_all(&*key)?;
            sandsurf_native::storage::sync_file(&file)?;
            drop(file);
            fs::rename(&temporary, &key_path)?;
            sync_directory(root)?;
        }
        let mut file = sandsurf_native::local::open_private_file(
            &key_path,
            sandsurf_native::PrivateFileAccess::ReadOnly,
        )?;
        if file.metadata()?.len() != 32 {
            return Err(SecretError::Invalid(
                "secret integrity key is malformed; store preserved",
            ));
        }
        let mut integrity_key = Zeroizing::new([0u8; 32]);
        file.read_exact(&mut *integrity_key)?;
        Ok(Self {
            root: root.to_path_buf(),
            integrity_key,
        })
    }

    fn mac(&self, id: &SecretId, version: &SecretVersionId, bytes: &[u8]) -> IntegrityMac {
        let mut mac =
            IntegrityMac::new_from_slice(&*self.integrity_key).expect("fixed integrity key length");
        mac.update(b"sandsurf-private-secret-integrity-v1");
        for value in [id.as_str().as_bytes(), version.as_str().as_bytes(), bytes] {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value);
        }
        mac
    }

    /// An opaque host-keyed commitment, never a public plaintext hash.
    pub fn commitment(
        &self,
        id: &SecretId,
        version: &SecretVersionId,
        bytes: &[u8],
    ) -> Result<Digest, SecretError> {
        validate_bytes(bytes)?;
        let tag = self.mac(id, version, bytes).finalize().into_bytes();
        let value: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
        value
            .try_into()
            .map_err(|_| SecretError::Invalid("integrity tag encoding failed"))
    }

    pub fn put(
        &self,
        id: SecretId,
        version: SecretVersionId,
        bytes: &[u8],
    ) -> Result<SecretVersion, SecretError> {
        validate_bytes(bytes)?;
        let directory = self.root.join(id.as_str());
        sandsurf_native::local::ensure_private_directory(&directory)?;
        let path = directory.join(version.as_str());
        let exists = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if exists {
            if self.read(&id, &version)?.as_slice() != bytes {
                return Err(SecretError::Conflict(
                    "opaque secret version already has different bytes",
                ));
            }
        } else {
            let nonce = random_nonce()?;
            let temporary = directory.join(format!(".{nonce}.pending"));
            let mut file = sandsurf_native::local::create_private_file(&temporary)?;
            file.write_all(MAGIC)?;
            file.write_all(&self.mac(&id, &version, bytes).finalize().into_bytes())?;
            file.write_all(&(bytes.len() as u64).to_be_bytes())?;
            file.write_all(bytes)?;
            sandsurf_native::storage::sync_file(&file)?;
            drop(file);
            // The exclusively owned host catalog admits the version before publication.
            fs::rename(&temporary, &path)?;
            sync_directory(&directory)?;
        }
        Ok(SecretVersion {
            id,
            version,
            bytes: Counter::try_from(bytes.len() as u64)
                .map_err(|_| SecretError::Invalid("secret length cannot be represented"))?,
        })
    }

    pub fn read(&self, id: &SecretId, version: &SecretVersionId) -> Result<Vec<u8>, SecretError> {
        let mut file = sandsurf_native::local::open_private_file(
            &self.root.join(id.as_str()).join(version.as_str()),
            sandsurf_native::PrivateFileAccess::ReadOnly,
        )?;
        let length = file.metadata()?.len();
        if length <= HEADER_BYTES as u64 || length > (MAX_SECRET_BYTES + HEADER_BYTES) as u64 {
            return Err(SecretError::Invalid(
                "secret object size is outside its bound",
            ));
        }
        let mut header = [0u8; HEADER_BYTES];
        file.read_exact(&mut header)?;
        let declared = u64::from_be_bytes(header[40..48].try_into().expect("fixed length field"));
        if &header[..8] != MAGIC || declared.checked_add(HEADER_BYTES as u64) != Some(length) {
            return Err(SecretError::Invalid("secret object header is malformed"));
        }
        let mut bytes = vec![0; declared as usize];
        file.read_exact(&mut bytes)?;
        self.mac(id, version, &bytes)
            .verify_slice(&header[8..40])
            .map_err(|_| SecretError::Conflict("private secret integrity check failed"))?;
        Ok(bytes)
    }
}

fn validate_bytes(bytes: &[u8]) -> Result<(), SecretError> {
    if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
        return Err(SecretError::Invalid(
            "secret must contain 1 byte through 1 MiB",
        ));
    }
    Ok(())
}
fn random_nonce() -> Result<String, SecretError> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| SecretError::Invalid("secret publication entropy unavailable"))?;
    Ok(nonce.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn sync_directory(path: &Path) -> io::Result<()> {
    sandsurf_native::storage::sync_directory(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn opaque_versions_are_immutable_and_privately_integrity_checked() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-secrets-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = SecretAuthority::open(&root).unwrap();
        let id: SecretId = "registry-token".try_into().unwrap();
        let first = authority
            .put(id.clone(), "version-one".try_into().unwrap(), b"one")
            .unwrap();
        let second = authority
            .put(id.clone(), "version-two".try_into().unwrap(), b"one")
            .unwrap();
        assert_ne!(first.version, second.version); // Equal secrets need not expose equality.
        assert_eq!(authority.read(&id, &first.version).unwrap(), b"one");
        assert!(
            authority
                .put(id.clone(), first.version.clone(), b"two")
                .is_err()
        );
        let object = root.join(id.as_str()).join(first.version.as_str());
        let mut bytes = fs::read(&object).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&object, bytes).unwrap();
        assert!(authority.read(&id, &first.version).is_err());
        assert_eq!(
            SecretAuthority::open(&root)
                .unwrap()
                .read(&id, &second.version)
                .unwrap(),
            b"one"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
