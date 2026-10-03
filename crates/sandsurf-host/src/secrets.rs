use hmac::{Hmac, Mac};
use sandsurf_native::storage::object_name;
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
        let root = sandsurf_native::local::canonical_private_directory(root)?;
        // The API service and the independently supervised image pool both
        // open this store. Initialization is one storage transaction, not a
        // check-then-rename that can replace another owner's integrity key.
        let _custody = sandsurf_native::storage::disk_lease(&root.join(".integrity-key.lock"))?;
        let key_path = root.join(".integrity-key");
        let temporary = root.join(".integrity-key.pending");
        let key_missing = match fs::symlink_metadata(&key_path) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        if key_missing {
            // Losing a published key is corruption, not an empty store. Never
            // manufacture a new authority for already retained secret bytes.
            for entry in fs::read_dir(&root)?.take(3) {
                let name = entry?.file_name();
                if name != ".integrity-key.lock" && name != ".integrity-key.pending" {
                    return Err(SecretError::Invalid(
                        "secret integrity key is missing from a populated store; store preserved",
                    ));
                }
            }
        }
        reclaim_key_stage(&temporary, &root)?;
        if key_missing {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(&mut *key)
                .map_err(|_| SecretError::Invalid("secret integrity entropy unavailable"))?;
            let mut file = sandsurf_native::local::create_private_file(&temporary)?;
            file.write_all(&*key)?;
            sandsurf_native::storage::sync_file(&file)?;
            drop(file);
            sandsurf_native::storage::publish_new_file(&temporary, &key_path)?;
            sync_directory(&root)?;
            reclaim_key_stage(&temporary, &root)?;
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
            root,
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
        let directory = self.root.join(object_name(id.as_str()));
        sandsurf_native::local::ensure_private_directory(&directory)?;
        let name = object_name(version.as_str());
        let path = directory.join(&name);
        // One physical writer owns this version and its unpublished stage.
        // A crash releases the lease; an exact retry reclaims interrupted bytes
        // without scanning or deleting another version's active preparation.
        let _custody =
            sandsurf_native::storage::disk_lease(&directory.join(format!(".{name}.lock")))?;
        let temporary = directory.join(format!(".{name}.pending"));
        match fs::remove_file(&temporary) {
            Ok(()) => sync_directory(&directory)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let exists = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if exists {
            if Zeroizing::new(self.read(&id, &version)?).as_slice() != bytes {
                return Err(SecretError::Conflict(
                    "opaque secret version already has different bytes",
                ));
            }
        } else {
            let result = (|| {
                let mut file = sandsurf_native::local::create_private_file(&temporary)?;
                file.write_all(MAGIC)?;
                file.write_all(&self.mac(&id, &version, bytes).finalize().into_bytes())?;
                file.write_all(&(bytes.len() as u64).to_be_bytes())?;
                file.write_all(bytes)?;
                sandsurf_native::storage::sync_file(&file)?;
                drop(file);
                // Catalog admission is not a filesystem writer lease. Concurrent
                // admitted effects must never replace an immutable version.
                match sandsurf_native::storage::publish_new_file(&temporary, &path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        if Zeroizing::new(self.read(&id, &version)?).as_slice() != bytes {
                            return Err(SecretError::Conflict(
                                "opaque secret version already has different bytes",
                            ));
                        }
                        Ok(())
                    }
                    Err(error) => Err(error.into()),
                }
            })();
            match fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            result?;
        }
        // A racing identical publication can observe the name before its
        // original publisher's directory fsync. This caller commits it too.
        sync_directory(&directory)?;
        Ok(SecretVersion {
            id,
            version,
            bytes: Counter::try_from(bytes.len() as u64)
                .map_err(|_| SecretError::Invalid("secret length cannot be represented"))?,
        })
    }

    pub fn read(&self, id: &SecretId, version: &SecretVersionId) -> Result<Vec<u8>, SecretError> {
        let mut file = sandsurf_native::local::open_private_file(
            &self
                .root
                .join(object_name(id.as_str()))
                .join(object_name(version.as_str())),
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
        let mut bytes = Zeroizing::new(vec![0; declared as usize]);
        file.read_exact(&mut bytes)?;
        self.mac(id, version, &bytes)
            .verify_slice(&header[8..40])
            .map_err(|_| SecretError::Conflict("private secret integrity check failed"))?;
        Ok(std::mem::take(&mut *bytes))
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
// Only the sole key writer may reclaim this exact unpublished object. Unknown
// files, foreign owners, links and oversized bytes never acquire that owner.
fn reclaim_key_stage(path: &Path, root: &Path) -> Result<(), SecretError> {
    let file = match sandsurf_native::local::open_private_file(
        path,
        sandsurf_native::PrivateFileAccess::ReadOnly,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > 32 {
        return Err(SecretError::Invalid(
            "unowned secret integrity-key stage; store preserved",
        ));
    }
    drop(file);
    fs::remove_file(path)?;
    sync_directory(root)?;
    Ok(())
}
fn sync_directory(path: &Path) -> io::Result<()> {
    sandsurf_native::storage::sync_directory(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn fresh_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sandsurf-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn concurrent_store_open_has_one_integrity_key_and_all_versions_remain_readable() {
        use std::sync::{Arc, Barrier};
        let root = fresh_root("secret-key-race");
        sandsurf_native::local::ensure_private_directory(&root).unwrap();
        let barrier = Arc::new(Barrier::new(16));
        let commitments = std::thread::scope(|scope| {
            let workers = (0..16)
                .map(|index| {
                    let root = &root;
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(5);
                        let authority = loop {
                            match SecretAuthority::open(root) {
                                Err(SecretError::Io(error))
                                    if error.kind() == io::ErrorKind::WouldBlock =>
                                {
                                    assert!(std::time::Instant::now() < deadline);
                                    std::thread::sleep(std::time::Duration::from_millis(1));
                                }
                                result => break result.unwrap(),
                            }
                        };
                        let id: SecretId = format!("secret-{index}").try_into().unwrap();
                        let version: SecretVersionId = "version".try_into().unwrap();
                        authority.put(id, version, b"immutable secret").unwrap();
                        authority
                            .commitment(
                                &"same-id".try_into().unwrap(),
                                &"same-version".try_into().unwrap(),
                                b"same bytes",
                            )
                            .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(commitments.iter().all(|value| value == &commitments[0]));
        let authority = SecretAuthority::open(&root).unwrap();
        for index in 0..16 {
            assert_eq!(
                authority
                    .read(
                        &format!("secret-{index}").try_into().unwrap(),
                        &"version".try_into().unwrap()
                    )
                    .unwrap(),
                b"immutable secret"
            );
        }
        assert!(!root.join(".integrity-key.pending").exists());
        drop(authority);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_published_key_is_corruption_not_permission_to_reinitialize() {
        let root = fresh_root("secret-missing-key");
        let authority = SecretAuthority::open(&root).unwrap();
        authority
            .put(
                "secret".try_into().unwrap(),
                "version".try_into().unwrap(),
                b"retained",
            )
            .unwrap();
        drop(authority);
        let object = root
            .join(object_name("secret"))
            .join(object_name("version"));
        let before = fs::read(&object).unwrap();
        fs::remove_file(root.join(".integrity-key")).unwrap();
        assert!(matches!(
            SecretAuthority::open(&root),
            Err(SecretError::Invalid(_))
        ));
        assert!(!root.join(".integrity-key").exists());
        assert_eq!(fs::read(object).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_key_publication_is_reclaimed_only_under_original_writer_custody() {
        let root = fresh_root("secret-key-interruption");
        sandsurf_native::local::ensure_private_directory(&root).unwrap();
        let stage = root.join(".integrity-key.pending");
        let custody =
            sandsurf_native::storage::disk_lease(&root.join(".integrity-key.lock")).unwrap();
        let mut file = sandsurf_native::local::create_private_file(&stage).unwrap();
        file.write_all(b"interrupted").unwrap();
        drop(file);
        assert!(
            matches!(SecretAuthority::open(&root), Err(SecretError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(fs::read(&stage).unwrap(), b"interrupted");
        drop(custody);
        let authority = SecretAuthority::open(&root).unwrap();
        let key = fs::read(root.join(".integrity-key")).unwrap();
        assert_eq!(key.len(), 32);
        assert!(!stage.exists());
        // A crash after key publication but before unlinking its stage must
        // neither rotate the key nor retain the unfinished secret-bearing file.
        let mut file = sandsurf_native::local::create_private_file(&stage).unwrap();
        file.write_all(&key).unwrap();
        drop(file);
        let reopened = SecretAuthority::open(&root).unwrap();
        assert_eq!(fs::read(root.join(".integrity-key")).unwrap(), key);
        assert!(!stage.exists());
        drop((authority, reopened));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn initialization_refuses_unowned_key_stages_and_unknown_store_contents() {
        let root = fresh_root("secret-unowned-key-stage");
        sandsurf_native::local::ensure_private_directory(&root).unwrap();
        let stage = root.join(".integrity-key.pending");
        let mut file = sandsurf_native::local::create_private_file(&stage).unwrap();
        file.write_all(&[7; 33]).unwrap();
        drop(file);
        assert!(SecretAuthority::open(&root).is_err());
        assert_eq!(fs::read(&stage).unwrap(), [7; 33]);
        assert!(!root.join(".integrity-key").exists());
        fs::remove_file(&stage).unwrap();
        fs::write(root.join("unowned"), b"preserve").unwrap();
        assert!(SecretAuthority::open(&root).is_err());
        assert_eq!(fs::read(root.join("unowned")).unwrap(), b"preserve");
        assert!(!root.join(".integrity-key").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn secret_identities_and_versions_do_not_inherit_host_filename_semantics() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-secret-addresses-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let authority = SecretAuthority::open(&root).unwrap();
        for name in ["CON", "con", "Secret", "secret"] {
            let id: SecretId = name.try_into().unwrap();
            for version_name in ["Version", "version"] {
                let version: SecretVersionId = version_name.try_into().unwrap();
                let bytes = format!("{name}:{version_name}");
                authority
                    .put(id.clone(), version.clone(), bytes.as_bytes())
                    .unwrap();
                assert_eq!(
                    authority.read(&id, &version).unwrap().as_slice(),
                    bytes.as_bytes()
                );
            }
        }
        for name in ["CON", "con", "Secret", "secret"] {
            let id: SecretId = name.try_into().unwrap();
            for version_name in ["Version", "version"] {
                assert_eq!(
                    authority
                        .read(&id, &version_name.try_into().unwrap())
                        .unwrap()
                        .as_slice(),
                    format!("{name}:{version_name}").as_bytes()
                );
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_publication_never_replaces_an_opaque_version_or_leaves_stages() {
        use std::sync::{Arc, Barrier};
        let root = std::env::temp_dir().join(format!(
            "sandsurf-concurrent-secrets-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let authority = Arc::new(SecretAuthority::open(&root).unwrap());
        let version: SecretVersionId = "immutable-version".try_into().unwrap();
        for identical in [false, true] {
            let id: SecretId = format!("secret-{identical}").try_into().unwrap();
            let barrier = Arc::new(Barrier::new(8));
            let results = std::thread::scope(|scope| {
                let workers = (0..8)
                    .map(|index| {
                        let authority = Arc::clone(&authority);
                        let barrier = Arc::clone(&barrier);
                        let id = id.clone();
                        let version = version.clone();
                        scope.spawn(move || {
                            let marker = if identical { 9 } else { index };
                            let bytes = Zeroizing::new(vec![marker; MAX_SECRET_BYTES]);
                            barrier.wait();
                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(5);
                            loop {
                                match authority.put(id.clone(), version.clone(), &bytes) {
                                    Err(SecretError::Io(error))
                                        if error.kind() == io::ErrorKind::WouldBlock =>
                                    {
                                        assert!(
                                            std::time::Instant::now() < deadline,
                                            "writer custody did not release"
                                        );
                                        std::thread::sleep(std::time::Duration::from_millis(1));
                                    }
                                    result => break (marker, result),
                                }
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                workers
                    .into_iter()
                    .map(|worker| worker.join().unwrap())
                    .collect::<Vec<_>>()
            });
            let successes = results.iter().filter(|(_, result)| result.is_ok()).count();
            assert_eq!(successes, if identical { 8 } else { 1 });
            let actual = Zeroizing::new(authority.read(&id, &version).unwrap());
            assert_eq!(actual.len(), MAX_SECRET_BYTES);
            for (marker, result) in results {
                match result {
                    Ok(_) => assert!(
                        actual.iter().all(|byte| *byte == marker),
                        "a successful publisher's immutable bytes were replaced"
                    ),
                    Err(SecretError::Conflict(_)) => assert!(!identical),
                    Err(error) => panic!("unexpected publication failure: {error}"),
                }
            }
            let directory = root.join(object_name(id.as_str()));
            let entries = fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), 2);
            assert!(entries.contains(&std::ffi::OsString::from(object_name(version.as_str()))));
            assert!(
                entries.contains(&std::ffi::OsString::from(format!(
                    ".{}.lock",
                    object_name(version.as_str())
                ))),
                "a competing publication left secret-bearing pending bytes behind"
            );
        }
        drop(authority);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_secret_stage_is_reclaimed_only_under_its_version_custody() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-interrupted-secret-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let authority = SecretAuthority::open(&root).unwrap();
        let id: SecretId = "credential".try_into().unwrap();
        let version: SecretVersionId = "version".try_into().unwrap();
        let directory = root.join(object_name(id.as_str()));
        sandsurf_native::local::ensure_private_directory(&directory).unwrap();
        let name = object_name(version.as_str());
        let stage = directory.join(format!(".{name}.pending"));
        let unrelated = directory.join(".another-version.pending");
        fs::write(&stage, b"interrupted plaintext").unwrap();
        fs::write(&unrelated, b"other preparation").unwrap();
        let custody =
            sandsurf_native::storage::disk_lease(&directory.join(format!(".{name}.lock"))).unwrap();
        assert!(
            matches!(authority.put(id.clone(), version.clone(), b"published"),
            Err(SecretError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(fs::read(&stage).unwrap(), b"interrupted plaintext");
        drop(custody);
        drop(authority);
        let authority = SecretAuthority::open(&root).unwrap();
        authority
            .put(id.clone(), version.clone(), b"published")
            .unwrap();
        assert!(!stage.exists());
        assert_eq!(fs::read(unrelated).unwrap(), b"other preparation");
        assert_eq!(authority.read(&id, &version).unwrap(), b"published");
        assert!(
            authority
                .put(id.clone(), version.clone(), b"different")
                .is_err()
        );
        assert_eq!(authority.read(&id, &version).unwrap(), b"published");
        drop(authority);
        fs::remove_dir_all(root).unwrap();
    }

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
        let object = root
            .join(object_name(id.as_str()))
            .join(object_name(first.version.as_str()));
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
