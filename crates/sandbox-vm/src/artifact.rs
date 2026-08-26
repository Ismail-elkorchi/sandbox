use sandbox_digest::identity_digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactBundle {
    pub format_version: u32,
    pub digest: String,
    pub files: Vec<ArtifactEntry>,
    pub omissions: Vec<ImportOmission>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactEntry {
    pub path: String,
    pub kind: ArtifactKind,
    pub mode: u32,
    pub modified_unix_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    Directory,
    RegularFile,
    SymbolicLink,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportOmission {
    pub path: String,
    pub metadata: String,
    pub behavior: String,
}

#[derive(Debug)]
pub enum ArtifactError {
    Io(io::Error),
    InvalidPath(String),
    Unsupported(String),
    LimitExceeded,
    Digest(String),
}

impl Display for ArtifactError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "artifact I/O error: {error}"),
            Self::InvalidPath(path) => write!(formatter, "invalid artifact path: {path}"),
            Self::Unsupported(path) => write!(formatter, "unsupported artifact object: {path}"),
            Self::LimitExceeded => formatter.write_str("artifact byte limit exceeded"),
            Self::Digest(message) => write!(formatter, "artifact digest error: {message}"),
        }
    }
}

impl std::error::Error for ArtifactError {}

impl From<io::Error> for ArtifactError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn collect_artifacts(
    root: &Path,
    requested_paths: &[String],
    maximum_bytes: u64,
) -> Result<ArtifactBundle, ArtifactError> {
    if maximum_bytes == 0 || requested_paths.len() > 65_536 {
        return Err(ArtifactError::LimitExceeded);
    }
    let canonical_root = fs::canonicalize(root)?;
    let root_metadata = fs::metadata(&canonical_root)?;
    #[cfg(unix)]
    let root_device = {
        use std::os::unix::fs::MetadataExt;
        root_metadata.dev()
    };
    let mut files = Vec::new();
    let mut total = 0_u64;
    let mut seen_hardlinks = HashSet::new();
    #[cfg(target_os = "linux")]
    let root_descriptor = open_beneath_root(&canonical_root)?;
    for requested in requested_paths {
        validate_relative(requested)?;
        #[cfg(target_os = "linux")]
        {
            let object = open_beneath(root_descriptor.as_raw_fd(), Path::new(requested))?;
            walk_descriptor(
                object,
                requested,
                &mut files,
                &mut total,
                maximum_bytes,
                root_device,
                &mut seen_hardlinks,
            )?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let path = canonical_root.join(requested);
            walk(
                &canonical_root,
                &path,
                &mut files,
                &mut total,
                maximum_bytes,
                #[cfg(unix)]
                root_device,
                &mut seen_hardlinks,
            )?;
        }
    }
    finish_bundle(files)
}

fn finish_bundle(mut files: Vec<ArtifactEntry>) -> Result<ArtifactBundle, ArtifactError> {
    files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    files.dedup_by(|left, right| left.path == right.path);
    let digest =
        identity_digest(&files).map_err(|error| ArtifactError::Digest(error.to_string()))?;
    Ok(ArtifactBundle {
        format_version: 1,
        digest,
        files,
        omissions: vec![
            ImportOmission {
                path: "*".into(),
                metadata: "extended-attributes".into(),
                behavior: "omitted".into(),
            },
            ImportOmission {
                path: "*".into(),
                metadata: "access-control-lists".into(),
                behavior: "omitted".into(),
            },
        ],
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn collect_open_directory(
    directory: &File,
    maximum_bytes: u64,
) -> Result<ArtifactBundle, ArtifactError> {
    if maximum_bytes == 0 {
        return Err(ArtifactError::LimitExceeded);
    }
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(ArtifactError::Unsupported(".".into()));
    }
    let mut names = fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    if names.len() > 65_536 {
        return Err(ArtifactError::LimitExceeded);
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut files = Vec::new();
    let mut total = 0_u64;
    let mut hardlinks = HashSet::new();
    for name in names {
        let name = name
            .to_str()
            .filter(|name| *name != "." && *name != "..")
            .ok_or_else(|| ArtifactError::InvalidPath(".".into()))?;
        let child = open_beneath(directory.as_raw_fd(), Path::new(name))?;
        walk_descriptor(
            child,
            name,
            &mut files,
            &mut total,
            maximum_bytes,
            metadata.dev(),
            &mut hardlinks,
        )?;
    }
    finish_bundle(files)
}

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "linux")]
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[cfg(target_os = "linux")]
const RESOLVE_BENEATH: u64 = 0x08;
#[cfg(target_os = "linux")]
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
fn open_beneath_root(path: &Path) -> Result<File, ArtifactError> {
    use std::os::unix::fs::OpenOptionsExt;

    Ok(fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(target_os = "linux")]
fn open_beneath(directory_fd: RawFd, relative: &Path) -> Result<File, ArtifactError> {
    let relative = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| ArtifactError::InvalidPath(relative.display().to_string()))?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: relative and how are initialized live buffers, directory_fd is retained by the
    // caller, and a successful syscall returns one newly owned descriptor.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory_fd,
            relative.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        return Err(ArtifactError::Io(io::Error::last_os_error()));
    }
    // SAFETY: the successful openat2 result is a fresh descriptor transferred exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor as RawFd) })
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn walk_descriptor(
    object: File,
    relative: &str,
    output: &mut Vec<ArtifactEntry>,
    total: &mut u64,
    maximum: u64,
    root_device: u64,
    hardlinks: &mut HashSet<(u64, u64)>,
) -> Result<(), ArtifactError> {
    if output.len() >= 65_536 {
        return Err(ArtifactError::LimitExceeded);
    }
    let metadata = object.metadata()?;
    if metadata.dev() != root_device {
        return Err(ArtifactError::Unsupported(relative.into()));
    }
    let (mode, modified_unix_ms) = portable_metadata(&metadata);
    if metadata.is_dir() {
        output.push(ArtifactEntry {
            path: relative.into(),
            kind: ArtifactKind::Directory,
            mode,
            modified_unix_ms,
            content_hex: None,
            link_target: None,
            sha256: None,
        });
        let descriptor_path = format!("/proc/self/fd/{}", object.as_raw_fd());
        let mut names = fs::read_dir(descriptor_path)?
            .map(|entry| entry.map(|value| value.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        if names.len() > 65_536_usize.saturating_sub(output.len()) {
            return Err(ArtifactError::LimitExceeded);
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for name in names {
            let name_text = name
                .to_str()
                .filter(|name| *name != "." && *name != "..")
                .ok_or_else(|| ArtifactError::InvalidPath(relative.into()))?;
            let child_relative = format!("{relative}/{name_text}");
            let child = open_beneath(object.as_raw_fd(), Path::new(name_text))?;
            walk_descriptor(
                child,
                &child_relative,
                output,
                total,
                maximum,
                root_device,
                hardlinks,
            )?;
        }
    } else if metadata.is_file() {
        if metadata.nlink() > 1 && !hardlinks.insert((metadata.dev(), metadata.ino())) {
            return Err(ArtifactError::Unsupported(relative.into()));
        }
        let remaining = maximum
            .checked_sub(*total)
            .ok_or(ArtifactError::LimitExceeded)?;
        if metadata.size() > remaining {
            return Err(ArtifactError::LimitExceeded);
        }
        let mut reader = File::open(format!("/proc/self/fd/{}", object.as_raw_fd()))?;
        let opened = reader.metadata()?;
        if !same_identity(&metadata, &opened) {
            return Err(ArtifactError::Unsupported(relative.into()));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut reader)
            .take(remaining.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > remaining {
            return Err(ArtifactError::LimitExceeded);
        }
        let after = reader.metadata()?;
        if !same_identity(&opened, &after) {
            return Err(ArtifactError::Unsupported(format!(
                "{relative} changed while it was copied"
            )));
        }
        *total += bytes.len() as u64;
        output.push(ArtifactEntry {
            path: relative.into(),
            kind: ArtifactKind::RegularFile,
            mode,
            modified_unix_ms,
            content_hex: Some(encode_hex(&bytes)),
            link_target: None,
            sha256: Some(format!("{:x}", Sha256::digest(&bytes))),
        });
    } else if metadata.file_type().is_symlink() {
        let target = read_link_descriptor(object.as_raw_fd())?;
        let target = target
            .to_str()
            .filter(|target| !target.contains('\0'))
            .ok_or_else(|| ArtifactError::InvalidPath(relative.into()))?;
        output.push(ArtifactEntry {
            path: relative.into(),
            kind: ArtifactKind::SymbolicLink,
            mode,
            modified_unix_ms,
            content_hex: None,
            link_target: Some(target.into()),
            sha256: None,
        });
    } else {
        return Err(ArtifactError::Unsupported(relative.into()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_link_descriptor(descriptor: RawFd) -> Result<std::ffi::OsString, ArtifactError> {
    let empty = c"";
    let mut bytes = vec![0_u8; 16 * 1024];
    // SAFETY: descriptor is a retained O_PATH symlink descriptor, empty requests AT_EMPTY_PATH
    // semantics, and bytes is writable for its full advertised length.
    let count = unsafe {
        libc::readlinkat(
            descriptor,
            empty.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(ArtifactError::Io(io::Error::last_os_error()));
    }
    let count = usize::try_from(count).map_err(|_| ArtifactError::LimitExceeded)?;
    if count == bytes.len() {
        return Err(ArtifactError::LimitExceeded);
    }
    bytes.truncate(count);
    Ok(std::ffi::OsString::from_vec(bytes))
}

#[cfg(target_os = "linux")]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

/// Validate an artifact bundle received across a trust boundary without
/// touching the host filesystem.
pub fn validate_artifact_bundle(
    bundle: &ArtifactBundle,
    maximum_bytes: u64,
) -> Result<(), ArtifactError> {
    if bundle.format_version != 1 || bundle.files.len() > 65_536 || maximum_bytes == 0 {
        return Err(ArtifactError::LimitExceeded);
    }
    if bundle.omissions.len() > 256 {
        return Err(ArtifactError::LimitExceeded);
    }
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    for entry in &bundle.files {
        validate_relative(&entry.path)?;
        if previous.is_some_and(|path| path.as_bytes() >= entry.path.as_bytes()) {
            return Err(ArtifactError::InvalidPath(entry.path.clone()));
        }
        previous = Some(&entry.path);
        if entry.mode > 0o7777 {
            return Err(ArtifactError::Unsupported(entry.path.clone()));
        }
        match entry.kind {
            ArtifactKind::RegularFile => {
                if entry.link_target.is_some() {
                    return Err(ArtifactError::Unsupported(entry.path.clone()));
                }
                let content = entry
                    .content_hex
                    .as_deref()
                    .ok_or_else(|| ArtifactError::Unsupported(entry.path.clone()))?;
                let content = decode_hex(content)?;
                total = total
                    .checked_add(content.len() as u64)
                    .ok_or(ArtifactError::LimitExceeded)?;
                if total > maximum_bytes {
                    return Err(ArtifactError::LimitExceeded);
                }
                let expected = entry
                    .sha256
                    .as_deref()
                    .filter(|value| valid_sha256(value))
                    .ok_or_else(|| ArtifactError::Digest(entry.path.clone()))?;
                if format!("{:x}", Sha256::digest(&content)) != expected {
                    return Err(ArtifactError::Digest(entry.path.clone()));
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
                    return Err(ArtifactError::Unsupported(entry.path.clone()));
                }
            }
            ArtifactKind::Directory => {
                if entry.content_hex.is_some()
                    || entry.sha256.is_some()
                    || entry.link_target.is_some()
                {
                    return Err(ArtifactError::Unsupported(entry.path.clone()));
                }
            }
        }
    }
    for omission in &bundle.omissions {
        if omission.path.len() > 16 * 1024
            || omission.metadata.len() > 256
            || omission.behavior.len() > 256
            || omission.path.contains('\0')
            || omission.metadata.contains('\0')
            || omission.behavior.contains('\0')
        {
            return Err(ArtifactError::InvalidPath(omission.path.clone()));
        }
    }
    if !valid_sha256(&bundle.digest) {
        return Err(ArtifactError::Digest("invalid bundle digest".into()));
    }
    let actual =
        identity_digest(&bundle.files).map_err(|error| ArtifactError::Digest(error.to_string()))?;
    if actual != bundle.digest {
        return Err(ArtifactError::Digest("bundle digest mismatch".into()));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(target_os = "linux"))]
fn walk(
    root: &Path,
    path: &Path,
    output: &mut Vec<ArtifactEntry>,
    total: &mut u64,
    maximum: u64,
    #[cfg(unix)] root_device: u64,
    hardlinks: &mut HashSet<(u64, u64)>,
) -> Result<(), ArtifactError> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != root_device {
            return Err(ArtifactError::Unsupported(relative_text(root, path)?));
        }
    }
    let relative = relative_text(root, path)?;
    let (mode, modified_unix_ms) = portable_metadata(&metadata);
    if metadata.is_dir() {
        output.push(ArtifactEntry {
            path: relative,
            kind: ArtifactKind::Directory,
            mode,
            modified_unix_ms,
            content_hex: None,
            link_target: None,
            sha256: None,
        });
        let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            walk(
                root,
                &child.path(),
                output,
                total,
                maximum,
                #[cfg(unix)]
                root_device,
                hardlinks,
            )?;
        }
    } else if metadata.is_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() > 1 && !hardlinks.insert((metadata.dev(), metadata.ino())) {
                return Err(ArtifactError::Unsupported(relative));
            }
        }
        let bytes = fs::read(path)?;
        *total = total
            .checked_add(bytes.len() as u64)
            .ok_or(ArtifactError::LimitExceeded)?;
        if *total > maximum {
            return Err(ArtifactError::LimitExceeded);
        }
        output.push(ArtifactEntry {
            path: relative,
            kind: ArtifactKind::RegularFile,
            mode,
            modified_unix_ms,
            content_hex: Some(encode_hex(&bytes)),
            link_target: None,
            sha256: Some(format!("{:x}", Sha256::digest(&bytes))),
        });
    } else if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        let target = target
            .to_str()
            .ok_or_else(|| ArtifactError::InvalidPath(relative.clone()))?;
        if target.contains('\0') {
            return Err(ArtifactError::InvalidPath(relative));
        }
        output.push(ArtifactEntry {
            path: relative,
            kind: ArtifactKind::SymbolicLink,
            mode,
            modified_unix_ms,
            content_hex: None,
            link_target: Some(target.into()),
            sha256: None,
        });
    } else {
        return Err(ArtifactError::Unsupported(relative));
    }
    Ok(())
}

pub(crate) fn validate_relative(path: &str) -> Result<(), ArtifactError> {
    let path_value = Path::new(path);
    if path.is_empty()
        || path.contains('\0')
        || path_value.is_absolute()
        || path_value
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArtifactError::InvalidPath(path.into()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn relative_text(root: &Path, path: &Path) -> Result<String, ArtifactError> {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ArtifactError::InvalidPath(path.display().to_string()))
}

fn portable_metadata(metadata: &fs::Metadata) -> (u32, i64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let milliseconds = metadata
            .mtime()
            .saturating_mul(1000)
            .saturating_add(metadata.mtime_nsec() / 1_000_000);
        (metadata.mode() & 0o7777, milliseconds)
    }
    #[cfg(not(unix))]
    {
        let milliseconds = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|value| i64::try_from(value.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        (
            if metadata.permissions().readonly() {
                0o444
            } else {
                0o644
            },
            milliseconds,
        )
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, ArtifactError> {
    if !value.len().is_multiple_of(2) {
        return Err(ArtifactError::InvalidPath(
            "invalid content encoding".into(),
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| ArtifactError::InvalidPath("invalid content encoding".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandbox-artifact-{label}-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn collected_bundle_validates_and_tampering_fails() {
        let bytes = b"artifact";
        let mut files = vec![ArtifactEntry {
            path: "output.txt".into(),
            kind: ArtifactKind::RegularFile,
            mode: 0o644,
            modified_unix_ms: 0,
            content_hex: Some(encode_hex(bytes)),
            link_target: None,
            sha256: Some(format!("{:x}", Sha256::digest(bytes))),
        }];
        let digest = identity_digest(&files).unwrap();
        let mut bundle = ArtifactBundle {
            format_version: 1,
            digest,
            files: files.clone(),
            omissions: Vec::new(),
        };
        validate_artifact_bundle(&bundle, 1024).unwrap();
        bundle.files[0].content_hex = Some("00".into());
        assert!(validate_artifact_bundle(&bundle, 1024).is_err());
        files.push(files[0].clone());
        let duplicate = ArtifactBundle {
            format_version: 1,
            digest: identity_digest(&files).unwrap(),
            files,
            omissions: Vec::new(),
        };
        assert!(validate_artifact_bundle(&duplicate, 1024).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collection_never_follows_symbolic_links_outside_its_root() {
        let root = TestDirectory::new("root");
        let outside = TestDirectory::new("outside");
        fs::create_dir(root.0.join("workspace")).unwrap();
        fs::write(outside.0.join("secret"), b"host-secret").unwrap();
        std::os::unix::fs::symlink(&outside.0, root.0.join("workspace/link")).unwrap();

        let bundle = collect_artifacts(&root.0, &["workspace".into()], 1024).unwrap();
        let link = bundle
            .files
            .iter()
            .find(|entry| entry.path == "workspace/link")
            .unwrap();
        assert_eq!(link.kind, ArtifactKind::SymbolicLink);
        assert_eq!(link.content_hex, None);
        assert!(collect_artifacts(&root.0, &["workspace/link/secret".into()], 1024).is_err());
    }
}
