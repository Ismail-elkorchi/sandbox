#![deny(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sandbox_digest::identity_digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_IMAGE_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageManifest {
    pub format_version: u32,
    pub id: String,
    pub version: String,
    pub architecture: Architecture,
    pub kernel: ImageArtifact,
    pub rootfs: RootfsArtifact,
    pub guest_agent: GuestAgentArtifact,
    pub capabilities: ImageCapabilities,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X64,
    Arm64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageArtifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootfsArtifact {
    pub path: String,
    pub sha256: String,
    pub format: RootfsFormat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RootfsFormat {
    Ext4,
    Erofs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestAgentArtifact {
    pub version: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageCapabilities {
    pub overlayfs: bool,
    pub vsock: bool,
    pub seccomp: bool,
    pub cgroup_v2: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageTrust<'a> {
    ExplicitLocal,
    Bundled {
        manifest_digest: &'a str,
        release_public_key: &'a [u8; 32],
    },
}

#[derive(Debug, Clone)]
pub struct VerifiedImage {
    pub manifest: ImageManifest,
    pub manifest_path: PathBuf,
    pub manifest_digest: String,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
}

#[derive(Debug)]
pub enum ImageError {
    Io(io::Error),
    Invalid(String),
    DigestMismatch(&'static str),
    Signature,
}

impl Display for ImageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "image I/O error: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid image manifest: {message}"),
            Self::DigestMismatch(name) => write!(formatter, "{name} digest mismatch"),
            Self::Signature => formatter.write_str("image manifest signature is invalid"),
        }
    }
}

impl std::error::Error for ImageError {}

impl From<io::Error> for ImageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn verify_image(path: &Path, trust: ImageTrust<'_>) -> Result<VerifiedImage, ImageError> {
    if !path.is_absolute() {
        return Err(ImageError::Invalid("manifest path must be absolute".into()));
    }
    let mut manifest_file = open_regular_bounded(path, 1024 * 1024, "manifest")?;
    let mut manifest_bytes = Vec::new();
    manifest_file.read_to_end(&mut manifest_bytes)?;
    let manifest_digest = hex_sha256(&manifest_bytes);
    let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ImageError::Invalid(error.to_string()))?;
    validate_image_manifest(&manifest)?;
    match trust {
        ImageTrust::ExplicitLocal => {}
        ImageTrust::Bundled {
            manifest_digest: expected,
            release_public_key,
        } => {
            if expected != manifest_digest {
                return Err(ImageError::DigestMismatch("manifest"));
            }
            verify_signature(&manifest, release_public_key)?;
        }
    }
    let directory = path
        .parent()
        .ok_or_else(|| ImageError::Invalid("manifest has no parent directory".into()))?;
    let kernel_path = resolve_beneath(directory, &manifest.kernel.path)?;
    let rootfs_path = resolve_beneath(directory, &manifest.rootfs.path)?;
    verify_artifact(&kernel_path, &manifest.kernel.sha256, "kernel")?;
    verify_artifact(&rootfs_path, &manifest.rootfs.sha256, "rootfs")?;
    Ok(VerifiedImage {
        manifest,
        manifest_path: path.to_path_buf(),
        manifest_digest,
        kernel_path,
        rootfs_path,
    })
}

pub fn validate_image_manifest(manifest: &ImageManifest) -> Result<(), ImageError> {
    if manifest.format_version != 1
        || manifest.id.is_empty()
        || manifest.id.len() > 128
        || manifest.version.is_empty()
        || manifest.version.len() > 64
    {
        return Err(ImageError::Invalid("invalid version or identifier".into()));
    }
    if manifest.guest_agent.protocol_major != 1
        || !manifest.capabilities.vsock
        || !manifest.capabilities.seccomp
    {
        return Err(ImageError::Invalid(
            "guest must support protocol 1, vsock, and seccomp".into(),
        ));
    }
    for digest in [
        &manifest.kernel.sha256,
        &manifest.rootfs.sha256,
        &manifest.guest_agent.sha256,
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ImageError::Invalid(
                "artifact digest is not lowercase SHA-256".into(),
            ));
        }
    }
    Ok(())
}

fn verify_signature(manifest: &ImageManifest, public_key: &[u8; 32]) -> Result<(), ImageError> {
    let encoded = manifest.signature.as_deref().ok_or(ImageError::Signature)?;
    let signature_bytes = decode_hex::<64>(encoded).ok_or(ImageError::Signature)?;
    let mut unsigned = manifest.clone();
    unsigned.signature = None;
    let digest =
        identity_digest(&unsigned).map_err(|error| ImageError::Invalid(error.to_string()))?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| ImageError::Signature)?;
    key.verify(digest.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .map_err(|_| ImageError::Signature)
}

fn resolve_beneath(parent: &Path, relative: &str) -> Result<PathBuf, ImageError> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ImageError::Invalid(
            "artifact paths must be normalized and relative".into(),
        ));
    }
    let path = parent.join(relative);
    let canonical_parent = std::fs::canonicalize(parent)?;
    let canonical_path = std::fs::canonicalize(&path)?;
    if canonical_path.strip_prefix(&canonical_parent).is_err() {
        return Err(ImageError::Invalid(
            "artifact path escapes image directory".into(),
        ));
    }
    Ok(canonical_path)
}

fn verify_artifact(path: &Path, expected: &str, name: &'static str) -> Result<(), ImageError> {
    let mut file = open_regular_bounded(path, MAX_IMAGE_ARTIFACT_BYTES, name)?;
    if hex_sha256_reader(&mut file)? != expected {
        return Err(ImageError::DigestMismatch(name));
    }
    Ok(())
}

fn open_regular_bounded(path: &Path, maximum: u64, name: &str) -> Result<File, ImageError> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(ImageError::Invalid(format!(
            "{name} is not a bounded non-symbolic regular file"
        )));
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !same_file_identity(&before, &opened) {
        return Err(ImageError::Invalid(format!(
            "{name} changed while it was opened"
        )));
    }
    Ok(file)
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.size() == right.size()
}

#[cfg(not(unix))]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.is_file() == right.is_file()
        && left.len() == right.len()
        && left.created().ok() == right.created().ok()
        && left.modified().ok() == right.modified().ok()
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex_sha256_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let pair = &value.as_bytes()[index * 2..index * 2 + 2];
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandbox-image-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_manifest(kernel: &[u8], rootfs: &[u8]) -> ImageManifest {
        ImageManifest {
            format_version: 1,
            id: "test-image".into(),
            version: "1".into(),
            architecture: Architecture::X64,
            kernel: ImageArtifact {
                path: "kernel".into(),
                sha256: hex_sha256(kernel),
            },
            rootfs: RootfsArtifact {
                path: "rootfs".into(),
                sha256: hex_sha256(rootfs),
                format: RootfsFormat::Ext4,
            },
            guest_agent: GuestAgentArtifact {
                version: "1".into(),
                protocol_major: 1,
                protocol_minor: 3,
                sha256: hex_sha256(b"guest-agent"),
            },
            capabilities: ImageCapabilities {
                overlayfs: false,
                vsock: true,
                seccomp: true,
                cgroup_v2: true,
            },
            signature: None,
        }
    }

    fn write_image(
        directory: &Path,
        manifest: &ImageManifest,
        kernel: &[u8],
        rootfs: &[u8],
    ) -> PathBuf {
        fs::write(directory.join("kernel"), kernel).unwrap();
        fs::write(directory.join("rootfs"), rootfs).unwrap();
        let path = directory.join("manifest.json");
        fs::write(&path, serde_json::to_vec(manifest).unwrap()).unwrap();
        path
    }

    #[test]
    fn artifact_paths_reject_traversal() {
        let parent = std::env::temp_dir();
        assert!(resolve_beneath(&parent, "../outside").is_err());
        assert!(resolve_beneath(&parent, "/absolute").is_err());
    }

    #[test]
    fn hexadecimal_decoder_is_strict() {
        assert_eq!(decode_hex::<2>("00ff"), Some([0, 255]));
        assert_eq!(decode_hex::<2>("00fg"), None);
        assert_eq!(decode_hex::<2>("00"), None);
    }

    #[test]
    fn modified_kernel_and_root_images_fail_before_boot() {
        let temporary = TempDirectory::new();
        let manifest = test_manifest(b"approved-kernel", b"approved-rootfs");
        let path = write_image(
            &temporary.0,
            &manifest,
            b"approved-kernel",
            b"approved-rootfs",
        );
        verify_image(&path, ImageTrust::ExplicitLocal).unwrap();

        fs::write(temporary.0.join("kernel"), b"modified-kernel").unwrap();
        assert!(matches!(
            verify_image(&path, ImageTrust::ExplicitLocal),
            Err(ImageError::DigestMismatch("kernel"))
        ));
        fs::write(temporary.0.join("kernel"), b"approved-kernel").unwrap();
        fs::write(temporary.0.join("rootfs"), b"modified-rootfs").unwrap();
        assert!(matches!(
            verify_image(&path, ImageTrust::ExplicitLocal),
            Err(ImageError::DigestMismatch("rootfs"))
        ));
    }

    #[test]
    fn bundled_image_signature_is_mandatory_and_content_bound() {
        let temporary = TempDirectory::new();
        let mut manifest = test_manifest(b"kernel", b"rootfs");
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let unsigned_digest = identity_digest(&manifest).unwrap();
        manifest.signature = Some(format!(
            "{:x}",
            signing_key.sign(unsigned_digest.as_bytes())
        ));
        let path = write_image(&temporary.0, &manifest, b"kernel", b"rootfs");
        let bytes = fs::read(&path).unwrap();
        let digest = hex_sha256(&bytes);
        verify_image(
            &path,
            ImageTrust::Bundled {
                manifest_digest: &digest,
                release_public_key: &signing_key.verifying_key().to_bytes(),
            },
        )
        .unwrap();

        manifest.signature = Some("00".repeat(64));
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let invalid_digest = hex_sha256(&fs::read(&path).unwrap());
        assert!(matches!(
            verify_image(
                &path,
                ImageTrust::Bundled {
                    manifest_digest: &invalid_digest,
                    release_public_key: &signing_key.verifying_key().to_bytes(),
                },
            ),
            Err(ImageError::Signature)
        ));
    }

    #[test]
    fn image_artifact_paths_cannot_escape_or_follow_symbolic_links() {
        let temporary = TempDirectory::new();
        let outside = temporary.0.parent().unwrap().join(format!(
            "sandbox-image-outside-{}",
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&outside, b"outside").unwrap();
        let mut manifest = test_manifest(b"outside", b"rootfs");
        manifest.kernel.path = format!("../{}", outside.file_name().unwrap().to_string_lossy());
        let path = write_image(&temporary.0, &manifest, b"unused", b"rootfs");
        assert!(matches!(
            verify_image(&path, ImageTrust::ExplicitLocal),
            Err(ImageError::Invalid(_))
        ));

        #[cfg(unix)]
        {
            manifest.kernel.path = "kernel-link".into();
            std::os::unix::fs::symlink(&outside, temporary.0.join("kernel-link")).unwrap();
            fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            assert!(matches!(
                verify_image(&path, ImageTrust::ExplicitLocal),
                Err(ImageError::Invalid(_))
            ));
        }
        fs::remove_file(outside).unwrap();
    }
}
