//! Immutable image materialization intent owned by the host catalog. Source
//! addresses are inputs, not promises that external bytes have been retained.
//! Registry credentials are opaque host-secret identities, never plaintext.
use sandsurf_protocol::{Digest, Domain, Invalid, OperationId, SecretVersion, Snapshot, digest};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OciSource {
    Layout {
        path: PathBuf,
    },
    Archive {
        path: PathBuf,
    },
    Registry {
        reference: String,
        credential: Option<SecretVersion>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineImageRecipe {
    pub boot_image_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ImageImportInput {
    Native {
        manifest_path: PathBuf,
        manifest_digest: Digest,
    },
    Oci {
        source: OciSource,
        recipe: MachineImageRecipe,
        platform: String,
    },
    /// Exact immutable capture facts bound at admission, not another mutable
    /// snapshot owner. The catalog checks these against its retained snapshot.
    PublishSnapshot {
        snapshot: Box<Snapshot>,
        allow_sensitive: bool,
    },
}

impl ImageImportInput {
    pub fn request_digest(&self, operation: &OperationId) -> Result<Digest, Invalid> {
        self.validate()?;
        match self {
            Self::Native {
                manifest_path,
                manifest_digest,
            } => digest(
                Domain::Image,
                &(
                    "sandsurf-import-native-image-v1",
                    manifest_path,
                    manifest_digest,
                    operation,
                ),
            ),
            Self::Oci {
                source,
                recipe,
                platform,
            } => digest(
                Domain::Image,
                &(
                    "sandsurf-import-oci-v1",
                    source,
                    recipe,
                    platform,
                    operation,
                ),
            ),
            Self::PublishSnapshot {
                snapshot,
                allow_sensitive,
            } => digest(
                Domain::Image,
                &(
                    "sandsurf-publish-snapshot-image-v1",
                    &snapshot.request.id,
                    allow_sensitive,
                    operation,
                ),
            ),
        }
    }

    fn validate(&self) -> Result<(), Invalid> {
        fn path(path: &Path) -> Result<(), Invalid> {
            if !path.is_absolute()
                || path
                    .to_str()
                    .is_none_or(|value| value.len() > 4096 || value.chars().any(char::is_control))
            {
                return Err(Invalid("image input needs a bounded absolute source path"));
            }
            Ok(())
        }
        match self {
            Self::Native { manifest_path, .. } => path(manifest_path),
            Self::Oci {
                source, platform, ..
            } => {
                let mut parts = platform.split('/');
                let os = parts.next();
                let architecture = parts.next();
                let variant = parts.next();
                if os != Some("linux")
                    || !matches!(architecture, Some("amd64" | "arm64"))
                    || parts.next().is_some()
                    || platform.len() > 128
                    || variant.is_some_and(|value| {
                        value.is_empty()
                            || !value.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')
                            })
                    })
                {
                    return Err(Invalid("unsupported machine image platform"));
                }
                match source {
                    OciSource::Layout { path: source } | OciSource::Archive { path: source } => {
                        path(source)
                    }
                    OciSource::Registry { reference, .. }
                        if reference.is_empty()
                            || reference.len() > 4096
                            || reference.chars().any(char::is_control) =>
                    {
                        Err(Invalid("registry reference exceeds image input bounds"))
                    }
                    OciSource::Registry { .. } => Ok(()),
                }
            }
            Self::PublishSnapshot { .. } => Ok(()),
        }
    }
}
