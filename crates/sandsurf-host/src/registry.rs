//! Bounded OCI Distribution fetch into the host content-addressed image store.
//!
//! Registry credentials are supplied as immutable secret-version bytes by the
//! host authority. They never enter the OCI layout, image manifest, errors, or
//! request logs. Every published blob is verified against its descriptor before
//! it becomes visible in the shared CAS.

use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, WWW_AUTHENTICATE};
use sandbox_image::oci::{ConversionLimits, GuestPlatform};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const INDEX_MEDIA: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_INDEX_MEDIA: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const MANIFEST_MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST_MEDIA: &str = "application/vnd.docker.distribution.manifest.v2+json";
const CONFIG_MEDIA: &str = "application/vnd.oci.image.config.v1+json";
const DOCKER_CONFIG_MEDIA: &str = "application/vnd.docker.container.image.v1+json";
const LAYER_MEDIA: [&str; 5] = [
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];
const USER_AGENT: &str = "sandsurf/0.1 OCI-distribution";
const MAX_TOKEN_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub enum RegistryError {
    Io(io::Error),
    Http(reqwest::Error),
    Json(serde_json::Error),
    Invalid(String),
    Rejected(String),
    Limit(&'static str),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "OCI registry storage: {error}"),
            Self::Http(error) => write!(output, "OCI registry transport: {error}"),
            Self::Json(error) => write!(output, "OCI registry document: {error}"),
            Self::Invalid(message) => write!(output, "invalid OCI registry response: {message}"),
            Self::Rejected(message) => write!(output, "OCI registry rejected request: {message}"),
            Self::Limit(name) => write!(output, "OCI registry response exceeds {name} limit"),
        }
    }
}

impl std::error::Error for RegistryError {}
impl From<io::Error> for RegistryError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<reqwest::Error> for RegistryError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value)
    }
}
impl From<serde_json::Error> for RegistryError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryReference {
    registry: String,
    repository: String,
    selector: String,
    expected_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Credential {
    Basic { username: String, password: String },
    Bearer { token: String },
}

impl Drop for Credential {
    fn drop(&mut self) {
        match self {
            Self::Basic { username, password } => {
                username.zeroize();
                password.zeroize();
            }
            Self::Bearer { token } => token.zeroize(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default, rename = "os.version")]
    os_version: Option<String>,
    #[serde(default, rename = "os.features")]
    os_features: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<String>,
    manifests: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    subject: Option<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    token: Option<String>,
    #[serde(default, rename = "access_token")]
    access_token: Option<String>,
    #[serde(default, rename = "expires_in")]
    expires_in: Option<u64>,
    #[serde(default, rename = "issued_at")]
    issued_at: Option<String>,
}

struct RegistryClient {
    client: Client,
    reference: RegistryReference,
    credential: Option<Credential>,
    bearer: Option<Zeroizing<String>>,
    limits: ConversionLimits,
}

/// Resolve one registry reference for the exact requested platform and publish
/// all required content into a fresh OCI image-layout backed by the shared CAS.
pub fn fetch_layout(
    cas_root: &Path,
    destination: &Path,
    reference: &str,
    platform: &GuestPlatform,
    credential: Option<&[u8]>,
    limits: ConversionLimits,
) -> Result<(), RegistryError> {
    if !cas_root.is_absolute() || !destination.is_absolute() {
        return Err(RegistryError::Invalid(
            "CAS and OCI layout paths must be absolute".into(),
        ));
    }
    let reference = parse_reference(reference)?;
    let credential = credential.map(parse_credential).transpose()?;
    prepare_directory(cas_root)?;
    prepare_empty_directory(destination)?;
    prepare_directory(&destination.join("blobs"))?;
    prepare_directory(&destination.join("blobs/sha256"))?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(300))
        .user_agent(USER_AGENT)
        .build()?;
    let mut registry = RegistryClient {
        client,
        reference,
        credential,
        bearer: None,
        limits,
    };

    let root = registry.fetch_manifest(&registry.reference.selector.clone())?;
    if let Some(expected) = &registry.reference.expected_digest
        && &root.digest != expected
    {
        return Err(RegistryError::Invalid(
            "resolved manifest does not match the requested digest".into(),
        ));
    }
    publish_bytes(cas_root, destination, &root.digest, &root.bytes)?;

    let root_descriptor = Descriptor {
        media_type: root.media_type.clone(),
        digest: root.digest.clone(),
        size: root.bytes.len() as u64,
        platform: None,
        annotations: BTreeMap::new(),
    };
    let (index, selected) = if is_index_media(&root.media_type) {
        let index: Index = parse_json(&root.bytes, registry.limits.json_bytes)?;
        validate_index(&index, registry.limits.descriptors)?;
        let selected = select_platform(&index.manifests, platform)?.clone();
        (index, selected)
    } else if is_manifest_media(&root.media_type) {
        (
            Index {
                schema_version: 2,
                media_type: Some(INDEX_MEDIA.into()),
                manifests: vec![Descriptor {
                    platform: Some(Platform {
                        architecture: platform.architecture.clone(),
                        os: platform.os.clone(),
                        variant: platform.variant.clone(),
                        os_version: None,
                        os_features: Vec::new(),
                    }),
                    ..root_descriptor.clone()
                }],
                annotations: BTreeMap::new(),
            },
            Descriptor {
                platform: Some(Platform {
                    architecture: platform.architecture.clone(),
                    os: platform.os.clone(),
                    variant: platform.variant.clone(),
                    os_version: None,
                    os_features: Vec::new(),
                }),
                ..root_descriptor
            },
        )
    } else {
        return Err(RegistryError::Invalid(format!(
            "registry returned unsupported manifest media type {}",
            root.media_type
        )));
    };

    let selected_document = if selected.digest == root.digest {
        root
    } else {
        registry.fetch_descriptor(cas_root, destination, &selected)?
    };
    let selected_document = if is_index_media(&selected.media_type) {
        let nested: Index = parse_json(&selected_document.bytes, registry.limits.json_bytes)?;
        validate_index(&nested, registry.limits.descriptors)?;
        let manifest = select_platform(&nested.manifests, platform)?;
        if !is_manifest_media(&manifest.media_type) {
            return Err(RegistryError::Invalid(
                "registry index nesting exceeds the supported depth".into(),
            ));
        }
        registry.fetch_descriptor(cas_root, destination, manifest)?
    } else {
        selected_document
    };
    if !is_manifest_media(&selected_document.media_type) {
        return Err(RegistryError::Invalid(
            "selected registry descriptor is not an image manifest".into(),
        ));
    }
    let selected_bytes = selected_document.bytes;
    let manifest: Manifest = parse_json(&selected_bytes, registry.limits.json_bytes)?;
    validate_manifest(&manifest, &registry.limits)?;

    let mut aggregate = 0u64;
    for descriptor in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        aggregate = aggregate
            .checked_add(descriptor.size)
            .ok_or(RegistryError::Limit("aggregate compressed byte count"))?;
        if aggregate > registry.limits.compressed_bytes {
            return Err(RegistryError::Limit("aggregate compressed byte count"));
        }
        registry.fetch_blob(cas_root, destination, descriptor)?;
    }

    write_json_file(&destination.join("index.json"), &index)?;
    write_bytes_file(
        &destination.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )?;
    sync_directory(&destination.join("blobs/sha256"))?;
    sync_directory(&destination.join("blobs"))?;
    sync_directory(destination)?;
    Ok(())
}

struct ManifestDocument {
    media_type: String,
    digest: String,
    bytes: Vec<u8>,
}

impl RegistryClient {
    fn fetch_manifest(&mut self, selector: &str) -> Result<ManifestDocument, RegistryError> {
        let path = format!("/v2/{}/manifests/{selector}", self.reference.repository);
        let response = self.authorized_get(
            &path,
            Some(
                &[
                    INDEX_MEDIA,
                    DOCKER_INDEX_MEDIA,
                    MANIFEST_MEDIA,
                    DOCKER_MANIFEST_MEDIA,
                ]
                .join(", "),
            ),
        )?;
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| RegistryError::Invalid("manifest Content-Type is absent".into()))?
            .to_owned();
        let bytes = read_response(response, self.limits.json_bytes)?;
        let digest = format!("sha256:{}", hex_sha256(&bytes));
        Ok(ManifestDocument {
            media_type,
            digest,
            bytes,
        })
    }

    fn fetch_blob(
        &mut self,
        cas_root: &Path,
        layout: &Path,
        descriptor: &Descriptor,
    ) -> Result<(), RegistryError> {
        validate_descriptor(descriptor, self.limits.compressed_bytes)?;
        let hexadecimal = parse_digest(&descriptor.digest)?;
        let cas = cas_root.join("sha256").join(hexadecimal);
        prepare_directory(&cas_root.join("sha256"))?;
        if verify_file(&cas, &descriptor.digest, descriptor.size).is_ok() {
            link_blob(&cas, layout, &descriptor.digest)?;
            return Ok(());
        }
        if cas.exists() {
            return Err(RegistryError::Invalid(format!(
                "existing CAS blob {} is corrupt",
                descriptor.digest
            )));
        }
        let response = self.authorized_get(
            &format!(
                "/v2/{}/blobs/{}",
                self.reference.repository, descriptor.digest
            ),
            None,
        )?;
        if let Some(length) = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            && length != descriptor.size
        {
            return Err(RegistryError::Invalid(
                "blob Content-Length differs from its descriptor".into(),
            ));
        }
        let temporary = temporary_path(&cas_root.join("sha256"), hexadecimal)?;
        let result = write_verified_response(response, &temporary, descriptor);
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        set_read_only(&temporary)?;
        match fs::hard_link(&temporary, &cas) {
            Ok(()) => {
                fs::remove_file(&temporary)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary)?;
                verify_file(&cas, &descriptor.digest, descriptor.size)?;
            }
            Err(error) => return Err(error.into()),
        }
        sync_directory(&cas_root.join("sha256"))?;
        link_blob(&cas, layout, &descriptor.digest)
    }

    fn fetch_descriptor(
        &mut self,
        cas_root: &Path,
        layout: &Path,
        descriptor: &Descriptor,
    ) -> Result<ManifestDocument, RegistryError> {
        let document = self.fetch_manifest(&descriptor.digest)?;
        require_descriptor(descriptor, &document.digest, document.bytes.len())?;
        if document.media_type != descriptor.media_type {
            return Err(RegistryError::Invalid(
                "selected manifest media type changed during fetch".into(),
            ));
        }
        publish_bytes(cas_root, layout, &document.digest, &document.bytes)?;
        Ok(document)
    }

    fn authorized_get(
        &mut self,
        path: &str,
        accept: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let url = format!("https://{}{}", self.reference.registry, path);
        let first = self.send(self.client.get(&url), accept)?;
        if first.status() != StatusCode::UNAUTHORIZED {
            return require_success(first);
        }
        let challenge = first
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| RegistryError::Rejected("authentication challenge is absent".into()))?
            .to_owned();
        drop(first);
        self.authorize(&challenge)?;
        require_success(self.send(self.client.get(&url), accept)?)
    }

    fn send(
        &self,
        request: RequestBuilder,
        accept: Option<&str>,
    ) -> Result<Response, RegistryError> {
        let mut request = request;
        if let Some(value) = accept {
            request = request.header(ACCEPT, value);
        }
        if let Some(token) = &self.bearer {
            request = request.bearer_auth(token.as_str());
        } else if let Some(Credential::Bearer { token }) = &self.credential {
            request = request.bearer_auth(token);
        } else if let Some(Credential::Basic { username, password }) = &self.credential {
            request = request.basic_auth(username, Some(password));
        }
        Ok(request.send()?)
    }

    fn authorize(&mut self, challenge: &str) -> Result<(), RegistryError> {
        let (scheme, fields) = parse_challenge(challenge)?;
        if scheme.eq_ignore_ascii_case("basic") {
            return match self.credential {
                Some(Credential::Basic { .. }) => Ok(()),
                _ => Err(RegistryError::Rejected(
                    "registry requires a basic credential".into(),
                )),
            };
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(RegistryError::Rejected(
                "registry authentication scheme is unsupported".into(),
            ));
        }
        let realm = fields
            .get("realm")
            .ok_or_else(|| RegistryError::Invalid("bearer realm is absent".into()))?;
        let mut realm_url = reqwest::Url::parse(realm)
            .map_err(|_| RegistryError::Invalid("bearer realm URL is malformed".into()))?;
        if realm_url.scheme() != "https"
            || realm_url.host_str().is_none()
            || realm_url.username() != ""
            || realm_url.password().is_some()
            || realm_url.fragment().is_some()
        {
            return Err(RegistryError::Invalid(
                "bearer realm must be an HTTPS URL without embedded credentials or fragment".into(),
            ));
        }
        if let Some(service) = fields.get("service") {
            require_auth_field(service)?;
            realm_url.query_pairs_mut().append_pair("service", service);
        }
        let scope = fields
            .get("scope")
            .cloned()
            .unwrap_or_else(|| format!("repository:{}:pull", self.reference.repository));
        require_auth_field(&scope)?;
        realm_url.query_pairs_mut().append_pair("scope", &scope);
        let mut request = self.client.get(realm_url);
        if let Some(Credential::Basic { username, password }) = &self.credential {
            request = request.basic_auth(username, Some(password));
        } else if let Some(Credential::Bearer { token }) = &self.credential {
            request = request.bearer_auth(token);
        }
        let response = require_success(request.send()?)?;
        let bytes = read_response(response, MAX_TOKEN_BYTES)?;
        let token: TokenResponse = serde_json::from_slice(&bytes)?;
        let _ = (token.expires_in, token.issued_at);
        let value = token
            .token
            .or(token.access_token)
            .filter(|value| !value.is_empty() && value.len() <= 64 * 1024)
            .ok_or_else(|| RegistryError::Invalid("bearer token is absent or oversized".into()))?;
        if value.contains(['\r', '\n', '\0']) {
            return Err(RegistryError::Invalid("bearer token is malformed".into()));
        }
        self.bearer = Some(Zeroizing::new(value));
        Ok(())
    }
}

fn parse_reference(value: &str) -> Result<RegistryReference, RegistryError> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(['\0', '\r', '\n', ' ', '\t'])
        || value.contains("://")
        || value.contains(['?', '#'])
    {
        return Err(RegistryError::Invalid(
            "registry reference is empty, oversized, or contains URL syntax".into(),
        ));
    }
    let (name, digest) = match value.rsplit_once('@') {
        Some((name, digest)) => (name, Some(format!("sha256:{}", parse_digest(digest)?))),
        None => (value, None),
    };
    let first = name.split('/').next().unwrap_or_default();
    let explicit_registry =
        name.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    let (registry, mut repository) = if explicit_registry {
        let (registry, repository) = name
            .split_once('/')
            .ok_or_else(|| RegistryError::Invalid("registry repository is absent".into()))?;
        (registry.to_owned(), repository.to_owned())
    } else {
        ("registry-1.docker.io".into(), name.to_owned())
    };
    let mut tag = None;
    if digest.is_none()
        && let Some(index) = repository.rfind(':')
    {
        tag = Some(repository[index + 1..].to_owned());
        repository.truncate(index);
    }
    if !explicit_registry && !repository.contains('/') {
        repository = format!("library/{repository}");
    }
    validate_registry(&registry)?;
    validate_repository(&repository)?;
    let selector = if let Some(value) = &digest {
        value.clone()
    } else {
        let tag = tag.unwrap_or_else(|| "latest".into());
        validate_tag(&tag)?;
        tag
    };
    Ok(RegistryReference {
        registry,
        repository,
        selector,
        expected_digest: digest,
    })
}

fn parse_credential(bytes: &[u8]) -> Result<Credential, RegistryError> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(RegistryError::Invalid(
            "registry credential is empty or oversized".into(),
        ));
    }
    let value: Credential = serde_json::from_slice(bytes)
        .map_err(|_| RegistryError::Invalid("registry credential encoding is invalid".into()))?;
    match &value {
        Credential::Basic { username, password }
            if username.is_empty()
                || username.len() > 4096
                || password.is_empty()
                || password.len() > 64 * 1024
                || username.contains(['\0', '\r', '\n'])
                || password.contains(['\0', '\r', '\n']) =>
        {
            Err(RegistryError::Invalid(
                "registry basic credential is malformed".into(),
            ))
        }
        Credential::Bearer { token }
            if token.is_empty()
                || token.len() > 64 * 1024
                || token.contains(['\0', '\r', '\n']) =>
        {
            Err(RegistryError::Invalid(
                "registry bearer credential is malformed".into(),
            ))
        }
        _ => Ok(value),
    }
}

fn parse_challenge(value: &str) -> Result<(&str, BTreeMap<String, String>), RegistryError> {
    if value.len() > 64 * 1024 || value.contains(['\r', '\n', '\0']) {
        return Err(RegistryError::Invalid(
            "authentication challenge is oversized or malformed".into(),
        ));
    }
    let (scheme, rest) = value
        .split_once(' ')
        .map(|(scheme, rest)| (scheme.trim(), rest.trim()))
        .unwrap_or((value.trim(), ""));
    if scheme.is_empty() {
        return Err(RegistryError::Invalid(
            "authentication challenge scheme is absent".into(),
        ));
    }
    let mut fields = BTreeMap::new();
    let bytes = rest.as_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        while offset < bytes.len() && matches!(bytes[offset], b' ' | b',') {
            offset += 1;
        }
        if offset == bytes.len() {
            break;
        }
        let key_start = offset;
        while offset < bytes.len() && bytes[offset].is_ascii_alphanumeric() {
            offset += 1;
        }
        if offset == key_start || bytes.get(offset) != Some(&b'=') {
            return Err(RegistryError::Invalid(
                "authentication challenge field is malformed".into(),
            ));
        }
        let key = rest[key_start..offset].to_ascii_lowercase();
        offset += 1;
        if bytes.get(offset) != Some(&b'\"') {
            return Err(RegistryError::Invalid(
                "authentication challenge values must be quoted".into(),
            ));
        }
        offset += 1;
        let mut decoded = String::new();
        let mut closed = false;
        while offset < bytes.len() {
            match bytes[offset] {
                b'\"' => {
                    offset += 1;
                    closed = true;
                    break;
                }
                b'\\' => {
                    offset += 1;
                    let byte = *bytes.get(offset).ok_or_else(|| {
                        RegistryError::Invalid(
                            "authentication challenge escape is truncated".into(),
                        )
                    })?;
                    if !byte.is_ascii() {
                        return Err(RegistryError::Invalid(
                            "authentication challenge escape is non-ASCII".into(),
                        ));
                    }
                    decoded.push(char::from(byte));
                    offset += 1;
                }
                byte if byte.is_ascii() && byte >= 0x20 => {
                    decoded.push(char::from(byte));
                    offset += 1;
                }
                _ => {
                    return Err(RegistryError::Invalid(
                        "authentication challenge value is malformed".into(),
                    ));
                }
            }
        }
        if !closed || fields.insert(key, decoded).is_some() {
            return Err(RegistryError::Invalid(
                "authentication challenge is truncated or has duplicate fields".into(),
            ));
        }
        while offset < bytes.len() && bytes[offset] == b' ' {
            offset += 1;
        }
        if offset < bytes.len() && bytes[offset] != b',' {
            return Err(RegistryError::Invalid(
                "authentication challenge separator is malformed".into(),
            ));
        }
    }
    Ok((scheme, fields))
}

fn validate_registry(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > 253
        || value.contains('@')
        || value.contains('/')
        || reqwest::Url::parse(&format!("https://{value}/v2/"))
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_none()
    {
        return Err(RegistryError::Invalid("registry host is malformed".into()));
    }
    Ok(())
}

fn validate_repository(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > 255
        || value.split('/').any(|component| {
            component.is_empty()
                || !component.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
                || !component
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !component
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(RegistryError::Invalid(
            "registry repository name is malformed".into(),
        ));
    }
    Ok(())
}

fn validate_tag(value: &str) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(RegistryError::Invalid("registry tag is malformed".into()));
    }
    Ok(())
}

fn validate_index(index: &Index, maximum: usize) -> Result<(), RegistryError> {
    if index.schema_version != 2 || index.manifests.is_empty() || index.manifests.len() > maximum {
        return Err(RegistryError::Invalid(
            "registry index schema or descriptor count is invalid".into(),
        ));
    }
    for descriptor in &index.manifests {
        validate_descriptor(descriptor, 8 * 1024 * 1024)?;
        if !is_manifest_media(&descriptor.media_type) && !is_index_media(&descriptor.media_type) {
            return Err(RegistryError::Invalid(
                "registry index descriptor media type is unsupported".into(),
            ));
        }
    }
    Ok(())
}

fn validate_manifest(value: &Manifest, limits: &ConversionLimits) -> Result<(), RegistryError> {
    if value.schema_version != 2 || value.layers.is_empty() || value.layers.len() > limits.layers {
        return Err(RegistryError::Invalid(
            "registry manifest schema or layer count is invalid".into(),
        ));
    }
    if !matches!(
        value.media_type.as_deref(),
        None | Some(MANIFEST_MEDIA | DOCKER_MANIFEST_MEDIA)
    ) || !matches!(
        value.config.media_type.as_str(),
        CONFIG_MEDIA | DOCKER_CONFIG_MEDIA
    ) {
        return Err(RegistryError::Invalid(
            "registry manifest or configuration media type is invalid".into(),
        ));
    }
    validate_descriptor(&value.config, limits.json_bytes)?;
    for layer in &value.layers {
        validate_descriptor(layer, limits.compressed_bytes)?;
        if !LAYER_MEDIA.contains(&layer.media_type.as_str()) {
            return Err(RegistryError::Invalid(format!(
                "registry layer media type {} is unsupported",
                layer.media_type
            )));
        }
    }
    let _ = (&value.annotations, &value.subject);
    Ok(())
}

fn validate_descriptor(value: &Descriptor, maximum: u64) -> Result<(), RegistryError> {
    parse_digest(&value.digest)?;
    if value.size == 0 || value.size > maximum {
        return Err(RegistryError::Limit("descriptor byte count"));
    }
    Ok(())
}

fn select_platform<'a>(
    values: &'a [Descriptor],
    requested: &GuestPlatform,
) -> Result<&'a Descriptor, RegistryError> {
    let mut found = None;
    for value in values {
        if value.platform.as_ref().is_some_and(|platform| {
            platform.os == requested.os
                && platform.architecture == requested.architecture
                && platform.variant == requested.variant
        }) {
            if found.is_some() {
                return Err(RegistryError::Invalid(
                    "registry index has multiple descriptors for the requested platform".into(),
                ));
            }
            found = Some(value);
        }
    }
    found.ok_or_else(|| {
        RegistryError::Invalid("registry index does not contain the requested platform".into())
    })
}

fn is_index_media(value: &str) -> bool {
    matches!(value, INDEX_MEDIA | DOCKER_INDEX_MEDIA)
}

fn is_manifest_media(value: &str) -> bool {
    matches!(value, MANIFEST_MEDIA | DOCKER_MANIFEST_MEDIA)
}

fn parse_digest(value: &str) -> Result<&str, RegistryError> {
    let hexadecimal = value.strip_prefix("sha256:").unwrap_or(value);
    if hexadecimal.len() != 64
        || !hexadecimal
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RegistryError::Invalid(
            "descriptor digest is malformed".into(),
        ));
    }
    Ok(hexadecimal)
}

fn require_descriptor(
    descriptor: &Descriptor,
    digest: &str,
    length: usize,
) -> Result<(), RegistryError> {
    if descriptor.digest != digest || descriptor.size != length as u64 {
        return Err(RegistryError::Invalid(
            "fetched manifest differs from its selected descriptor".into(),
        ));
    }
    Ok(())
}

fn require_success(response: Response) -> Result<Response, RegistryError> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(RegistryError::Rejected(format!(
            "HTTP status {}",
            response.status().as_u16()
        )))
    }
}

fn read_response(mut response: Response, maximum: u64) -> Result<Vec<u8>, RegistryError> {
    if let Some(length) = response.content_length()
        && length > maximum
    {
        return Err(RegistryError::Limit("response byte count"));
    }
    let capacity = response
        .content_length()
        .unwrap_or(0)
        .min(maximum)
        .try_into()
        .unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    response
        .by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(RegistryError::Limit("response byte count"));
    }
    Ok(bytes)
}

fn write_verified_response(
    mut response: Response,
    path: &Path,
    descriptor: &Descriptor,
) -> Result<(), RegistryError> {
    let mut file = private_new_file(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = response.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(RegistryError::Limit("blob byte count"))?;
        if total > descriptor.size {
            return Err(RegistryError::Invalid(
                "blob exceeds its descriptor size".into(),
            ));
        }
        hasher.update(&buffer[..count]);
        file.write_all(&buffer[..count])?;
    }
    if total != descriptor.size || format!("sha256:{:x}", hasher.finalize()) != descriptor.digest {
        return Err(RegistryError::Invalid(
            "blob size or digest differs from its descriptor".into(),
        ));
    }
    file.sync_all()?;
    Ok(())
}

fn publish_bytes(
    cas_root: &Path,
    layout: &Path,
    digest: &str,
    bytes: &[u8],
) -> Result<(), RegistryError> {
    let hexadecimal = parse_digest(digest)?;
    let directory = cas_root.join("sha256");
    prepare_directory(&directory)?;
    let path = directory.join(hexadecimal);
    if path.exists() {
        verify_file(&path, digest, bytes.len() as u64)?;
    } else {
        let temporary = temporary_path(&directory, hexadecimal)?;
        write_bytes_file(&temporary, bytes)?;
        verify_file(&temporary, digest, bytes.len() as u64)?;
        set_read_only(&temporary)?;
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {
                fs::remove_file(&temporary)?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary)?;
                verify_file(&path, digest, bytes.len() as u64)?;
            }
            Err(error) => return Err(error.into()),
        }
        sync_directory(&directory)?;
    }
    link_blob(&path, layout, digest)
}

fn link_blob(source: &Path, layout: &Path, digest: &str) -> Result<(), RegistryError> {
    let destination = layout.join("blobs/sha256").join(parse_digest(digest)?);
    if destination.exists() {
        return verify_file(&destination, digest, fs::metadata(source)?.len());
    }
    match fs::hard_link(source, &destination) {
        Ok(()) => Ok(()),
        Err(_) if destination.exists() => {
            verify_file(&destination, digest, fs::metadata(source)?.len())
        }
        Err(_) => {
            let mut input = File::open(source)?;
            match private_new_file(&destination) {
                Ok(mut output) => {
                    io::copy(&mut input, &mut output)?;
                    output.sync_all()?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            verify_file(&destination, digest, fs::metadata(source)?.len())
        }
    }
}

fn temporary_path(directory: &Path, stem: &str) -> Result<std::path::PathBuf, RegistryError> {
    for _ in 0..32 {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|error| RegistryError::Invalid(format!("random source failed: {error}")))?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = directory.join(format!(".{stem}.part-{suffix}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(RegistryError::Invalid(
        "could not allocate a unique CAS temporary path".into(),
    ))
}

fn verify_file(path: &Path, digest: &str, length: u64) -> Result<(), RegistryError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != length {
        return Err(RegistryError::Invalid(
            "CAS blob type or size differs from its descriptor".into(),
        ));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut HashWriter(&mut hasher))?;
    if format!("sha256:{:x}", hasher.finalize()) != digest {
        return Err(RegistryError::Invalid("CAS blob digest mismatch".into()));
    }
    Ok(())
}

struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    maximum: u64,
) -> Result<T, RegistryError> {
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(RegistryError::Limit("JSON byte count"));
    }
    Ok(serde_json::from_slice(bytes)?)
}

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), RegistryError> {
    let bytes = serde_json::to_vec(value)?;
    write_bytes_file(path, &bytes)
}

fn write_bytes_file(path: &Path, bytes: &[u8]) -> Result<(), RegistryError> {
    let mut file = private_new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn prepare_empty_directory(path: &Path) -> Result<(), RegistryError> {
    if path.exists() {
        return Err(RegistryError::Invalid(
            "OCI layout destination already exists".into(),
        ));
    }
    prepare_directory(path)
}

fn prepare_directory(path: &Path) -> Result<(), RegistryError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(RegistryError::Invalid(
                "registry storage object is not a directory".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
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

fn set_read_only(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions)
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn require_auth_field(value: &str) -> Result<(), RegistryError> {
    if value.is_empty() || value.len() > 4096 || value.contains(['\0', '\r', '\n']) {
        return Err(RegistryError::Invalid(
            "authentication challenge field is malformed".into(),
        ));
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_canonical_and_digest_bound() {
        let docker = parse_reference("alpine:3.21").unwrap();
        assert_eq!(docker.registry, "registry-1.docker.io");
        assert_eq!(docker.repository, "library/alpine");
        assert_eq!(docker.selector, "3.21");

        let digest = "a".repeat(64);
        let exact = parse_reference(&format!("registry.example/team/dev@sha256:{digest}")).unwrap();
        assert_eq!(exact.registry, "registry.example");
        assert_eq!(exact.repository, "team/dev");
        assert_eq!(exact.selector, format!("sha256:{digest}"));
        assert_eq!(exact.expected_digest, Some(format!("sha256:{digest}")));

        for invalid in [
            "http://registry.example/image",
            "registry.example/../image",
            "UPPER/image",
            "registry.example/image:bad tag",
        ] {
            assert!(parse_reference(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn bearer_challenges_are_strict_and_bounded() {
        let (scheme, fields) = parse_challenge(
            r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:team/dev:pull""#,
        )
        .unwrap();
        assert_eq!(scheme, "Bearer");
        assert_eq!(fields["service"], "registry.example");
        assert_eq!(fields["scope"], "repository:team/dev:pull");
        assert!(parse_challenge("Bearer realm=https://auth.example").is_err());
        assert!(parse_challenge("Bearer realm=\"one\",realm=\"two\"").is_err());
    }

    #[test]
    fn credentials_have_an_explicit_non_ambient_encoding() {
        assert!(matches!(
            parse_credential(br#"{"kind":"basic","username":"agent","password":"secret"}"#)
                .unwrap(),
            Credential::Basic { .. }
        ));
        assert!(matches!(
            parse_credential(br#"{"kind":"bearer","token":"opaque"}"#).unwrap(),
            Credential::Bearer { .. }
        ));
        assert!(parse_credential(br#"{"username":"ambient"}"#).is_err());
    }

    #[test]
    #[ignore = "requires public registry network access"]
    fn public_registry_pull_is_digest_verified_and_layout_readable() {
        let root =
            std::env::temp_dir().join(format!("sandsurf-registry-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let layout = root.join("layout");
        fetch_layout(
            &root.join("cas"),
            &layout,
            "registry.k8s.io/pause:3.10.1",
            &GuestPlatform {
                architecture: std::env::consts::ARCH
                    .replace("x86_64", "amd64")
                    .replace("aarch64", "arm64"),
                os: "linux".into(),
                variant: None,
            },
            None,
            ConversionLimits::default(),
        )
        .unwrap();
        sandbox_image::oci::OciLayout::open(&layout, ConversionLimits::default())
            .unwrap()
            .resolve(&GuestPlatform {
                architecture: std::env::consts::ARCH
                    .replace("x86_64", "amd64")
                    .replace("aarch64", "arm64"),
                os: "linux".into(),
                variant: None,
            })
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
