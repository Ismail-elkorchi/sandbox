//! A single host-owned image worker pool, separate from the API and machine
//! units. Immutable job bindings and result bytes survive API disconnection.
//! The worker materializes admitted images; only the catalog owner publishes
//! their authority records. There is no worker-side catalog or authorization.
use crate::api::{MachineImageRecipe, OciSource};
use crate::service::{HostError, Result};
use sandsurf_native::local::{create_private_file, ensure_private_directory, open_private_file};
#[cfg(target_os = "linux")]
use sandsurf_native::service_pool::ServicePool;
use sandsurf_native::storage::{object_name, publish_new_file, sync_file};
use sandsurf_protocol::{Digest, OperationId, Snapshot};
use sandsurf_state::ImageRecord;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

const MAX_JOB_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const DEADLINE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Build {
    Native {
        manifest_path: PathBuf,
        manifest_digest: Digest,
    },
    Oci {
        source: OciSource,
        recipe: MachineImageRecipe,
        platform: String,
    },
    Snapshot {
        snapshot: Box<Snapshot>,
        allow_sensitive: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub operation: OperationId,
    pub request_digest: Digest,
    pub build: Build,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Outcome {
    request_digest: Digest,
    image: ImageRecord,
}

fn directory(root: &Path, operation: &OperationId) -> PathBuf {
    root.join("image-workers")
        .join(object_name(operation.as_str()))
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = open_private_file(path, sandsurf_native::PrivateFileAccess::ReadOnly)?;
    let mut bytes = Vec::new();
    file.take(MAX_JOB_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOB_BYTES {
        return Err(HostError::Invalid("image worker record exceeds bound"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn publish<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_JOB_BYTES {
        return Err(HostError::Invalid("image worker record exceeds bound"));
    }
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| HostError::Invalid("image worker entropy unavailable"))?;
    let pending = path.with_extension(format!(
        "{}.pending",
        sandsurf_protocol::bytes_digest(&nonce).as_str()
    ));
    let mut file = create_private_file(&pending)?;
    file.write_all(&bytes)?;
    sync_file(&file)?;
    drop(file);
    let result = publish_new_file(&pending, path);
    if result.is_err() {
        let _ = std::fs::remove_file(&pending);
    }
    Ok(result?)
}

fn result(root: &Path, job: &Job) -> Result<Option<ImageRecord>> {
    completed(root, &job.operation, &job.request_digest)
}

pub(crate) fn completed(
    root: &Path,
    operation: &OperationId,
    request_digest: &Digest,
) -> Result<Option<ImageRecord>> {
    let path = directory(root, operation).join("result.json");
    match read::<Outcome>(&path) {
        Ok(value) if value.request_digest == *request_digest => Ok(Some(value.image)),
        Ok(_) => Err(HostError::Invalid("image worker result binding changed")),
        Err(HostError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Submission never forks image processing in the API process. A busy pool
/// rejects new work for explicit retry; it does not grow a queue of builders.
pub fn execute(root: &Path, executable: &Path, job: Job) -> Result<ImageRecord> {
    let root = sandsurf_native::local::canonical_private_directory(root)?;
    sandsurf_native::volume::inspect(&root)?;
    ensure_private_directory(&root.join("image-workers"))?;
    let stage = directory(&root, &job.operation);
    ensure_private_directory(&stage)?;
    let binding = stage.join("job.json");
    match read::<Job>(&binding) {
        Ok(old) if serde_json::to_vec(&old)? == serde_json::to_vec(&job)? => {}
        Ok(_) => return Err(HostError::Invalid("image worker operation binding changed")),
        Err(HostError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            if let Err(error) = publish(&binding, &job) {
                // Concurrent submissions may publish exactly the same job.
                if serde_json::to_vec(&read::<Job>(&binding)?)? != serde_json::to_vec(&job)? {
                    return Err(error);
                }
            }
        }
        Err(error) => return Err(error),
    }
    if let Some(image) = result(&root, &job)? {
        return Ok(image);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = executable;
        Err(HostError::Invalid(
            "externally limited image workers are unsupported on this platform",
        ))
    }
    #[cfg(target_os = "linux")]
    {
        let unit = ServicePool::Images.unit(&root)?;
        let mut command = Command::new("systemd-run");
        command.args([
            "--user",
            "--quiet",
            "--collect",
            "--service-type=exec",
            "--unit",
            &unit,
        ]);
        for property in ServicePool::Images.properties() {
            command.arg(format!("--property={property}"));
        }
        command
            .arg(executable)
            .arg("image-worker")
            .arg("--directory")
            .arg(&root)
            .arg("--operation")
            .arg(job.operation.as_str());
        // A failed start can mean this exact pool is already serving this
        // operation. Do not kill/restart it or replay its publication.
        let started = sandsurf_native::resources::run_bounded(command).is_ok();
        let deadline = Instant::now() + DEADLINE;
        let mut next_probe = Instant::now() + Duration::from_millis(500);
        loop {
            if let Some(image) = result(&root, &job)? {
                return Ok(image);
            }
            if !started {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "image pool busy or unavailable; inspect/retry the admitted operation",
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "image worker result remains unavailable; operation retained",
                )
                .into());
            }
            if Instant::now() >= next_probe {
                let mut probe = Command::new("systemctl");
                probe.args(["--user", "is-active", "--quiet", &unit]);
                if sandsurf_native::resources::run_bounded(probe).is_err() {
                    // Recheck after observing unit completion: publication may
                    // have happened between the first read and the probe.
                    if let Some(image) = result(&root, &job)? {
                        return Ok(image);
                    }
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe,
                        "image worker ended without a complete result; admitted operation remains retained and can be retried").into());
                }
                next_probe = Instant::now() + Duration::from_millis(500);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

pub fn capability(root: &Path) -> sandsurf_protocol::Capability {
    if cfg!(target_os = "linux") {
        if let Err(error) = sandsurf_native::volume::inspect(root) {
            return sandsurf_protocol::Capability::Unsupported {
                reasons: vec![error.to_string()],
            };
        }
        sandsurf_protocol::Capability::Supported {
            qualification: crate::images::qualification(),
        }
    } else {
        sandsurf_protocol::Capability::Unsupported {
            reasons: vec!["this adapter has no externally limited image-worker pool".into()],
        }
    }
}

/// Entry point receives only an operation address, then loads the immutable
/// host binding. No credentials are serialized in job/result files or argv.
pub fn serve(root: &Path, operation: OperationId) -> Result<()> {
    let root = sandsurf_native::local::canonical_private_directory(root)?;
    sandsurf_native::volume::inspect(&root)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = operation;
        let _ = root;
        Err(HostError::Invalid("image worker envelope unsupported"))
    }
    #[cfg(target_os = "linux")]
    {
        if !ServicePool::Images.current(&root)? {
            return Err(HostError::Invalid("image worker outside its owned unit"));
        }
        let pool = root.join("image-workers");
        ensure_private_directory(&pool)?;
        let lease_path = pool.join(".lease");
        let lease = match create_private_file(&lease_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_private_file(&lease_path, sandsurf_native::PrivateFileAccess::ReadWrite)?
            }
            Err(error) => return Err(error.into()),
        };
        lease
            .try_lock()
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error.to_string()))?;
        let job: Job = read(&directory(&root, &operation).join("job.json"))?;
        if job.operation != operation {
            return Err(HostError::Invalid("image worker job identity changed"));
        }
        if result(&root, &job)?.is_some() {
            return Ok(());
        }
        let image = match &job.build {
            Build::Native {
                manifest_path,
                manifest_digest,
            } => crate::images::import_native(
                &root,
                manifest_path,
                manifest_digest,
                &operation,
                &job.request_digest,
            )?,
            Build::Oci {
                source,
                recipe,
                platform,
            } => {
                let credential = match source {
                    OciSource::Registry {
                        credential: Some(secret),
                        ..
                    } => {
                        let bytes = crate::secrets::SecretAuthority::open(&root.join("secrets"))?
                            .read(&secret.id, &secret.version)?;
                        if bytes.len() as u64 != secret.bytes.get() {
                            return Err(HostError::Invalid(
                                "approved registry credential size changed",
                            ));
                        }
                        Some(Zeroizing::new(bytes))
                    }
                    _ => None,
                };
                crate::images::import_oci(
                    &root,
                    &std::env::current_exe()?,
                    crate::images::OciBuildInput {
                        source,
                        recipe,
                        platform,
                    },
                    &operation,
                    &job.request_digest,
                    credential.as_ref().map(|v| v.as_slice()),
                )?
            }
            Build::Snapshot {
                snapshot,
                allow_sensitive,
            } => crate::images::publish_snapshot(
                &root,
                snapshot,
                *allow_sensitive,
                &operation,
                &job.request_digest,
            )?,
        };
        publish(
            &directory(&root, &operation).join("result.json"),
            &Outcome {
                request_digest: job.request_digest,
                image,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(target_os = "linux")]
    fn shared_workers_have_a_complete_separate_process_envelope() {
        let limits = sandsurf_native::service_pool::ServicePool::Images.properties();
        for required in [
            "CPUQuota=100%",
            "MemoryMax=1073741824",
            "MemorySwapMax=0",
            "TasksMax=64",
            "KillMode=control-group",
            "RuntimeMaxSec=300",
        ] {
            assert!(limits.contains(&required.to_owned()));
        }
    }

    #[test]
    fn immutable_binding_and_result_survive_owner_reconnection() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-image-worker-{}-{}",
            std::process::id(),
            sandsurf_protocol::bytes_digest(
                &std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    .to_le_bytes()
            )
            .as_str()
        ));
        ensure_private_directory(&root).unwrap();
        let operation: OperationId = "image-operation".try_into().unwrap();
        let binding = sandsurf_protocol::bytes_digest(b"approved image import");
        let stage = directory(&root, &operation);
        ensure_private_directory(&root.join("image-workers")).unwrap();
        ensure_private_directory(&stage).unwrap();
        let image = ImageRecord {
            digest: sandsurf_protocol::bytes_digest(b"image"),
            source_digest: sandsurf_protocol::bytes_digest(b"source"),
            platform: "linux".into(),
            architecture: "amd64".into(),
            logical_bytes: sandsurf_protocol::Counter::ONE,
            storage_bytes: sandsurf_protocol::Counter::ONE,
            provenance_digest: sandsurf_protocol::bytes_digest(b"provenance"),
            sensitive: false,
        };
        assert!(completed(&root, &operation, &binding).unwrap().is_none());
        publish(
            &stage.join("result.json"),
            &Outcome {
                request_digest: binding.clone(),
                image: image.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            completed(&root, &operation, &binding).unwrap(),
            Some(image.clone())
        );
        assert!(
            completed(
                &root,
                &operation,
                &sandsurf_protocol::bytes_digest(b"other")
            )
            .is_err()
        );
        assert!(
            publish(
                &stage.join("result.json"),
                &Outcome {
                    request_digest: binding.clone(),
                    image: image.clone()
                }
            )
            .is_err()
        );
        assert_eq!(completed(&root, &operation, &binding).unwrap(), Some(image));
        std::fs::remove_dir_all(root).unwrap();
    }
}
