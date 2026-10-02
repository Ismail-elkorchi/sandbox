//! A single host-owned image worker pool, separate from the API and machine
//! units. Immutable job bindings and result bytes survive API disconnection.
//! The worker materializes admitted images; only the catalog owner publishes
//! their authority records. There is no worker-side catalog or authorization.
use crate::api::{MachineImageRecipe, OciSource};
use crate::image_records::{publish, read};
use crate::service::{HostError, Result};
use sandsurf_native::local::ensure_private_directory;
use sandsurf_native::service_pool::ServicePool;
use sandsurf_native::storage::object_name;
use sandsurf_protocol::{Digest, OperationId, Snapshot};
use sandsurf_state::ImageRecord;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

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

fn directory(root: &Path, operation: &OperationId) -> PathBuf {
    root.join("image-workers")
        .join(object_name(operation.as_str()))
}

fn result(root: &Path, job: &Job) -> Result<Option<ImageRecord>> {
    completed(root, &job.operation, &job.request_digest)
}

pub(crate) fn completed(
    root: &Path,
    operation: &OperationId,
    request_digest: &Digest,
) -> Result<Option<ImageRecord>> {
    Ok(crate::images::completed(root, operation, request_digest)?)
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
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Err(error) = publish(&binding, &job) {
                // Concurrent submissions may publish exactly the same job.
                if serde_json::to_vec(&read::<Job>(&binding)?)? != serde_json::to_vec(&job)? {
                    return Err(error.into());
                }
            }
        }
        Err(error) => return Err(error.into()),
    }
    if let Some(image) = result(&root, &job)? {
        return Ok(image);
    }
    #[cfg(target_os = "linux")]
    let unit = ServicePool::Images.unit(&root)?;
    #[cfg(target_os = "linux")]
    let mut command = Command::new("systemd-run");
    #[cfg(target_os = "linux")]
    {
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
    }
    #[cfg(target_os = "linux")]
    let started = sandsurf_native::resources::run_bounded(command).is_ok();
    #[cfg(any(target_os = "macos", windows))]
    let started = {
        let _ = executable;
        crate::supervision::call(
            &root,
            crate::supervision::Request::EnsureImage {
                operation: job.operation.clone(),
            },
        )
        .is_ok()
    };
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
            #[cfg(target_os = "linux")]
            let alive = {
                let mut probe = Command::new("systemctl");
                probe.args(["--user", "is-active", "--quiet", &unit]);
                sandsurf_native::resources::run_bounded(probe).is_ok()
            };
            #[cfg(any(target_os = "macos", windows))]
            let alive = crate::supervision::call(
                &root,
                crate::supervision::Request::CheckImage {
                    operation: job.operation.clone(),
                },
            )
            .is_ok();
            if !alive {
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

pub fn capability(root: &Path) -> sandsurf_protocol::Capability {
    if let Err(error) = sandsurf_native::volume::inspect(root) {
        return sandsurf_protocol::Capability::Unsupported {
            reasons: vec![error.to_string()],
        };
    }
    // This describes the independently owned worker pool, not the offline
    // filesystem executor. Bytewise native import needs no disk appliance;
    // recipes that need filesystem execution check their executor separately.
    sandsurf_protocol::Capability::Supported {
        qualification: sandsurf_protocol::Qualification::Unqualified {
            reasons: vec!["native image-pool custody, process envelopes and interrupted publication need qualification for this exact host/build".into()],
        },
    }
}

/// Entry point receives only an operation address, then loads the immutable
/// host binding. No credentials are serialized in job/result files or argv.
pub(crate) fn admitted(root: &Path, operation: &OperationId) -> Result<Job> {
    let job: Job = read(&directory(root, operation).join("job.json"))?;
    if job.operation != *operation {
        return Err(HostError::Invalid("image worker job identity changed"));
    }
    Ok(job)
}

pub fn serve(root: &Path, operation: OperationId, lease: std::fs::File) -> Result<()> {
    let root = sandsurf_native::local::canonical_private_directory(root)?;
    sandsurf_native::volume::inspect(&root)?;
    #[cfg(target_os = "linux")]
    if !ServicePool::Images.current(&root)? {
        return Err(HostError::Invalid("image worker outside its owned unit"));
    }
    #[cfg(target_os = "macos")]
    if sandsurf_native::resource_broker::macos::current_worker_budget()
        != Some(sandsurf_native::resource_broker::worker_budget(
            ServicePool::Images.process_budget(),
        )?)
    {
        return Err(HostError::Invalid(
            "image worker outside its owned native envelope",
        ));
    }
    #[cfg(windows)]
    sandsurf_native::process_budget::windows::JobEnvelope::verify_current_factory(
        ServicePool::Images.process_budget(),
    )?;
    sandsurf_native::storage::verify_transferred_lease(&lease, &root.join("image-workers/.lease"))?;
    let _custody = lease;
    let job = admitted(&root, &operation)?;
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
            crate::images::oci::import(
                &root,
                crate::images::oci::BuildInput {
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
    // Builders publish the same operation outcome before returning. Do not
    // write a second completion record or acknowledge a reference-only result.
    if completed(&root, &operation, &job.request_digest)?.as_ref() != Some(&image) {
        return Err(HostError::Invalid(
            "image builder returned without its matching complete outcome",
        ));
    }
    Ok(())
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
    fn immutable_job_has_one_operation_binding_and_no_path_launch_authority() {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "sandsurf-image-job-{}",
            sandsurf_protocol::bytes_digest(&nonce).as_str()
        ));
        ensure_private_directory(&root).unwrap();
        ensure_private_directory(&root.join("image-workers")).unwrap();
        let operation: OperationId = "image-operation".try_into().unwrap();
        let stage = directory(&root, &operation);
        ensure_private_directory(&stage).unwrap();
        let job = Job {
            operation: operation.clone(),
            request_digest: sandsurf_protocol::bytes_digest(b"request"),
            build: Build::Native {
                manifest_path: root.join("manifest.json"),
                manifest_digest: sandsurf_protocol::bytes_digest(b"image"),
            },
        };
        publish(&stage.join("job.json"), &job).unwrap();
        assert_eq!(
            serde_json::to_vec(&admitted(&root, &operation).unwrap()).unwrap(),
            serde_json::to_vec(&job).unwrap()
        );
        assert!(publish(&stage.join("job.json"), &job).is_err());
        let wrong: OperationId = "other-operation".try_into().unwrap();
        let wrong_stage = directory(&root, &wrong);
        ensure_private_directory(&wrong_stage).unwrap();
        publish(&wrong_stage.join("job.json"), &job).unwrap();
        assert!(admitted(&root, &wrong).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
