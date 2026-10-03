//! A single host-owned image worker pool, separate from the API and machine
//! units. Immutable job bindings and result bytes survive API disconnection.
//! The worker materializes admitted images; only the catalog owner publishes
//! their authority records. There is no worker-side catalog or authorization.
use crate::image_records::{publish, read};
use crate::service::{HostError, Result};
use sandsurf_native::local::ensure_private_directory;
use sandsurf_native::service_pool::ServicePool;
use sandsurf_native::storage::object_name;
use sandsurf_protocol::{Counter, Digest, Domain, MachineId, OperationId, Snapshot, digest};
use sandsurf_state::{ImageImportInput, ImageRecord, OciSource};
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
    Image {
        input: ImageImportInput,
    },
    DiskSnapshot {
        snapshot: Box<Snapshot>,
    },
    /// Internal native-boot preparation, not image publication or new authority.
    /// All paths are derived from existing host-owned identities.
    Boot {
        machine_id: MachineId,
        generation: Counter,
        image_digest: Digest,
        disk_bytes: u64,
        boot_name: String,
    },
    Fork {
        snapshot: Box<Snapshot>,
        machine_id: MachineId,
        profile: sandsurf_image::identity::CloneProfile,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub operation: OperationId,
    pub request_digest: Digest,
    pub build: Build,
}

impl Job {
    fn validate(&self) -> Result<()> {
        if let Build::Image { input } = &self.build
            && input.request_digest(&self.operation)? != self.request_digest
        {
            return Err(HostError::Invalid(
                "image worker recipe differs from approved request",
            ));
        }
        Ok(())
    }
}

fn directory(root: &Path, operation: &OperationId) -> PathBuf {
    root.join("image-workers")
        .join(object_name(operation.as_str()))
}

#[derive(Debug)]
enum Outcome {
    Image {
        image: ImageRecord,
    },
    Boot {
        boot: sandsurf_image::boot::FrozenBoot,
    },
    Fork {
        customized: Digest,
    },
    DiskSnapshot {
        capture: crate::snapshots::CaptureResult,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ForkResult {
    request_digest: Digest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootResult {
    request_digest: Digest,
    boot: sandsurf_image::boot::FrozenBoot,
}

fn result(root: &Path, job: &Job) -> Result<Option<Outcome>> {
    if let Build::DiskSnapshot { snapshot } = &job.build {
        return Ok(crate::snapshots::published_filesystem(
            &crate::snapshots::root(root, snapshot),
            snapshot,
        )?
        .map(|capture| Outcome::DiskSnapshot { capture }));
    }
    if let Build::Fork {
        snapshot,
        machine_id,
        profile,
    } = &job.build
    {
        let record: ForkResult = match read(&directory(root, &job.operation).join("result.json")) {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if record.request_digest != job.request_digest {
            return Err(HostError::Invalid("fork worker completion binding changed"));
        }
        let customized =
            crate::snapshots::verify_fork(snapshot, &fork_disk(root, machine_id), profile)?;
        return Ok(Some(Outcome::Fork { customized }));
    }
    if matches!(job.build, Build::Boot { .. }) {
        let record: BootResult = match read(&directory(root, &job.operation).join("result.json")) {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if record.request_digest != job.request_digest {
            return Err(HostError::Invalid("boot worker completion binding changed"));
        }
        let Build::Boot {
            machine_id,
            generation,
            boot_name,
            ..
        } = &job.build
        else {
            unreachable!()
        };
        if crate::storage::read_boot(&boot_directory(root, machine_id, *generation, boot_name)?)?
            != record.boot
        {
            return Err(HostError::Invalid(
                "boot worker completion has no matching retained bytes",
            ));
        }
        Ok(Some(Outcome::Boot { boot: record.boot }))
    } else {
        Ok(
            crate::images::completed(root, &job.operation, &job.request_digest)?
                .map(|image| Outcome::Image { image }),
        )
    }
}

/// Submission never forks image processing in the API process. A busy pool
/// rejects new work for explicit retry; it does not grow a queue of builders.
pub fn execute(root: &Path, executable: &Path, job: Job) -> Result<ImageRecord> {
    if !matches!(job.build, Build::Image { .. }) {
        return Err(HostError::Invalid(
            "machine disk preparation is not image publication",
        ));
    }
    match dispatch(root, executable, job)? {
        Outcome::Image { image } => Ok(image),
        Outcome::Boot { .. } | Outcome::Fork { .. } | Outcome::DiskSnapshot { .. } => Err(
            HostError::Invalid("image worker returned a machine preparation result"),
        ),
    }
}

/// Offline preparation belongs to the shared worker envelope, never the small
/// per-machine guardian. The guardian reacquires native attachment custody
/// after publication; a result or observed stopped state is not that lease.
pub(crate) fn prepare_boot(
    machine_root: &Path,
    machine_id: &MachineId,
    generation: Counter,
    image_digest: &Digest,
    disk_bytes: u64,
) -> Result<(PathBuf, sandsurf_image::boot::FrozenBoot)> {
    let root = machine_root
        .parent()
        .and_then(Path::parent)
        .ok_or(HostError::Invalid("machine storage has no host owner"))?;
    let expected = root.join("machines").join(object_name(machine_id.as_str()));
    if machine_root != expected {
        return Err(HostError::Invalid("boot preparation machine path changed"));
    }
    let job = boot_job(machine_id, generation, image_digest, disk_bytes)?;
    let Build::Boot { boot_name, .. } = &job.build else {
        unreachable!()
    };
    let destination = boot_directory(root, machine_id, generation, boot_name)?;
    let outcome = dispatch(root, &std::env::current_exe()?, job)?;
    let Outcome::Boot { boot } = outcome else {
        return Err(HostError::Invalid("boot worker returned an image result"));
    };
    if crate::storage::read_boot(&destination)? != boot {
        return Err(HostError::Invalid(
            "boot worker returned unbacked artifacts",
        ));
    }
    Ok((destination, boot))
}

fn boot_job(
    machine_id: &MachineId,
    generation: Counter,
    image_digest: &Digest,
    disk_bytes: u64,
) -> Result<Job> {
    // A response loss reuses the exact operation and frozen bytes. A fresh
    // native boot has a new host generation, not a new random retry identity.
    let identity = digest(
        Domain::Image,
        &(
            "sandsurf-boot-object-v1",
            machine_id,
            generation,
            image_digest,
            disk_bytes,
        ),
    )?;
    let boot_name = format!("boot-{}-{}", generation.get(), identity.as_str());
    let build = Build::Boot {
        machine_id: machine_id.clone(),
        generation,
        image_digest: image_digest.clone(),
        disk_bytes,
        boot_name,
    };
    let request_digest = digest(Domain::Image, &("sandsurf-boot-preparation-v1", &build))?;
    let operation = format!("boot-{}", request_digest.as_str()).try_into()?;
    Ok(Job {
        operation,
        request_digest,
        build,
    })
}

fn fork_disk(root: &Path, machine_id: &MachineId) -> PathBuf {
    root.join("machines")
        .join(object_name(machine_id.as_str()))
        .join("disks/system.ext4")
}

pub(crate) fn materialize_fork(
    root: &Path,
    executable: &Path,
    snapshot: &Snapshot,
    machine_id: &MachineId,
    profile: sandsurf_image::identity::CloneProfile,
    operation: &OperationId,
) -> Result<Digest> {
    let build = Build::Fork {
        snapshot: Box::new(snapshot.clone()),
        machine_id: machine_id.clone(),
        profile,
    };
    let request_digest = digest(
        Domain::Image,
        &("sandsurf-fork-preparation-v1", operation, &build),
    )?;
    let job = Job {
        operation: format!("fork-{}", request_digest.as_str()).try_into()?,
        request_digest,
        build,
    };
    match dispatch(root, executable, job)? {
        Outcome::Fork { customized } => Ok(customized),
        _ => Err(HostError::Invalid(
            "fork worker returned a different result kind",
        )),
    }
}

pub(crate) fn finish_disk_snapshot(
    root: &Path,
    executable: &Path,
    snapshot: &Snapshot,
) -> Result<crate::snapshots::CaptureResult> {
    let build = Build::DiskSnapshot {
        snapshot: Box::new(snapshot.clone()),
    };
    let request_digest = digest(
        Domain::Image,
        &("sandsurf-disk-capture-finishing-v1", &build),
    )?;
    let job = Job {
        operation: format!("capture-{}", request_digest.as_str()).try_into()?,
        request_digest,
        build,
    };
    match dispatch(root, executable, job)? {
        Outcome::DiskSnapshot { capture } => Ok(capture),
        _ => Err(HostError::Invalid(
            "snapshot worker returned a different result kind",
        )),
    }
}

fn dispatch(root: &Path, executable: &Path, job: Job) -> Result<Outcome> {
    job.validate()?;
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
    job.validate()?;
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
        Build::DiskSnapshot { snapshot } => {
            let image = crate::images::resolve_native_image(&root, &snapshot.image_digest)?;
            crate::snapshots::finish_filesystem(
                &crate::snapshots::root(&root, snapshot),
                snapshot,
                &image,
            )?;
            return Ok(());
        }
        Build::Fork {
            snapshot,
            machine_id,
            profile,
        } => {
            let image = crate::images::resolve_native_image(&root, &snapshot.image_digest)?;
            if image.manifest.system.clone_profile != *profile {
                return Err(HostError::Invalid(
                    "fork profile differs from its admitted image",
                ));
            }
            crate::snapshots::materialize_fork(
                &crate::snapshots::root(&root, snapshot),
                snapshot,
                &fork_disk(&root, machine_id),
                profile,
            )?;
            publish(
                &directory(&root, &operation).join("result.json"),
                &ForkResult {
                    request_digest: job.request_digest.clone(),
                },
            )?;
            return Ok(());
        }
        Build::Boot {
            machine_id,
            generation,
            image_digest,
            disk_bytes,
            boot_name,
        } => {
            prepare_machine(
                &root,
                machine_id,
                *generation,
                image_digest,
                *disk_bytes,
                boot_name,
            )?;
            let boot = crate::storage::read_boot(
                &root
                    .join("machines")
                    .join(object_name(machine_id.as_str()))
                    .join("guardian")
                    .join(boot_name),
            )?;
            publish(
                &directory(&root, &operation).join("result.json"),
                &BootResult {
                    request_digest: job.request_digest.clone(),
                    boot,
                },
            )?;
            return Ok(());
        }
        Build::Image {
            input:
                ImageImportInput::Native {
                    manifest_path,
                    manifest_digest,
                },
        } => crate::images::import_native(
            &root,
            manifest_path,
            manifest_digest,
            &operation,
            &job.request_digest,
        )?,
        Build::Image {
            input:
                ImageImportInput::Oci {
                    source,
                    recipe,
                    platform,
                },
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
        Build::Image {
            input:
                ImageImportInput::PublishSnapshot {
                    snapshot,
                    allow_sensitive,
                },
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
    if crate::images::completed(&root, &operation, &job.request_digest)?.as_ref() != Some(&image) {
        return Err(HostError::Invalid(
            "image builder returned without its matching complete outcome",
        ));
    }
    Ok(())
}

fn boot_directory(
    root: &Path,
    machine: &MachineId,
    generation: Counter,
    boot_name: &str,
) -> Result<PathBuf> {
    let prefix = format!("boot-{}-", generation.get());
    if boot_name.strip_prefix(&prefix).is_none_or(|nonce| {
        nonce.len() != 64
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }) {
        return Err(HostError::Invalid("invalid boot preparation object name"));
    }
    Ok(root
        .join("machines")
        .join(object_name(machine.as_str()))
        .join("guardian")
        .join(boot_name))
}

fn prepare_machine(
    root: &Path,
    machine: &MachineId,
    generation: Counter,
    image_digest: &Digest,
    disk_bytes: u64,
    boot_name: &str,
) -> Result<()> {
    let boot_directory = boot_directory(root, machine, generation, boot_name)?;
    let machine_root = root.join("machines").join(object_name(machine.as_str()));
    sandsurf_native::local::canonical_private_directory(&machine_root)?;
    let image = crate::images::resolve_native_image(root, image_digest)?;
    let disk = machine_root.join("disks/system.ext4");
    crate::storage::materialize(&image.system_path, &disk, disk_bytes, |staged| {
        sandsurf_image::identity::customize(staged, &image.manifest.system.clone_profile)
    })?;
    let _custody = crate::storage::attach(&disk)?;
    crate::storage::freeze_boot(&image, &disk, &boot_directory)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_jobs_bind_every_input_and_cannot_address_arbitrary_host_paths() {
        let root = Path::new("/host-owner");
        let machine: MachineId = "computer".try_into().unwrap();
        let generation: Counter = 7.try_into().unwrap();
        let image = sandsurf_protocol::bytes_digest(b"image");
        assert_eq!(
            serde_json::to_vec(&boot_job(&machine, generation, &image, 8192).unwrap()).unwrap(),
            serde_json::to_vec(&boot_job(&machine, generation, &image, 8192).unwrap()).unwrap()
        );
        assert_ne!(
            boot_job(&machine, generation, &image, 8192)
                .unwrap()
                .operation,
            boot_job(&machine, generation.next().unwrap(), &image, 8192)
                .unwrap()
                .operation
        );
        let name = format!("boot-7-{}", "a".repeat(64));
        assert_eq!(
            boot_directory(root, &machine, generation, &name).unwrap(),
            root.join("machines")
                .join(object_name(machine.as_str()))
                .join("guardian")
                .join(&name)
        );
        for name in [
            "../outside",
            "/host/kernel",
            "boot-8-aaaa",
            "boot-7-aaa",
            &format!("boot-7-{}", "A".repeat(64)),
        ] {
            assert!(boot_directory(root, &machine, generation, name).is_err());
        }
        let build = Build::Boot {
            machine_id: machine,
            generation,
            image_digest: sandsurf_protocol::bytes_digest(b"image"),
            disk_bytes: 8192,
            boot_name: name,
        };
        let encoded = serde_json::to_value(&build).unwrap();
        let identity = digest(Domain::Image, &("sandsurf-boot-preparation-v1", &build)).unwrap();
        for (key, value) in [
            ("machineId", serde_json::json!("other-computer")),
            ("generation", serde_json::json!(8)),
            (
                "imageDigest",
                serde_json::json!(sandsurf_protocol::bytes_digest(b"other-image")),
            ),
            ("diskBytes", serde_json::json!(16384)),
            (
                "bootName",
                serde_json::json!(format!("boot-7-{}", "b".repeat(64))),
            ),
        ] {
            let mut changed = encoded.clone();
            changed[key] = value;
            let changed: Build = serde_json::from_value(changed).unwrap();
            assert_ne!(
                digest(Domain::Image, &("sandsurf-boot-preparation-v1", &changed)).unwrap(),
                identity
            );
        }
        let mut invalid = encoded;
        invalid["diskPath"] = serde_json::json!("/arbitrary/host/data");
        assert!(serde_json::from_value::<Build>(invalid).is_err());
    }

    #[test]
    fn boot_completion_reference_alone_is_not_a_completed_preparation() {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "sandsurf-boot-result-{}",
            sandsurf_protocol::bytes_digest(&nonce).as_str()
        ));
        ensure_private_directory(&root).unwrap();
        ensure_private_directory(&root.join("image-workers")).unwrap();
        let job = Job {
            operation: "boot-operation".try_into().unwrap(),
            request_digest: sandsurf_protocol::bytes_digest(b"job"),
            build: Build::Boot {
                machine_id: "computer".try_into().unwrap(),
                generation: 7.try_into().unwrap(),
                image_digest: sandsurf_protocol::bytes_digest(b"image"),
                disk_bytes: 8192,
                boot_name: format!("boot-7-{}", "a".repeat(64)),
            },
        };
        ensure_private_directory(&directory(&root, &job.operation)).unwrap();
        assert!(result(&root, &job).unwrap().is_none());
        let boot = sandsurf_image::boot::FrozenBoot {
            architecture: sandsurf_image::Architecture::X64,
            kernel: sandsurf_image::ImageArtifact {
                path: "kernel".into(),
                sha256: "a".repeat(64),
            },
            initramfs: None,
        };
        publish(
            &directory(&root, &job.operation).join("result.json"),
            &BootResult {
                request_digest: job.request_digest.clone(),
                boot,
            },
        )
        .unwrap();
        assert!(result(&root, &job).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
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
        let input = ImageImportInput::Native {
            manifest_path: root.join("manifest.json"),
            manifest_digest: sandsurf_protocol::bytes_digest(b"image"),
        };
        let job = Job {
            operation: operation.clone(),
            request_digest: input.request_digest(&operation).unwrap(),
            build: Build::Image { input },
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
        let altered: OperationId = "altered-operation".try_into().unwrap();
        let altered_stage = directory(&root, &altered);
        ensure_private_directory(&altered_stage).unwrap();
        let mut changed = job;
        changed.operation = altered.clone();
        // Even a well-formed job cannot change its executable input while
        // retaining another request's approval digest.
        publish(&altered_stage.join("job.json"), &changed).unwrap();
        assert!(admitted(&root, &altered).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
