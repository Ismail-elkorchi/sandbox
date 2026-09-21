//! Windows guardian integration for one retained Hyper-V/HCS Linux VM.

use crate::guest::{GuestClient, RemoteWorkloadDriver};
use sandbox_guest::{
    AUTHENTICATION_MAGIC, GUEST_BOOTSTRAP_PORT, GUEST_CONTROL_PORT, GUEST_EXPOSURE_PORT,
    NETWORK_DNS_TCP_PORT, NETWORK_DNS_UDP_PORT, NETWORK_HTTP_PORT, NETWORK_SOCKS_PORT,
};
use sandbox_image::{Architecture, ImageTrust, VerifiedImage, verify_image};
use sandsurf_control::{
    EffectOutcome, Error as ControlError, GuardianEffect, Result as ControlResult, WorkloadDriver,
};
use sandsurf_machine::windows::{HyperVConfig, HyperVDisk, HyperVDriver, HyperVQualification};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_native::{GuestChannel, HyperVChannel, virtual_disk};
use sandsurf_protocol::{
    Capability, Counter, Digest, Domain, GuestServiceRequest, GuestServiceResponse,
    LifecycleCommand, MachineObservation, MachineState, Mutation, Resources, RuntimeConfiguration,
    SandboxId, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONFIG_VERSION: u16 = 1;
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const BUNDLED_IMAGE_MANIFEST_DIGEST: Option<&str> =
    option_env!("SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST");

#[derive(Debug)]
pub enum WindowsError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandbox_image::ImageError),
    Invalid(String),
}

impl fmt::Display for WindowsError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "Windows guardian I/O: {error}"),
            Self::Json(error) => write!(output, "Windows guardian configuration: {error}"),
            Self::Image(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for WindowsError {}
impl From<io::Error> for WindowsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for WindowsError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandbox_image::ImageError> for WindowsError {
    fn from(value: sandbox_image::ImageError) -> Self {
        Self::Image(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsGuardianConfig {
    format_version: u16,
    sandbox_id: SandboxId,
    image_digest: Digest,
    resources: Resources,
    image_manifest: PathBuf,
    vm_id: String,
    hvsock_security_descriptor: String,
}

pub fn prepare_config(
    host_root: &Path,
    executable: &Path,
    sandbox_id: &SandboxId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<WindowsGuardianConfig, WindowsError> {
    let path = host_root
        .join("sandboxes")
        .join(sandbox_id.as_str())
        .join("guardian/config.json");
    if path.exists() {
        let existing = read_config(&path, sandbox_id)?;
        if existing.image_digest != *image_digest || existing.resources != *resources {
            return Err(WindowsError::Invalid(
                "existing Sandbox configuration conflicts with create request".into(),
            ));
        }
        return Ok(existing);
    }
    let image = resolve_source_bundle(host_root, executable, image_digest)?;
    if image.manifest.architecture != Architecture::X64 || image.windows_x64.is_none() {
        return Err(WindowsError::Invalid(
            "image has no qualified Windows x64 boot artifacts".into(),
        ));
    }
    if resources.vcpus.get() > 64
        || resources.memory_mib.get() < 256
        || resources.memory_mib.get() > 1_048_576
        || resources.disk_bytes.get() > MAX_ARTIFACT_BYTES
    {
        return Err(WindowsError::Invalid(
            "requested VM shape is outside the Hyper-V envelope".into(),
        ));
    }
    Ok(WindowsGuardianConfig {
        format_version: CONFIG_VERSION,
        sandbox_id: sandbox_id.clone(),
        image_digest: image_digest.clone(),
        resources: resources.clone(),
        image_manifest: image.manifest_path,
        vm_id: deterministic_vm_id(host_root, sandbox_id),
        hvsock_security_descriptor: sandsurf_native::local::current_user_sddl()?,
    })
}

pub fn write_config(path: &Path, config: &WindowsGuardianConfig) -> Result<(), WindowsError> {
    if path.exists() {
        return if read_json::<WindowsGuardianConfig>(path, 1024 * 1024)? == *config {
            Ok(())
        } else {
            Err(WindowsError::Invalid(
                "guardian configuration is already bound to different inputs".into(),
            ))
        };
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer(&mut file, config)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn read_config(
    path: &Path,
    sandbox_id: &SandboxId,
) -> Result<WindowsGuardianConfig, WindowsError> {
    let value: WindowsGuardianConfig = read_json(path, 1024 * 1024)?;
    if value.format_version != CONFIG_VERSION || value.sandbox_id != *sandbox_id {
        return Err(WindowsError::Invalid(
            "guardian configuration identity is invalid".into(),
        ));
    }
    let image = verify_image(&value.image_manifest, ImageTrust::ExplicitLocal)?;
    if image.manifest_digest != value.image_digest.as_str() || image.windows_x64.is_none() {
        return Err(WindowsError::Invalid(
            "guardian image artifact identity changed".into(),
        ));
    }
    Ok(value)
}

pub fn workload_defaults(
    host_root: &Path,
    image_digest: &Digest,
) -> Result<crate::api::WorkloadDefaultsView, WindowsError> {
    let image = verify_image(
        &host_root
            .join("images")
            .join(image_digest.as_str())
            .join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if image.manifest_digest != image_digest.as_str() {
        return Err(WindowsError::Invalid(
            "installed image identity changed".into(),
        ));
    }
    let defaults = image.manifest.workload.defaults;
    Ok(crate::api::WorkloadDefaultsView {
        environment: defaults.environment,
        user: defaults.user,
        working_directory: defaults.working_directory,
        entrypoint: defaults.entrypoint,
        command: defaults.command,
    })
}

pub struct WindowsGuardianEffect {
    machine: HyperVDriver,
    workload: WindowsWorkload,
    pending: Option<PendingGuest>,
    installed_runtime: Option<InstalledRuntime>,
}

#[derive(Clone)]
struct ActiveGuest {
    vm_id: String,
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
}

struct PendingGuest {
    active: ActiveGuest,
    authentication: Vec<u8>,
}

struct WindowsWorkload {
    active: Arc<Mutex<Option<ActiveGuest>>>,
}

struct InstalledRuntime {
    epoch: Counter,
    configuration: RuntimeConfiguration,
    evidence: Digest,
}

impl WindowsGuardianEffect {
    pub fn open(sandbox_root: &Path, config: WindowsGuardianConfig) -> Result<Self, WindowsError> {
        let image = verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        let windows = image
            .windows_x64
            .ok_or_else(|| WindowsError::Invalid("image has no Windows boot artifacts".into()))?;
        let disks = sandbox_root.join("disks");
        fs::create_dir_all(&disks)?;
        let workload_state = disks.join("workload-state.vhdx");
        let control_state = disks.join("control-state.vhdx");
        ensure_mutable_vhdx(
            &windows.state_template_path,
            &workload_state,
            config.resources.disk_bytes.get(),
        )?;
        let control_bytes = config
            .resources
            .output_bytes
            .get()
            .checked_add(64 * 1024 * 1024)
            .ok_or_else(|| WindowsError::Invalid("control disk size overflow".into()))?
            .max(128 * 1024 * 1024);
        ensure_mutable_vhdx(&windows.state_template_path, &control_state, control_bytes)?;
        let ports = vec![
            GUEST_BOOTSTRAP_PORT,
            GUEST_CONTROL_PORT,
            GUEST_EXPOSURE_PORT,
            NETWORK_HTTP_PORT,
            NETWORK_SOCKS_PORT,
            NETWORK_DNS_TCP_PORT,
            NETWORK_DNS_UDP_PORT,
        ];
        let machine = HyperVDriver::new(HyperVConfig {
            sandbox_id: config.sandbox_id.clone(),
            vm_id: config.vm_id.clone(),
            guest_architecture: crate::service::native_guest_architecture(),
            memory_mib: config.resources.memory_mib.get(),
            vcpus: u32::try_from(config.resources.vcpus.get())
                .map_err(|_| WindowsError::Invalid("vCPU count overflow".into()))?,
            kernel: windows.kernel_path,
            command_line:
                "console=ttyS0 reboot=k panic=1 root=/dev/sda ro init=/sbin/sandbox-guest".into(),
            disks: vec![
                HyperVDisk {
                    path: windows.bootstrap_path,
                    read_only: true,
                },
                HyperVDisk {
                    path: windows.workload_path,
                    read_only: true,
                },
                HyperVDisk {
                    path: workload_state,
                    read_only: false,
                },
                HyperVDisk {
                    path: control_state,
                    read_only: false,
                },
            ],
            hvsock_security_descriptor: config.hvsock_security_descriptor,
            hvsock_ports: ports,
            operation_timeout: HyperVDriver::default_timeout(),
            qualification: HyperVQualification {
                lifecycle: None,
                full_state: None,
            },
        })
        .map_err(|error| WindowsError::Invalid(format!("invalid Hyper-V VM: {error:?}")))?;
        let active = Arc::new(Mutex::new(None));
        Ok(Self {
            machine,
            workload: WindowsWorkload { active },
            pending: None,
            installed_runtime: None,
        })
    }

    fn prepare_boot(&mut self, command: &LifecycleCommand, epoch: Counter) -> Result<(), Digest> {
        let capability = random_bytes().map_err(|_| bytes_digest(b"hyper-v-boot-entropy"))?;
        let network_capability =
            random_bytes().map_err(|_| bytes_digest(b"hyper-v-network-entropy"))?;
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-hyper-v-boot-v1",
                &command.sandbox_id,
                sandbox_guest::GUEST_PROTOCOL_MAJOR,
                sandbox_guest::GUEST_PROTOCOL_MINOR,
            ),
        )
        .map_err(|_| bytes_digest(b"hyper-v-boot-identity"))?;
        let authentication = authentication_record(
            &command.sandbox_id,
            epoch,
            &boot_identity,
            &capability,
            &network_capability,
        )
        .map_err(|_| bytes_digest(b"hyper-v-authentication-record"))?;
        self.pending = Some(PendingGuest {
            active: ActiveGuest {
                vm_id: self.machine.vm_id().to_owned(),
                sandbox_id: command.sandbox_id.clone(),
                epoch,
                boot_identity,
                capability,
            },
            authentication,
        });
        Ok(())
    }

    fn authenticate_pending(&mut self) -> Result<ActiveGuest, Digest> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"hyper-v-pending-guest-missing"))?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let provisioned = HyperVChannel {
                vm_id: pending.active.vm_id.clone(),
                guest_port: GUEST_BOOTSTRAP_PORT,
                timeout: Duration::from_secs(10),
            }
            .connect()
            .and_then(|mut stream| {
                stream.write_all(&pending.authentication)?;
                stream.flush()?;
                Ok(())
            });
            if provisioned.is_ok() {
                break;
            }
            if !self.machine.has_live_owner() || Instant::now() >= deadline {
                return Err(bytes_digest(b"hyper-v-bootstrap-timeout"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        loop {
            match guest_client(&pending.active).call(&GuestServiceRequest::ProbeIdentity) {
                Ok(GuestServiceResponse::Identity {
                    sandbox_id,
                    epoch,
                    boot_identity,
                }) if sandbox_id == pending.active.sandbox_id
                    && epoch == pending.active.epoch
                    && boot_identity == pending.active.boot_identity =>
                {
                    return Ok(pending.active);
                }
                _ if !self.machine.has_live_owner() || Instant::now() >= deadline => {
                    return Err(bytes_digest(b"hyper-v-guest-authentication-timeout"));
                }
                _ => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    fn install_runtime(&mut self, configuration: &RuntimeConfiguration) -> RuntimeInstallation {
        let Some(active) = self.workload.endpoint() else {
            return RuntimeInstallation::Unknown;
        };
        if let Some(installed) = self.installed_runtime.as_ref()
            && installed.epoch == active.epoch
            && installed.configuration == *configuration
        {
            return RuntimeInstallation::Applied(installed.evidence.clone());
        }
        if !configuration.network.rules.is_empty() || !configuration.exposures.is_empty() {
            return RuntimeInstallation::NotApplied(bytes_digest(
                b"hyper-v-managed-network-data-plane-not-qualified",
            ));
        }
        let resource_evidence =
            match guest_client(&active).call(&GuestServiceRequest::ApplyResources {
                resources: configuration.resources.clone(),
            }) {
                Ok(GuestServiceResponse::ResourcesApplied { evidence }) => evidence,
                _ => return RuntimeInstallation::Unknown,
            };
        match digest(
            Domain::Grant,
            &(
                "sandsurf-hyper-v-runtime-configuration-v1",
                resource_evidence,
                configuration,
            ),
        ) {
            Ok(evidence) => {
                self.installed_runtime = Some(InstalledRuntime {
                    epoch: active.epoch,
                    configuration: configuration.clone(),
                    evidence: evidence.clone(),
                });
                RuntimeInstallation::Applied(evidence)
            }
            Err(_) => RuntimeInstallation::Unknown,
        }
    }

    fn contain_unpublished(&mut self) {
        self.machine.contain_unobserved();
        self.pending = None;
        self.installed_runtime = None;
        if let Ok(mut active) = self.workload.active.lock() {
            *active = None;
        }
    }
}

enum RuntimeInstallation {
    Applied(Digest),
    NotApplied(Digest),
    Unknown,
}

impl WindowsWorkload {
    fn endpoint(&self) -> Option<ActiveGuest> {
        self.active.lock().ok()?.clone()
    }
}

impl WorkloadDriver for WindowsWorkload {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        let Some(active) = self.endpoint() else {
            return EffectOutcome::NotApplied(bytes_digest(b"hyper-v-guest-not-running"));
        };
        RemoteWorkloadDriver::new(guest_client(&active)).dispatch(mutation, capability)
    }

    fn reconcile(&mut self, journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        if let Some(active) = self.endpoint() {
            RemoteWorkloadDriver::new(guest_client(&active)).reconcile(journal)?;
        }
        Ok(())
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        let active = self.endpoint().ok_or(ControlError::Unsupported(
            "guest is unavailable because the Hyper-V VM has no live owner",
        ))?;
        RemoteWorkloadDriver::new(guest_client(&active)).query(request)
    }
}

impl GuardianEffect for WindowsGuardianEffect {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        self.workload.dispatch(mutation, capability)
    }

    fn transition(
        &mut self,
        command: &LifecycleCommand,
        current: Option<&MachineObservation>,
    ) -> MachineOutcome {
        let cold_boot = command.desired == sandsurf_protocol::DesiredState::Running
            && current.is_none_or(|value| {
                matches!(value.state, MachineState::Stopped | MachineState::Failed)
            });
        if cold_boot {
            let epoch = match current {
                Some(value) => match value.epoch.next() {
                    Ok(value) => value,
                    Err(_) => return MachineOutcome::Unknown,
                },
                None => Counter::ONE,
            };
            if let Err(evidence) = self.prepare_boot(command, epoch) {
                return MachineOutcome::NotApplied(evidence);
            }
        }
        let mut outcome = apply_lifecycle(&mut self.machine, command, current);
        let running = matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| value.state == MachineState::Running)
        );
        if running {
            if cold_boot {
                match self.authenticate_pending() {
                    Ok(active) => {
                        if let Ok(mut endpoint) = self.workload.active.lock() {
                            *endpoint = Some(active);
                        } else {
                            self.contain_unpublished();
                            return MachineOutcome::Unknown;
                        }
                    }
                    Err(evidence) => {
                        self.contain_unpublished();
                        return MachineOutcome::NotApplied(evidence);
                    }
                }
            }
            let runtime = match self.install_runtime(&command.configuration) {
                RuntimeInstallation::Applied(value) => value,
                RuntimeInstallation::NotApplied(value) => {
                    self.contain_unpublished();
                    return MachineOutcome::NotApplied(value);
                }
                RuntimeInstallation::Unknown => {
                    self.contain_unpublished();
                    return MachineOutcome::Unknown;
                }
            };
            if let MachineOutcome::Observed(values) = &mut outcome
                && let Some(last) = values.last_mut()
            {
                match digest(
                    Domain::Grant,
                    &(
                        "sandsurf-hyper-v-running-with-configuration-v1",
                        &last.evidence_digest,
                        runtime,
                        command.revision,
                    ),
                ) {
                    Ok(evidence) => last.evidence_digest = evidence,
                    Err(_) => {
                        self.contain_unpublished();
                        return MachineOutcome::Unknown;
                    }
                }
            }
        }
        if matches!(
            &outcome,
            MachineOutcome::Observed(values)
                if values.last().is_some_and(|value| matches!(value.state, MachineState::Stopped | MachineState::Suspended | MachineState::Destroyed))
        ) {
            self.installed_runtime = None;
            if let Ok(mut active) = self.workload.active.lock() {
                *active = None;
            }
        }
        outcome
    }

    fn configure(
        &mut self,
        command: &sandsurf_protocol::ConfigurationCommand,
        current: &MachineObservation,
    ) -> EffectOutcome {
        match self.machine.configure(command, current) {
            sandsurf_machine::ConfigurationOutcome::Applied(machine) => {
                match self.install_runtime(&command.configuration) {
                    RuntimeInstallation::Applied(runtime) => digest(
                        Domain::Grant,
                        &(
                            "sandsurf-hyper-v-configuration-applied-v1",
                            machine,
                            runtime,
                            &command.configuration,
                        ),
                    )
                    .map_or(EffectOutcome::Unknown, EffectOutcome::Applied),
                    RuntimeInstallation::NotApplied(value) => EffectOutcome::NotApplied(value),
                    RuntimeInstallation::Unknown => EffectOutcome::Unknown,
                }
            }
            sandsurf_machine::ConfigurationOutcome::NotApplied(value) => {
                EffectOutcome::NotApplied(value)
            }
            sandsurf_machine::ConfigurationOutcome::Unknown => EffectOutcome::Unknown,
        }
    }

    fn reconcile(&mut self, journal: &mut RuntimeJournal) -> sandsurf_state::Result<()> {
        if journal
            .last_observation()?
            .is_some_and(|value| value.value().state == MachineState::Running)
        {
            self.workload.reconcile(journal)?;
        }
        Ok(())
    }

    fn query(&mut self, request: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        if let GuestServiceRequest::PrepareFilesystemCapture { operation_id } = &request {
            let operation_id = operation_id.clone();
            let response = self.workload.query(request)?;
            if !matches!(
                response,
                GuestServiceResponse::FilesystemCapturePrepared { .. }
            ) {
                return Ok(response);
            }
            if self.machine.pause_for_capture().is_err() {
                let _ = self
                    .workload
                    .query(GuestServiceRequest::FinishFilesystemCapture { operation_id });
                return Err(ControlError::Unsupported(
                    "Hyper-V VM could not establish the filesystem capture pause",
                ));
            }
            return Ok(response);
        }
        if let GuestServiceRequest::FinishFilesystemCapture { operation_id } = request {
            self.machine.resume_after_capture().map_err(|_| {
                ControlError::Unsupported("Hyper-V VM could not leave the filesystem capture pause")
            })?;
            return self
                .workload
                .query(GuestServiceRequest::FinishFilesystemCapture { operation_id });
        }
        self.workload.query(request)
    }

    fn live_observation_reachable(&mut self) -> bool {
        self.machine.has_live_owner()
    }
}

fn guest_client(active: &ActiveGuest) -> GuestClient<HyperVChannel> {
    GuestClient::new(
        HyperVChannel {
            vm_id: active.vm_id.clone(),
            guest_port: GUEST_CONTROL_PORT,
            timeout: Duration::from_secs(10),
        },
        active.sandbox_id.clone(),
        active.epoch,
        active.boot_identity.clone(),
        active.capability,
    )
}

fn authentication_record(
    sandbox_id: &SandboxId,
    epoch: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
    network_capability: &[u8; 32],
) -> Result<Vec<u8>, WindowsError> {
    let identity = sandbox_id.as_str().as_bytes();
    let size = u16::try_from(identity.len())
        .map_err(|_| WindowsError::Invalid("sandbox identity is too long".into()))?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(AUTHENTICATION_MAGIC);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(identity);
    bytes.extend_from_slice(&epoch.get().to_be_bytes());
    bytes.extend_from_slice(&decode_hex(boot_identity.as_str())?);
    bytes.extend_from_slice(capability);
    bytes.extend_from_slice(network_capability);
    bytes.resize(512, 0);
    Ok(bytes)
}

fn ensure_mutable_vhdx(source: &Path, destination: &Path, bytes: u64) -> Result<(), WindowsError> {
    if !bytes.is_multiple_of(1024 * 1024) || bytes < 64 * 1024 * 1024 || bytes > MAX_ARTIFACT_BYTES
    {
        return Err(WindowsError::Invalid(
            "persistent VHDX geometry is outside the envelope".into(),
        ));
    }
    if !destination.exists() {
        copy_artifact(source, destination)?;
        virtual_disk::grow_virtual_disk(destination, bytes)?;
    }
    let actual = virtual_disk::virtual_disk_size(destination)?;
    if actual != bytes {
        return Err(WindowsError::Invalid(format!(
            "persistent VHDX virtual size changed: expected {bytes}, observed {actual}"
        )));
    }
    Ok(())
}

fn resolve_source_bundle(
    host_root: &Path,
    executable: &Path,
    expected: &Digest,
) -> Result<VerifiedImage, WindowsError> {
    let installed = host_root.join("images").join(expected.as_str());
    if installed.exists() {
        return Ok(verify_image(
            &installed.join("manifest.json"),
            ImageTrust::ExplicitLocal,
        )?);
    }
    let package = executable
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| WindowsError::Invalid("native package layout is invalid".into()))?;
    let relative = "minimal-x64/manifest.json";
    let index: ImageIndex = read_json(&package.join("images/manifest.json"), 1024 * 1024)?;
    let indexed = index
        .files
        .get(relative)
        .ok_or_else(|| WindowsError::Invalid("packaged image manifest is absent".into()))?;
    let pinned = BUNDLED_IMAGE_MANIFEST_DIGEST.ok_or_else(|| {
        WindowsError::Invalid("native host has no bundled image trust identity".into())
    })?;
    if indexed != pinned || expected.as_str() != pinned {
        return Err(WindowsError::Invalid(
            "packaged image index differs from the native trust identity".into(),
        ));
    }
    let image = verify_image(
        &package.join("images").join(relative),
        ImageTrust::Pinned {
            manifest_digest: pinned,
        },
    )?;
    let installed = install_image(host_root, &image)?;
    Ok(verify_image(
        &installed.join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageIndex {
    #[serde(rename = "formatVersion")]
    _format_version: u16,
    #[serde(rename = "buildId")]
    _build_id: String,
    files: BTreeMap<String, String>,
}

fn install_image(host_root: &Path, image: &VerifiedImage) -> Result<PathBuf, WindowsError> {
    let root = host_root.join("images").join(&image.manifest_digest);
    if root.exists() {
        return Ok(root);
    }
    let staging = host_root
        .join("images")
        .join(format!("stage-{}", hex(&random_bytes()?)));
    fs::create_dir(&staging)?;
    let result = (|| -> Result<(), WindowsError> {
        copy_artifact(&image.manifest_path, &staging.join("manifest.json"))?;
        copy_artifact(
            &image.kernel_path,
            &staging.join(&image.manifest.boot_bundle.kernel.path),
        )?;
        copy_artifact(
            &image.bootstrap_path,
            &staging.join(&image.manifest.boot_bundle.bootstrap.path),
        )?;
        copy_artifact(
            &image.workload_path,
            &staging.join(&image.manifest.workload.rootfs.path),
        )?;
        if let Some(template) = &image.manifest.workload.state_template {
            let source = image
                .manifest_path
                .parent()
                .ok_or_else(|| WindowsError::Invalid("image manifest has no parent".into()))?
                .join(&template.path);
            copy_artifact(&source, &staging.join(&template.path))?;
        }
        let windows = image
            .windows_x64
            .as_ref()
            .ok_or_else(|| WindowsError::Invalid("Windows artifacts are absent".into()))?;
        let manifest = image
            .manifest
            .platform_artifacts
            .windows_x64
            .as_ref()
            .ok_or_else(|| WindowsError::Invalid("Windows artifact metadata is absent".into()))?;
        for (source, relative) in [
            (&windows.kernel_path, &manifest.kernel.path),
            (&windows.bootstrap_path, &manifest.bootstrap.path),
            (&windows.workload_path, &manifest.workload.path),
            (&windows.state_template_path, &manifest.state_template.path),
        ] {
            copy_artifact(source, &staging.join(relative))?;
        }
        let copied = verify_image(&staging.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if copied.manifest_digest != image.manifest_digest {
            return Err(WindowsError::Invalid(
                "copied image identity changed".into(),
            ));
        }
        fs::rename(&staging, &root)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok(root)
}

fn copy_artifact(source: &Path, destination: &Path) -> Result<(), WindowsError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn deterministic_vm_id(host_root: &Path, sandbox_id: &SandboxId) -> String {
    let hash = Sha256::digest(format!("{}\0{}", host_root.display(), sandbox_id.as_str()));
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hash[..16]);
    raw[6] = (raw[6] & 0x0f) | 0x50;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[0],
        raw[1],
        raw[2],
        raw[3],
        raw[4],
        raw[5],
        raw[6],
        raw[7],
        raw[8],
        raw[9],
        raw[10],
        raw[11],
        raw[12],
        raw[13],
        raw[14],
        raw[15]
    )
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, WindowsError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(WindowsError::Invalid(
            "JSON artifact is not a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(WindowsError::Invalid("JSON artifact exceeds bound".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn random_bytes() -> Result<[u8; 32], WindowsError> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| WindowsError::Invalid("host entropy unavailable".into()))?;
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<[u8; 32], WindowsError> {
    if value.len() != 64 {
        return Err(WindowsError::Invalid("digest is malformed".into()));
    }
    let mut bytes = [0; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| WindowsError::Invalid("digest is malformed".into()))?;
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("hex formatting cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_identity_is_stable_and_canonical() {
        let sandbox: SandboxId = "box".try_into().unwrap();
        let first = deterministic_vm_id(Path::new(r"C:\Sandsurf"), &sandbox);
        let second = deterministic_vm_id(Path::new(r"C:\Sandsurf"), &sandbox);
        assert_eq!(first, second);
        assert_eq!(first.len(), 36);
        assert_eq!(&first[14..15], "5");
    }
}
