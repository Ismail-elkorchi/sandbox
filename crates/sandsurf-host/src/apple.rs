//! macOS guardian integration for one retained Virtualization.framework VM.

use crate::guest::{GuestClient, RemoteWorkloadDriver};
use sandbox_guest::{
    AUTHENTICATION_MAGIC, GUEST_CONTROL_PORT, GUEST_EXPOSURE_PORT, NETWORK_DNS_TCP_PORT,
    NETWORK_DNS_UDP_PORT, NETWORK_HTTP_PORT, NETWORK_SOCKS_PORT,
};
use sandbox_image::{Architecture, ImageTrust, RootfsFormat, VerifiedImage, verify_image};
use sandbox_vm::{VmNetworkBridge, VmPortGateway};
use sandsurf_control::{
    EffectOutcome, Error as ControlError, GuardianEffect, Result as ControlResult, WorkloadDriver,
};
use sandsurf_machine::macos::{AppleConfig, AppleDisk, AppleDriver, AppleQualification};
use sandsurf_machine::{MachineDriver, MachineOutcome, apply_lifecycle};
use sandsurf_native::UnixVsockChannel;
use sandsurf_protocol::{
    Capability, Counter, Digest, Domain, GuestServiceRequest, GuestServiceResponse,
    LifecycleCommand, MachineObservation, MachineState, Mutation, NetworkDestination,
    NetworkPolicy, Resources, RuntimeConfiguration, SandboxId, bytes_digest, digest,
};
use sandsurf_state::RuntimeJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONFIG_VERSION: u16 = 1;
const BUNDLED_IMAGE_MANIFEST_DIGEST: Option<&str> =
    option_env!("SANDSURF_BUNDLED_IMAGE_MANIFEST_DIGEST");

#[derive(Debug)]
pub enum AppleError {
    Io(io::Error),
    Json(serde_json::Error),
    Image(sandbox_image::ImageError),
    Invalid(String),
}

impl fmt::Display for AppleError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "Apple guardian I/O: {error}"),
            Self::Json(error) => write!(output, "Apple guardian configuration: {error}"),
            Self::Image(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for AppleError {}
impl From<io::Error> for AppleError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for AppleError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandbox_image::ImageError> for AppleError {
    fn from(value: sandbox_image::ImageError) -> Self {
        Self::Image(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppleGuardianConfig {
    format_version: u16,
    sandbox_id: SandboxId,
    image_digest: Digest,
    resources: Resources,
    helper: PathBuf,
    helper_digest: Digest,
    image_manifest: PathBuf,
    disk_template: PathBuf,
    disk_template_sha256: String,
    control_socket: PathBuf,
}

pub fn prepare_config(
    host_root: &Path,
    executable: &Path,
    sandbox_id: &SandboxId,
    image_digest: &Digest,
    resources: &Resources,
) -> Result<AppleGuardianConfig, AppleError> {
    let existing_path = host_root
        .join("sandboxes")
        .join(sandbox_id.as_str())
        .join("guardian/config.json");
    if existing_path.exists() {
        let existing = read_config(&existing_path, sandbox_id)?;
        if existing.image_digest != *image_digest || existing.resources != *resources {
            return Err(AppleError::Invalid(
                "existing Sandbox configuration conflicts with create request".into(),
            ));
        }
        return Ok(existing);
    }
    let (verified, template) = resolve_source_bundle(host_root, executable, image_digest)?;
    if verified.manifest.architecture
        != if cfg!(target_arch = "aarch64") {
            Architecture::Arm64
        } else {
            Architecture::X64
        }
        || verified.manifest.boot_bundle.bootstrap.format != RootfsFormat::Ext4
        || verified.manifest.workload.rootfs.format != RootfsFormat::Ext4
        || !verified.manifest.boot_bundle.capabilities.overlayfs
        || !verified.manifest.boot_bundle.capabilities.cgroup_v2
        || !verified.manifest.boot_bundle.capabilities.devpts
        || !verified.manifest.boot_bundle.capabilities.vsock
    {
        return Err(AppleError::Invalid(
            "image does not satisfy the Apple Linux guest contract".into(),
        ));
    }
    let helper_name = format!(
        "sandsurf-vz-helper-{}",
        if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x64"
        }
    );
    let helper = executable
        .parent()
        .ok_or_else(|| AppleError::Invalid("native executable has no directory".into()))?
        .join(helper_name);
    require_regular(&helper, 64 * 1024 * 1024)?;
    if resources.vcpus.get() > 32
        || resources.memory_mib.get() < 256
        || resources.memory_mib.get() > 65_536
    {
        return Err(AppleError::Invalid(
            "requested VM shape is outside the Apple envelope".into(),
        ));
    }
    let socket_identity =
        bytes_digest(format!("{}:{}", host_root.display(), sandbox_id.as_str()).as_bytes());
    let socket_root =
        std::env::temp_dir().join(format!("sandsurf-vz-{}", &socket_identity.as_str()[..24]));
    ensure_private_directory(&socket_root)?;
    Ok(AppleGuardianConfig {
        format_version: CONFIG_VERSION,
        sandbox_id: sandbox_id.clone(),
        image_digest: image_digest.clone(),
        resources: resources.clone(),
        helper_digest: file_digest(&helper, 64 * 1024 * 1024)?,
        helper,
        image_manifest: verified.manifest_path,
        disk_template_sha256: sha256_file(&template, 128 * 1024 * 1024 * 1024)?,
        disk_template: template,
        control_socket: socket_root.join("control.sock"),
    })
}

pub fn write_config(path: &Path, config: &AppleGuardianConfig) -> Result<(), AppleError> {
    if path.exists() {
        return if read_json::<AppleGuardianConfig>(path, 1024 * 1024)? == *config {
            Ok(())
        } else {
            Err(AppleError::Invalid(
                "guardian configuration is already bound to different inputs".into(),
            ))
        };
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    serde_json::to_writer(&mut file, config)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| AppleError::Invalid("guardian configuration has no parent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}

pub fn read_config(path: &Path, sandbox_id: &SandboxId) -> Result<AppleGuardianConfig, AppleError> {
    let value: AppleGuardianConfig = read_json(path, 1024 * 1024)?;
    if value.format_version != CONFIG_VERSION || value.sandbox_id != *sandbox_id {
        return Err(AppleError::Invalid(
            "guardian configuration identity is invalid".into(),
        ));
    }
    let image = verify_image(&value.image_manifest, ImageTrust::ExplicitLocal)?;
    if image.manifest_digest != value.image_digest.as_str()
        || file_digest(&value.helper, 64 * 1024 * 1024)? != value.helper_digest
        || sha256_file(&value.disk_template, 128 * 1024 * 1024 * 1024)?
            != value.disk_template_sha256
    {
        return Err(AppleError::Invalid(
            "guardian configuration artifact identity changed".into(),
        ));
    }
    ensure_private_directory(
        value
            .control_socket
            .parent()
            .ok_or_else(|| AppleError::Invalid("control socket has no parent".into()))?,
    )?;
    Ok(value)
}

pub fn workload_defaults(
    host_root: &Path,
    image_digest: &Digest,
) -> Result<crate::api::WorkloadDefaultsView, AppleError> {
    let image = verify_image(
        &host_root
            .join("images")
            .join(image_digest.as_str())
            .join("manifest.json"),
        ImageTrust::ExplicitLocal,
    )?;
    if image.manifest_digest != image_digest.as_str() {
        return Err(AppleError::Invalid(
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

pub struct AppleGuardianEffect {
    machine: AppleDriver,
    workload: AppleWorkload,
    pending: Option<ActiveGuest>,
    authentication_disk: PathBuf,
    control_socket: PathBuf,
    network: Arc<Mutex<Option<VmNetworkBridge>>>,
    exposures: Arc<Mutex<Option<VmPortGateway>>>,
    installed_runtime: Option<InstalledRuntime>,
}

#[derive(Clone)]
struct ActiveGuest {
    socket: PathBuf,
    sandbox_id: SandboxId,
    epoch: Counter,
    boot_identity: Digest,
    capability: [u8; 32],
    network_capability: [u8; 32],
}

struct AppleWorkload {
    active: Arc<Mutex<Option<ActiveGuest>>>,
}

struct InstalledRuntime {
    epoch: Counter,
    configuration: RuntimeConfiguration,
    evidence: Digest,
}

impl AppleGuardianEffect {
    pub fn open(sandbox_root: &Path, config: AppleGuardianConfig) -> Result<Self, AppleError> {
        let image = verify_image(&config.image_manifest, ImageTrust::ExplicitLocal)?;
        let disks = sandbox_root.join("disks");
        ensure_private_directory(&disks)?;
        let workload_state = disks.join("workload-state.ext4");
        let control_state = disks.join("control-state.ext4");
        ensure_mutable_disk(
            &config.disk_template,
            &workload_state,
            config.resources.disk_bytes.get(),
        )?;
        let control_bytes = config
            .resources
            .output_bytes
            .get()
            .checked_add(64 * 1024 * 1024)
            .ok_or_else(|| AppleError::Invalid("control disk size overflow".into()))?
            .max(128 * 1024 * 1024);
        ensure_mutable_disk(&config.disk_template, &control_state, control_bytes)?;
        let authentication_disk = sandbox_root.join("guardian/auth.img");
        let apple = AppleConfig {
            sandbox_id: config.sandbox_id.clone(),
            helper: config.helper,
            helper_digest: config.helper_digest,
            guest_architecture: crate::service::native_guest_architecture(),
            kernel: image.kernel_path,
            initial_ramdisk: None,
            command_line: "console=hvc0 reboot=k panic=1 root=/dev/vda ro init=/sbin/sandbox-guest"
                .into(),
            disks: vec![
                AppleDisk {
                    path: image.bootstrap_path,
                    read_only: true,
                },
                AppleDisk {
                    path: image.workload_path,
                    read_only: true,
                },
                AppleDisk {
                    path: workload_state,
                    read_only: false,
                },
                AppleDisk {
                    path: control_state,
                    read_only: false,
                },
                AppleDisk {
                    path: authentication_disk.clone(),
                    read_only: true,
                },
            ],
            memory_bytes: config
                .resources
                .memory_mib
                .get()
                .checked_mul(1024 * 1024)
                .ok_or_else(|| AppleError::Invalid("memory envelope overflow".into()))?,
            vcpus: u32::try_from(config.resources.vcpus.get())
                .map_err(|_| AppleError::Invalid("vCPU count overflow".into()))?,
            control_socket: config.control_socket.clone(),
            host_connect_ports: vec![GUEST_CONTROL_PORT, GUEST_EXPOSURE_PORT],
            guest_listen_ports: vec![
                NETWORK_HTTP_PORT,
                NETWORK_SOCKS_PORT,
                NETWORK_DNS_TCP_PORT,
                NETWORK_DNS_UDP_PORT,
            ],
            operation_timeout: AppleDriver::default_timeout(),
            qualification: AppleQualification {
                lifecycle: None,
                full_state: None,
            },
        };
        let active = Arc::new(Mutex::new(None));
        Ok(Self {
            machine: AppleDriver::new(apple)
                .map_err(|error| AppleError::Invalid(format!("invalid Apple VM: {error:?}")))?,
            workload: AppleWorkload {
                active: Arc::clone(&active),
            },
            pending: None,
            authentication_disk,
            control_socket: config.control_socket,
            network: Arc::new(Mutex::new(None)),
            exposures: Arc::new(Mutex::new(None)),
            installed_runtime: None,
        })
    }

    fn prepare_boot(&mut self, command: &LifecycleCommand, epoch: Counter) -> Result<(), Digest> {
        let capability = random_bytes().map_err(|_| bytes_digest(b"apple-boot-entropy"))?;
        let network_capability =
            random_bytes().map_err(|_| bytes_digest(b"apple-network-entropy"))?;
        let boot_identity = digest(
            Domain::Image,
            &(
                "sandsurf-apple-boot-v1",
                &command.sandbox_id,
                sandbox_guest::GUEST_PROTOCOL_MAJOR,
                sandbox_guest::GUEST_PROTOCOL_MINOR,
            ),
        )
        .map_err(|_| bytes_digest(b"apple-boot-identity"))?;
        write_authentication(
            &self.authentication_disk,
            &command.sandbox_id,
            epoch,
            &boot_identity,
            &capability,
            &network_capability,
        )
        .map_err(|_| bytes_digest(b"apple-authentication-disk"))?;
        self.pending = Some(ActiveGuest {
            socket: self.control_socket.clone(),
            sandbox_id: command.sandbox_id.clone(),
            epoch,
            boot_identity,
            capability,
            network_capability,
        });
        Ok(())
    }

    fn authenticate_pending(&mut self) -> Result<ActiveGuest, Digest> {
        let active = self
            .pending
            .take()
            .ok_or_else(|| bytes_digest(b"apple-pending-guest-missing"))?;
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            match guest_client(&active).call(&GuestServiceRequest::ProbeIdentity) {
                Ok(GuestServiceResponse::Identity {
                    sandbox_id,
                    epoch,
                    boot_identity,
                }) if sandbox_id == active.sandbox_id
                    && epoch == active.epoch
                    && boot_identity == active.boot_identity =>
                {
                    return Ok(active);
                }
                _ if !self.machine.has_live_owner() || Instant::now() >= deadline => {
                    return Err(bytes_digest(b"apple-guest-authentication-timeout"));
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
        self.stop_data_planes();
        let rules = match network_rules(&configuration.network) {
            Ok(value) => value,
            Err(_) => {
                return RuntimeInstallation::NotApplied(bytes_digest(
                    b"apple-network-policy-normalization-failed",
                ));
            }
        };
        let bridge = match VmNetworkBridge::start_partitioned(
            &active.socket,
            active.network_capability,
            rules,
        ) {
            Ok(value) => value,
            Err(_) => return RuntimeInstallation::Unknown,
        };
        if let Ok(mut network) = self.network.lock() {
            *network = Some(bridge);
        } else {
            return RuntimeInstallation::Unknown;
        }
        let gateway = match VmPortGateway::start(
            &active.socket,
            active.network_capability,
            &configuration.exposures,
        ) {
            Ok(value) => value,
            Err(_) => {
                self.stop_data_planes();
                return RuntimeInstallation::Unknown;
            }
        };
        if let Ok(mut exposures) = self.exposures.lock() {
            *exposures = Some(gateway);
        } else {
            self.stop_data_planes();
            return RuntimeInstallation::Unknown;
        }
        let resource_evidence =
            match guest_client(&active).call(&GuestServiceRequest::ApplyResources {
                resources: configuration.resources.clone(),
            }) {
                Ok(GuestServiceResponse::ResourcesApplied { evidence }) => evidence,
                _ => {
                    self.stop_data_planes();
                    return RuntimeInstallation::Unknown;
                }
            };
        match digest(
            Domain::Grant,
            &(
                "sandsurf-apple-runtime-configuration-v1",
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

    fn stop_data_planes(&mut self) {
        self.installed_runtime = None;
        if let Ok(mut network) = self.network.lock()
            && let Some(bridge) = network.take()
        {
            let _ = bridge.stop();
        }
        if let Ok(mut exposures) = self.exposures.lock()
            && let Some(gateway) = exposures.take()
        {
            let _ = gateway.stop();
        }
    }

    fn contain_unpublished(&mut self) {
        self.machine.contain_unobserved();
        self.pending = None;
        if let Ok(mut active) = self.workload.active.lock() {
            *active = None;
        }
        self.stop_data_planes();
    }
}

enum RuntimeInstallation {
    Applied(Digest),
    NotApplied(Digest),
    Unknown,
}

impl AppleWorkload {
    fn endpoint(&self) -> Option<ActiveGuest> {
        self.active.lock().ok()?.clone()
    }
}

impl WorkloadDriver for AppleWorkload {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        let Some(active) = self.endpoint() else {
            return EffectOutcome::NotApplied(bytes_digest(b"apple-guest-not-running"));
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
            "guest is unavailable because the Apple VM has no live owner",
        ))?;
        RemoteWorkloadDriver::new(guest_client(&active)).query(request)
    }
}

impl GuardianEffect for AppleGuardianEffect {
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
                        "sandsurf-apple-running-with-configuration-v1",
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
            if let Ok(mut active) = self.workload.active.lock() {
                *active = None;
            }
            self.stop_data_planes();
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
                            "sandsurf-apple-configuration-applied-v1",
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
                    "Apple VM could not establish the filesystem capture pause",
                ));
            }
            return Ok(response);
        }
        if let GuestServiceRequest::FinishFilesystemCapture { operation_id } = request {
            self.machine.resume_after_capture().map_err(|_| {
                ControlError::Unsupported("Apple VM could not leave the filesystem capture pause")
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

fn guest_client(active: &ActiveGuest) -> GuestClient<UnixVsockChannel> {
    GuestClient::new(
        UnixVsockChannel {
            socket_path: active.socket.clone(),
            guest_port: GUEST_CONTROL_PORT,
            timeout: Duration::from_secs(10),
        },
        active.sandbox_id.clone(),
        active.epoch,
        active.boot_identity.clone(),
        active.capability,
    )
}

fn network_rules(
    policy: &NetworkPolicy,
) -> Result<sandbox_network_broker::BrokerPolicy, AppleError> {
    policy
        .validate()
        .map_err(|error| AppleError::Invalid(error.to_string()))?;
    let mut rules = sandbox_network_broker::BrokerPolicy::default();
    for rule in &policy.rules {
        let destination = match &rule.destination {
            NetworkDestination::Dns {
                name,
                include_subdomains,
                allow_private_addresses,
            } => sandbox_policy::ManagedNetworkDestination::Dns {
                name: sandbox_policy::normalize_dns_name(name)
                    .map_err(|error| AppleError::Invalid(error.to_string()))?,
                include_subdomains: *include_subdomains,
                allow_private_addresses: *allow_private_addresses,
            },
            NetworkDestination::Ip { cidr } => {
                sandbox_policy::ManagedNetworkDestination::Ip { cidr: cidr.clone() }
            }
        };
        let ports = rule
            .ports
            .iter()
            .map(|range| {
                if range.from == range.to {
                    sandbox_policy::ManagedNetworkPort::Single(range.from)
                } else {
                    sandbox_policy::ManagedNetworkPort::Range {
                        from: range.from,
                        to: range.to,
                    }
                }
            })
            .collect();
        let managed = sandbox_policy::ManagedNetworkRule {
            transport: "tcp".into(),
            destination,
            ports,
        };
        match rule.plane {
            sandsurf_protocol::NetworkPlane::NamedProxy => rules.named_proxy.push(managed),
            sandsurf_protocol::NetworkPlane::DirectTcp => rules.direct_tcp.push(managed),
            sandsurf_protocol::NetworkPlane::Dns => rules.dns.push(managed),
        }
    }
    Ok(rules)
}

fn resolve_source_bundle(
    host_root: &Path,
    executable: &Path,
    expected: &Digest,
) -> Result<(VerifiedImage, PathBuf), AppleError> {
    let installed = host_root.join("images").join(expected.as_str());
    if installed.exists() {
        let image = verify_image(&installed.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        let template = state_template_path(&image)?;
        return Ok((image, template));
    }
    let package = executable
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| AppleError::Invalid("native package layout is invalid".into()))?;
    let architecture = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let relative = format!("minimal-{architecture}/manifest.json");
    let index: ImageIndex = read_json(&package.join("images/manifest.json"), 1024 * 1024)?;
    let indexed = index
        .files
        .get(&relative)
        .ok_or_else(|| AppleError::Invalid("packaged image manifest is absent".into()))?;
    let pinned = BUNDLED_IMAGE_MANIFEST_DIGEST.ok_or_else(|| {
        AppleError::Invalid("native host has no bundled image trust identity".into())
    })?;
    if indexed != pinned || expected.as_str() != pinned {
        return Err(AppleError::Invalid(
            "packaged image index differs from the native trust identity".into(),
        ));
    }
    let image = verify_image(
        &package.join("images").join(relative),
        ImageTrust::Pinned {
            manifest_digest: pinned,
        },
    )?;
    let template = state_template_path(&image)?;
    let installed = install_image(host_root, &image, &template)?;
    let copied = verify_image(&installed.join("manifest.json"), ImageTrust::ExplicitLocal)?;
    let copied_template = state_template_path(&copied)?;
    Ok((copied, copied_template))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageIndex {
    #[serde(rename = "formatVersion")]
    _format_version: u16,
    #[serde(rename = "buildId")]
    _build_id: String,
    files: std::collections::BTreeMap<String, String>,
}

fn state_template_path(image: &VerifiedImage) -> Result<PathBuf, AppleError> {
    let template = image
        .manifest
        .workload
        .state_template
        .as_ref()
        .ok_or_else(|| AppleError::Invalid("image has no writable-state template".into()))?;
    Ok(image
        .manifest_path
        .parent()
        .ok_or_else(|| AppleError::Invalid("image manifest has no parent".into()))?
        .join(&template.path))
}

fn install_image(
    host_root: &Path,
    image: &VerifiedImage,
    template: &Path,
) -> Result<PathBuf, AppleError> {
    let root = host_root.join("images").join(&image.manifest_digest);
    if root.exists() {
        return Ok(root);
    }
    let staging = host_root
        .join("images")
        .join(format!("stage-{}", hex(&random_bytes()?)));
    ensure_private_directory(&staging)?;
    let result = (|| -> Result<(), AppleError> {
        for (source, destination) in [
            (image.manifest_path.as_path(), staging.join("manifest.json")),
            (
                image.kernel_path.as_path(),
                staging.join(&image.manifest.boot_bundle.kernel.path),
            ),
            (
                image.bootstrap_path.as_path(),
                staging.join(&image.manifest.boot_bundle.bootstrap.path),
            ),
            (
                image.workload_path.as_path(),
                staging.join(&image.manifest.workload.rootfs.path),
            ),
            (template, staging.join("empty-workspace.ext4")),
        ] {
            copy_artifact(source, &destination)?;
        }
        if let Some(windows) = &image.windows_x64 {
            let manifest = image
                .manifest
                .platform_artifacts
                .windows_x64
                .as_ref()
                .ok_or_else(|| AppleError::Invalid("Windows artifact metadata is absent".into()))?;
            for (source, relative) in [
                (&windows.kernel_path, &manifest.kernel.path),
                (&windows.bootstrap_path, &manifest.bootstrap.path),
                (&windows.workload_path, &manifest.workload.path),
                (&windows.state_template_path, &manifest.state_template.path),
            ] {
                copy_artifact(source, &staging.join(relative))?;
            }
        }
        let copied = verify_image(&staging.join("manifest.json"), ImageTrust::ExplicitLocal)?;
        if copied.manifest_digest != image.manifest_digest {
            return Err(AppleError::Invalid("copied image identity changed".into()));
        }
        File::open(&staging)?.sync_all()?;
        fs::rename(&staging, &root)?;
        File::open(host_root.join("images"))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok(root)
}

fn ensure_mutable_disk(source: &Path, destination: &Path, bytes: u64) -> Result<(), AppleError> {
    let source_bytes = fs::metadata(source)?.len();
    if bytes < source_bytes || !bytes.is_multiple_of(4096) || bytes > 128 * 1024 * 1024 * 1024 {
        return Err(AppleError::Invalid(
            "persistent disk geometry is outside the ext4 envelope".into(),
        ));
    }
    if !destination.exists() {
        copy_artifact(source, destination)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(destination)?;
        file.set_len(bytes)?;
        file.sync_all()?;
    }
    let metadata = fs::symlink_metadata(destination)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != bytes {
        return Err(AppleError::Invalid(
            "persistent disk geometry or type changed".into(),
        ));
    }
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_authentication(
    path: &Path,
    sandbox_id: &SandboxId,
    epoch: Counter,
    boot_identity: &Digest,
    capability: &[u8; 32],
    network_capability: &[u8; 32],
) -> Result<(), AppleError> {
    let identity = sandbox_id.as_str().as_bytes();
    let size = u16::try_from(identity.len())
        .map_err(|_| AppleError::Invalid("sandbox identity is too long".into()))?;
    let digest = decode_hex(boot_identity.as_str())?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(AUTHENTICATION_MAGIC);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(identity);
    bytes.extend_from_slice(&epoch.get().to_be_bytes());
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(capability);
    bytes.extend_from_slice(network_capability);
    bytes.resize(512, 0);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), AppleError> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AppleError::Invalid(
            "Apple private state directory is not protected".into(),
        ));
    }
    Ok(())
}

fn copy_artifact(source: &Path, destination: &Path) -> Result<(), AppleError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn require_regular(path: &Path, maximum: u64) -> Result<(), AppleError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AppleError::Invalid(
            "artifact must be a bounded absolute regular file".into(),
        ));
    }
    Ok(())
}

fn file_digest(path: &Path, maximum: u64) -> Result<Digest, AppleError> {
    sha256_file(path, maximum)?
        .try_into()
        .map_err(|error| AppleError::Invalid(format!("artifact digest is invalid: {error}")))
}

fn sha256_file(path: &Path, maximum: u64) -> Result<String, AppleError> {
    require_regular(path, maximum)?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| AppleError::Invalid("artifact length overflow".into()))?;
        if total > maximum {
            return Err(AppleError::Invalid("artifact exceeds bound".into()));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, AppleError> {
    require_regular(path, maximum)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(AppleError::Invalid("JSON artifact exceeds bound".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn random_bytes() -> Result<[u8; 32], AppleError> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| AppleError::Invalid("host entropy unavailable".into()))?;
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<[u8; 32], AppleError> {
    if value.len() != 64 {
        return Err(AppleError::Invalid("digest is malformed".into()));
    }
    let mut bytes = [0; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| AppleError::Invalid("digest is malformed".into()))?;
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
