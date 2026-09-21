use crate::api::{
    HOST_API_VERSION, HostInspection, HostRequest, HostResponse, ReservationView, SandboxView,
};
#[cfg(not(target_os = "linux"))]
use sandsurf_control::{EffectOutcome, GuardianEffect, LifecycleEffect, Result as ControlResult};
use sandsurf_control::{
    Guardian, GuardianClient, HostGuardianLink, apply_lifecycle, serve_guardian,
};
use sandsurf_machine::GuestArchitecture;
#[cfg(not(target_os = "linux"))]
use sandsurf_machine::MachineOutcome;
use sandsurf_native::local::{LocalConnection, LocalListener};
use sandsurf_protocol::*;
use sandsurf_state::{
    Approval, CatalogLimits, GrantChange, HostCatalog, ReservationState, RuntimeJournal,
    RuntimeLimits, SandboxRecord,
};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const API_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum HostError {
    Io(io::Error),
    Json(serde_json::Error),
    State(sandsurf_state::Error),
    Control(sandsurf_control::Error),
    Contract(sandsurf_protocol::Invalid),
    #[cfg(target_os = "linux")]
    Linux(crate::linux::LinuxError),
    Invalid(&'static str),
}

impl fmt::Display for HostError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "host I/O: {error}"),
            Self::Json(error) => write!(output, "host message: {error}"),
            Self::State(error) => write!(output, "host catalog: {error}"),
            Self::Control(error) => write!(output, "host/guardian: {error}"),
            Self::Contract(error) => write!(output, "host contract: {error}"),
            #[cfg(target_os = "linux")]
            Self::Linux(error) => error.fmt(output),
            Self::Invalid(message) => output.write_str(message),
        }
    }
}
impl std::error::Error for HostError {}
impl From<io::Error> for HostError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for HostError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<sandsurf_state::Error> for HostError {
    fn from(value: sandsurf_state::Error) -> Self {
        Self::State(value)
    }
}
impl From<sandsurf_control::Error> for HostError {
    fn from(value: sandsurf_control::Error) -> Self {
        Self::Control(value)
    }
}
impl From<sandsurf_protocol::Invalid> for HostError {
    fn from(value: sandsurf_protocol::Invalid) -> Self {
        Self::Contract(value)
    }
}
#[cfg(target_os = "linux")]
impl From<crate::linux::LinuxError> for HostError {
    fn from(value: crate::linux::LinuxError) -> Self {
        Self::Linux(value)
    }
}

pub type Result<T> = std::result::Result<T, HostError>;

pub struct HostService {
    root: PathBuf,
    catalog: HostCatalog,
    executable: PathBuf,
    verified_guardians: BTreeSet<SandboxId>,
}

impl HostService {
    pub fn open(root: &Path, executable: PathBuf) -> Result<Self> {
        prepare_directory(root)?;
        let catalog_path = root.join("catalog");
        let catalog = if catalog_path.exists() {
            HostCatalog::open(&catalog_path)?
        } else {
            let host_id = random_id("host")?
                .try_into()
                .map_err(|_| HostError::Invalid("host identity generation failed"))?;
            HostCatalog::create(&catalog_path, host_id, catalog_limits())?
        };
        prepare_directory(&root.join("api"))?;
        prepare_directory(&root.join("sandboxes"))?;
        prepare_directory(&root.join("images"))?;
        prepare_directory(&root.join("checkpoints"))?;
        prepare_directory(&root.join("transfers"))?;
        Ok(Self {
            root: root.to_path_buf(),
            catalog,
            executable,
            verified_guardians: BTreeSet::new(),
        })
    }

    pub fn endpoint(&self) -> PathBuf {
        self.root.join("api")
    }

    pub fn handle(&mut self, request: HostRequest) -> HostResponse {
        match self.handle_inner(request) {
            Ok(response) => response,
            Err(error) => HostResponse::Rejected {
                category: error_category(&error).into(),
                message: error.to_string(),
            },
        }
    }

    fn handle_inner(&mut self, request: HostRequest) -> Result<HostResponse> {
        match request {
            HostRequest::Inspect => Ok(HostResponse::Inspection {
                value: self.inspect(),
            }),
            HostRequest::StopService => Ok(HostResponse::Complete),
            HostRequest::ListSandboxes { after, maximum } => {
                let records = self.catalog.sandboxes(after.as_ref(), maximum)?;
                let values = records
                    .into_iter()
                    .map(|record| self.view(record))
                    .collect::<Result<Vec<_>>>()?;
                Ok(HostResponse::Sandboxes { values })
            }
            HostRequest::GetSandbox { sandbox_id } => {
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox does not exist"))?;
                Ok(HostResponse::Sandbox {
                    value: self.view(record)?,
                })
            }
            HostRequest::CreateSandbox {
                sandbox_id,
                image_digest,
                resources,
                operation_id,
                approval_id,
            } => {
                #[cfg(target_os = "linux")]
                let native_config = crate::linux::prepare_config(
                    &self.root,
                    &self.executable,
                    &sandbox_id,
                    &image_digest,
                    &resources,
                )?;
                let approval = Approval {
                    id: approval_id,
                    request_digest: digest(
                        Domain::Sandbox,
                        &(&sandbox_id, &image_digest, &resources, &operation_id),
                    )?,
                };
                self.catalog.create_sandbox(
                    sandbox_id.clone(),
                    image_digest,
                    resources,
                    operation_id.clone(),
                    approval,
                )?;
                #[cfg(target_os = "linux")]
                self.provision_guardian_with_config(&sandbox_id, Some(&native_config))?;
                #[cfg(not(target_os = "linux"))]
                self.provision_guardian(&sandbox_id)?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &operation_id)?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid(
                        "created sandbox disappeared from catalog",
                    ))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::Lifecycle {
                sandbox_id,
                operation_id,
                expected_revision,
                desired,
                approval_id,
            } => {
                let approval = Approval {
                    id: approval_id,
                    request_digest: digest(
                        Domain::Operation,
                        &(&sandbox_id, &operation_id, expected_revision, desired),
                    )?,
                };
                self.catalog.request_lifecycle(
                    &sandbox_id,
                    operation_id.clone(),
                    expected_revision,
                    desired,
                    approval,
                )?;
                self.provision_guardian(&sandbox_id)?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let lifecycle = apply_lifecycle(&mut self.catalog, endpoint, &operation_id)?;
                let record = self
                    .catalog
                    .sandbox(&sandbox_id)?
                    .ok_or(HostError::Invalid("sandbox disappeared from catalog"))?;
                Ok(HostResponse::Lifecycle {
                    operation: lifecycle.guardian_operation,
                    sandbox: self.view(record)?,
                })
            }
            HostRequest::SetGrant {
                sandbox_id,
                grant_id,
                expected_revision,
                capability,
                scope_digest,
                revoked,
                approval_id,
            } => {
                let request_digest = digest(
                    Domain::Grant,
                    &(
                        &sandbox_id,
                        &grant_id,
                        expected_revision,
                        capability,
                        &scope_digest,
                        revoked,
                    ),
                )?;
                let grant = self.catalog.set_grant(
                    GrantChange {
                        sandbox_id: sandbox_id.clone(),
                        id: grant_id,
                        expected_revision,
                        capability,
                        scope_digest,
                        revoked,
                    },
                    Approval {
                        id: approval_id,
                        request_digest,
                    },
                )?;
                self.provision_guardian(&sandbox_id)?;
                let authorization = self
                    .catalog
                    .authorize_configuration(&sandbox_id, grant.revision)?;
                let operation = GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                    .transition(authorization)?;
                if operation.delivery != Delivery::Applied
                    || operation.command.revision != grant.revision
                {
                    return Err(HostError::Invalid(
                        "guardian did not apply the host configuration revision",
                    ));
                }
                Ok(HostResponse::Grant { grant })
            }
            HostRequest::Workload {
                sandbox_id,
                epoch,
                operation_id,
                expected_revision,
                request,
                scope_digest,
            } => {
                let capability = request.required_capability();
                let grant = self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    capability,
                    &scope_digest,
                )?;
                let mutation = Mutation::new(
                    sandbox_id.clone(),
                    epoch,
                    operation_id,
                    grant.id,
                    expected_revision,
                    request,
                )?;
                self.provision_guardian(&sandbox_id)?;
                let endpoint = self.guardian_endpoint(&sandbox_id);
                let link = HostGuardianLink::new(&self.catalog, endpoint);
                Ok(HostResponse::Dispatch {
                    operation: link.dispatch(mutation, capability, &scope_digest)?,
                })
            }
            HostRequest::Guest {
                sandbox_id,
                expected_revision,
                capability,
                scope_digest,
                request,
            } => {
                if matches!(
                    request,
                    GuestServiceRequest::Dispatch { .. } | GuestServiceRequest::PrepareStop
                ) {
                    return Err(HostError::Invalid(
                        "internal guest control requests cannot use the application route",
                    ));
                }
                self.catalog.active_grant(
                    &sandbox_id,
                    expected_revision,
                    capability,
                    &scope_digest,
                )?;
                self.provision_guardian(&sandbox_id)?;
                Ok(HostResponse::Guest {
                    response: GuardianClient::new(self.guardian_endpoint(&sandbox_id))
                        .guest(sandbox_id, request)?,
                })
            }
        }
    }

    fn inspect(&self) -> HostInspection {
        let engine = if cfg!(target_os = "macos") {
            VmEngine::AppleVirtualization
        } else if cfg!(target_os = "windows") {
            VmEngine::HyperV
        } else {
            VmEngine::Firecracker
        };
        let reason = format!(
            "{} driver has no retained real-hardware qualification for this exact build/configuration",
            std::env::consts::OS
        );
        HostInspection {
            host_id: self.catalog.host_id().as_str().into(),
            platform: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            guest_architecture: match native_guest_architecture() {
                GuestArchitecture::Amd64 => "amd64",
                GuestArchitecture::Arm64 => "arm64",
            }
            .into(),
            engine,
            lifecycle: Qualification::Unqualified {
                reasons: vec![reason.clone()],
            },
            full_state: Qualification::Unqualified {
                reasons: vec![reason],
            },
        }
    }

    fn provision_guardian(&mut self, sandbox: &SandboxId) -> Result<()> {
        #[cfg(target_os = "linux")]
        return self.provision_guardian_with_config(sandbox, None);
        #[cfg(not(target_os = "linux"))]
        self.provision_guardian_inner(sandbox)
    }

    #[cfg(target_os = "linux")]
    fn provision_guardian_with_config(
        &mut self,
        sandbox: &SandboxId,
        config: Option<&crate::linux::LinuxGuardianConfig>,
    ) -> Result<()> {
        let root = self.sandbox_root(sandbox);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        let config_path = root.join("guardian/config.json");
        if let Some(config) = config {
            crate::linux::write_config(&config_path, config)?;
            self.verified_guardians.insert(sandbox.clone());
        } else if !self.verified_guardians.contains(sandbox) {
            crate::linux::read_config(&config_path, sandbox)?;
            self.verified_guardians.insert(sandbox.clone());
        }
        self.provision_guardian_inner(sandbox)
    }

    fn provision_guardian_inner(&self, sandbox: &SandboxId) -> Result<()> {
        let root = self.sandbox_root(sandbox);
        prepare_directory(&root)?;
        prepare_directory(&root.join("guardian"))?;
        prepare_directory(&root.join("disks"))?;
        prepare_directory(&root.join("output"))?;
        let runtime = root.join("runtime");
        if !runtime.exists() {
            RuntimeJournal::create(
                &runtime,
                sandbox.clone(),
                runtime_limits(),
                self.catalog.authority_binding().clone(),
            )?;
        }
        let endpoint = self.guardian_endpoint(sandbox);
        if GuardianClient::new(endpoint.clone())
            .inspect(sandbox.clone(), None)
            .is_ok()
        {
            return Ok(());
        }
        let guardian_log = open_guardian_log(&root.join("guardian/guardian.log"))?;
        Command::new(&self.executable)
            .arg("guardian")
            .arg("--directory")
            .arg(&self.root)
            .arg("--sandbox")
            .arg(sandbox.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(guardian_log))
            .spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if GuardianClient::new(endpoint.clone())
                .inspect(sandbox.clone(), None)
                .is_ok()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(HostError::Invalid("guardian did not become reachable"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn view(&self, record: SandboxRecord) -> Result<SandboxView> {
        let machine = match GuardianClient::new(self.guardian_endpoint(&record.id))
            .inspect(record.id.clone(), None)
        {
            Ok(value) => value.observation,
            Err(_) => Observation::Unavailable { last_known: None },
        };
        Ok(SandboxView {
            id: record.id,
            image_digest: record.image_digest,
            resources: record.resources,
            configuration_revision: record.configuration_revision,
            reservation: match record.reservation {
                ReservationState::Held => ReservationView::Held,
                ReservationState::Released => ReservationView::Released,
            },
            lifecycle_intent: record.latest_intent,
            machine,
        })
    }

    fn sandbox_root(&self, sandbox: &SandboxId) -> PathBuf {
        self.root.join("sandboxes").join(sandbox.as_str())
    }

    fn guardian_endpoint(&self, sandbox: &SandboxId) -> PathBuf {
        self.sandbox_root(sandbox).join("guardian")
    }
}

pub fn serve_host(root: &Path, executable: PathBuf) -> Result<()> {
    let mut service = HostService::open(root, executable)?;
    let listener = LocalListener::bind(&service.endpoint())?;
    loop {
        let mut connection = match listener.accept(Duration::from_secs(1)) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            Err(error) => return Err(error.into()),
        };
        let frame = match connection.read_frame(API_TIMEOUT) {
            Ok(Some(value)) => value,
            Ok(None) | Err(_) => continue,
        };
        let sequence = frame.sequence;
        let parsed = parse_host_request(frame);
        let stopping = matches!(&parsed, Ok(HostRequest::StopService));
        let response = parsed
            .map(|request| service.handle(request))
            .unwrap_or_else(|error| HostResponse::Rejected {
                category: error_category(&error).into(),
                message: error.to_string(),
            });
        let _ = connection.write_frame(&host_response_frame(sequence, &response)?, API_TIMEOUT);
        if stopping {
            return Ok(());
        }
    }
}

pub fn serve_sandbox_guardian(root: &Path, sandbox: SandboxId) -> Result<()> {
    let sandbox_root = root.join("sandboxes").join(sandbox.as_str());
    let journal = RuntimeJournal::open(&sandbox_root.join("runtime"), &sandbox)?;
    #[cfg(target_os = "linux")]
    {
        let config =
            crate::linux::read_config(&sandbox_root.join("guardian/config.json"), &sandbox)?;
        let effect = crate::linux::LinuxGuardianEffect::open(&sandbox_root, config)?;
        let mut guardian = Guardian::new(journal, effect);
        serve_guardian(&sandbox_root.join("guardian"), &mut guardian)?;
    }
    #[cfg(not(target_os = "linux"))]
    let mut guardian = Guardian::new(journal, UnqualifiedEffect);
    #[cfg(not(target_os = "linux"))]
    serve_guardian(&sandbox_root.join("guardian"), &mut guardian)?;
    Ok(())
}

pub fn host_call(root: &Path, request: HostRequest) -> Result<HostResponse> {
    let mut connection = LocalConnection::connect(&root.join("api"), API_TIMEOUT)?;
    let payload = serde_json::to_vec(&(HOST_API_VERSION, request))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(HostError::Invalid("host request exceeds control bound"));
    }
    connection.write_frame(
        &Frame {
            kind: FrameKind::Control,
            stream: 0,
            sequence: Counter::ONE,
            authentication: [0; AUTHENTICATION_BYTES],
            payload,
        },
        API_TIMEOUT,
    )?;
    let frame = connection
        .read_frame(API_TIMEOUT)?
        .ok_or(HostError::Invalid("host closed without a response"))?;
    parse_host_response(frame)
}

#[cfg(not(target_os = "linux"))]
struct UnqualifiedEffect;
#[cfg(not(target_os = "linux"))]
impl GuardianEffect for UnqualifiedEffect {
    fn dispatch(&mut self, _: &Mutation, _: Capability) -> EffectOutcome {
        EffectOutcome::NotApplied(bytes_digest(b"native-guest-driver-unqualified"))
    }

    fn transition(
        &mut self,
        _: &LifecycleCommand,
        _: Option<&MachineObservation>,
    ) -> LifecycleEffect {
        MachineOutcome::NotApplied(bytes_digest(b"native-machine-driver-unqualified"))
    }

    fn query(&mut self, _: GuestServiceRequest) -> ControlResult<GuestServiceResponse> {
        Err(sandsurf_control::Error::Unsupported(
            "guest is unavailable because this native configuration is unqualified",
        ))
    }
}

fn parse_host_request(frame: Frame) -> Result<HostRequest> {
    require_frame(&frame)?;
    let (version, request): (u16, HostRequest) = serde_json::from_slice(&frame.payload)?;
    if version != HOST_API_VERSION {
        return Err(HostError::Invalid("host API version mismatch"));
    }
    Ok(request)
}

fn host_response_frame(sequence: Counter, response: &HostResponse) -> Result<Frame> {
    let payload = serde_json::to_vec(&(HOST_API_VERSION, response))?;
    if payload.len() > MAX_CONTROL_BYTES {
        return Err(HostError::Invalid("host response exceeds control bound"));
    }
    Ok(Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence,
        authentication: [0; AUTHENTICATION_BYTES],
        payload,
    })
}

fn parse_host_response(frame: Frame) -> Result<HostResponse> {
    require_frame(&frame)?;
    if frame.sequence != Counter::ONE {
        return Err(HostError::Invalid("host response sequence mismatch"));
    }
    let (version, response): (u16, HostResponse) = serde_json::from_slice(&frame.payload)?;
    if version != HOST_API_VERSION {
        return Err(HostError::Invalid("host API version mismatch"));
    }
    Ok(response)
}

fn require_frame(frame: &Frame) -> Result<()> {
    if frame.kind != FrameKind::Control
        || frame.stream != 0
        || frame.sequence == Counter::ZERO
        || frame.authentication != [0; AUTHENTICATION_BYTES]
    {
        return Err(HostError::Invalid("host API frame is malformed"));
    }
    Ok(())
}

fn catalog_limits() -> CatalogLimits {
    CatalogLimits {
        identities: counter(4096),
        operations: counter(1_000_000),
        grants: counter(100_000),
        usage_records: counter(1_000_000),
        resources: Resources {
            vcpus: counter(4096),
            memory_mib: counter(4 * 1024 * 1024),
            disk_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
            output_bytes: counter(1024 * 1024 * 1024 * 1024),
            processes: counter(1_000_000),
        },
    }
}

fn runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        identities: counter(1_000_000),
        operations: counter(1_000_000),
        observations: counter(1_000_000),
        chunks: counter(10_000_000),
        pins: counter(1_000_000),
        output_bytes: counter(1024 * 1024 * 1024 * 1024),
        disks: counter(100_000),
        disk_bytes: counter(16 * 1024 * 1024 * 1024 * 1024),
        disk_headroom_bytes: counter(64 * 1024 * 1024),
    }
}

fn counter(value: u64) -> Counter {
    Counter::try_from(value).expect("static host bound is a safe integer")
}

fn random_id(prefix: &str) -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| HostError::Invalid("host entropy unavailable"))?;
    let mut value = String::with_capacity(prefix.len() + 33);
    value.push_str(prefix);
    value.push('-');
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("string formatting cannot fail");
    }
    Ok(value)
}

pub(crate) fn native_guest_architecture() -> GuestArchitecture {
    if cfg!(target_arch = "aarch64") {
        GuestArchitecture::Arm64
    } else {
        GuestArchitecture::Amd64
    }
}

fn error_category(error: &HostError) -> &'static str {
    match error {
        HostError::Io(_) => "transport",
        HostError::Json(_) | HostError::Contract(_) | HostError::Invalid(_) => "protocol",
        #[cfg(target_os = "linux")]
        HostError::Linux(_) => "native",
        HostError::State(_) => "state",
        HostError::Control(_) => "guardian",
    }
}

#[cfg(unix)]
fn open_guardian_log(path: &Path) -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(windows)]
fn open_guardian_log(path: &Path) -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?)
}

#[cfg(unix)]
fn prepare_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(HostError::Invalid(
            "host state directory must be private and non-symbolic",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn prepare_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        sandsurf_native::local::create_private_directory(path)?;
    }
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(HostError::Invalid(
            "host state path is not a private directory",
        ));
    }
    Ok(())
}
