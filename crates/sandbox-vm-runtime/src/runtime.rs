use sandbox_digest::{execution_digest, identity_digest, policy_digest};
use sandbox_guest::{
    GUEST_CONTROL_PORT, GUEST_HTTP_PROXY_PORT, GUEST_PROTOCOL_MAJOR, GUEST_PROTOCOL_MINOR,
    GUEST_SOCKS_PROXY_PORT, GuestArtifactEntry, GuestLimits, GuestMask, GuestMount,
    GuestPrivateDirectory, GuestRequest, GuestResponse, MAX_GUEST_FRAME,
};
use sandbox_image::{Architecture, ImageTrust, VerifiedImage, verify_image};
use sandbox_launcher_linux::{kill_process, try_lock_exclusive};
use sandbox_policy::{
    ActivateSessionMessage, EnforcementBoundary, EnforcementCaveat, EnforcementConformance,
    EnforcementHost, EnforcementReport, EnforcementRuntimeView, EnforcementTarget, ErrorData,
    GUARANTEES, GuaranteeFact, IdMessage, Isolation, NormalizedExecution, NormalizedPolicy,
    PrepareProcessMessage, PrepareRunMessage, PrepareSessionMessage, StartProcessMessage,
    StartRunMessage, TerminateMessage, normalize_process, normalize_run, normalize_session,
};
use sandbox_protocol::{
    Frame, Hello, INITIAL_STREAM_CREDIT, MessageType, PROTOCOL_MAJOR, PROTOCOL_MINOR,
    ProtocolError, StreamCreditMessage, read_frame, write_frame,
};
use sandbox_vm::{
    ApplyError, ArtifactEntry, ArtifactKind, BrokerSnapshot, ChangeOperation, ChangeSet,
    FirecrackerConfig, FirecrackerProcess, GuestChannel, NetworkViolation, UnixVsockChannel,
    VmNetworkBridge, apply_change_set, collect_artifacts, create_change_set,
    recover_interrupted_apply,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BACKEND_ID: &str = "linux-firecracker-v1";
const FIRECRACKER_SHA256_X64: &str =
    "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7";
const FIRECRACKER_NAME_X64: &str = "firecracker-v1.16.1-x86_64";
const WORKSPACE_TEMPLATE: &str = "empty-workspace.ext4";
const WORKSPACE_TEMPLATE_SHA256: &str = match option_env!("SANDBOX_WORKSPACE_SHA256") {
    Some(value) => value,
    None => "",
};
const AUTH_MAGIC: &[u8; 8] = b"SBXAUTH1";
const MAX_STDIN_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTSTANDING_CREDIT: u64 = 16 * 1024 * 1024;
const RELEASE_PUBLIC_KEY: [u8; 32] = [
    0x49, 0x5b, 0x4a, 0x26, 0xa6, 0x5d, 0xf6, 0x6f, 0x70, 0x90, 0x06, 0x5e, 0xd2, 0x3a, 0x30, 0xa2,
    0x9a, 0xd3, 0xb5, 0x3e, 0x0e, 0xd9, 0x0d, 0x65, 0x06, 0xa2, 0xd6, 0xc8, 0xc0, 0xab, 0xa6, 0x84,
];
static IDS: AtomicU64 = AtomicU64::new(1);

pub fn run() {
    let mut arguments = std::env::args_os();
    let _ = arguments.next();
    match arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("--linux-launcher") => std::process::exit(sandbox_launcher_linux::launcher_main()),
        Some("--linux-probe") => std::process::exit(sandbox_launcher_linux::probe_main()),
        Some("--apply-change-set") => std::process::exit(change_set_apply_main(arguments)),
        Some("--recover-change-set") => std::process::exit(change_set_recover_main(arguments)),
        Some(_) => {
            eprintln!("invalid internal VM runtime mode");
            std::process::exit(2);
        }
        None => {
            if let Err(error) = runtime_main() {
                eprintln!(
                    "sandbox VM runtime emergency failure: {}",
                    bounded(&error.to_string())
                );
                std::process::exit(1);
            }
        }
    }
}

fn change_set_apply_main(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> i32 {
    let Some(root) = arguments.next().map(PathBuf::from) else {
        return write_change_set_cli_error("invalid", "workspace root is missing");
    };
    let Some(recovery) = arguments.next().map(PathBuf::from) else {
        return write_change_set_cli_error("invalid", "recovery directory is missing");
    };
    if arguments.next().is_some() {
        return write_change_set_cli_error("invalid", "unexpected apply arguments");
    }
    let mut bytes = Vec::new();
    if io::stdin()
        .take(140 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > 140 * 1024 * 1024
    {
        return write_change_set_cli_error("invalid", "change-set input exceeds its limit");
    }
    let change_set: ChangeSet = match serde_json::from_slice(&bytes) {
        Ok(change_set) => change_set,
        Err(error) => return write_change_set_cli_error("invalid", &error.to_string()),
    };
    match apply_change_set(&root, &recovery, &change_set) {
        Ok(report) => write_change_set_cli_success(&report),
        Err(error) => write_change_set_apply_error(&error),
    }
}

fn change_set_recover_main(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> i32 {
    let Some(journal) = arguments.next().map(PathBuf::from) else {
        return write_change_set_cli_error("invalid", "recovery journal is missing");
    };
    if arguments.next().is_some() {
        return write_change_set_cli_error("invalid", "unexpected recovery arguments");
    }
    match recover_interrupted_apply(&journal) {
        Ok(report) => write_change_set_cli_success(&report),
        Err(error) => write_change_set_apply_error(&error),
    }
}

fn write_change_set_cli_success(report: &sandbox_vm::ApplyReport) -> i32 {
    println!(
        "{}",
        json!({
            "ok": true,
            "applied": report.applied,
            "recovered": report.recovered,
            "journalPath": report.journal_path,
        })
    );
    0
}

fn write_change_set_apply_error(error: &ApplyError) -> i32 {
    let kind = match error {
        ApplyError::Conflict(_) => "conflict",
        ApplyError::Invalid(_) | ApplyError::Artifact(_) => "invalid",
        ApplyError::Io(_) => "io",
    };
    write_change_set_cli_error(kind, &error.to_string())
}

fn write_change_set_cli_error(kind: &str, message: &str) -> i32 {
    println!(
        "{}",
        json!({"ok": false, "kind": kind, "message": bounded(message)})
    );
    2
}

#[derive(Clone)]
struct ProtocolWriter {
    output: Arc<Mutex<io::Stdout>>,
}

impl ProtocolWriter {
    fn control<T: Serialize>(&self, message_type: MessageType, value: &T) -> Result<(), ErrorData> {
        let frame = Frame::control(message_type, value).map_err(protocol_error)?;
        let mut output = self.output.lock().map_err(|_| lock_error())?;
        write_frame(&mut *output, &frame).map_err(protocol_error)
    }

    fn binary(&self, message_type: MessageType, value: Vec<u8>) -> Result<(), ErrorData> {
        let frame = Frame::binary(message_type, value).map_err(protocol_error)?;
        let mut output = self.output.lock().map_err(|_| lock_error())?;
        write_frame(&mut *output, &frame).map_err(protocol_error)
    }

    fn error(&self, request_id: Option<&str>, error: &ErrorData) {
        let mut error = error.clone();
        error.backend = Some(BACKEND_ID.into());
        let _ = self.control(
            MessageType::Error,
            &json!({"requestId": request_id, "error": error}),
        );
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedGrant {
    requested_host_path: String,
    resolved_host_path: String,
    host_identity_digest: String,
    target_path: String,
    access: String,
    execution: String,
    guest_source: String,
}

struct PreparedPolicy {
    normalized: NormalizedPolicy,
    grants: Vec<PreparedGrant>,
    mounts: Vec<GuestMount>,
    workspace_bases: Vec<WorkspaceBase>,
    policy_digest: String,
    manifest_digest: String,
    enforcement: EnforcementReport,
    authority: Arc<VmAuthority>,
}

struct WorkspaceBase {
    target_path: String,
    guest_path: String,
    directory: bool,
    files: Vec<ArtifactEntry>,
}

struct PreparedExecution {
    normalized: NormalizedExecution,
    execution_digest: String,
    executable_sha256: String,
    executable_identity_digest: String,
    cwd_identity_digest: String,
}

struct PreparedRun {
    id: String,
    policy: Arc<PreparedPolicy>,
    execution: Arc<PreparedExecution>,
    deadline: Instant,
}

struct PreparedProcess {
    id: String,
    execution: Arc<PreparedExecution>,
    deadline: Instant,
}

struct Session {
    id: String,
    policy: Arc<PreparedPolicy>,
    deadline: Option<Instant>,
    active: bool,
    prepared: Option<PreparedProcess>,
    running: Option<Arc<Running>>,
}

enum RuntimeState {
    Empty,
    PreparedRun(PreparedRun),
    Session(Session),
}

enum InputEvent {
    Frame(Frame),
    Eof,
    Error(String),
}

struct VmAuthority {
    vmm: Mutex<Option<FirecrackerProcess>>,
    connection: Mutex<Option<Box<dyn sandbox_vm::GuestConnection>>>,
    network: Mutex<Option<VmNetworkBridge>>,
    state_root: PathBuf,
    lease: Mutex<Option<File>>,
    cleaned: AtomicBool,
}

impl VmAuthority {
    fn request(&self, request: &GuestRequest) -> Result<GuestResponse, ErrorData> {
        let mut connection = self.connection.lock().map_err(|_| lock_error())?;
        let connection = connection.as_mut().ok_or_else(|| {
            ErrorData::new("vm.channel_closed", "guest channel is closed", "execute")
        })?;
        connection
            .set_io_timeout(Some(Duration::from_secs(30)))
            .and_then(|()| write_guest_frame(connection.as_mut(), request))
            .and_then(|()| read_guest_frame(connection.as_mut()))
            .map_err(|error| os_error("vm.guest_protocol", &error, "execute"))
    }

    fn terminate(&self) -> Result<(), ErrorData> {
        if let Ok(mut vmm) = self.vmm.lock()
            && let Some(vmm) = vmm.as_mut()
        {
            vmm.terminate()
                .map_err(|error| ErrorData::new("vm.terminate", error.to_string(), "terminate"))?;
        }
        Ok(())
    }

    fn network_snapshot(&self) -> BrokerSnapshot {
        self.network
            .lock()
            .ok()
            .and_then(|network| network.as_ref().map(VmNetworkBridge::snapshot))
            .unwrap_or_default()
    }

    fn take_network_violations(&self) -> Vec<NetworkViolation> {
        self.network
            .lock()
            .ok()
            .and_then(|network| network.as_ref().map(VmNetworkBridge::take_violations))
            .unwrap_or_default()
    }

    fn cleanup(&self) -> Vec<Value> {
        if self.cleaned.swap(true, Ordering::AcqRel) {
            return Vec::new();
        }
        let mut failures = Vec::new();
        if let Ok(mut network_guard) = self.network.lock()
            && let Some(network) = network_guard.take()
        {
            let report = network.stop();
            for failure in report.cleanup_failures {
                failures.push(cleanup_failure("vm.network_cleanup", "network", &failure));
            }
        }
        if let Ok(mut connection_guard) = self.connection.lock() {
            if let Some(connection) = connection_guard.as_mut() {
                if let Err(error) = connection.set_io_timeout(Some(Duration::from_secs(5))) {
                    failures.push(cleanup_failure(
                        "vm.channel_timeout",
                        "guest",
                        &error.to_string(),
                    ));
                }
                if let Err(error) = write_guest_frame(connection.as_mut(), &GuestRequest::Shutdown)
                {
                    failures.push(cleanup_failure("vm.shutdown", "guest", &error.to_string()));
                } else if let Err(error) = read_guest_frame(connection.as_mut()) {
                    failures.push(cleanup_failure(
                        "vm.shutdown_ack",
                        "guest",
                        &error.to_string(),
                    ));
                }
            }
            *connection_guard = None;
        }
        if let Ok(mut vmm_guard) = self.vmm.lock() {
            if let Some(vmm_process) = vmm_guard.as_mut()
                && let Err(error) = vmm_process.wait()
            {
                let _ = vmm_process.terminate();
                failures.push(cleanup_failure("vm.vmm_wait", "vmm", &error.to_string()));
            }
            *vmm_guard = None;
        }
        if let Err(error) = fs::remove_dir_all(&self.state_root)
            && error.kind() != io::ErrorKind::NotFound
        {
            failures.push(cleanup_failure(
                "vm.state_remove",
                "state-directory",
                &error.to_string(),
            ));
        }
        if let Ok(mut lease) = self.lease.lock() {
            *lease = None;
        }
        failures
    }
}

impl Drop for VmAuthority {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct OutputCredits {
    values: Mutex<(u64, u64)>,
    changed: Condvar,
}

struct ExportedArtifacts {
    metadata: Value,
    content: Vec<u8>,
}

struct ExportedChangeSets {
    metadata: Value,
    content: Vec<u8>,
}

impl OutputCredits {
    fn new() -> Self {
        Self {
            values: Mutex::new((INITIAL_STREAM_CREDIT, INITIAL_STREAM_CREDIT)),
            changed: Condvar::new(),
        }
    }

    fn grant(&self, stream: &str, amount: u64) -> Result<(), ErrorData> {
        if amount == 0 || amount > MAX_OUTSTANDING_CREDIT {
            return Err(ErrorData::new(
                "protocol.credit",
                "invalid stream credit",
                "execute",
            ));
        }
        let mut values = self.values.lock().map_err(|_| lock_error())?;
        let value = match stream {
            "stdout" => &mut values.0,
            "stderr" => &mut values.1,
            _ => {
                return Err(ErrorData::new(
                    "protocol.credit_stream",
                    "invalid stream",
                    "execute",
                ));
            }
        };
        *value = value
            .checked_add(amount)
            .filter(|value| *value <= MAX_OUTSTANDING_CREDIT)
            .ok_or_else(|| {
                ErrorData::new("protocol.credit_overflow", "credit overflow", "execute")
            })?;
        self.changed.notify_all();
        Ok(())
    }

    fn reserve(&self, stdout: bool, maximum: usize, alive: &AtomicBool) -> Option<usize> {
        let mut values = self.values.lock().ok()?;
        loop {
            let value = if stdout { &mut values.0 } else { &mut values.1 };
            if *value > 0 {
                let count = maximum.min((*value).try_into().unwrap_or(maximum));
                *value -= count as u64;
                return Some(count);
            }
            if !alive.load(Ordering::Acquire) {
                return None;
            }
            values = self.changed.wait(values).ok()?;
        }
    }
}

struct Running {
    id: String,
    policy: Arc<PreparedPolicy>,
    execution: Arc<PreparedExecution>,
    stdin: Mutex<StdinQueue>,
    stdin_credit: Mutex<u64>,
    worker_started: AtomicBool,
    alive: AtomicBool,
    target_done: AtomicBool,
    termination_reason: Mutex<Option<String>>,
    credits: OutputCredits,
    writer: ProtocolWriter,
    one_shot: bool,
    network_connections_at_start: u64,
    network_violations_at_start: u64,
}

struct StdinQueue {
    chunks: VecDeque<Vec<u8>>,
    bytes: usize,
    close_requested: bool,
    close_sent: bool,
}

fn runtime_main() -> Result<(), Box<dyn std::error::Error>> {
    let writer = ProtocolWriter {
        output: Arc::new(Mutex::new(io::stdout())),
    };
    let (input_tx, input_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut input = io::stdin();
        loop {
            match read_frame(&mut input) {
                Ok(Some(frame)) => {
                    if input_tx.send(InputEvent::Frame(frame)).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = input_tx.send(InputEvent::Eof);
                    return;
                }
                Err(error) => {
                    let _ = input_tx.send(InputEvent::Error(bounded(&error.to_string())));
                    return;
                }
            }
        }
    });
    let mut state = RuntimeState::Empty;
    let mut hello = false;
    let mut request_ids = HashSet::new();
    loop {
        let timeout = next_timeout(&state).unwrap_or(Duration::from_secs(3600));
        match input_rx.recv_timeout(timeout) {
            Ok(InputEvent::Frame(frame)) => {
                match handle_frame(frame, &writer, &mut state, &mut request_ids, &mut hello) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(error) => {
                        writer.error(None, &error);
                        cleanup_state(&state);
                        return Err(error.message.into());
                    }
                }
            }
            Ok(InputEvent::Eof) => {
                cleanup_state(&state);
                return Ok(());
            }
            Ok(InputEvent::Error(message)) => {
                let error = ErrorData::new("protocol.read", message, "execute");
                writer.error(None, &error);
                cleanup_state(&state);
                return Ok(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if expire_prepared(&writer, &mut state) {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                cleanup_state(&state);
                return Ok(());
            }
        }
    }
}

fn handle_frame(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
    hello_complete: &mut bool,
) -> Result<bool, ErrorData> {
    if !*hello_complete {
        if frame.message_type != MessageType::Hello {
            return Err(ErrorData::new(
                "protocol.hello_required",
                "HELLO must be first",
                "validate",
            ));
        }
        let hello: Hello = parse(&frame)?;
        if hello.protocol_major != PROTOCOL_MAJOR {
            return Err(ErrorData::new(
                "protocol.major_mismatch",
                "protocol major mismatch",
                "validate",
            ));
        }
        *hello_complete = true;
        writer.control(
            MessageType::HelloAck,
            &json!({
                "protocolMajor": PROTOCOL_MAJOR,
                "protocolMinor": PROTOCOL_MINOR,
                "runtimeVersion": env!("CARGO_PKG_VERSION"),
                "backendVersions": {BACKEND_ID: env!("CARGO_PKG_VERSION")},
            }),
        )?;
        return Ok(false);
    }
    match frame.message_type {
        MessageType::Probe => {
            let value: Value = parse(&frame)?;
            let request_id = request_id(&value)?;
            unique(request_ids, &request_id)?;
            let capability = probe();
            writer.control(
                MessageType::ProbeResult,
                &json!({
                    "requestId": request_id,
                    "support": {
                        "protocol": {"major": PROTOCOL_MAJOR, "minor": PROTOCOL_MINOR},
                        "packageVersion": env!("CARGO_PKG_VERSION"),
                        "host": {"platform": "linux", "architecture": std::env::consts::ARCH},
                        "backends": [{
                            "id": BACKEND_ID,
                            "isolation": "hardware-vm",
                            "stability": "experimental",
                            "available": capability.get("available").and_then(Value::as_bool).unwrap_or(false),
                            "capabilities": capability,
                        }],
                    },
                }),
            )?;
        }
        MessageType::PrepareRun => prepare_run(frame, writer, state, request_ids)?,
        MessageType::StartPreparedRun => start_prepared_run(frame, writer, state, request_ids)?,
        MessageType::CancelPreparedRun => {
            let message: IdMessage = parse(&frame)?;
            unique(request_ids, &message.request_id)?;
            if matches!(state, RuntimeState::PreparedRun(run) if run.id == message.id) {
                *state = RuntimeState::Empty;
            }
            writer.control(
                MessageType::Event,
                &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id}),
            )?;
        }
        MessageType::PrepareSession => prepare_session(frame, writer, state, request_ids)?,
        MessageType::ActivateSession => activate_session(frame, writer, state, request_ids)?,
        MessageType::CancelPreparedSession => {
            let message: IdMessage = parse(&frame)?;
            unique(request_ids, &message.request_id)?;
            if matches!(state, RuntimeState::Session(session) if !session.active && session.id == message.id)
            {
                *state = RuntimeState::Empty;
            }
            writer.control(
                MessageType::Event,
                &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id}),
            )?;
        }
        MessageType::PrepareProcess => prepare_process(frame, writer, state, request_ids)?,
        MessageType::StartPreparedProcess => {
            start_prepared_process(frame, writer, state, request_ids)?
        }
        MessageType::CancelPreparedProcess => {
            let message: IdMessage = parse(&frame)?;
            unique(request_ids, &message.request_id)?;
            if let Ok(session) = session_mut(state)
                && session
                    .prepared
                    .as_ref()
                    .is_some_and(|prepared| prepared.id == message.id)
            {
                session.prepared = None;
            }
            writer.control(
                MessageType::Event,
                &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id}),
            )?;
        }
        MessageType::Stdin => {
            let running = running(state)?;
            let length = u64::try_from(frame.payload.len()).map_err(|_| {
                ErrorData::new("protocol.stdin", "stdin frame length overflow", "execute")
            })?;
            {
                let mut credit = running.stdin_credit.lock().map_err(|_| lock_error())?;
                if length > *credit {
                    return Err(ErrorData::new(
                        "protocol.credit_exceeded",
                        "stdin sender exceeded granted credit",
                        "execute",
                    ));
                }
                *credit -= length;
            }
            let mut input = running.stdin.lock().map_err(|_| lock_error())?;
            if input.close_requested {
                return Err(ErrorData::new(
                    "protocol.stdin_closed",
                    "stdin is closed",
                    "execute",
                ));
            }
            if input.bytes.saturating_add(frame.payload.len()) > MAX_STDIN_BYTES {
                return Err(ErrorData::new(
                    "resource.stdin_limit",
                    "queued stdin exceeds the bounded credit window",
                    "execute",
                ));
            }
            input.bytes += frame.payload.len();
            input.chunks.push_back(frame.payload);
        }
        MessageType::CloseStdin => {
            let message: IdMessage = parse(&frame)?;
            unique(request_ids, &message.request_id)?;
            let running = running(state)?;
            if running.id != message.id {
                return Err(state_error("process identity does not match"));
            }
            running
                .stdin
                .lock()
                .map_err(|_| lock_error())?
                .close_requested = true;
            writer.control(
                MessageType::Event,
                &json!({"requestId": message.request_id, "kind": "stdin-closed", "id": message.id}),
            )?;
        }
        MessageType::StreamCredit => {
            let message: StreamCreditMessage = parse(&frame)?;
            running(state)?
                .credits
                .grant(&message.stream, message.bytes)?;
        }
        MessageType::Terminate => terminate_process(frame, writer, state, request_ids)?,
        MessageType::CloseSession => close_session(frame, writer, state, request_ids)?,
        MessageType::Shutdown => {
            let value: Value = parse(&frame)?;
            let request_id = request_id(&value)?;
            unique(request_ids, &request_id)?;
            cleanup_state(state);
            writer.control(
                MessageType::RuntimeMetrics,
                &json!({"requestId": request_id, "shutdown": true}),
            )?;
            return Ok(true);
        }
        MessageType::Hello
        | MessageType::HelloAck
        | MessageType::ProbeResult
        | MessageType::RunPrepared
        | MessageType::SessionPrepared
        | MessageType::SessionActive
        | MessageType::ProcessPrepared
        | MessageType::ProcessStarted
        | MessageType::Stdout
        | MessageType::Stderr
        | MessageType::Event
        | MessageType::ProcessExit
        | MessageType::SessionClosed
        | MessageType::Error
        | MessageType::RuntimeMetrics
        | MessageType::Artifact => {
            return Err(ErrorData::new(
                "protocol.direction",
                "message is not valid from the host",
                "validate",
            ));
        }
    }
    Ok(false)
}

fn prepare_run(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    ensure_empty(state)?;
    let message: PrepareRunMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let (policy, execution) =
        normalize_run(message.options, host_memory()?).map_err(|error| *error.0)?;
    let policy = Arc::new(prepare_policy(policy)?);
    let execution = Arc::new(prepare_execution(&policy, execution)?);
    let id = new_id("run");
    let (deadline, expires_at_ms) = expiration(policy.normalized.prepared_ttl_ms);
    writer.control(
        MessageType::RunPrepared,
        &json!({
            "requestId": message.request_id,
            "id": id,
            "policyDigest": policy.policy_digest,
            "executionDigest": execution.execution_digest,
            "summary": run_summary(&policy, &execution),
            "enforcement": policy.enforcement,
            "expiresAtMs": expires_at_ms,
        }),
    )?;
    *state = RuntimeState::PreparedRun(PreparedRun {
        id,
        policy,
        execution,
        deadline,
    });
    Ok(())
}

fn start_prepared_run(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    let message: StartRunMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let prepared = match std::mem::replace(state, RuntimeState::Empty) {
        RuntimeState::PreparedRun(prepared) => prepared,
        other => {
            *state = other;
            return Err(state_error("no prepared run exists"));
        }
    };
    validate_start(
        &prepared.id,
        &prepared.policy.policy_digest,
        &prepared.execution.execution_digest,
        prepared.deadline,
        &message.id,
        &message.policy_digest,
        &message.execution_digest,
    )?;
    let running = start_running(
        message.request_id,
        prepared.policy.clone(),
        prepared.execution.clone(),
        writer.clone(),
        true,
    )?;
    *state = RuntimeState::Session(Session {
        id: String::new(),
        policy: prepared.policy,
        deadline: None,
        active: false,
        prepared: None,
        running: Some(running),
    });
    Ok(())
}

fn prepare_session(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    ensure_empty(state)?;
    let message: PrepareSessionMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let normalized =
        normalize_session(message.options, host_memory()?).map_err(|error| *error.0)?;
    let policy = Arc::new(prepare_policy(normalized)?);
    let id = new_id("session");
    let (deadline, expires_at_ms) = expiration(policy.normalized.prepared_ttl_ms);
    writer.control(
        MessageType::SessionPrepared,
        &json!({
            "requestId": message.request_id,
            "id": id,
            "policyDigest": policy.policy_digest,
            "summary": session_summary(&policy),
            "enforcement": policy.enforcement,
            "expiresAtMs": expires_at_ms,
        }),
    )?;
    *state = RuntimeState::Session(Session {
        id,
        policy,
        deadline: Some(deadline),
        active: false,
        prepared: None,
        running: None,
    });
    Ok(())
}

fn activate_session(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    let message: ActivateSessionMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let session = session_mut(state)?;
    if session.active || session.id != message.id {
        return Err(state_error("prepared session is unavailable"));
    }
    if session
        .deadline
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        return Err(expired_error());
    }
    if session.policy.policy_digest != message.policy_digest {
        return Err(digest_error());
    }
    session.active = true;
    session.deadline = None;
    writer.control(
        MessageType::SessionActive,
        &json!({
            "requestId": message.request_id,
            "id": session.id,
            "policyDigest": session.policy.policy_digest,
            "enforcement": session.policy.enforcement,
        }),
    )
}

fn prepare_process(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    let message: PrepareProcessMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let session = active_session(state, &message.session_id)?;
    clear_finished(session);
    if session.running.is_some() || session.prepared.is_some() {
        return Err(state_error("session is busy"));
    }
    let normalized = normalize_process(message.process, &session.policy.normalized.resources)
        .map_err(|error| *error.0)?;
    let execution = Arc::new(prepare_execution(&session.policy, normalized)?);
    let id = new_id("process");
    let (deadline, expires_at_ms) = expiration(session.policy.normalized.prepared_ttl_ms);
    writer.control(
        MessageType::ProcessPrepared,
        &json!({
            "requestId": message.request_id,
            "id": id,
            "policyDigest": session.policy.policy_digest,
            "executionDigest": execution.execution_digest,
            "summary": process_summary(&execution),
            "expiresAtMs": expires_at_ms,
        }),
    )?;
    session.prepared = Some(PreparedProcess {
        id,
        execution,
        deadline,
    });
    Ok(())
}

fn start_prepared_process(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    let message: StartProcessMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let session = session_mut(state)?;
    clear_finished(session);
    if !session.active || session.running.is_some() {
        return Err(state_error("session cannot start a process"));
    }
    let prepared = session
        .prepared
        .take()
        .ok_or_else(|| state_error("no prepared process exists"))?;
    validate_start(
        &prepared.id,
        &session.policy.policy_digest,
        &prepared.execution.execution_digest,
        prepared.deadline,
        &message.id,
        &message.policy_digest,
        &message.execution_digest,
    )?;
    session.running = Some(start_running(
        message.request_id,
        session.policy.clone(),
        prepared.execution,
        writer.clone(),
        false,
    )?);
    Ok(())
}

fn terminate_process(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    let message: TerminateMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let running = running(state)?;
    if running.id != message.id {
        return Err(state_error("process identity does not match"));
    }
    *running
        .termination_reason
        .lock()
        .map_err(|_| lock_error())? = Some(message.reason.clone());
    running.policy.authority.terminate()?;
    launch_worker(running.clone())?;
    writer.control(
        MessageType::Event,
        &json!({
            "requestId": message.request_id,
            "kind": "termination-started",
            "id": message.id,
            "reason": message.reason,
        }),
    )
}

fn close_session(
    frame: Frame,
    writer: &ProtocolWriter,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<(), ErrorData> {
    let message: IdMessage = parse(&frame)?;
    unique(request_ids, &message.request_id)?;
    let session = session_mut(state)?;
    if session.id != message.id
        || session
            .running
            .as_ref()
            .is_some_and(|run| run.alive.load(Ordering::Acquire))
    {
        return Err(state_error("session cannot be closed"));
    }
    let failures = session.policy.authority.cleanup();
    let completed = failures.is_empty();
    *state = RuntimeState::Empty;
    writer.control(
        MessageType::SessionClosed,
        &json!({
            "requestId": message.request_id,
            "id": message.id,
            "cleanup": {"completed": completed, "failures": failures},
        }),
    )
}

fn prepare_policy(normalized: NormalizedPolicy) -> Result<PreparedPolicy, ErrorData> {
    recover_abandoned_vm_state()?;
    if !normalized.requirements.allow_experimental_backend {
        return Err(ErrorData::new(
            "requirement.experimental_backend",
            "the hardware-VM backend requires explicit experimental activation",
            "prepare",
        ));
    }
    if normalized.network != "none" && normalized.network != "managed" {
        return Err(ErrorData::new(
            "unsupported.vm_network",
            "the hardware-VM runtime supports network none or managed",
            "prepare",
        ));
    }
    let Isolation::HardwareVm {
        image,
        filesystem_transport,
    } = &normalized.isolation
    else {
        return Err(ErrorData::new(
            "unsupported.isolation",
            "VM runtime requires hardware-vm isolation",
            "prepare",
        ));
    };
    if filesystem_transport == "ephemeral" && !normalized.grants.is_empty() {
        return Err(ErrorData::new(
            "policy.vm_ephemeral_grants",
            "ephemeral VM mode does not implicitly import host grants",
            "prepare",
        ));
    }
    let trust = if image.trust == "explicit-local" {
        ImageTrust::ExplicitLocal
    } else {
        let digest = image.digest.as_deref().ok_or_else(|| {
            ErrorData::new(
                "image.bundled_digest",
                "bundled images require an exact manifest digest",
                "prepare",
            )
        })?;
        ImageTrust::Bundled {
            manifest_digest: digest,
            release_public_key: &RELEASE_PUBLIC_KEY,
        }
    };
    let verified = verify_image(Path::new(&image.manifest_path), trust)
        .map_err(|error| ErrorData::new("image.verify", error.to_string(), "prepare"))?;
    if image
        .digest
        .as_ref()
        .is_some_and(|expected| expected != &verified.manifest_digest)
    {
        return Err(ErrorData::new(
            "image.digest",
            "image manifest digest mismatch",
            "prepare",
        ));
    }
    validate_image_architecture(&verified)?;
    let (entries, grants, mounts, workspace_bases, import_digest, import_bytes) =
        if filesystem_transport == "import" {
            prepare_imports(&normalized)?
        } else {
            (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                identity_digest(&Vec::<String>::new()).map_err(digest_data)?,
                0,
            )
        };
    let authority = Arc::new(boot_vm(&normalized, &verified)?);
    if !entries.is_empty() {
        transfer_imports(&authority, entries, import_bytes)?;
    }
    let manifest_digest = identity_digest(&json!({
        "imageManifest": verified.manifest_digest,
        "kernel": verified.manifest.kernel.sha256,
        "rootfs": verified.manifest.rootfs.sha256,
        "guestAgent": verified.manifest.guest_agent,
        "firecracker": firecracker_digest(),
        "workspaceTemplate": WORKSPACE_TEMPLATE_SHA256,
        "import": import_digest,
    }))
    .map_err(digest_data)?;
    let enforcement = enforcement_report(&normalized, &manifest_digest, &verified);
    match_requirements(&normalized, &enforcement)?;
    let policy_digest = policy_digest(&json!({
        "digestFormat": 1,
        "protocolMajor": PROTOCOL_MAJOR,
        "backend": {"id": BACKEND_ID, "version": env!("CARGO_PKG_VERSION"), "stability": "experimental"},
        "targetOperatingSystem": "linux",
        "policy": normalized,
        "verifiedImage": {
            "manifestDigest": verified.manifest_digest,
            "kernelSha256": verified.manifest.kernel.sha256,
            "rootfsSha256": verified.manifest.rootfs.sha256,
            "guestAgentSha256": verified.manifest.guest_agent.sha256,
        },
        "firecrackerSha256": firecracker_digest(),
        "workspaceTemplateSha256": WORKSPACE_TEMPLATE_SHA256,
        "importDigest": import_digest,
        "grants": grants,
    }))
    .map_err(digest_data)?;
    Ok(PreparedPolicy {
        normalized,
        grants,
        mounts,
        workspace_bases,
        policy_digest,
        manifest_digest,
        enforcement,
        authority,
    })
}

fn prepare_execution(
    policy: &PreparedPolicy,
    normalized: NormalizedExecution,
) -> Result<PreparedExecution, ErrorData> {
    if normalized.change_set.is_some() {
        if policy.workspace_bases.is_empty() {
            return Err(ErrorData::new(
                "vm.change_set_grants",
                "workspace change-set export requires at least one read-write imported grant",
                "prepare",
            ));
        }
        if policy.workspace_bases.iter().any(|base| !base.directory) {
            return Err(ErrorData::new(
                "vm.change_set_root",
                "workspace change-set export supports read-write directory grants",
                "prepare",
            ));
        }
    }
    let response = policy.authority.request(&GuestRequest::Inspect {
        executable: normalized.executable.clone(),
        cwd: normalized.cwd.clone(),
        mounts: policy.mounts.clone(),
        masks: guest_masks(&policy.normalized),
        system_runtime: policy.normalized.runtime_view == "system",
    })?;
    let GuestResponse::Inspected {
        executable_sha256,
        executable_identity_digest,
        cwd_identity_digest,
    } = response
    else {
        return match response {
            GuestResponse::Error { code, message, .. } => {
                Err(ErrorData::new(code.as_str(), message, "prepare"))
            }
            _ => Err(ErrorData::new(
                "vm.inspect_response",
                "guest returned an invalid inspect response",
                "prepare",
            )),
        };
    };
    let execution_digest = execution_digest(&json!({
        "policyDigest": policy.policy_digest,
        "executable": normalized.executable,
        "executableIdentity": executable_identity_digest,
        "executableContentSha256": executable_sha256,
        "args": normalized.args,
        "cwd": normalized.cwd,
        "cwdIdentity": cwd_identity_digest,
        "environment": normalized.environment,
        "stdin": normalized.stdin,
        "stdout": normalized.stdout,
        "stderr": normalized.stderr,
        "artifacts": normalized.artifacts,
        "changeSet": normalized.change_set,
        "resources": normalized.resources,
    }))
    .map_err(digest_data)?;
    Ok(PreparedExecution {
        normalized,
        execution_digest,
        executable_sha256,
        executable_identity_digest,
        cwd_identity_digest,
    })
}

fn boot_vm(policy: &NormalizedPolicy, image: &VerifiedImage) -> Result<VmAuthority, ErrorData> {
    let executable =
        std::env::current_exe().map_err(|error| os_error("vm.runtime_path", &error, "prepare"))?;
    let native = executable.parent().ok_or_else(|| {
        ErrorData::new(
            "vm.runtime_path",
            "runtime has no parent directory",
            "prepare",
        )
    })?;
    let firecracker = native.join(firecracker_name());
    let template = native.join(WORKSPACE_TEMPLATE);
    verify_file_digest(&firecracker, firecracker_digest(), "Firecracker")?;
    let mut template =
        open_verified_file(&template, WORKSPACE_TEMPLATE_SHA256, "workspace template")?;
    let mut state = VmStateGuard::create()?;
    let state_root = state.path().to_path_buf();
    let kernel = snapshot_verified_artifact(
        &image.kernel_path,
        &image.manifest.kernel.sha256,
        "guest kernel",
        &state_root.join("kernel"),
    )?;
    let rootfs = snapshot_verified_artifact(
        &image.rootfs_path,
        &image.manifest.rootfs.sha256,
        "guest root image",
        &state_root.join("rootfs"),
    )?;
    let workspace = state_root.join("workspace.ext4");
    let mut workspace_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&workspace)
        .map_err(|error| os_error("vm.workspace_copy", &error, "prepare"))?;
    io::copy(&mut template, &mut workspace_file)
        .map_err(|error| os_error("vm.workspace_copy", &error, "prepare"))?;
    workspace_file
        .flush()
        .map_err(|error| os_error("vm.workspace_copy", &error, "prepare"))?;
    drop(workspace_file);
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o600))
        .map_err(|error| os_error("vm.workspace_permissions", &error, "prepare"))?;
    let (authentication, nonce) = create_authentication_drive(&state_root)?;
    let owner_token = encode_hex(&nonce);
    let vmm_state = state_root.join("vmm");
    let memory_mib = ((policy.resources.memory_bytes / (1024 * 1024)).clamp(128, 65_536)) as u32;
    let mut vmm = FirecrackerProcess::spawn(&FirecrackerConfig {
        launcher_executable: PathBuf::from("/proc/self/exe"),
        firecracker_executable: firecracker,
        firecracker_sha256: firecracker_digest().into(),
        state_directory: vmm_state,
        kernel_image: kernel,
        rootfs_image: rootfs,
        workspace_image: workspace,
        authentication_image: authentication,
        owner_token: owner_token.clone(),
        guest_cid: 52,
        guest_port: GUEST_CONTROL_PORT,
        vcpu_count: 1,
        memory_mib,
    })
    .map_err(|error| ErrorData::new("vm.spawn", error.to_string(), "spawn"))?;
    write_vm_owner_record(&state_root, vmm.process_id(), &owner_token)?;
    let boot_log = Arc::new(Mutex::new(Vec::new()));
    if let Some(stdout) = vmm.stdout.take() {
        let log = boot_log.clone();
        thread::spawn(move || drain_capture(stdout, &log));
    }
    if let Some(stderr) = vmm.stderr.take() {
        let log = boot_log.clone();
        thread::spawn(move || drain_capture(stderr, &log));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let connection = loop {
        let mut channel = UnixVsockChannel {
            socket_path: vmm.vsock_path.clone(),
            guest_port: GUEST_CONTROL_PORT,
            timeout: Duration::from_secs(2),
        };
        match channel.connect() {
            Ok(connection) => break connection,
            Err(error) if Instant::now() < deadline => {
                if vmm.has_exited().map_err(|failure| {
                    ErrorData::new("vm.vmm_status", failure.to_string(), "spawn")
                })? {
                    let details = boot_log
                        .lock()
                        .ok()
                        .map(|bytes| {
                            let start = bytes.len().saturating_sub(3_500);
                            String::from_utf8_lossy(&bytes[start..]).into_owned()
                        })
                        .unwrap_or_default();
                    return Err(ErrorData::new(
                        "vm.boot_failure",
                        format!("{error}: {}", bounded(&details)),
                        "spawn",
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                let _ = vmm.terminate();
                let details = boot_log
                    .lock()
                    .ok()
                    .map(|bytes| {
                        let start = bytes.len().saturating_sub(3_500);
                        String::from_utf8_lossy(&bytes[start..]).into_owned()
                    })
                    .unwrap_or_default();
                return Err(ErrorData::new(
                    "vm.boot_timeout",
                    format!("{error}: {}", bounded(&details)),
                    "spawn",
                ));
            }
        }
    };
    let (state_root, lease) = state.handoff();
    let authority = VmAuthority {
        vmm: Mutex::new(Some(vmm)),
        connection: Mutex::new(Some(connection)),
        network: Mutex::new(None),
        state_root,
        lease: Mutex::new(Some(lease)),
        cleaned: AtomicBool::new(false),
    };
    match authority.request(&GuestRequest::Authenticate {
        protocol_major: GUEST_PROTOCOL_MAJOR,
        protocol_minor: GUEST_PROTOCOL_MINOR,
        nonce_hex: encode_hex(&nonce),
    })? {
        GuestResponse::Authenticated {
            protocol_major,
            protocol_minor,
            agent_version,
            agent_sha256,
        } if protocol_major == GUEST_PROTOCOL_MAJOR
            && protocol_minor == GUEST_PROTOCOL_MINOR
            && image.manifest.guest_agent.protocol_major == GUEST_PROTOCOL_MAJOR
            && image.manifest.guest_agent.protocol_minor == GUEST_PROTOCOL_MINOR
            && agent_version == image.manifest.guest_agent.version
            && agent_sha256 == image.manifest.guest_agent.sha256 => {}
        GuestResponse::Error { code, message, .. } => {
            return Err(ErrorData::new(code.as_str(), message, "prepare"));
        }
        _ => {
            return Err(ErrorData::new(
                "vm.guest_identity",
                "guest agent identity or protocol mismatch",
                "prepare",
            ));
        }
    }
    if policy.network == "managed" {
        let vsock_path = authority
            .vmm
            .lock()
            .map_err(|_| lock_error())?
            .as_ref()
            .map(|vmm| vmm.vsock_path.clone())
            .ok_or_else(|| ErrorData::new("vm.vmm", "VMM is unavailable", "prepare"))?;
        let bridge =
            VmNetworkBridge::start(&vsock_path, nonce, policy.managed_network_rules.clone())
                .map_err(|error| os_error("vm.network_bridge", &error, "prepare"))?;
        *authority.network.lock().map_err(|_| lock_error())? = Some(bridge);
    }
    Ok(authority)
}

struct VmStateGuard {
    path: Option<PathBuf>,
    lease: Option<File>,
}

impl VmStateGuard {
    fn create() -> Result<Self, ErrorData> {
        let (path, lease) = create_state_root()?;
        Ok(Self {
            path: Some(path),
            lease: Some(lease),
        })
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("VM state guard owns its path")
    }

    fn handoff(&mut self) -> (PathBuf, File) {
        (
            self.path.take().expect("VM state guard owns its path"),
            self.lease.take().expect("VM state guard owns its lease"),
        )
    }
}

impl Drop for VmStateGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
        self.lease = None;
    }
}

fn guest_masks(policy: &NormalizedPolicy) -> Vec<GuestMask> {
    policy
        .masks
        .iter()
        .map(|mask| GuestMask {
            target: mask.target_path.clone(),
            replacement: mask.replacement.clone(),
        })
        .collect()
}

fn start_running(
    request_id: String,
    policy: Arc<PreparedPolicy>,
    execution: Arc<PreparedExecution>,
    writer: ProtocolWriter,
    one_shot: bool,
) -> Result<Arc<Running>, ErrorData> {
    let id = new_id("process");
    let closed = execution.normalized.stdin == "closed";
    // Session bridges outlive individual commands. Discard already-attributed detail records and
    // bind both counters to this process so sequential results cannot inherit each other's usage.
    let _ = policy.authority.take_network_violations();
    let network_at_start = policy.authority.network_snapshot();
    let running = Arc::new(Running {
        id: id.clone(),
        policy,
        execution,
        stdin: Mutex::new(StdinQueue {
            chunks: VecDeque::new(),
            bytes: 0,
            close_requested: closed,
            close_sent: false,
        }),
        stdin_credit: Mutex::new(INITIAL_STREAM_CREDIT),
        worker_started: AtomicBool::new(false),
        alive: AtomicBool::new(true),
        target_done: AtomicBool::new(false),
        termination_reason: Mutex::new(None),
        credits: OutputCredits::new(),
        writer: writer.clone(),
        one_shot,
        network_connections_at_start: network_at_start.connections,
        network_violations_at_start: network_at_start.violations,
    });
    let activation = (|| {
        match running
            .policy
            .authority
            .request(&guest_run_request(&running))?
        {
            GuestResponse::RunStarted => {}
            GuestResponse::Error {
                code,
                message,
                target_executed,
            } => {
                let mut error = ErrorData::new(code.as_str(), message, "spawn");
                error.target_executed = target_executed;
                return Err(error);
            }
            _ => return Err(state_error("guest returned an invalid run-start response")),
        }
        writer.control(
            MessageType::ProcessStarted,
            &json!({"requestId": request_id, "id": id, "identity": {"kind": "opaque"}}),
        )?;
        writer.control(
            MessageType::StreamCredit,
            &StreamCreditMessage {
                stream: "stdin".into(),
                bytes: INITIAL_STREAM_CREDIT,
            },
        )
    })();
    if let Err(error) = activation {
        let _ = running.policy.authority.terminate();
        return Err(error);
    }
    let watchdog = running.clone();
    let duration = Duration::from_millis(
        watchdog
            .execution
            .normalized
            .resources
            .wall_time_ms
            .saturating_add(1_000),
    );
    thread::spawn(move || {
        thread::sleep(duration);
        if watchdog.alive.load(Ordering::Acquire) && !watchdog.target_done.load(Ordering::Acquire) {
            if let Ok(mut reason) = watchdog.termination_reason.lock() {
                *reason = Some("timeout".into());
            }
            let _ = watchdog.policy.authority.terminate();
        }
    });
    launch_worker(running.clone())?;
    Ok(running)
}

fn launch_worker(running: Arc<Running>) -> Result<(), ErrorData> {
    if running.worker_started.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    thread::spawn(move || run_worker(running));
    Ok(())
}

fn guest_run_request(running: &Running) -> GuestRequest {
    let mut environment = running
        .execution
        .normalized
        .environment
        .iter()
        .map(|(name, value)| (name.clone(), value.value.clone()))
        .collect::<BTreeMap<_, _>>();
    if running.policy.normalized.network == "managed" {
        environment.insert(
            "HTTP_PROXY".into(),
            format!("http://127.0.0.1:{GUEST_HTTP_PROXY_PORT}"),
        );
        environment.insert(
            "HTTPS_PROXY".into(),
            format!("http://127.0.0.1:{GUEST_HTTP_PROXY_PORT}"),
        );
        environment.insert(
            "ALL_PROXY".into(),
            format!("socks5h://127.0.0.1:{GUEST_SOCKS_PROXY_PORT}"),
        );
        environment.insert("NO_PROXY".into(), String::new());
    }
    let limits = &running.execution.normalized.resources;
    GuestRequest::Run {
        executable: running.execution.normalized.executable.clone(),
        expected_executable_sha256: running.execution.executable_sha256.clone(),
        expected_executable_identity_digest: running.execution.executable_identity_digest.clone(),
        args: running.execution.normalized.args.clone(),
        cwd: running.execution.normalized.cwd.clone(),
        expected_cwd_identity_digest: running.execution.cwd_identity_digest.clone(),
        environment,
        mounts: running.policy.mounts.clone(),
        masks: guest_masks(&running.policy.normalized),
        private_home: GuestPrivateDirectory {
            enabled: running.policy.normalized.private_home.enabled,
            size_bytes: running.policy.normalized.private_home.size_bytes,
            executable: running.policy.normalized.private_home.executable,
        },
        temporary: GuestPrivateDirectory {
            enabled: true,
            size_bytes: running.policy.normalized.temporary.size_bytes,
            executable: running.policy.normalized.temporary.executable,
        },
        network_mode: running.policy.normalized.network.clone(),
        system_runtime: running.policy.normalized.runtime_view == "system",
        limits: GuestLimits {
            wall_time_ms: limits.wall_time_ms,
            cpu_time_ms: limits.cpu_time_ms,
            memory_bytes: limits.memory_bytes,
            max_processes: limits.max_processes,
            max_open_files: limits.max_open_files_per_process,
            max_single_file_bytes: limits.max_single_file_bytes,
            max_output_bytes: limits.max_output_bytes,
            termination_grace_ms: limits.termination_grace_ms,
        },
    }
}

fn run_worker(running: Arc<Running>) {
    let started = Instant::now();
    let (stdout_sender, stdout_receiver) = mpsc::channel::<Vec<u8>>();
    let (stderr_sender, stderr_receiver) = mpsc::channel::<Vec<u8>>();
    let stdout_running = running.clone();
    let stdout_thread = thread::spawn(move || {
        for chunk in stdout_receiver {
            send_output(&stdout_running, MessageType::Stdout, &chunk);
        }
    });
    let stderr_running = running.clone();
    let stderr_thread = thread::spawn(move || {
        for chunk in stderr_receiver {
            send_output(&stderr_running, MessageType::Stderr, &chunk);
        }
    });
    let response = poll_guest_run(&running, &stdout_sender, &stderr_sender);
    running.target_done.store(true, Ordering::Release);
    drop(stdout_sender);
    drop(stderr_sender);
    let stdout_ok = stdout_thread.join().is_ok();
    let stderr_ok = stderr_thread.join().is_ok();
    let output_threads_ok = stdout_ok && stderr_ok;
    let response = if output_threads_ok {
        response
    } else {
        Err(ErrorData::new(
            "vm.output_thread",
            "VM output forwarding thread panicked",
            "execute",
        ))
    };
    finish_worker(running, response, started);
}

fn poll_guest_run(
    running: &Running,
    stdout: &mpsc::Sender<Vec<u8>>,
    stderr: &mpsc::Sender<Vec<u8>>,
) -> Result<GuestResponse, ErrorData> {
    let mut termination_sent = false;
    loop {
        let termination = running
            .termination_reason
            .lock()
            .map_err(|_| lock_error())?
            .clone();
        if let Some(reason) = termination
            && !termination_sent
        {
            match running
                .policy
                .authority
                .request(&GuestRequest::TerminateRun { reason })?
            {
                GuestResponse::TerminationStarted => termination_sent = true,
                GuestResponse::Error {
                    code,
                    message,
                    target_executed,
                } => {
                    let mut error = ErrorData::new(code.as_str(), message, "terminate");
                    error.target_executed = target_executed;
                    return Err(error);
                }
                _ => {
                    return Err(state_error(
                        "guest returned an invalid termination response",
                    ));
                }
            }
        }

        let stdin = running
            .stdin
            .lock()
            .map_err(|_| lock_error())?
            .chunks
            .front()
            .cloned();
        if let Some(chunk) = stdin {
            let accepted = match running
                .policy
                .authority
                .request(&GuestRequest::WriteStdin {
                    content_hex: encode_hex(&chunk),
                })? {
                GuestResponse::StdinAccepted { bytes } => usize::try_from(bytes)
                    .ok()
                    .filter(|bytes| *bytes <= chunk.len())
                    .ok_or_else(|| state_error("guest accepted an invalid stdin byte count"))?,
                GuestResponse::Error {
                    code,
                    message,
                    target_executed,
                } => {
                    let mut error = ErrorData::new(code.as_str(), message, "execute");
                    error.target_executed = target_executed;
                    return Err(error);
                }
                _ => return Err(state_error("guest returned an invalid stdin response")),
            };
            if accepted > 0 {
                {
                    let mut stdin = running.stdin.lock().map_err(|_| lock_error())?;
                    let empty = {
                        let front = stdin
                            .chunks
                            .front_mut()
                            .ok_or_else(|| state_error("stdin queue changed unexpectedly"))?;
                        front.drain(..accepted);
                        front.is_empty()
                    };
                    stdin.bytes = stdin.bytes.saturating_sub(accepted);
                    if empty {
                        stdin.chunks.pop_front();
                    }
                }
                {
                    let mut credit = running.stdin_credit.lock().map_err(|_| lock_error())?;
                    *credit = credit
                        .checked_add(accepted as u64)
                        .filter(|value| *value <= INITIAL_STREAM_CREDIT)
                        .ok_or_else(|| state_error("stdin credit accounting overflow"))?;
                }
                running.writer.control(
                    MessageType::StreamCredit,
                    &StreamCreditMessage {
                        stream: "stdin".into(),
                        bytes: accepted as u64,
                    },
                )?;
            }
        }

        let should_close = {
            let stdin = running.stdin.lock().map_err(|_| lock_error())?;
            stdin.close_requested && stdin.chunks.is_empty() && !stdin.close_sent
        };
        if should_close {
            match running
                .policy
                .authority
                .request(&GuestRequest::CloseStdin)?
            {
                GuestResponse::StdinClosed => {
                    running.stdin.lock().map_err(|_| lock_error())?.close_sent = true;
                }
                GuestResponse::Error {
                    code,
                    message,
                    target_executed,
                } => {
                    let mut error = ErrorData::new(code.as_str(), message, "execute");
                    error.target_executed = target_executed;
                    return Err(error);
                }
                _ => {
                    return Err(state_error(
                        "guest returned an invalid stdin-close response",
                    ));
                }
            }
        }

        match running.policy.authority.request(&GuestRequest::PollRun)? {
            GuestResponse::RunOutput {
                stdout_hex,
                stderr_hex,
            } => {
                let stdout_chunk = decode_hex(&stdout_hex)
                    .map_err(|error| os_error("vm.guest_stdout", &error, "execute"))?;
                let stderr_chunk = decode_hex(&stderr_hex)
                    .map_err(|error| os_error("vm.guest_stderr", &error, "execute"))?;
                if !stdout_chunk.is_empty() {
                    stdout
                        .send(stdout_chunk)
                        .map_err(|_| state_error("stdout forwarding channel closed"))?;
                }
                if !stderr_chunk.is_empty() {
                    stderr
                        .send(stderr_chunk)
                        .map_err(|_| state_error("stderr forwarding channel closed"))?;
                }
            }
            complete @ GuestResponse::RunComplete { .. } => return Ok(complete),
            GuestResponse::Error {
                code,
                message,
                target_executed,
            } => {
                let mut error = ErrorData::new(code.as_str(), message, "execute");
                error.target_executed = target_executed;
                return Err(error);
            }
            _ => return Err(state_error("guest returned an invalid run-poll response")),
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn finish_worker(
    running: Arc<Running>,
    response: Result<GuestResponse, ErrorData>,
    started: Instant,
) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_count = 0_u64;
    let mut stderr_count = 0_u64;
    let mut guest_wall_time_ms = None;
    let mut cpu_time_ms = None;
    let mut peak_memory_bytes = None;
    let mut max_concurrent_processes = None;
    let mut termination = json!({
        "reason": "runtime-failure",
        "error": ErrorData::new("vm.guest", "guest execution failed", "execute")
    });
    match response {
        Ok(GuestResponse::RunComplete {
            exit_code,
            signal,
            termination_reason,
            runtime_error,
            stdout_hex,
            stderr_hex,
            stdout_bytes,
            stderr_bytes,
            wall_time_ms,
            cpu_time_ms: guest_cpu_time_ms,
            peak_memory_bytes: guest_peak_memory_bytes,
            max_concurrent_processes: guest_max_concurrent_processes,
        }) => {
            stdout = decode_hex(&stdout_hex).unwrap_or_default();
            stderr = decode_hex(&stderr_hex).unwrap_or_default();
            stdout_count = stdout_bytes;
            stderr_count = stderr_bytes;
            guest_wall_time_ms = Some(wall_time_ms);
            cpu_time_ms = guest_cpu_time_ms;
            peak_memory_bytes = guest_peak_memory_bytes;
            max_concurrent_processes = guest_max_concurrent_processes;
            termination = if let Some(reason) = running
                .termination_reason
                .lock()
                .ok()
                .and_then(|value| value.clone())
            {
                json!({"reason": if reason == "timeout" { "timeout" } else { "cancelled" }})
            } else if let Some(error) = runtime_error {
                let mut error = ErrorData::new("vm.guest_runtime", error, "execute");
                error.target_executed = true;
                json!({
                    "reason": "runtime-failure",
                    "error": error,
                })
            } else if let Some(reason) = termination_reason {
                json!({"reason": reason})
            } else if let Some(signal) = signal {
                json!({"reason": "signal", "signal": signal_name(signal)})
            } else {
                json!({"reason": "exit", "code": exit_code.unwrap_or(125)})
            };
        }
        Ok(GuestResponse::Error {
            code,
            message,
            target_executed,
        }) => {
            let mut error = ErrorData::new(code.as_str(), message, "execute");
            error.target_executed = target_executed;
            termination = json!({"reason": "runtime-failure", "error": error});
        }
        Ok(_) => {}
        Err(error) => {
            if let Some(reason) = running
                .termination_reason
                .lock()
                .ok()
                .and_then(|value| value.clone())
            {
                termination =
                    json!({"reason": if reason == "timeout" { "timeout" } else { "cancelled" }});
            } else {
                termination = json!({"reason": "runtime-failure", "error": error});
            }
        }
    }
    if stdout_count == 0 {
        stdout_count = stdout.len() as u64;
    }
    if stderr_count == 0 {
        stderr_count = stderr.len() as u64;
    }
    send_output(&running, MessageType::Stdout, &stdout);
    send_output(&running, MessageType::Stderr, &stderr);
    let target_runtime_failed =
        termination.get("reason").and_then(Value::as_str) == Some("runtime-failure");
    let artifacts = match if target_runtime_failed {
        Ok(None)
    } else {
        export_requested(&running)
    } {
        Ok(artifacts) => artifacts,
        Err(mut error) => {
            error.phase = "artifact-export".into();
            error.target_executed = true;
            termination = json!({"reason": "runtime-failure", "error": error});
            None
        }
    };
    let artifact_bytes = artifacts
        .as_ref()
        .map_or(0, |artifacts| artifacts.content.len());
    let change_sets =
        match if termination.get("reason").and_then(Value::as_str) == Some("runtime-failure") {
            Ok(None)
        } else {
            export_change_sets(&running, artifact_bytes)
        } {
            Ok(change_sets) => change_sets,
            Err(mut error) => {
                error.phase = "artifact-export".into();
                error.target_executed = true;
                termination = json!({"reason": "runtime-failure", "error": error});
                None
            }
        };
    let mut binary_content = Vec::with_capacity(
        artifact_bytes
            + change_sets
                .as_ref()
                .map_or(0, |change_sets| change_sets.content.len()),
    );
    if let Some(artifacts) = &artifacts {
        binary_content.extend_from_slice(&artifacts.content);
    }
    if let Some(change_sets) = &change_sets {
        binary_content.extend_from_slice(&change_sets.content);
    }
    for chunk in binary_content.chunks(sandbox_protocol::MAX_STREAM_PAYLOAD) {
        if running
            .writer
            .binary(MessageType::Artifact, chunk.to_vec())
            .is_err()
        {
            termination = json!({
                "reason": "runtime-failure",
                "error": ErrorData::new(
                    "vm.artifact_protocol",
                    "artifact and change-set stream could not be delivered",
                    "artifact-export",
                ),
            });
            break;
        }
    }
    let network_snapshot = running.policy.authority.network_snapshot();
    let network_connections = network_snapshot
        .connections
        .saturating_sub(running.network_connections_at_start);
    let network_violation_count = network_snapshot
        .violations
        .saturating_sub(running.network_violations_at_start);
    let mut violations = running
        .policy
        .authority
        .take_network_violations()
        .into_iter()
        .map(|violation| {
            json!({
                "id": new_id("violation"),
                "kind": "network-denied",
                "processId": running.id,
                "timestampMs": epoch_ms(),
                "mechanism": "managed-network-vsock-broker",
                "details": {
                    "destination": violation.destination,
                    "port": violation.port,
                    "transport": "tcp",
                    "ruleReason": violation.rule_reason,
                },
            })
        })
        .collect::<Vec<_>>();
    let omitted_violations = network_violation_count.saturating_sub(violations.len() as u64);
    if omitted_violations > 0 {
        violations.push(json!({
            "id": new_id("violation"),
            "kind": "network-denied-events-truncated",
            "processId": running.id,
            "timestampMs": epoch_ms(),
            "mechanism": "managed-network-vsock-broker",
            "details": {
                "omittedCount": omitted_violations,
                "recordedCount": violations.len(),
            },
        }));
    }
    for violation in &violations {
        let _ = running.writer.control(
            MessageType::Event,
            &json!({"kind": "violation", "violation": violation}),
        );
    }
    let failures = if running.one_shot
        || !matches!(
            termination.get("reason").and_then(Value::as_str),
            Some("exit") | Some("signal")
        ) {
        running.policy.authority.cleanup()
    } else {
        Vec::new()
    };
    let completed = failures.is_empty();
    if termination.get("reason").and_then(Value::as_str) == Some("runtime-failure")
        && let Some(error) = termination.get_mut("error").and_then(Value::as_object_mut)
    {
        error.insert("backend".into(), json!(BACKEND_ID));
        error.insert("platform".into(), json!("linux"));
    }
    running.alive.store(false, Ordering::Release);
    running.credits.changed.notify_all();
    let mut usage = json!({
        "wallTimeMs": guest_wall_time_ms.unwrap_or_else(|| started.elapsed().as_millis() as u64),
        "stdoutBytes": stdout_count,
        "stderrBytes": stderr_count,
        "networkConnections": network_connections,
    });
    let usage = usage.as_object_mut().expect("usage object");
    if let Some(value) = cpu_time_ms {
        usage.insert("cpuTimeMs".into(), json!(value));
    }
    if let Some(value) = peak_memory_bytes {
        usage.insert("peakMemoryBytes".into(), json!(value));
    }
    if let Some(value) = max_concurrent_processes {
        usage.insert("maxConcurrentProcesses".into(), json!(value));
    }
    let mut result = json!({
        "processId": running.id,
        "policyDigest": running.policy.policy_digest,
        "executionDigest": running.execution.execution_digest,
        "termination": termination,
        "enforcement": running.policy.enforcement,
        "violations": violations,
        "usage": usage,
        "cleanup": {"completed": completed, "failures": failures},
    });
    if let Some(artifacts) = artifacts {
        result
            .as_object_mut()
            .expect("object")
            .insert("artifacts".into(), artifacts.metadata);
    }
    if let Some(change_sets) = change_sets {
        result
            .as_object_mut()
            .expect("object")
            .insert("changeSets".into(), change_sets.metadata);
    }
    let _ = running.writer.control(MessageType::ProcessExit, &result);
}

fn export_requested(running: &Running) -> Result<Option<ExportedArtifacts>, ErrorData> {
    let Some(request) = &running.execution.normalized.artifacts else {
        return Ok(None);
    };
    let translated = request
        .paths
        .iter()
        .map(|path| translate_export_path(path, &running.policy.grants))
        .collect::<Result<Vec<_>, _>>()?;
    let (mut entries, bytes) =
        read_guest_export(&running.policy.authority, translated, request.max_bytes)?;
    for entry in &mut entries {
        entry.path = restore_export_path(&entry.path, &running.policy.grants);
    }
    let digest = identity_digest(&entries).map_err(digest_data)?;
    let (files, content) = encode_guest_entries(entries)?;
    if content.len() as u64 != bytes {
        return Err(ErrorData::new(
            "vm.artifact_size",
            "artifact content length does not match the guest manifest",
            "artifact-export",
        ));
    }
    let metadata = json!({"digest": digest, "files": files, "bytes": bytes, "binaryOffset": 0});
    ensure_export_manifest_size(&metadata)?;
    Ok(Some(ExportedArtifacts { metadata, content }))
}

fn export_change_sets(
    running: &Running,
    binary_offset: usize,
) -> Result<Option<ExportedChangeSets>, ErrorData> {
    let Some(request) = &running.execution.normalized.change_set else {
        return Ok(None);
    };
    let mut remaining = request.max_bytes;
    let mut content = Vec::new();
    let mut values = Vec::with_capacity(running.policy.workspace_bases.len());
    for base in &running.policy.workspace_bases {
        let (entries, bytes) = read_guest_export(
            &running.policy.authority,
            vec![base.guest_path.clone()],
            remaining.max(1),
        )?;
        if bytes > remaining {
            return Err(ErrorData::new(
                "vm.change_set_limit",
                "workspace change-set content exceeded the requested limit",
                "artifact-export",
            ));
        }
        remaining -= bytes;
        let prefix = format!("{}/", base.guest_path);
        let current = entries
            .into_iter()
            .filter_map(|entry| guest_entry_for_change_set(entry, &base.guest_path, &prefix))
            .collect::<Result<Vec<_>, _>>()?;
        let change_set = create_change_set(&base.files, &current).map_err(|error| {
            ErrorData::new("vm.change_set", error.to_string(), "artifact-export")
        })?;
        let segment_start = content.len();
        let mut value = serde_json::to_value(&change_set).map_err(|error| {
            ErrorData::new(
                "vm.change_set_encoding",
                error.to_string(),
                "artifact-export",
            )
        })?;
        let operation_values = value
            .get_mut("operations")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                ErrorData::new(
                    "vm.change_set_encoding",
                    "change-set operations are not an array",
                    "artifact-export",
                )
            })?;
        for (operation, operation_value) in change_set
            .operations
            .iter()
            .zip(operation_values.iter_mut())
        {
            let ChangeOperation::Upsert { entry } = operation else {
                continue;
            };
            if entry.kind != ArtifactKind::RegularFile {
                continue;
            }
            let bytes = entry
                .content_hex
                .as_deref()
                .map(decode_hex)
                .transpose()
                .map_err(|error| {
                    ErrorData::new(
                        "vm.change_set_encoding",
                        error.to_string(),
                        "artifact-export",
                    )
                })?
                .ok_or_else(|| {
                    ErrorData::new(
                        "vm.change_set_encoding",
                        "regular-file upsert has no content",
                        "artifact-export",
                    )
                })?;
            let offset = content.len() - segment_start;
            content.extend_from_slice(&bytes);
            let entry_value = operation_value
                .get_mut("entry")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    ErrorData::new(
                        "vm.change_set_encoding",
                        "upsert entry is not an object",
                        "artifact-export",
                    )
                })?;
            entry_value.remove("contentHex");
            entry_value.insert("contentOffset".into(), json!(offset));
            entry_value.insert("contentLength".into(), json!(bytes.len()));
        }
        let segment_bytes = content.len() - segment_start;
        values.push(json!({
            "targetPath": base.target_path,
            "binaryOffset": binary_offset + segment_start,
            "bytes": segment_bytes,
            "changeSet": value,
        }));
    }
    let metadata = Value::Array(values);
    ensure_export_manifest_size(&metadata)?;
    Ok(Some(ExportedChangeSets { metadata, content }))
}

fn guest_entry_for_change_set(
    entry: GuestArtifactEntry,
    root: &str,
    prefix: &str,
) -> Option<Result<ArtifactEntry, ErrorData>> {
    if entry.path == root {
        return None;
    }
    let path = match entry.path.strip_prefix(prefix) {
        Some(path) if !path.is_empty() => path.to_owned(),
        _ => {
            return Some(Err(ErrorData::new(
                "vm.change_set_path",
                "guest change-set entry escaped its workspace root",
                "artifact-export",
            )));
        }
    };
    let kind = match entry.kind.as_str() {
        "directory" => ArtifactKind::Directory,
        "regular-file" => ArtifactKind::RegularFile,
        "symbolic-link" => ArtifactKind::SymbolicLink,
        _ => {
            return Some(Err(ErrorData::new(
                "vm.change_set_kind",
                "guest returned an invalid change-set entry kind",
                "artifact-export",
            )));
        }
    };
    Some(Ok(ArtifactEntry {
        path,
        kind,
        mode: entry.mode,
        modified_unix_ms: entry.modified_unix_ms,
        content_hex: entry.content_hex,
        link_target: entry.link_target,
        sha256: entry.sha256,
    }))
}

fn read_guest_export(
    authority: &VmAuthority,
    paths: Vec<String>,
    max_bytes: u64,
) -> Result<(Vec<GuestArtifactEntry>, u64), ErrorData> {
    let response = authority.request(&GuestRequest::Export { paths, max_bytes })?;
    let GuestResponse::Exported {
        mut entries, bytes, ..
    } = response
    else {
        return match response {
            GuestResponse::Error { code, message, .. } => {
                Err(ErrorData::new(code.as_str(), message, "artifact-export"))
            }
            _ => Err(ErrorData::new(
                "vm.export_response",
                "guest returned an invalid export response",
                "artifact-export",
            )),
        };
    };
    let mut collected = 0_u64;
    for entry in &mut entries {
        if entry.kind != "regular-file" {
            continue;
        }
        let mut content = Vec::new();
        loop {
            let offset = content.len() as u64;
            match authority.request(&GuestRequest::ReadArtifact {
                path: entry.path.clone(),
                offset,
                max_bytes: 1024 * 1024,
            })? {
                GuestResponse::ArtifactChunk {
                    path,
                    offset: returned_offset,
                    content_hex,
                    complete,
                } if path == entry.path && returned_offset == offset => {
                    let chunk = decode_hex(&content_hex).map_err(|error| {
                        ErrorData::new("vm.artifact_chunk", error.to_string(), "artifact-export")
                    })?;
                    if chunk.is_empty() && !complete {
                        return Err(ErrorData::new(
                            "vm.artifact_chunk",
                            "guest returned an empty non-final artifact chunk",
                            "artifact-export",
                        ));
                    }
                    collected = collected.saturating_add(chunk.len() as u64);
                    if collected > max_bytes {
                        return Err(ErrorData::new(
                            "vm.artifact_limit",
                            "guest artifact content exceeded the requested limit",
                            "artifact-export",
                        ));
                    }
                    content.extend_from_slice(&chunk);
                    if complete {
                        break;
                    }
                }
                GuestResponse::Error { code, message, .. } => {
                    return Err(ErrorData::new(code.as_str(), message, "artifact-export"));
                }
                _ => {
                    return Err(ErrorData::new(
                        "vm.artifact_chunk",
                        "guest returned an invalid artifact chunk",
                        "artifact-export",
                    ));
                }
            }
        }
        let actual = format!("{:x}", Sha256::digest(&content));
        if entry.sha256.as_deref() != Some(actual.as_str()) {
            return Err(ErrorData::new(
                "vm.artifact_digest",
                "guest artifact content digest mismatch",
                "artifact-export",
            ));
        }
        entry.content_hex = Some(encode_hex(&content));
    }
    if collected != bytes {
        return Err(ErrorData::new(
            "vm.artifact_size",
            "guest artifact byte count mismatch",
            "artifact-export",
        ));
    }
    Ok((entries, bytes))
}

fn encode_guest_entries(
    entries: Vec<GuestArtifactEntry>,
) -> Result<(Vec<Value>, Vec<u8>), ErrorData> {
    let mut content = Vec::new();
    let mut files = Vec::with_capacity(entries.len());
    for mut entry in entries {
        let regular_file = entry.kind == "regular-file";
        let entry_content = entry
            .content_hex
            .take()
            .map(|value| decode_hex(&value))
            .transpose()
            .map_err(|error| {
                ErrorData::new("vm.artifact_encoding", error.to_string(), "artifact-export")
            })?
            .unwrap_or_default();
        let offset = content.len();
        content.extend_from_slice(&entry_content);
        let mut value = serde_json::to_value(entry).map_err(|error| {
            ErrorData::new("vm.artifact_encoding", error.to_string(), "artifact-export")
        })?;
        if regular_file {
            let object = value.as_object_mut().expect("artifact entry is an object");
            object.insert("contentOffset".into(), json!(offset));
            object.insert("contentLength".into(), json!(entry_content.len()));
        }
        files.push(value);
    }
    Ok((files, content))
}

fn ensure_export_manifest_size(metadata: &Value) -> Result<(), ErrorData> {
    if serde_json::to_vec(metadata)
        .map_err(|error| {
            ErrorData::new("vm.artifact_encoding", error.to_string(), "artifact-export")
        })?
        .len()
        > sandbox_protocol::MAX_CONTROL_PAYLOAD / 2
    {
        return Err(ErrorData::new(
            "vm.artifact_manifest_limit",
            "artifact manifest exceeds the control protocol limit",
            "artifact-export",
        ));
    }
    Ok(())
}

fn send_output(running: &Running, message_type: MessageType, bytes: &[u8]) {
    let stdout = message_type == MessageType::Stdout;
    let mut offset = 0;
    while offset < bytes.len() && running.alive.load(Ordering::Acquire) {
        let maximum = (bytes.len() - offset).min(sandbox_protocol::MAX_STREAM_PAYLOAD);
        let Some(count) = running.credits.reserve(stdout, maximum, &running.alive) else {
            return;
        };
        if running
            .writer
            .binary(message_type, bytes[offset..offset + count].to_vec())
            .is_err()
        {
            return;
        }
        offset += count;
    }
}

type ImportPreparation = (
    Vec<GuestArtifactEntry>,
    Vec<PreparedGrant>,
    Vec<GuestMount>,
    Vec<WorkspaceBase>,
    String,
    u64,
);

fn transfer_imports(
    authority: &VmAuthority,
    mut entries: Vec<GuestArtifactEntry>,
    expected_bytes: u64,
) -> Result<(), ErrorData> {
    const CHUNK_BYTES: usize = 1024 * 1024;
    let mut contents = BTreeMap::new();
    for entry in &mut entries {
        if let Some(content) = entry.content_hex.take() {
            contents.insert(
                entry.path.clone(),
                decode_hex(&content).map_err(|error| {
                    ErrorData::new("vm.import_content", error.to_string(), "prepare")
                })?,
            );
        }
    }
    match authority.request(&GuestRequest::BeginImport {
        entries: entries.clone(),
        max_bytes: expected_bytes.max(1),
    })? {
        GuestResponse::ImportReady { entries: count } if count == entries.len() => {}
        GuestResponse::Error { code, message, .. } => {
            return Err(ErrorData::new(code.as_str(), message, "prepare"));
        }
        _ => {
            return Err(ErrorData::new(
                "vm.import_response",
                "guest returned an invalid import-begin response",
                "prepare",
            ));
        }
    }
    for entry in &entries {
        let Some(content) = contents.get(&entry.path) else {
            continue;
        };
        let mut offset = 0_usize;
        while offset < content.len() {
            let end = offset.saturating_add(CHUNK_BYTES).min(content.len());
            match authority.request(&GuestRequest::ImportChunk {
                path: entry.path.clone(),
                offset: offset as u64,
                content_hex: encode_hex(&content[offset..end]),
            })? {
                GuestResponse::ImportChunkAccepted { path, bytes }
                    if path == entry.path && bytes == (end - offset) as u64 => {}
                GuestResponse::Error { code, message, .. } => {
                    return Err(ErrorData::new(code.as_str(), message, "prepare"));
                }
                _ => {
                    return Err(ErrorData::new(
                        "vm.import_response",
                        "guest returned an invalid import-chunk response",
                        "prepare",
                    ));
                }
            }
            offset = end;
        }
    }
    match authority.request(&GuestRequest::CompleteImport)? {
        GuestResponse::Imported {
            entries: count,
            bytes,
        } if count == entries.len() && bytes == expected_bytes => Ok(()),
        GuestResponse::Error { code, message, .. } => {
            Err(ErrorData::new(code.as_str(), message, "prepare"))
        }
        _ => Err(ErrorData::new(
            "vm.import_response",
            "guest returned an invalid import-complete response",
            "prepare",
        )),
    }
}

fn prepare_imports(policy: &NormalizedPolicy) -> Result<ImportPreparation, ErrorData> {
    let mut entries = vec![GuestArtifactEntry {
        path: "imports".into(),
        kind: "directory".into(),
        mode: 0o700,
        modified_unix_ms: 0,
        content_hex: None,
        link_target: None,
        sha256: None,
    }];
    let mut grants = Vec::new();
    let mut mounts = Vec::new();
    let mut workspace_bases = Vec::new();
    let mut total = 0_u64;
    let maximum = policy.resources.memory_bytes.min(1024 * 1024 * 1024);
    for (index, grant) in policy.grants.iter().enumerate() {
        let requested = Path::new(&grant.requested_host_path);
        if grant.root_resolution == "reject-if-link"
            && fs::symlink_metadata(requested)
                .map_err(|error| os_error("vm.import", &error, "prepare"))?
                .file_type()
                .is_symlink()
        {
            return Err(ErrorData::new(
                "vm.import_link",
                "grant root is a symbolic link",
                "prepare",
            ));
        }
        let resolved = fs::canonicalize(requested)
            .map_err(|error| os_error("vm.import", &error, "prepare"))?;
        let parent = resolved.parent().ok_or_else(|| {
            ErrorData::new(
                "vm.import_root",
                "host filesystem root cannot be imported",
                "prepare",
            )
        })?;
        let name = resolved
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ErrorData::new("vm.import_name", "import root is not UTF-8", "prepare"))?
            .to_owned();
        let remaining = maximum.checked_sub(total).ok_or_else(|| {
            ErrorData::new("vm.import_limit", "import exceeds byte limit", "prepare")
        })?;
        let bundle = collect_artifacts(parent, std::slice::from_ref(&name), remaining)
            .map_err(|error| ErrorData::new("vm.import", error.to_string(), "prepare"))?;
        let source_relative = format!("imports/{index}");
        let mut base_files = Vec::new();
        for entry in bundle.files {
            let suffix = entry
                .path
                .strip_prefix(&name)
                .unwrap_or(&entry.path)
                .trim_start_matches('/');
            let path = if suffix.is_empty() {
                source_relative.clone()
            } else {
                format!("{source_relative}/{suffix}")
            };
            let kind = match entry.kind {
                ArtifactKind::Directory => "directory",
                ArtifactKind::RegularFile => "regular-file",
                ArtifactKind::SymbolicLink => "symbolic-link",
            };
            if !suffix.is_empty() {
                base_files.push(ArtifactEntry {
                    path: suffix.to_owned(),
                    kind: entry.kind,
                    mode: entry.mode,
                    modified_unix_ms: entry.modified_unix_ms,
                    content_hex: None,
                    link_target: entry.link_target.clone(),
                    sha256: entry.sha256.clone(),
                });
            }
            if let Some(content) = &entry.content_hex {
                total = total.saturating_add((content.len() / 2) as u64);
            }
            entries.push(GuestArtifactEntry {
                path,
                kind: kind.into(),
                mode: entry.mode,
                modified_unix_ms: entry.modified_unix_ms,
                content_hex: entry.content_hex,
                link_target: entry.link_target,
                sha256: entry.sha256,
            });
        }
        let identity = identity_digest(&json!({
            "resolvedPath": resolved,
            "artifactDigest": bundle.digest,
        }))
        .map_err(digest_data)?;
        let guest_source = format!("/workspace/{source_relative}");
        grants.push(PreparedGrant {
            requested_host_path: grant.requested_host_path.clone(),
            resolved_host_path: resolved.to_string_lossy().into_owned(),
            host_identity_digest: identity,
            target_path: grant.target_path.clone(),
            access: grant.access.clone(),
            execution: grant.execution.clone(),
            guest_source: guest_source.clone(),
        });
        mounts.push(GuestMount {
            source: guest_source,
            target: grant.target_path.clone(),
            read_only: grant.access == "read",
            executable: grant.execution == "allow",
        });
        if grant.access == "read-write" {
            base_files.sort_by(|left, right| left.path.cmp(&right.path));
            workspace_bases.push(WorkspaceBase {
                target_path: grant.target_path.clone(),
                guest_path: source_relative,
                directory: resolved.is_dir(),
                files: base_files,
            });
        }
    }
    entries.sort_by(|left, right| {
        Path::new(&left.path)
            .components()
            .count()
            .cmp(&Path::new(&right.path).components().count())
            .then_with(|| left.path.cmp(&right.path))
    });
    let digest = identity_digest(&entries).map_err(digest_data)?;
    Ok((entries, grants, mounts, workspace_bases, digest, total))
}

fn enforcement_report(
    policy: &NormalizedPolicy,
    manifest_digest: &str,
    image: &VerifiedImage,
) -> EnforcementReport {
    let guarantees = GUARANTEES
        .iter()
        .map(|id| vm_guarantee(policy, id, image))
        .collect();
    EnforcementReport {
        boundary: EnforcementBoundary {
            kind: "hardware-virtualized".into(),
            backend_id: BACKEND_ID.into(),
            backend_version: env!("CARGO_PKG_VERSION").into(),
            stability: "experimental".into(),
            mechanism: vec![
                "KVM hardware virtualization through pinned Firecracker".into(),
                "verified read-only guest root and authenticated virtio-vsock agent".into(),
                if policy.network == "managed" {
                    "Firecracker has no virtual NIC; authenticated guest-initiated vsock tunnels reach the policy broker".into()
                } else {
                    "Firecracker confined by linux-namespace-v1 without a virtual NIC".into()
                },
            ],
        },
        host: EnforcementHost {
            platform: "linux".into(),
            architecture: std::env::consts::ARCH.into(),
            path_style: "posix".into(),
        },
        target: EnforcementTarget {
            operating_system: "linux".into(),
            path_style: "posix".into(),
        },
        guarantees,
        runtime_view: EnforcementRuntimeView {
            kind: policy.runtime_view.clone(),
            manifest_digest: manifest_digest.into(),
            visible_roots: if policy.runtime_view == "system" {
                let mut roots = vec![
                    "/bin".into(),
                    "/usr".into(),
                    "/lib".into(),
                    "/workspace".into(),
                ];
                if policy.network == "managed" {
                    roots.push("/etc/resolv.conf".into());
                }
                roots
            } else {
                let mut roots = vec!["/workspace".into()];
                if policy.network == "managed" {
                    roots.push("/etc/resolv.conf".into());
                }
                roots
            },
        },
        caveats: {
            let mut caveats = vec![EnforcementCaveat {
                code: "experimental.hardware-vm".into(),
                message: "the Firecracker backend remains experimental until dedicated KVM-host conformance passes".into(),
                affected_guarantees: Vec::new(),
            }];
            if policy.network == "managed" {
                caveats.push(EnforcementCaveat {
                    code: "network.supported-protocols".into(),
                    message: "managed VM egress supports DNS and proxy-aware TCP clients; the guest has no direct network route".into(),
                    affected_guarantees: vec!["network.egress-brokered".into()],
                });
            }
            caveats
        },
        conformance: EnforcementConformance {
            manifest_id: "linux-firecracker-v1-conformance-1".into(),
            build_id: concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).into(),
        },
    }
}

fn vm_guarantee(policy: &NormalizedPolicy, id: &str, image: &VerifiedImage) -> GuaranteeFact {
    let satisfied = match id {
        "runtime.setup-before-exec"
        | "runtime.no-ambient-environment"
        | "runtime.no-ambient-handles"
        | "runtime.executable-identity-bound"
        | "filesystem.grant-roots-identity-bound"
        | "filesystem.read-confined"
        | "filesystem.content-write-confined"
        | "filesystem.namespace-mutation-confined"
        | "filesystem.metadata-mutation-confined"
        | "filesystem.host-user-data-hidden"
        | "process.host-enumeration-denied"
        | "process.host-control-denied"
        | "process.complete-tree-termination"
        | "ipc.host-endpoints-hidden-outside-grants"
        | "ipc.host-shared-memory-hidden"
        | "resource.wall-time-hard"
        | "resource.output-hard"
        | "resource.memory-hard"
        | "resource.cpu-time-hard"
        | "resource.process-count-hard"
        | "resource.open-files-hard"
        | "resource.single-file-size-hard"
        | "vm.boot-artifacts-verified"
        | "vm.guest-control-authenticated"
        | "vm.control-plane-hidden-from-target"
        | "vm.host-filesystem-absent-outside-imports" => true,
        "filesystem.execution-confined" => false,
        "network.no-external-connect"
        | "network.no-external-listen"
        | "network.no-host-loopback" => policy.network != "unrestricted",
        "network.egress-brokered" | "network.private-addresses-denied" => {
            policy.network == "managed"
        }
        _ => false,
    };
    GuaranteeFact {
        id: id.into(),
        status: if satisfied {
            "satisfied"
        } else {
            "unsatisfied"
        }
        .into(),
        enforced_by: if satisfied {
            vec![
                "hypervisor".into(),
                "guest-kernel".into(),
                "guest-agent".into(),
            ]
        } else {
            Vec::new()
        },
        mechanism: match id {
            "vm.boot-artifacts-verified" => vec![format!(
                "SHA-256 verified kernel and {:?} root image",
                image.manifest.rootfs.format
            )],
            "network.no-external-connect"
            | "network.no-external-listen"
            | "network.no-host-loopback" => {
                vec!["Firecracker configuration contains no network interface".into()]
            }
            "network.egress-brokered" | "network.private-addresses-denied" => vec![
                "guest loopback proxies use nonce-authenticated guest-initiated vsock tunnels to the host policy broker; no virtual NIC is attached".into(),
            ],
            "vm.guest-control-authenticated" => {
                vec!["single-use 256-bit nonce on a read-only private block device".into()]
            }
            "vm.control-plane-hidden-from-target" => vec![
                "target mount namespace has no vsock device and seccomp denies AF_VSOCK".into(),
            ],
            _ if satisfied => vec!["verified VM boundary and restricted guest target".into()],
            _ => Vec::new(),
        },
        evidence: if satisfied {
            vec![format!("backend={BACKEND_ID}")]
        } else {
            Vec::new()
        },
        caveats: if id == "filesystem.execution-confined" {
            vec!["noexec controls direct kernel execution but cannot prevent an interpreter from reading code as data".into()]
        } else {
            Vec::new()
        },
    }
}

fn match_requirements(
    policy: &NormalizedPolicy,
    report: &EnforcementReport,
) -> Result<(), ErrorData> {
    let unmet = policy
        .requirements
        .required
        .iter()
        .filter(|required| {
            !report
                .guarantees
                .iter()
                .any(|fact| &fact.id == *required && fact.status == "satisfied")
        })
        .cloned()
        .collect::<Vec<_>>();
    if unmet.is_empty() {
        Ok(())
    } else {
        let mut error = ErrorData::new(
            "requirement.unsatisfied",
            format!("required guarantees are unsatisfied: {}", unmet.join(", ")),
            "prepare",
        );
        error.enforcement = Some(report.clone());
        Err(error)
    }
}

fn run_summary(policy: &PreparedPolicy, execution: &PreparedExecution) -> Value {
    let mut value = session_summary(policy);
    value
        .as_object_mut()
        .expect("object")
        .insert("execution".into(), execution_summary(execution));
    value
}

fn session_summary(policy: &PreparedPolicy) -> Value {
    let Isolation::HardwareVm {
        image,
        filesystem_transport,
    } = &policy.normalized.isolation
    else {
        unreachable!()
    };
    json!({
        "isolation": {"kind": "hardware-vm", "image": image, "filesystemTransport": filesystem_transport},
        "backend": {"id": BACKEND_ID, "version": env!("CARGO_PKG_VERSION"), "stability": "experimental"},
        "filesystem": {
            "runtimeView": policy.normalized.runtime_view,
            "runtimeManifestDigest": policy.manifest_digest,
            "grants": policy.grants,
            "masks": policy.normalized.masks,
            "privateHomePath": if policy.normalized.private_home.enabled { Some("/home/sandbox") } else { None },
            "temporaryPath": "/tmp",
        },
        "network": {"mode": "none", "topology": "no-virtual-nic"},
        "process": policy.normalized.process,
        "resources": policy.normalized.resources,
    })
}

fn process_summary(execution: &PreparedExecution) -> Value {
    json!({
        "resources": execution.normalized.resources,
        "execution": execution_summary(execution)
    })
}

fn execution_summary(execution: &PreparedExecution) -> Value {
    let environment_names = execution
        .normalized
        .environment
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let sensitive_environment_names = execution
        .normalized
        .environment
        .iter()
        .filter(|(_, value)| value.sensitive)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    json!({
        "executable": execution.normalized.executable,
        "executableIdentityDigest": execution.executable_identity_digest,
        "executableContentSha256": execution.executable_sha256,
        "args": execution.normalized.args,
        "cwd": execution.normalized.cwd,
        "cwdIdentityDigest": execution.cwd_identity_digest,
        "environmentNames": environment_names,
        "sensitiveEnvironmentNames": sensitive_environment_names,
        "stdin": execution.normalized.stdin,
        "stdout": execution.normalized.stdout,
        "stderr": execution.normalized.stderr,
    })
}

fn translate_export_path(path: &str, grants: &[PreparedGrant]) -> Result<String, ErrorData> {
    let absolute = format!("/{path}");
    let target = Path::new(&absolute);
    if let Some((index, grant)) = grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| target.starts_with(&grant.target_path))
        .max_by_key(|(_, grant)| Path::new(&grant.target_path).components().count())
    {
        let suffix = target
            .strip_prefix(&grant.target_path)
            .map_err(|_| state_error("invalid artifact mapping"))?;
        return Ok(Path::new("imports")
            .join(index.to_string())
            .join(suffix)
            .to_string_lossy()
            .into_owned());
    }
    target
        .strip_prefix("/workspace")
        .ok()
        .and_then(|path| path.to_str())
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            ErrorData::new(
                "artifact.outside_workspace",
                "artifact path is outside an imported grant or /workspace",
                "artifact-export",
            )
        })
}

fn restore_export_path(path: &str, grants: &[PreparedGrant]) -> String {
    for (index, grant) in grants.iter().enumerate() {
        let prefix = format!("imports/{index}");
        if let Some(suffix) = path.strip_prefix(&prefix) {
            return format!("{}{}", grant.target_path, suffix);
        }
    }
    format!("/workspace/{path}")
}

fn probe() -> Value {
    let executable = std::env::current_exe().ok();
    let native = executable.as_deref().and_then(Path::parent);
    let kvm = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/kvm")
        .is_ok();
    let firecracker = native
        .map(|path| path.join(firecracker_name()))
        .is_some_and(|path| verify_file_digest(&path, firecracker_digest(), "Firecracker").is_ok());
    let workspace = native
        .map(|path| path.join(WORKSPACE_TEMPLATE))
        .is_some_and(|path| {
            verify_file_digest(&path, WORKSPACE_TEMPLATE_SHA256, "workspace template").is_ok()
        });
    let recovery = recover_abandoned_vm_state();
    let recovery_available = recovery.is_ok();
    let recovered_state_directories = recovery.as_ref().copied().unwrap_or_default();
    let recovery_error = recovery.err().map(|error| error.message);
    json!({
        "available": kvm && firecracker && workspace && recovery_available,
        "kvm": kvm,
        "firecrackerVerified": firecracker,
        "workspaceTemplate": workspace,
        "abandonedStateRecovery": recovery_available,
        "recoveredStateDirectories": recovered_state_directories,
        "recoveryError": recovery_error,
        "guestChannel": "virtio-vsock",
        "networkNone": "no-virtual-nic",
        "managedNetwork": "authenticated-vsock-policy-broker",
    })
}

fn validate_image_architecture(image: &VerifiedImage) -> Result<(), ErrorData> {
    let expected = match std::env::consts::ARCH {
        "x86_64" => Architecture::X64,
        "aarch64" => Architecture::Arm64,
        _ => {
            return Err(ErrorData::new(
                "unsupported.vm_architecture",
                "host architecture is unsupported",
                "prepare",
            ));
        }
    };
    if image.manifest.architecture != expected {
        return Err(ErrorData::new(
            "image.architecture",
            "image architecture does not match the host",
            "prepare",
        ));
    }
    Ok(())
}

fn firecracker_name() -> &'static str {
    FIRECRACKER_NAME_X64
}

fn firecracker_digest() -> &'static str {
    FIRECRACKER_SHA256_X64
}

fn verify_file_digest(path: &Path, expected: &str, label: &str) -> Result<(), ErrorData> {
    open_verified_file(path, expected, label).map(drop)
}

fn open_verified_file(path: &Path, expected: &str, label: &str) -> Result<File, ErrorData> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ErrorData::new(
            "vm.artifact_pin",
            format!("{label} is not pinned by this runtime build"),
            "prepare",
        ));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| os_error("vm.artifact", &error, "prepare"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ErrorData::new(
            "vm.artifact_type",
            format!("{label} is not an immutable regular file"),
            "prepare",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| os_error("vm.artifact", &error, "prepare"))?;
    let opened = file
        .metadata()
        .map_err(|error| os_error("vm.artifact", &error, "prepare"))?;
    use std::os::unix::fs::MetadataExt;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(ErrorData::new(
            "vm.artifact_replaced",
            format!("{label} changed while opening"),
            "prepare",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| os_error("vm.artifact", &error, "prepare"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if format!("{:x}", hasher.finalize()) != expected {
        return Err(ErrorData::new(
            "vm.artifact_digest",
            format!("{label} digest mismatch"),
            "prepare",
        ));
    }
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|error| os_error("vm.artifact", &error, "prepare"))?;
    Ok(file)
}

fn snapshot_verified_artifact(
    source_path: &Path,
    expected: &str,
    label: &str,
    destination: &Path,
) -> Result<PathBuf, ErrorData> {
    let mut source = open_verified_file(source_path, expected, label)?;
    let length = source
        .metadata()
        .map_err(|error| os_error("vm.artifact", &error, "prepare"))?
        .len();
    if length == 0 || length > 16 * 1024 * 1024 * 1024 {
        return Err(ErrorData::new(
            "vm.artifact_size",
            format!("{label} has an invalid size"),
            "prepare",
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| os_error("vm.artifact_snapshot", &error, "prepare"))?;
    let copied = io::copy(&mut source, &mut output)
        .map_err(|error| os_error("vm.artifact_snapshot", &error, "prepare"))?;
    output
        .flush()
        .map_err(|error| os_error("vm.artifact_snapshot", &error, "prepare"))?;
    if copied != length {
        return Err(ErrorData::new(
            "vm.artifact_snapshot",
            format!("{label} changed while it was snapshotted"),
            "prepare",
        ));
    }
    drop(output);
    verify_file_digest(destination, expected, label)?;
    Ok(destination.to_path_buf())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VmOwnerRecord {
    format_version: u32,
    launcher_pid: u32,
    owner_token: String,
}

fn create_state_root() -> Result<(PathBuf, File), ErrorData> {
    for _ in 0..100 {
        let path = std::env::temp_dir().join(new_id("vm-state"));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| os_error("vm.state", &error, "prepare"))?;
                let lease = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path.join("owner.lock"))
                    .map_err(|error| os_error("vm.state_lease", &error, "prepare"))?;
                if !try_lock_exclusive(&lease)
                    .map_err(|error| os_error("vm.state_lease", &error, "prepare"))?
                {
                    let _ = fs::remove_dir_all(&path);
                    return Err(ErrorData::new(
                        "vm.state_lease",
                        "new VM state lease is unexpectedly owned",
                        "prepare",
                    ));
                }
                return Ok((path, lease));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(os_error("vm.state", &error, "prepare")),
        }
    }
    Err(ErrorData::new(
        "vm.state",
        "could not allocate unique VM state",
        "prepare",
    ))
}

fn write_vm_owner_record(
    root: &Path,
    launcher_pid: u32,
    owner_token: &str,
) -> Result<(), ErrorData> {
    let record = VmOwnerRecord {
        format_version: 1,
        launcher_pid,
        owner_token: owner_token.into(),
    };
    let bytes = serde_json::to_vec(&record)
        .map_err(|error| ErrorData::new("vm.owner_record", error.to_string(), "prepare"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("owner.json"))
        .map_err(|error| os_error("vm.owner_record", &error, "prepare"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| os_error("vm.owner_record", &error, "prepare"))
}

fn recover_abandoned_vm_state() -> Result<u64, ErrorData> {
    recover_abandoned_vm_state_at(&std::env::temp_dir())
}

fn recover_abandoned_vm_state_at(parent: &Path) -> Result<u64, ErrorData> {
    const MAX_STALE_ROOTS: usize = 1024;
    let mut recovered = 0_u64;
    let mut matching_entries = 0_usize;
    let entries =
        fs::read_dir(parent).map_err(|error| os_error("vm.recovery_scan", &error, "cleanup"))?;
    for entry in entries {
        let entry = entry.map_err(|error| os_error("vm.recovery_scan", &error, "cleanup"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with("vm-state-") {
            continue;
        }
        matching_entries = matching_entries.saturating_add(1);
        if matching_entries > MAX_STALE_ROOTS {
            return Err(ErrorData::new(
                "vm.recovery_limit",
                "VM recovery scan exceeded its bounded state-directory count",
                "cleanup",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| os_error("vm.recovery_scan", &error, "cleanup"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ErrorData::new(
                "vm.recovery_state_type",
                "VM recovery state is not a plain directory",
                "cleanup",
            ));
        }
        let lease = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(entry.path().join("owner.lock"))
        {
            Ok(lease) => lease,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::remove_dir_all(entry.path())
                    .map_err(|failure| os_error("vm.recovery_remove", &failure, "cleanup"))?;
                recovered = recovered.saturating_add(1);
                continue;
            }
            Err(error) => return Err(os_error("vm.recovery_lease", &error, "cleanup")),
        };
        if !try_lock_exclusive(&lease)
            .map_err(|error| os_error("vm.recovery_lease", &error, "cleanup"))?
        {
            continue;
        }
        let owner_path = entry.path().join("owner.json");
        if let Some(owner) = read_vm_owner_record(&owner_path)? {
            if owner.format_version != 1
                || owner.owner_token.len() != 64
                || !owner
                    .owner_token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(ErrorData::new(
                    "vm.recovery_owner",
                    "VM owner record is invalid",
                    "cleanup",
                ));
            }
            if process_has_owner_token(owner.launcher_pid, &owner.owner_token)? {
                kill_process(owner.launcher_pid)
                    .map_err(|error| os_error("vm.recovery_kill", &error, "cleanup"))?;
                let deadline = Instant::now() + Duration::from_secs(2);
                while Path::new(&format!("/proc/{}", owner.launcher_pid)).exists()
                    && Instant::now() < deadline
                {
                    thread::sleep(Duration::from_millis(10));
                }
                if Path::new(&format!("/proc/{}", owner.launcher_pid)).exists() {
                    return Err(ErrorData::new(
                        "vm.recovery_kill",
                        "stale VM launcher termination was not confirmed",
                        "cleanup",
                    ));
                }
            }
        }
        fs::remove_dir_all(entry.path())
            .map_err(|error| os_error("vm.recovery_remove", &error, "cleanup"))?;
        recovered = recovered.saturating_add(1);
        drop(lease);
    }
    Ok(recovered)
}

fn read_vm_owner_record(path: &Path) -> Result<Option<VmOwnerRecord>, ErrorData> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(os_error("vm.recovery_owner", &error, "cleanup")),
    };
    if file
        .metadata()
        .map_err(|error| os_error("vm.recovery_owner", &error, "cleanup"))?
        .len()
        > 4096
    {
        return Err(ErrorData::new(
            "vm.recovery_owner",
            "VM owner record exceeds its bound",
            "cleanup",
        ));
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| os_error("vm.recovery_owner", &error, "cleanup"))?;
    if bytes.len() > 4096 {
        return Err(ErrorData::new(
            "vm.recovery_owner",
            "VM owner record exceeds its bound",
            "cleanup",
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| ErrorData::new("vm.recovery_owner", error.to_string(), "cleanup"))
}

fn process_has_owner_token(pid: u32, token: &str) -> Result<bool, ErrorData> {
    let path = PathBuf::from(format!("/proc/{pid}/environ"));
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(os_error("vm.recovery_process", &error, "cleanup")),
    };
    let expected = format!("SANDBOX_VM_OWNER_TOKEN={token}");
    Ok(bytes
        .split(|byte| *byte == 0)
        .any(|entry| entry == expected.as_bytes()))
}

fn create_authentication_drive(root: &Path) -> Result<(PathBuf, [u8; 32]), ErrorData> {
    let mut nonce = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|error| os_error("vm.random", &error, "prepare"))?;
    let path = root.join("authentication.bin");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| os_error("vm.authentication", &error, "prepare"))?;
    file.write_all(AUTH_MAGIC)
        .and_then(|()| file.write_all(&nonce))
        .and_then(|()| file.set_len(4096))
        .map_err(|error| os_error("vm.authentication", &error, "prepare"))?;
    Ok((path, nonce))
}

fn host_memory() -> Result<u64, ErrorData> {
    let text = fs::read_to_string("/proc/meminfo")
        .map_err(|error| os_error("preparation.host_memory", &error, "prepare"))?;
    let kib = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemTotal:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .ok_or_else(|| {
            ErrorData::new(
                "preparation.host_memory",
                "MemTotal is unavailable",
                "prepare",
            )
        })?;
    kib.checked_mul(1024)
        .ok_or_else(|| ErrorData::new("preparation.host_memory", "host memory overflow", "prepare"))
}

fn cleanup_state(state: &RuntimeState) {
    match state {
        RuntimeState::PreparedRun(run) => {
            let _ = run.policy.authority.cleanup();
        }
        RuntimeState::Session(session) => {
            if session
                .running
                .as_ref()
                .is_some_and(|running| running.alive.load(Ordering::Acquire))
            {
                let _ = session.policy.authority.terminate();
            }
            let _ = session.policy.authority.cleanup();
        }
        RuntimeState::Empty => {}
    }
}

fn next_timeout(state: &RuntimeState) -> Option<Duration> {
    let deadline = match state {
        RuntimeState::PreparedRun(prepared) => Some(prepared.deadline),
        RuntimeState::Session(session) if !session.active => session.deadline,
        RuntimeState::Session(session) => {
            session.prepared.as_ref().map(|prepared| prepared.deadline)
        }
        RuntimeState::Empty => None,
    }?;
    Some(deadline.saturating_duration_since(Instant::now()))
}

fn expire_prepared(writer: &ProtocolWriter, state: &mut RuntimeState) -> bool {
    let now = Instant::now();
    match state {
        RuntimeState::PreparedRun(prepared) if now >= prepared.deadline => {
            let id = prepared.id.clone();
            *state = RuntimeState::Empty;
            let _ = writer.control(
                MessageType::Event,
                &json!({"kind": "preparation-expired", "id": id}),
            );
            true
        }
        RuntimeState::Session(session)
            if !session.active && session.deadline.is_some_and(|deadline| now >= deadline) =>
        {
            let id = session.id.clone();
            *state = RuntimeState::Empty;
            let _ = writer.control(
                MessageType::Event,
                &json!({"kind": "preparation-expired", "id": id}),
            );
            true
        }
        RuntimeState::Session(session)
            if session
                .prepared
                .as_ref()
                .is_some_and(|prepared| now >= prepared.deadline) =>
        {
            if let Some(prepared) = session.prepared.take() {
                let _ = writer.control(
                    MessageType::Event,
                    &json!({"kind": "preparation-expired", "id": prepared.id}),
                );
            }
            false
        }
        _ => false,
    }
}

fn clear_finished(session: &mut Session) {
    if session
        .running
        .as_ref()
        .is_some_and(|running| !running.alive.load(Ordering::Acquire))
    {
        session.running = None;
    }
}

fn session_mut(state: &mut RuntimeState) -> Result<&mut Session, ErrorData> {
    match state {
        RuntimeState::Session(session) => Ok(session),
        _ => Err(state_error("session does not exist")),
    }
}

fn active_session<'a>(state: &'a mut RuntimeState, id: &str) -> Result<&'a mut Session, ErrorData> {
    let session = session_mut(state)?;
    if !session.active || session.id != id {
        return Err(state_error("active session is unavailable"));
    }
    Ok(session)
}

fn running(state: &RuntimeState) -> Result<Arc<Running>, ErrorData> {
    match state {
        RuntimeState::Session(session) => session
            .running
            .clone()
            .ok_or_else(|| state_error("no process is running")),
        _ => Err(state_error("no process is running")),
    }
}

fn ensure_empty(state: &RuntimeState) -> Result<(), ErrorData> {
    if matches!(state, RuntimeState::Empty) {
        Ok(())
    } else {
        Err(state_error("runtime already owns prepared state"))
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_start(
    id: &str,
    policy: &str,
    execution: &str,
    deadline: Instant,
    requested_id: &str,
    requested_policy: &str,
    requested_execution: &str,
) -> Result<(), ErrorData> {
    if Instant::now() >= deadline {
        return Err(expired_error());
    }
    if id != requested_id {
        return Err(state_error("prepared identity does not match"));
    }
    if policy != requested_policy || execution != requested_execution {
        return Err(digest_error());
    }
    Ok(())
}

fn expiration(ttl_ms: u64) -> (Instant, u64) {
    let duration = Duration::from_millis(ttl_ms);
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (
        Instant::now() + duration,
        epoch
            .as_millis()
            .saturating_add(ttl_ms as u128)
            .min(u64::MAX as u128) as u64,
    )
}

fn new_id(prefix: &str) -> String {
    let sequence = IDS.fetch_add(1, Ordering::Relaxed);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{time:032x}-{sequence:016x}")
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn request_id(value: &Value) -> Result<String, ErrorData> {
    value
        .get("requestId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .map(str::to_owned)
        .ok_or_else(|| {
            ErrorData::new(
                "protocol.request_id",
                "requestId is missing or invalid",
                "validate",
            )
        })
}

fn unique(ids: &mut HashSet<String>, id: &str) -> Result<(), ErrorData> {
    if ids.len() >= 65_536 {
        ids.clear();
    }
    if ids.insert(id.into()) {
        Ok(())
    } else {
        Err(ErrorData::new(
            "protocol.duplicate_request",
            "requestId was reused",
            "validate",
        ))
    }
}

fn parse<T: for<'de> serde::Deserialize<'de>>(frame: &Frame) -> Result<T, ErrorData> {
    frame.parse_control().map_err(protocol_error)
}

fn write_guest_frame(
    writer: &mut dyn sandbox_vm::GuestConnection,
    value: &GuestRequest,
) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    if payload.is_empty() || payload.len() > MAX_GUEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest frame exceeds limit",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn read_guest_frame(reader: &mut dyn sandbox_vm::GuestConnection) -> io::Result<GuestResponse> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_GUEST_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid guest frame length",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(io::Error::other)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, io::Error> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hex data",
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
                .and_then(|value| u8::from_str_radix(value, 16).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid hex data"))
        })
        .collect()
}

fn drain_capture(mut reader: impl Read, output: &Mutex<Vec<u8>>) {
    let mut buffer = [0_u8; 4096];
    loop {
        let Ok(count) = reader.read(&mut buffer) else {
            return;
        };
        if count == 0 {
            return;
        }
        if let Ok(mut output) = output.lock() {
            output.extend_from_slice(&buffer[..count]);
            if output.len() > 16 * 1024 {
                let excess = output.len() - 16 * 1024;
                output.drain(..excess);
            }
        }
    }
}

fn signal_name(signal: i32) -> String {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        _ => return format!("SIG{signal}"),
    }
    .into()
}

fn cleanup_failure(code: &str, resource: &str, message: &str) -> Value {
    json!({"code": code, "resource": resource, "message": bounded(message)})
}

fn state_error(message: &str) -> ErrorData {
    ErrorData::new("preparation.state", message, "activate")
}

fn expired_error() -> ErrorData {
    ErrorData::new(
        "preparation_expired.vm",
        "prepared authority expired",
        "activate",
    )
}

fn digest_error() -> ErrorData {
    ErrorData::new("digest_mismatch.vm", "prepared digest mismatch", "activate")
}

fn lock_error() -> ErrorData {
    ErrorData::new("runtime.lock", "runtime lock poisoned", "execute")
}

fn digest_data(error: sandbox_digest::DigestError) -> ErrorData {
    ErrorData::new("preparation.digest", error.to_string(), "prepare")
}

fn protocol_error(error: ProtocolError) -> ErrorData {
    ErrorData::new("protocol.frame", error.to_string(), "validate")
}

fn os_error(code: &str, error: &impl std::fmt::Display, phase: &str) -> ErrorData {
    ErrorData::new(code, bounded(&error.to_string()), phase)
}

fn bounded(value: &str) -> String {
    value.chars().take(4096).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_vm_state_is_recovered_but_a_live_lease_is_preserved() {
        let parent = std::env::temp_dir().join(new_id("vm-recovery-test"));
        fs::create_dir(&parent).expect("create test parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("protect test parent");
        let state = parent.join("vm-state-stale");
        fs::create_dir(&state).expect("create stale state");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state.join("owner.lock"))
            .expect("create owner lease");
        assert!(try_lock_exclusive(&lease).expect("hold owner lease"));
        assert_eq!(
            recover_abandoned_vm_state_at(&parent).expect("scan live state"),
            0
        );
        assert!(state.exists());
        drop(lease);
        assert_eq!(
            recover_abandoned_vm_state_at(&parent).expect("recover stale state"),
            1
        );
        assert!(!state.exists());
        fs::remove_dir(&parent).expect("remove test parent");
    }
}
