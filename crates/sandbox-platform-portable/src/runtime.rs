use sandbox_digest::{execution_digest, identity_digest, policy_digest};
use sandbox_policy::{
    ActivateSessionMessage, EnforcementBoundary, EnforcementCaveat, EnforcementConformance,
    EnforcementHost, EnforcementReport, EnforcementRuntimeView, EnforcementTarget, ErrorData,
    GUARANTEES, GuaranteeFact, IdMessage, NormalizedExecution, NormalizedPolicy,
    PrepareProcessMessage, PrepareRunMessage, PrepareSessionMessage, StartProcessMessage,
    StartRunMessage, TerminateMessage, normalize_process, normalize_run, normalize_session,
};
use sandbox_protocol::{
    Frame, Hello, INITIAL_STREAM_CREDIT, MessageType, PROTOCOL_MAJOR, PROTOCOL_MINOR,
    ProtocolError, StreamCreditMessage, read_frame, write_frame,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BACKEND_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_OUTSTANDING_CREDIT: u64 = 16 * 1024 * 1024;
static IDS: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "windows")]
const BACKEND_ID: &str = sandbox_launcher_windows::BACKEND_ID;
#[cfg(target_os = "macos")]
const BACKEND_ID: &str = sandbox_launcher_macos::BACKEND_ID;

#[cfg(target_os = "windows")]
const CONFORMANCE_ID: &str = "windows-appcontainer-v1-conformance-1";
#[cfg(target_os = "macos")]
const CONFORMANCE_ID: &str = "darwin-seatbelt-v1-conformance-1";

#[cfg(target_os = "windows")]
const HOST_PLATFORM: &str = "win32";
#[cfg(target_os = "macos")]
const HOST_PLATFORM: &str = "darwin";

#[cfg(target_os = "windows")]
const TARGET_OPERATING_SYSTEM: &str = "windows";
#[cfg(target_os = "macos")]
const TARGET_OPERATING_SYSTEM: &str = "macos";

#[derive(Clone)]
struct ProtocolWriter {
    output: Arc<Mutex<io::Stdout>>,
}

impl ProtocolWriter {
    fn control<T: Serialize>(&self, kind: MessageType, value: &T) -> Result<(), ErrorData> {
        let frame = Frame::control(kind, value).map_err(protocol_error)?;
        let mut output = self.output.lock().map_err(|_| lock_error())?;
        write_frame(&mut *output, &frame).map_err(protocol_error)
    }

    fn binary(&self, kind: MessageType, bytes: Vec<u8>) -> Result<(), ErrorData> {
        let frame = Frame::binary(kind, bytes).map_err(protocol_error)?;
        let mut output = self.output.lock().map_err(|_| lock_error())?;
        write_frame(&mut *output, &frame).map_err(protocol_error)
    }

    fn error(&self, request_id: Option<&str>, error: &ErrorData) {
        let _ = self.control(
            MessageType::Error,
            &json!({
                "requestId": request_id,
                "error": error,
            }),
        );
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedGrant {
    requested_host_path: String,
    resolved_host_path: String,
    host_identity_digest: String,
    target_path: String,
    access: String,
    execution: String,
}

struct PreparedPolicy {
    normalized: NormalizedPolicy,
    grants: Vec<PreparedGrant>,
    digest: String,
    manifest_digest: String,
    report: EnforcementReport,
    private_home: PathBuf,
    temporary: PathBuf,
    authority: Arc<Mutex<PlatformAuthority>>,
    held_grants: Vec<File>,
}

struct PreparedExecution {
    normalized: NormalizedExecution,
    executable_content_sha256: String,
    executable_identity_digest: String,
    cwd_identity_digest: String,
    digest: String,
    held_executable: File,
    held_cwd: File,
}

struct PreparedHostObject {
    file: File,
    resolved_path: PathBuf,
    identity_digest: String,
}

struct PreparedRun {
    id: String,
    policy: PreparedPolicy,
    execution: PreparedExecution,
    deadline: Instant,
}

struct PreparedProcess {
    id: String,
    execution: PreparedExecution,
    deadline: Instant,
}

struct Session {
    id: String,
    policy: PreparedPolicy,
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

struct OutputCredits {
    values: Mutex<(u64, u64)>,
    changed: Condvar,
}

impl OutputCredits {
    fn new() -> Self {
        Self {
            values: Mutex::new((0, 0)),
            changed: Condvar::new(),
        }
    }

    fn grant(&self, stream: &str, bytes: u64) -> Result<(), ErrorData> {
        if bytes == 0 {
            return Err(ErrorData::new(
                "protocol.credit",
                "credit must be positive",
                "execute",
            ));
        }
        let mut values = self.values.lock().map_err(|_| lock_error())?;
        let value = match stream {
            "stdout" => &mut values.0,
            "stderr" => &mut values.1,
            _ => {
                return Err(ErrorData::new(
                    "protocol.credit",
                    "invalid credit stream",
                    "execute",
                ));
            }
        };
        *value = value.checked_add(bytes).ok_or_else(|| {
            ErrorData::new("protocol.credit", "output credit overflow", "execute")
        })?;
        if *value > MAX_OUTSTANDING_CREDIT {
            return Err(ErrorData::new(
                "protocol.credit",
                "output credit exceeds limit",
                "execute",
            ));
        }
        self.changed.notify_all();
        Ok(())
    }

    fn take(&self, stream: &str, maximum: usize, alive: &AtomicBool) -> io::Result<usize> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| io::Error::other("credit lock poisoned"))?;
        loop {
            let available = if stream == "stdout" {
                values.0
            } else {
                values.1
            };
            if available > 0 {
                let count = usize::try_from(available.min(maximum as u64)).unwrap_or(maximum);
                if stream == "stdout" {
                    values.0 -= count as u64;
                } else {
                    values.1 -= count as u64;
                }
                return Ok(count);
            }
            if !alive.load(Ordering::Acquire) {
                return Ok(0);
            }
            values = self
                .changed
                .wait(values)
                .map_err(|_| io::Error::other("credit lock poisoned"))?;
        }
    }
}

enum Control {
    Terminate(String),
}

struct Running {
    id: String,
    policy_digest: String,
    execution_digest: String,
    enforcement: EnforcementReport,
    alive: AtomicBool,
    stdin_credit: Mutex<u64>,
    stdin: mpsc::Sender<Option<Vec<u8>>>,
    control: mpsc::Sender<Control>,
    credits: OutputCredits,
    stdout_bytes: AtomicU64,
    stderr_bytes: AtomicU64,
    started: Instant,
}

pub fn runtime_main() {
    #[cfg(target_os = "macos")]
    {
        let mut arguments = std::env::args_os();
        let _ = arguments.next();
        match (arguments.next(), arguments.next()) {
            (Some(mode), None) if mode == std::ffi::OsStr::new("--macos-launcher") => {
                std::process::exit(sandbox_launcher_macos::launcher_main());
            }
            (None, None) => {}
            _ => {
                eprintln!("sandbox portable runtime received unsupported arguments");
                std::process::exit(2);
            }
        }
    }
    if let Err(error) = run() {
        eprintln!(
            "sandbox portable runtime emergency failure: {}",
            bounded(&error.message)
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), ErrorData> {
    #[cfg(target_os = "windows")]
    recover_abandoned_windows_authority()?;
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
                    let _ = input_tx.send(InputEvent::Error(error.to_string()));
                    return;
                }
            }
        }
    });
    let mut hello = false;
    let mut state = RuntimeState::Empty;
    let mut request_ids = HashSet::new();
    loop {
        let timeout = next_timeout(&state).unwrap_or(Duration::from_secs(3600));
        match input_rx.recv_timeout(timeout) {
            Ok(InputEvent::Frame(frame)) => {
                let request_id = request_id(&frame);
                match handle_frame(frame, &writer, &mut hello, &mut state, &mut request_ids) {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Shutdown) => {
                        cleanup_state(&mut state);
                        return Ok(());
                    }
                    Err(error) => writer.error(request_id.as_deref(), &error),
                }
            }
            Ok(InputEvent::Eof) => {
                cleanup_state(&mut state);
                return Ok(());
            }
            Ok(InputEvent::Error(message)) => {
                cleanup_state(&mut state);
                return Err(ErrorData::new("protocol.read", message, "execute"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if expire_prepared(&writer, &mut state) {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                cleanup_state(&mut state);
                return Ok(());
            }
        }
    }
}

enum Flow {
    Continue,
    Shutdown,
}

fn handle_frame(
    frame: Frame,
    writer: &ProtocolWriter,
    hello_complete: &mut bool,
    state: &mut RuntimeState,
    request_ids: &mut HashSet<String>,
) -> Result<Flow, ErrorData> {
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
                "runtimeVersion": BACKEND_VERSION,
                "backendVersions": {BACKEND_ID: BACKEND_VERSION},
            }),
        )?;
        return Ok(Flow::Continue);
    }
    match frame.message_type {
        MessageType::Probe => {
            let value: Value = parse(&frame)?;
            let id = request_id_value(&value)?;
            unique_request(request_ids, &id)?;
            let capability = functional_probe();
            writer.control(
                MessageType::ProbeResult,
                &json!({
                    "requestId": id,
                    "support": {
                        "protocol": {"major": PROTOCOL_MAJOR, "minor": PROTOCOL_MINOR},
                        "packageVersion": BACKEND_VERSION,
                        "host": {"platform": HOST_PLATFORM, "architecture": std::env::consts::ARCH},
                        "backends": [{
                            "id": BACKEND_ID,
                            "isolation": "process",
                            "stability": "experimental",
                            "available": capability.available,
                            "capabilities": capability,
                        }],
                    }
                }),
            )?;
        }
        MessageType::PrepareRun => {
            ensure_empty(state)?;
            let message: PrepareRunMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let (policy, execution) =
                normalize_run(message.options, host_memory()).map_err(|error| *error.0)?;
            let policy = prepare_policy(policy)?;
            let execution = prepare_execution(&policy, execution)?;
            let id = new_id("run");
            let (deadline, expires) = expiration(policy.normalized.prepared_ttl_ms);
            writer.control(
                MessageType::RunPrepared,
                &json!({
                    "requestId": message.request_id,
                    "id": id,
                    "policyDigest": policy.digest,
                    "executionDigest": execution.digest,
                    "summary": run_summary(&policy, &execution),
                    "enforcement": policy.report,
                    "expiresAtMs": expires,
                }),
            )?;
            *state = RuntimeState::PreparedRun(PreparedRun {
                id,
                policy,
                execution,
                deadline,
            });
        }
        MessageType::StartPreparedRun => {
            let message: StartRunMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let prepared = match std::mem::replace(state, RuntimeState::Empty) {
                RuntimeState::PreparedRun(prepared) => prepared,
                other => {
                    *state = other;
                    return Err(ErrorData::new(
                        "preparation.state",
                        "no prepared run exists",
                        "activate",
                    ));
                }
            };
            validate_run(&prepared, &message)?;
            let running =
                start_process(&prepared.policy, &prepared.execution, writer.clone(), true)?;
            *state = RuntimeState::Session(Session {
                id: String::new(),
                policy: prepared.policy,
                deadline: None,
                active: false,
                prepared: None,
                running: Some(Arc::clone(&running)),
            });
            process_started(writer, &message.request_id, &running)?;
            send_stdin_credit(writer)?;
            if prepared.execution.normalized.stdin == "closed" {
                close_stdin(&running)?;
            }
        }
        MessageType::CancelPreparedRun => {
            let message: IdMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            if matches!(state, RuntimeState::PreparedRun(value) if value.id == message.id) {
                *state = RuntimeState::Empty;
            }
            writer.control(
                MessageType::Event,
                &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id}),
            )?;
        }
        MessageType::PrepareSession => {
            ensure_empty(state)?;
            let message: PrepareSessionMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let normalized =
                normalize_session(message.options, host_memory()).map_err(|error| *error.0)?;
            let policy = prepare_policy(normalized)?;
            let id = new_id("session");
            let (deadline, expires) = expiration(policy.normalized.prepared_ttl_ms);
            writer.control(
                MessageType::SessionPrepared,
                &json!({
                    "requestId": message.request_id,
                    "id": id,
                    "policyDigest": policy.digest,
                    "summary": session_summary(&policy),
                    "enforcement": policy.report,
                    "expiresAtMs": expires,
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
        }
        MessageType::ActivateSession => {
            let message: ActivateSessionMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let session = session_mut(state)?;
            if session.active || session.id != message.id {
                return Err(ErrorData::new(
                    "preparation.state",
                    "prepared session unavailable",
                    "activate",
                ));
            }
            if session
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Err(ErrorData::new(
                    "preparation_expired.session",
                    "prepared session expired",
                    "activate",
                ));
            }
            if message.policy_digest != session.policy.digest {
                return Err(ErrorData::new(
                    "digest_mismatch.policy",
                    "policy digest mismatch",
                    "activate",
                ));
            }
            session.active = true;
            session.deadline = None;
            writer.control(
                MessageType::SessionActive,
                &json!({
                    "requestId": message.request_id,
                    "id": session.id,
                    "policyDigest": session.policy.digest,
                    "enforcement": session.policy.report,
                }),
            )?;
        }
        MessageType::CancelPreparedSession => {
            let message: IdMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            if matches!(state, RuntimeState::Session(value) if !value.active && value.id == message.id)
            {
                *state = RuntimeState::Empty;
            }
            writer.control(
                MessageType::Event,
                &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id}),
            )?;
        }
        MessageType::PrepareProcess => {
            let message: PrepareProcessMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let session = active_session(state, &message.session_id)?;
            clear_finished(session);
            if session.running.is_some() || session.prepared.is_some() {
                return Err(ErrorData::new(
                    "preparation.busy",
                    "session already has a process",
                    "prepare",
                ));
            }
            let normalized =
                normalize_process(message.process, &session.policy.normalized.resources)
                    .map_err(|error| *error.0)?;
            let execution = prepare_execution(&session.policy, normalized)?;
            let id = new_id("process");
            let (deadline, expires) = expiration(session.policy.normalized.prepared_ttl_ms);
            writer.control(
                MessageType::ProcessPrepared,
                &json!({
                    "requestId": message.request_id,
                    "id": id,
                    "policyDigest": session.policy.digest,
                    "executionDigest": execution.digest,
                    "summary": process_summary(&execution),
                    "expiresAtMs": expires,
                }),
            )?;
            session.prepared = Some(PreparedProcess {
                id,
                execution,
                deadline,
            });
        }
        MessageType::StartPreparedProcess => {
            let message: StartProcessMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let session = session_mut(state)?;
            clear_finished(session);
            if !session.active || session.running.is_some() {
                return Err(ErrorData::new(
                    "preparation.state",
                    "session is not ready",
                    "activate",
                ));
            }
            let prepared = session.prepared.take().ok_or_else(|| {
                ErrorData::new(
                    "preparation.state",
                    "no prepared process exists",
                    "activate",
                )
            })?;
            validate_process(&session.policy, &prepared, &message)?;
            let running =
                start_process(&session.policy, &prepared.execution, writer.clone(), false)?;
            session.running = Some(Arc::clone(&running));
            process_started(writer, &message.request_id, &running)?;
            send_stdin_credit(writer)?;
            if prepared.execution.normalized.stdin == "closed" {
                close_stdin(&running)?;
            }
        }
        MessageType::CancelPreparedProcess => {
            let message: IdMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            if let Ok(session) = session_mut(state)
                && session
                    .prepared
                    .as_ref()
                    .is_some_and(|value| value.id == message.id)
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
            let length = frame.payload.len() as u64;
            let mut credit = running.stdin_credit.lock().map_err(|_| lock_error())?;
            if length > *credit {
                return Err(ErrorData::new(
                    "protocol.credit_exceeded",
                    "stdin credit exceeded",
                    "execute",
                ));
            }
            *credit -= length;
            drop(credit);
            running.stdin.send(Some(frame.payload)).map_err(|_| {
                ErrorData::new(
                    "runtime.stdin_backpressure",
                    "stdin queue is full or closed",
                    "execute",
                )
            })?;
        }
        MessageType::CloseStdin => {
            let message: IdMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let running = running(state)?;
            if running.id != message.id {
                return Err(ErrorData::new(
                    "protocol.process_id",
                    "stdin process id mismatch",
                    "execute",
                ));
            }
            close_stdin(running)?;
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
        MessageType::Terminate => {
            let message: TerminateMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let running = running(state)?;
            if running.id != message.id {
                return Err(ErrorData::new(
                    "protocol.process_id",
                    "termination process id mismatch",
                    "terminate",
                ));
            }
            running
                .control
                .send(Control::Terminate(message.reason.clone()))
                .map_err(|_| {
                    ErrorData::new(
                        "termination.channel",
                        "process control channel closed",
                        "terminate",
                    )
                })?;
            writer.control(MessageType::Event, &json!({"requestId": message.request_id, "kind": "termination-started", "reason": message.reason}))?;
        }
        MessageType::CloseSession => {
            let message: IdMessage = parse(&frame)?;
            unique_request(request_ids, &message.request_id)?;
            let mut failures = Vec::new();
            if let RuntimeState::Session(session) = state {
                if !session.id.is_empty() && session.id != message.id {
                    return Err(ErrorData::new(
                        "protocol.session_id",
                        "session id mismatch",
                        "cleanup",
                    ));
                }
                terminate_and_wait(session.running.as_ref());
                if session
                    .running
                    .as_ref()
                    .is_some_and(|running| running.alive.load(Ordering::Acquire))
                {
                    failures.push(cleanup_failure(
                        "cleanup.tree_unconfirmed",
                        "target-process-tree",
                        "target process-tree death was not confirmed",
                    ));
                }
                failures.extend(cleanup_authority(&session.policy.authority));
            }
            *state = RuntimeState::Empty;
            let completed = failures.is_empty();
            writer.control(
                MessageType::SessionClosed,
                &json!({
                    "requestId": message.request_id,
                    "id": message.id,
                    "cleanup": {"completed": completed, "failures": failures},
                }),
            )?;
        }
        MessageType::Shutdown => {
            let value: Value = parse(&frame)?;
            let id = request_id_value(&value)?;
            unique_request(request_ids, &id)?;
            cleanup_state(state);
            writer.control(
                MessageType::RuntimeMetrics,
                &json!({"requestId": id, "shutdown": true}),
            )?;
            return Ok(Flow::Shutdown);
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
                "message is invalid in this direction",
                "validate",
            ));
        }
    }
    Ok(Flow::Continue)
}

fn prepare_policy(normalized: NormalizedPolicy) -> Result<PreparedPolicy, ErrorData> {
    if !normalized.requirements.allow_experimental_backend {
        return Err(ErrorData::new(
            "requirement.experimental_backend",
            format!("{BACKEND_ID} requires explicit experimental-backend permission"),
            "prepare",
        ));
    }
    #[cfg(target_os = "windows")]
    if normalized.network != "none" {
        return Err(ErrorData::new(
            "unsupported.network",
            "windows-appcontainer-v1 supports only network none",
            "prepare",
        ));
    }
    #[cfg(target_os = "macos")]
    if normalized.network == "managed" {
        return Err(ErrorData::new(
            "unsupported.network",
            "darwin-seatbelt-v1 does not provide managed networking",
            "prepare",
        ));
    }
    #[cfg(target_os = "windows")]
    if !normalized.masks.is_empty() {
        return Err(ErrorData::new(
            "unsupported.filesystem_masks",
            "windows-appcontainer-v1 does not yet provide mask replacement semantics",
            "prepare",
        ));
    }
    let state_root = create_state_root()?;
    let private_home = state_root.join("home");
    let temporary = state_root.join("tmp");
    fs::create_dir(&private_home)
        .map_err(|error| os_error("preparation.private_home", &error, "prepare"))?;
    fs::create_dir(&temporary)
        .map_err(|error| os_error("preparation.temporary", &error, "prepare"))?;
    let mut authority =
        PlatformAuthority::create(&state_root, &normalized, &private_home, &temporary)?;
    let mut grants = Vec::with_capacity(normalized.grants.len());
    let mut held_grants = Vec::with_capacity(normalized.grants.len());
    let preparation = (|| {
        for grant in &normalized.grants {
            if grant.root_resolution == "reject-if-link"
                && final_component_is_link(Path::new(&grant.requested_host_path))?
            {
                return Err(ErrorData::new(
                    "preparation.grant_link",
                    "grant root is a symbolic link or reparse point",
                    "prepare",
                ));
            }
            let prepared = prepare_host_object(Path::new(&grant.requested_host_path))?;
            let resolved = &prepared.resolved_path;
            if !same_path(Path::new(&grant.target_path), resolved) {
                return Err(ErrorData::new(
                    "unsupported.path_remapping",
                    format!("{BACKEND_ID} requires targetPath to equal the resolved host path"),
                    "prepare",
                ));
            }
            #[cfg(target_os = "windows")]
            if grant.access == "read-write" {
                validate_windows_writable_grant(resolved)?;
            }
            authority.grant(
                resolved,
                grant.access == "read-write",
                grant.execution == "allow",
            )?;
            grants.push(PreparedGrant {
                requested_host_path: grant.requested_host_path.clone(),
                resolved_host_path: resolved.to_string_lossy().into_owned(),
                host_identity_digest: prepared.identity_digest,
                target_path: grant.target_path.clone(),
                access: grant.access.clone(),
                execution: grant.execution.clone(),
            });
            held_grants.push(prepared.file);
        }
        Ok(())
    })();
    if let Err(error) = preparation {
        let _ = authority.cleanup();
        return Err(error);
    }
    let authority = Arc::new(Mutex::new(authority));
    let visible_roots = runtime_roots(&normalized);
    let manifest_digest = identity_digest(&json!({
        "backend": BACKEND_ID,
        "runtimeView": normalized.runtime_view,
        "visibleRoots": visible_roots,
    }))
    .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    let report = enforcement_report(&normalized, &manifest_digest, &visible_roots);
    match_requirements(&normalized, &report)?;
    let digest = policy_digest(&json!({
        "digestFormat": 1,
        "protocolMajor": PROTOCOL_MAJOR,
        "backend": {"id": BACKEND_ID, "version": BACKEND_VERSION, "stability": "experimental"},
        "targetOperatingSystem": TARGET_OPERATING_SYSTEM,
        "policy": normalized,
        "runtimeManifestDigest": manifest_digest,
        "grants": grants,
    }))
    .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    Ok(PreparedPolicy {
        normalized,
        grants,
        digest,
        manifest_digest,
        report,
        private_home,
        temporary,
        authority,
        held_grants,
    })
}

fn prepare_execution(
    policy: &PreparedPolicy,
    normalized: NormalizedExecution,
) -> Result<PreparedExecution, ErrorData> {
    if normalized.change_set.is_some() {
        return Err(ErrorData::new(
            "unsupported.change_set",
            "workspace change sets require hardware-vm import mode",
            "prepare",
        ));
    }
    let executable = prepare_host_object(Path::new(&normalized.executable))?;
    let cwd = prepare_host_object(Path::new(&normalized.cwd))?;
    if !cwd
        .file
        .metadata()
        .map_err(|error| os_error("preparation.cwd", &error, "prepare"))?
        .is_dir()
        || !executable
            .file
            .metadata()
            .map_err(|error| os_error("preparation.executable", &error, "prepare"))?
            .is_file()
    {
        return Err(ErrorData::new(
            "preparation.execution_type",
            "executable must be a file and cwd must be a directory",
            "prepare",
        ));
    }
    if !same_path(Path::new(&normalized.executable), &executable.resolved_path)
        || !same_path(Path::new(&normalized.cwd), &cwd.resolved_path)
    {
        return Err(ErrorData::new(
            "unsupported.path_identity",
            format!("{BACKEND_ID} requires executable and cwd to be canonical paths"),
            "prepare",
        ));
    }
    if !path_visible(policy, &executable.resolved_path, true)
        || !path_visible(policy, &cwd.resolved_path, false)
    {
        return Err(ErrorData::new(
            "policy.execution_visibility",
            "executable or cwd is outside the prepared runtime view",
            "prepare",
        ));
    }
    let executable_identity_digest = executable.identity_digest.clone();
    let cwd_identity_digest = cwd.identity_digest.clone();
    let executable_content_sha256 = hash_file(&executable.file)?;
    let digest = execution_digest(&json!({
        "policyDigest": policy.digest,
        "executable": normalized.executable,
        "executableIdentity": executable_identity_digest,
        "executableContentSha256": executable_content_sha256,
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
    .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))?;
    Ok(PreparedExecution {
        normalized,
        executable_content_sha256,
        executable_identity_digest,
        cwd_identity_digest,
        digest,
        held_executable: executable.file,
        held_cwd: cwd.file,
    })
}

fn enforcement_report(
    policy: &NormalizedPolicy,
    manifest_digest: &str,
    visible_roots: &[String],
) -> EnforcementReport {
    let guarantees = GUARANTEES.iter().map(|id| guarantee(policy, id)).collect();
    let mut caveats = vec![EnforcementCaveat {
        code: "experimental.compatibility-boundary".into(),
        message: format!(
            "{BACKEND_ID} is experimental and must not be treated as a Linux namespace-equivalent boundary"
        ),
        affected_guarantees: vec![
            "process.host-enumeration-denied".into(),
            "ipc.host-endpoints-hidden-outside-grants".into(),
        ],
    }];
    #[cfg(target_os = "windows")]
    caveats.push(EnforcementCaveat {
        code: "windows.path-identity".into(),
        message: "Handle-based canonicalization and content verification detect changes before launch, but ACLs and path-based CreateProcess leave a final path-resolution race; object-identity guarantees remain unsatisfied".into(),
        affected_guarantees: vec![
            "filesystem.grant-roots-identity-bound".into(),
            "runtime.executable-identity-bound".into(),
            "filesystem.read-confined".into(),
            "filesystem.metadata-mutation-confined".into(),
        ],
    });
    #[cfg(target_os = "macos")]
    caveats.push(EnforcementCaveat {
        code: "macos.path-identity".into(),
        message: "Seatbelt grants and target exec are path-based; retained descriptors and pre-launch hashes detect changes but do not preserve the approved object through exec".into(),
        affected_guarantees: vec![
            "filesystem.grant-roots-identity-bound".into(),
            "runtime.executable-identity-bound".into(),
            "filesystem.execution-confined".into(),
        ],
    });
    #[cfg(target_os = "macos")]
    caveats.push(EnforcementCaveat {
        code: "macos.process-namespace".into(),
        message: "Seatbelt provides no PID namespace: unrelated process visibility and same-user signalling are not claimed, and cleanup owns a process group rather than an unescapable kernel job".into(),
        affected_guarantees: vec![
            "process.host-enumeration-denied".into(),
            "process.host-control-denied".into(),
            "process.complete-tree-termination".into(),
        ],
    });
    #[cfg(target_os = "macos")]
    caveats.push(EnforcementCaveat {
        code: "macos.mach-bootstrap-services".into(),
        message: "The compatibility profile permits only the documented runtime Mach lookups, but macOS supplies no private bootstrap namespace and the backend does not claim host IPC endpoint isolation".into(),
        affected_guarantees: vec![
            "ipc.host-endpoints-hidden-outside-grants".into(),
            "ipc.host-shared-memory-hidden".into(),
        ],
    });
    #[cfg(target_os = "macos")]
    caveats.push(EnforcementCaveat {
        code: "macos.desktop-services".into(),
        message: "Pasteboard and GUI services are not granted by the generated profile; this is a compatibility policy, not a private desktop or login session".into(),
        affected_guarantees: vec!["ipc.host-endpoints-hidden-outside-grants".into()],
    });
    #[cfg(target_os = "macos")]
    caveats.push(EnforcementCaveat {
        code: "macos.local-sockets".into(),
        message: "network none denies local sockets with all other networking; unrestricted mode exposes host-local and Unix-socket endpoints, so host IPC isolation remains unsatisfied in either compatibility mode".into(),
        affected_guarantees: vec!["ipc.host-endpoints-hidden-outside-grants".into()],
    });
    #[cfg(target_os = "macos")]
    caveats.push(EnforcementCaveat {
        code: "macos.process-limit-scope".into(),
        message: "RLIMIT_NPROC is scoped to the host user rather than the target tree and is not reported as a hard target-tree process limit".into(),
        affected_guarantees: vec![
            "resource.process-count-hard".into(),
        ],
    });
    EnforcementReport {
        boundary: EnforcementBoundary {
            kind: "os-process".into(),
            backend_id: BACKEND_ID.into(),
            backend_version: BACKEND_VERSION.into(),
            stability: "experimental".into(),
            mechanism: mechanisms(),
        },
        host: EnforcementHost {
            platform: HOST_PLATFORM.into(),
            architecture: std::env::consts::ARCH.into(),
            path_style: if cfg!(target_os = "windows") {
                "windows"
            } else {
                "posix"
            }
            .into(),
        },
        target: EnforcementTarget {
            operating_system: TARGET_OPERATING_SYSTEM.into(),
            path_style: if cfg!(target_os = "windows") {
                "windows"
            } else {
                "posix"
            }
            .into(),
        },
        guarantees,
        runtime_view: EnforcementRuntimeView {
            kind: policy.runtime_view.clone(),
            manifest_digest: manifest_digest.into(),
            visible_roots: visible_roots.to_vec(),
        },
        caveats,
        conformance: EnforcementConformance {
            manifest_id: CONFORMANCE_ID.into(),
            build_id: format!("sandbox-platform-portable-{BACKEND_VERSION}"),
        },
    }
}

fn guarantee(policy: &NormalizedPolicy, id: &str) -> GuaranteeFact {
    let network_none = policy.network == "none";
    let status = match id {
        "runtime.setup-before-exec"
        | "runtime.no-ambient-environment"
        | "runtime.no-ambient-handles"
        | "filesystem.content-write-confined"
        | "filesystem.namespace-mutation-confined"
        | "filesystem.host-user-data-hidden"
        | "resource.wall-time-hard"
        | "resource.output-hard" => true,
        "filesystem.read-confined" => cfg!(target_os = "macos"),
        "resource.single-file-size-hard" => cfg!(target_os = "macos"),
        "network.no-external-connect"
        | "network.no-external-listen"
        | "network.no-host-loopback" => network_none,
        "process.complete-tree-termination" => cfg!(target_os = "windows"),
        "resource.memory-hard" | "resource.process-count-hard" => cfg!(target_os = "windows"),
        "resource.cpu-time-hard" | "resource.open-files-hard" => cfg!(target_os = "macos"),
        _ => false,
    };
    GuaranteeFact {
        id: id.into(),
        status: if status { "satisfied" } else { "unsatisfied" }.into(),
        enforced_by: if status {
            vec!["kernel".into(), "supervisor".into()]
        } else {
            Vec::new()
        },
        mechanism: if status { mechanisms() } else { Vec::new() },
        evidence: Vec::new(),
        caveats: Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn mechanisms() -> Vec<String> {
    vec![
        "per-session AppContainer profile with zero network capabilities".into(),
        "STARTUPINFOEX security capabilities and exact handle list".into(),
        "suspended CreateProcess followed by Job Object assignment".into(),
        "journaled per-session ACL entries".into(),
    ]
}

#[cfg(target_os = "macos")]
fn mechanisms() -> Vec<String> {
    vec![
        "direct sandbox_init with generated deny-default Seatbelt profile".into(),
        "private home and temporary directories".into(),
        "parent-lifeline guardian, process-group supervision, and rlimits".into(),
    ]
}

fn match_requirements(
    policy: &NormalizedPolicy,
    report: &EnforcementReport,
) -> Result<(), ErrorData> {
    for required in &policy.requirements.required {
        if !report
            .guarantees
            .iter()
            .any(|fact| fact.id == *required && fact.status == "satisfied")
        {
            let mut error = ErrorData::new(
                "requirement.unsatisfied",
                format!("required guarantee {required} is unsatisfied"),
                "prepare",
            );
            error.enforcement = Some(report.clone());
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
struct PlatformAuthority {
    session: Option<sandbox_launcher_windows::Session>,
    state_root: Option<PathBuf>,
}

#[cfg(target_os = "windows")]
impl PlatformAuthority {
    fn create(
        state_root: &Path,
        _policy: &NormalizedPolicy,
        private_home: &Path,
        temporary: &Path,
    ) -> Result<Self, ErrorData> {
        let parent = state_root.parent().ok_or_else(|| {
            ErrorData::new("preparation.state", "state root has no parent", "prepare")
        })?;
        // The AppContainer session owns a separate sibling state directory. The portable state
        // root remains the recovery anchor for this runtime invocation.
        let mut session = sandbox_launcher_windows::Session::create(parent)
            .map_err(|error| os_error("preparation.appcontainer", &error, "prepare"))?;
        session
            .grant(
                private_home,
                sandbox_launcher_windows::GrantAccess::ReadWrite,
            )
            .map_err(|error| os_error("preparation.private_home_acl", &error, "prepare"))?;
        session
            .grant(temporary, sandbox_launcher_windows::GrantAccess::ReadWrite)
            .map_err(|error| os_error("preparation.temporary_acl", &error, "prepare"))?;
        Ok(Self {
            session: Some(session),
            state_root: Some(state_root.to_path_buf()),
        })
    }

    fn grant(&mut self, path: &Path, writable: bool, executable: bool) -> Result<(), ErrorData> {
        let access = match (writable, executable) {
            (false, false) => sandbox_launcher_windows::GrantAccess::Read,
            (true, false) => sandbox_launcher_windows::GrantAccess::ReadWrite,
            (false, true) => sandbox_launcher_windows::GrantAccess::ReadExecute,
            (true, true) => sandbox_launcher_windows::GrantAccess::ReadWriteExecute,
        };
        self.session
            .as_mut()
            .ok_or_else(|| {
                ErrorData::new(
                    "preparation.authority",
                    "AppContainer session was cleaned",
                    "prepare",
                )
            })?
            .grant(path, access)
            .map_err(|error| os_error("preparation.grant_acl", &error, "prepare"))
    }

    fn cleanup(&mut self) -> Vec<Value> {
        let Some(session) = self.session.take() else {
            return Vec::new();
        };
        let mut failures = session
            .cleanup()
            .failures
            .into_iter()
            .map(|message| {
                cleanup_failure(
                    "cleanup.windows_authority",
                    "appcontainer-and-acl",
                    &message,
                )
            })
            .collect::<Vec<_>>();
        if let Some(path) = self.state_root.take()
            && let Err(error) = fs::remove_dir_all(&path)
            && error.kind() != io::ErrorKind::NotFound
        {
            failures.push(cleanup_failure(
                "cleanup.state",
                "state-directory",
                &error.to_string(),
            ));
        }
        failures
    }
}

#[cfg(target_os = "macos")]
struct PlatformAuthority {
    state_root: Option<PathBuf>,
}

#[cfg(target_os = "macos")]
impl PlatformAuthority {
    fn create(
        state_root: &Path,
        _policy: &NormalizedPolicy,
        _private_home: &Path,
        _temporary: &Path,
    ) -> Result<Self, ErrorData> {
        Ok(Self {
            state_root: Some(state_root.to_path_buf()),
        })
    }

    fn grant(&mut self, _path: &Path, _writable: bool, _executable: bool) -> Result<(), ErrorData> {
        Ok(())
    }

    fn cleanup(&mut self) -> Vec<Value> {
        let Some(path) = self.state_root.take() else {
            return Vec::new();
        };
        match fs::remove_dir_all(&path) {
            Ok(()) => Vec::new(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => vec![cleanup_failure(
                "cleanup.state",
                "state-directory",
                &error.to_string(),
            )],
        }
    }
}

impl Drop for PreparedPolicy {
    fn drop(&mut self) {
        cleanup_authority(&self.authority);
    }
}

impl Drop for PlatformAuthority {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn cleanup_authority(authority: &Arc<Mutex<PlatformAuthority>>) -> Vec<Value> {
    authority
        .lock()
        .map(|mut value| value.cleanup())
        .unwrap_or_else(|_| {
            vec![cleanup_failure(
                "cleanup.lock",
                "platform-authority",
                "authority lock poisoned",
            )]
        })
}

fn session_summary(policy: &PreparedPolicy) -> Value {
    json!({
        "isolation": {"kind": "process"},
        "backend": {"id": BACKEND_ID, "version": BACKEND_VERSION, "stability": "experimental"},
        "filesystem": {
            "runtimeView": policy.normalized.runtime_view,
            "runtimeManifestDigest": policy.manifest_digest,
            "grants": policy.grants,
            "masks": policy.normalized.masks,
            "privateHomePath": if policy.normalized.private_home.enabled {
                Value::String(policy.private_home.to_string_lossy().into_owned())
            } else {
                Value::Null
            },
            "temporaryPath": policy.temporary.to_string_lossy(),
        },
        "network": match policy.normalized.network.as_str() {
            "none" => json!({"mode": "none", "topology": "private-namespace"}),
            "unrestricted" => json!({"mode": "unrestricted", "topology": "host-network-namespace"}),
            _ => json!({"mode": "managed", "topology": "private-namespace-broker", "allow": policy.normalized.managed_network_rules}),
        },
        "process": {"hostProcesses": "deny", "hostIpc": "deny"},
        "resources": policy.normalized.resources,
    })
}

fn run_summary(policy: &PreparedPolicy, execution: &PreparedExecution) -> Value {
    let mut summary = session_summary(policy);
    if let Value::Object(object) = &mut summary {
        object.insert("execution".into(), execution_value(execution));
    }
    summary
}

fn process_summary(execution: &PreparedExecution) -> Value {
    json!({
        "resources": execution.normalized.resources,
        "execution": execution_value(execution),
    })
}

fn execution_value(execution: &PreparedExecution) -> Value {
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
        "executableContentSha256": execution.executable_content_sha256,
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

fn runtime_roots(policy: &NormalizedPolicy) -> Vec<String> {
    if policy.runtime_view == "empty" {
        return Vec::new();
    }
    #[cfg(target_os = "windows")]
    {
        vec![
            "%SystemRoot%\\System32".into(),
            "%SystemRoot%\\SysWOW64".into(),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            "/System".into(),
            "/usr/bin".into(),
            "/usr/lib".into(),
            "/bin".into(),
            "/sbin".into(),
            "/Library/Apple".into(),
            "/private/etc".into(),
        ]
    }
}

fn path_visible(policy: &PreparedPolicy, path: &Path, executable: bool) -> bool {
    if policy.grants.iter().any(|grant| {
        path_within(Path::new(&grant.resolved_host_path), path)
            && (!executable || grant.execution == "allow")
    }) {
        return true;
    }
    if policy.normalized.runtime_view != "system" {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .is_some_and(|root| {
                path_within(&root.join("System32"), path)
                    || path_within(&root.join("SysWOW64"), path)
            })
    }
    #[cfg(target_os = "macos")]
    {
        [
            "/System",
            "/usr/bin",
            "/usr/lib",
            "/bin",
            "/sbin",
            "/Library/Apple",
            "/private/etc",
        ]
        .iter()
        .any(|root| path_within(Path::new(root), path))
    }
}

fn path_within(parent: &Path, child: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let parent = windows_path_key(parent);
        let child = windows_path_key(child);
        child == parent
            || if parent.ends_with('\\') {
                child.starts_with(&parent)
            } else {
                child
                    .strip_prefix(&parent)
                    .is_some_and(|remainder| remainder.starts_with('\\'))
            }
    }
    #[cfg(target_os = "macos")]
    {
        parent == child || child.strip_prefix(parent).is_ok()
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        windows_path_key(left) == windows_path_key(right)
    }
    #[cfg(target_os = "macos")]
    {
        left == right
    }
}

#[cfg(target_os = "windows")]
fn windows_path_key(path: &Path) -> String {
    let replaced = path.to_string_lossy().replace('/', "\\");
    let ordinary = replaced
        .strip_prefix(r"\\?\UNC\")
        .map(|suffix| format!(r"\\{suffix}"))
        .or_else(|| replaced.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or(replaced);
    ordinary.to_uppercase()
}

fn prepare_host_object(path: &Path) -> Result<PreparedHostObject, ErrorData> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| os_error("preparation.canonicalize", &error, "prepare"))?;
    #[cfg(target_os = "windows")]
    let file = {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&canonical)
            .map_err(|error| os_error("preparation.open", &error, "prepare"))?
    };
    #[cfg(target_os = "macos")]
    let file =
        File::open(&canonical).map_err(|error| os_error("preparation.open", &error, "prepare"))?;
    #[cfg(target_os = "windows")]
    let resolved_path = final_path_from_handle(&file)?;
    #[cfg(target_os = "macos")]
    let resolved_path = canonical;
    let identity_digest = file_identity_digest(&file)?;
    Ok(PreparedHostObject {
        file,
        resolved_path,
        identity_digest,
    })
}

fn final_component_is_link(path: &Path) -> Result<bool, ErrorData> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| os_error("preparation.link", &error, "prepare"))?;
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        Ok(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(metadata.file_type().is_symlink())
    }
}

#[cfg(target_os = "windows")]
fn validate_windows_writable_grant(root: &Path) -> Result<(), ErrorData> {
    use std::collections::BTreeSet;
    use std::mem::zeroed;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
    };

    const MAX_ENTRIES: usize = 100_000;
    const MAX_DEPTH: usize = 256;
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut observed = 0_usize;
    while let Some((path, depth)) = pending.pop() {
        observed = observed.saturating_add(1);
        if observed > MAX_ENTRIES || depth > MAX_DEPTH {
            return Err(ErrorData::new(
                "preparation.writable_grant_complexity",
                "writable Windows grant exceeds the bounded validation tree",
                "prepare",
            ));
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| os_error("preparation.writable_grant", &error, "prepare"))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ErrorData::new(
                "preparation.writable_grant_reparse",
                "writable Windows grants cannot contain reparse points or junctions",
                "prepare",
            ));
        }
        if metadata.is_dir() {
            let mut names = BTreeSet::new();
            for entry in fs::read_dir(&path)
                .map_err(|error| os_error("preparation.writable_grant", &error, "prepare"))?
            {
                let entry = entry
                    .map_err(|error| os_error("preparation.writable_grant", &error, "prepare"))?;
                let name = entry.file_name().to_string_lossy().to_uppercase();
                if !names.insert(name) {
                    return Err(ErrorData::new(
                        "preparation.writable_grant_case_collision",
                        "writable Windows grant contains a case-insensitive name collision",
                        "prepare",
                    ));
                }
                pending.push((entry.path(), depth + 1));
            }
            continue;
        }
        if !metadata.is_file() {
            return Err(ErrorData::new(
                "preparation.writable_grant_type",
                "writable Windows grant contains an unsupported filesystem object",
                "prepare",
            ));
        }
        let file = File::open(&path)
            .map_err(|error| os_error("preparation.writable_grant", &error, "prepare"))?;
        // SAFETY: the structure is plain output data and the file owns a live handle.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        // SAFETY: the output pointer is writable for the exact ABI structure size.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(os_error(
                "preparation.writable_grant",
                &io::Error::last_os_error(),
                "prepare",
            ));
        }
        if information.nNumberOfLinks > 1 {
            return Err(ErrorData::new(
                "preparation.writable_grant_hardlink",
                "writable Windows grants cannot contain multiply-linked files",
                "prepare",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn final_path_from_handle(file: &File) -> Result<PathBuf, ErrorData> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_DOS};

    let handle = file.as_raw_handle();
    // SAFETY: the file owns a live handle and a null buffer with length zero requests the size.
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, VOLUME_NAME_DOS) };
    if required == 0 {
        return Err(os_error(
            "preparation.final_path",
            &io::Error::last_os_error(),
            "prepare",
        ));
    }
    let mut buffer = vec![0_u16; required as usize + 1];
    // SAFETY: `buffer` is writable for the advertised length and the handle remains live.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).unwrap_or(u32::MAX),
            VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(os_error(
            "preparation.final_path",
            &io::Error::last_os_error(),
            "prepare",
        ));
    }
    let value = String::from_utf16_lossy(&buffer[..written as usize]);
    let ordinary = value
        .strip_prefix(r"\\?\UNC\")
        .map(|suffix| format!(r"\\{suffix}"))
        .or_else(|| value.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or(value);
    Ok(PathBuf::from(ordinary))
}

fn file_identity_digest(file: &File) -> Result<String, ErrorData> {
    let metadata = file
        .metadata()
        .map_err(|error| os_error("preparation.identity", &error, "prepare"))?;
    #[cfg(target_os = "windows")]
    let value = {
        use std::mem::{size_of, zeroed};
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };

        // SAFETY: FILE_ID_INFO is plain C data for an output-only Windows API buffer.
        let mut identity: FILE_ID_INFO = unsafe { zeroed() };
        // SAFETY: the file handle is live and `identity` is writable for its exact ABI size.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut identity as *mut FILE_ID_INFO).cast(),
                u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits u32"),
            )
        } == 0
        {
            return Err(os_error(
                "preparation.identity",
                &io::Error::last_os_error(),
                "prepare",
            ));
        }
        json!({
            "volumeSerialNumber": identity.VolumeSerialNumber,
            "fileId": identity.FileId.Identifier,
            "attributes": metadata.file_attributes(),
            "creationTime": metadata.creation_time(),
            "size": metadata.file_size(),
            "lastWriteTime": metadata.last_write_time(),
        })
    };
    #[cfg(target_os = "macos")]
    let value = {
        use std::os::unix::fs::MetadataExt;
        json!({
            "device": metadata.dev(),
            "inode": metadata.ino(),
            "mode": metadata.mode(),
            "size": metadata.size(),
            "mtime": metadata.mtime(),
            "mtimeNsec": metadata.mtime_nsec(),
        })
    };
    identity_digest(&value)
        .map_err(|error| ErrorData::new("preparation.digest", error.to_string(), "prepare"))
}

fn hash_file(file: &File) -> Result<String, ErrorData> {
    let mut reader = file
        .try_clone()
        .map_err(|error| os_error("preparation.executable", &error, "prepare"))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| os_error("preparation.executable", &error, "prepare"))?;
    hash_reader(&mut reader)
}

fn hash_reader(reader: &mut impl Read) -> Result<String, ErrorData> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| os_error("preparation.executable_hash", &error, "prepare"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > 1024 * 1024 * 1024 {
            return Err(ErrorData::new(
                "preparation.executable_size",
                "executable exceeds 1 GiB",
                "prepare",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeResult {
    available: bool,
    app_container: bool,
    seatbelt: bool,
    suspended_launch: bool,
    job_object: bool,
    handle_whitelist: bool,
    network_none: bool,
    errors: Vec<String>,
}

#[cfg(target_os = "windows")]
fn functional_probe() -> ProbeResult {
    let parent = std::env::temp_dir().join(format!("sandbox-probe-{}", new_id("windows")));
    let mut errors = Vec::new();
    let result = fs::create_dir(&parent)
        .and_then(|()| sandbox_launcher_windows::Session::create(&parent))
        .map(|session| session.cleanup());
    let available = match result {
        Ok(report) => {
            errors.extend(report.failures);
            errors.is_empty()
        }
        Err(error) => {
            errors.push(error.to_string());
            false
        }
    };
    let _ = fs::remove_dir_all(parent);
    ProbeResult {
        available,
        app_container: available,
        seatbelt: false,
        suspended_launch: available,
        job_object: available,
        handle_whitelist: available,
        network_none: available,
        errors,
    }
}

#[cfg(target_os = "macos")]
fn functional_probe() -> ProbeResult {
    use std::os::fd::AsRawFd;

    let root = std::env::temp_dir().join(format!("sandbox-probe-{}", new_id("macos")));
    let home = root.join("home");
    let temporary = root.join("tmp");
    let mut errors = Vec::new();
    let result = (|| -> io::Result<()> {
        fs::create_dir(&root)?;
        fs::create_dir(&home)?;
        fs::create_dir(&temporary)?;
        let policy = sandbox_launcher_macos::SeatbeltPolicy::generate(
            &[],
            home,
            temporary,
            sandbox_launcher_macos::NetworkMode::None,
        )?;
        let null = File::options().read(true).write(true).open("/dev/null")?;
        let launcher = std::env::current_exe()?;
        let mut process =
            sandbox_launcher_macos::Process::spawn(&sandbox_launcher_macos::ProcessLaunchSpec {
                launcher_executable: &launcher,
                executable: Path::new("/usr/bin/true"),
                args: &[],
                cwd: Path::new("/"),
                environment: &[],
                stdin_fd: null.as_raw_fd(),
                stdout_fd: null.as_raw_fd(),
                stderr_fd: null.as_raw_fd(),
                policy: &policy,
                resources: sandbox_launcher_macos::ResourceLimits {
                    cpu_time_ms: Some(1_000),
                    max_file_bytes: Some(1_024 * 1_024),
                    max_processes: Some(4),
                    max_open_files: Some(32),
                },
            })?;
        let status = process.wait()?;
        if status.exit_code != Some(0) {
            return Err(io::Error::other(format!(
                "Seatbelt probe exited with {status:?}"
            )));
        }
        process.terminate_descendants()
    })();
    let available = match result {
        Ok(()) => true,
        Err(error) => {
            errors.push(error.to_string());
            false
        }
    };
    let _ = fs::remove_dir_all(root);
    ProbeResult {
        available,
        app_container: false,
        seatbelt: available,
        suspended_launch: false,
        job_object: false,
        handle_whitelist: false,
        network_none: available,
        errors,
    }
}

struct SpawnedProcess {
    process: PlatformProcess,
    stdin: File,
    stdout: File,
    stderr: File,
}

#[cfg(target_os = "windows")]
type PlatformProcess = sandbox_launcher_windows::Process;
#[cfg(target_os = "macos")]
type PlatformProcess = sandbox_launcher_macos::Process;

#[derive(Debug)]
enum PlatformExit {
    Code(i32),
    #[cfg(target_os = "macos")]
    Signal(i32),
}

fn start_process(
    policy: &PreparedPolicy,
    execution: &PreparedExecution,
    writer: ProtocolWriter,
    cleanup_after_exit: bool,
) -> Result<Arc<Running>, ErrorData> {
    verify_policy(policy)?;
    verify_execution(execution)?;
    let SpawnedProcess {
        mut process,
        mut stdin,
        mut stdout,
        mut stderr,
    } = platform_spawn(policy, execution)?;
    let (stdin_tx, stdin_rx) = mpsc::channel();
    let (control_tx, control_rx) = mpsc::channel();
    let running = Arc::new(Running {
        id: new_id("target"),
        policy_digest: policy.digest.clone(),
        execution_digest: execution.digest.clone(),
        enforcement: policy.report.clone(),
        alive: AtomicBool::new(true),
        stdin_credit: Mutex::new(INITIAL_STREAM_CREDIT),
        stdin: stdin_tx,
        control: control_tx,
        credits: OutputCredits::new(),
        stdout_bytes: AtomicU64::new(0),
        stderr_bytes: AtomicU64::new(0),
        started: Instant::now(),
    });
    let stdin_running = Arc::downgrade(&running);
    let stdin_writer = writer.clone();
    thread::spawn(move || {
        while let Ok(message) = stdin_rx.recv() {
            match message {
                Some(bytes) => {
                    if stdin.write_all(&bytes).is_err() {
                        return;
                    }
                    let Some(stdin_running) = stdin_running.upgrade() else {
                        return;
                    };
                    if let Ok(mut credit) = stdin_running.stdin_credit.lock() {
                        *credit = credit.saturating_add(bytes.len() as u64);
                    }
                    let _ = stdin_writer.control(
                        MessageType::StreamCredit,
                        &StreamCreditMessage {
                            stream: "stdin".into(),
                            bytes: bytes.len() as u64,
                        },
                    );
                }
                None => return,
            }
        }
    });
    let stdout_thread = output_thread(
        Arc::clone(&running),
        writer.clone(),
        "stdout",
        execution.normalized.stdout.clone(),
        execution.normalized.resources.max_output_bytes,
        &mut stdout,
    )?;
    let stderr_thread = output_thread(
        Arc::clone(&running),
        writer.clone(),
        "stderr",
        execution.normalized.stderr.clone(),
        execution.normalized.resources.max_output_bytes,
        &mut stderr,
    )?;
    let authority = Arc::clone(&policy.authority);
    let lifecycle_running = Arc::clone(&running);
    let wall_limit = Duration::from_millis(execution.normalized.resources.wall_time_ms);
    let grace = Duration::from_millis(execution.normalized.resources.termination_grace_ms);
    thread::spawn(move || {
        let mut requested_reason: Option<String> = None;
        let deadline = Instant::now() + wall_limit;
        let platform_exit = loop {
            match platform_try_wait(&mut process) {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(error) => break Err(error),
            }
            match control_rx.try_recv() {
                Ok(Control::Terminate(reason)) => {
                    requested_reason = Some(reason);
                    match platform_terminate(&mut process, grace) {
                        Ok(status) => break Ok(status),
                        Err(error) => break Err(error),
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) | Err(mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                requested_reason = Some("timeout".into());
                match platform_terminate(&mut process, grace) {
                    Ok(status) => break Ok(status),
                    Err(error) => break Err(error),
                }
            }
            thread::sleep(Duration::from_millis(5));
        };
        let tree_cleanup = platform_cleanup_tree(&mut process);
        lifecycle_running.alive.store(false, Ordering::Release);
        lifecycle_running.credits.changed.notify_all();
        let mut cleanup_failures = Vec::new();
        if let Err(error) = tree_cleanup {
            cleanup_failures.push(cleanup_failure(
                "cleanup.target_tree",
                "target-process-tree",
                &error.to_string(),
            ));
        }
        if stdout_thread.join().is_err() {
            cleanup_failures.push(cleanup_failure(
                "cleanup.stdout",
                "stdout-pump",
                "stdout pump panicked",
            ));
        }
        if stderr_thread.join().is_err() {
            cleanup_failures.push(cleanup_failure(
                "cleanup.stderr",
                "stderr-pump",
                "stderr pump panicked",
            ));
        }
        if cleanup_after_exit {
            cleanup_failures.extend(cleanup_authority(&authority));
        }
        let termination = match (requested_reason.as_deref(), platform_exit) {
            (Some("timeout"), _) => json!({"reason": "timeout"}),
            (Some("cancelled" | "caller-request"), _) => json!({"reason": "cancelled"}),
            (Some("output-limit"), _) => json!({"reason": "output-limit"}),
            (_, Ok(PlatformExit::Code(code))) => json!({"reason": "exit", "code": code}),
            #[cfg(target_os = "macos")]
            (_, Ok(PlatformExit::Signal(signal))) => signal_termination(signal),
            (_, Err(error)) => json!({
                "reason": "runtime-failure",
                "error": {
                    "code": "runtime.platform_wait",
                    "message": bounded(&error.to_string()),
                    "phase": "execute",
                    "targetExecuted": true,
                    "backend": BACKEND_ID,
                    "platform": HOST_PLATFORM,
                }
            }),
        };
        let _ = writer.control(
            MessageType::ProcessExit,
            &json!({
                "processId": lifecycle_running.id,
                "policyDigest": lifecycle_running.policy_digest,
                "executionDigest": lifecycle_running.execution_digest,
                "termination": termination,
                "enforcement": lifecycle_running.enforcement,
                "violations": [],
                "usage": {
                    "wallTimeMs": lifecycle_running.started.elapsed().as_millis() as u64,
                    "stdoutBytes": lifecycle_running.stdout_bytes.load(Ordering::Relaxed),
                    "stderrBytes": lifecycle_running.stderr_bytes.load(Ordering::Relaxed),
                },
                "cleanup": {"completed": cleanup_failures.is_empty(), "failures": cleanup_failures},
            }),
        );
    });
    Ok(running)
}

fn output_thread(
    running: Arc<Running>,
    writer: ProtocolWriter,
    stream: &'static str,
    mode: String,
    maximum: u64,
    file: &mut File,
) -> Result<thread::JoinHandle<()>, ErrorData> {
    let mut reader = file
        .try_clone()
        .map_err(|error| os_error("spawn.output_clone", &error, "spawn"))?;
    Ok(thread::spawn(move || {
        let counter = if stream == "stdout" {
            &running.stdout_bytes
        } else {
            &running.stderr_bytes
        };
        let message = if stream == "stdout" {
            MessageType::Stdout
        } else {
            MessageType::Stderr
        };
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = match reader.read(&mut buffer) {
                Ok(0) => return,
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            let previous = counter.fetch_add(count as u64, Ordering::AcqRel);
            let combined = running
                .stdout_bytes
                .load(Ordering::Acquire)
                .saturating_add(running.stderr_bytes.load(Ordering::Acquire));
            if previous.saturating_add(count as u64) > maximum || combined > maximum {
                let _ = running
                    .control
                    .send(Control::Terminate("output-limit".into()));
                return;
            }
            if mode == "discard" {
                continue;
            }
            let mut offset = 0;
            while offset < count {
                let allowed = match running.credits.take(stream, count - offset, &running.alive) {
                    Ok(0) | Err(_) => return,
                    Ok(value) => value,
                };
                if writer
                    .binary(message, buffer[offset..offset + allowed].to_vec())
                    .is_err()
                {
                    let _ = running
                        .control
                        .send(Control::Terminate("runtime-disconnect".into()));
                    return;
                }
                offset += allowed;
            }
        }
    }))
}

fn verify_policy(policy: &PreparedPolicy) -> Result<(), ErrorData> {
    if policy.grants.len() != policy.held_grants.len() {
        return Err(ErrorData::new(
            "preparation.grant_state",
            "prepared grant handles do not match the authorized manifest",
            "activate",
        ));
    }
    for (grant, held) in policy.grants.iter().zip(&policy.held_grants) {
        let current = prepare_host_object(Path::new(&grant.resolved_host_path))?;
        if file_identity_digest(held)? != grant.host_identity_digest
            || current.identity_digest != grant.host_identity_digest
            || !same_path(&current.resolved_path, Path::new(&grant.resolved_host_path))
        {
            return Err(ErrorData::new(
                "preparation.grant_changed",
                "grant root identity changed after approval",
                "activate",
            ));
        }
    }
    Ok(())
}

fn verify_execution(execution: &PreparedExecution) -> Result<(), ErrorData> {
    let executable = prepare_host_object(Path::new(&execution.normalized.executable))?;
    let cwd = prepare_host_object(Path::new(&execution.normalized.cwd))?;
    if file_identity_digest(&execution.held_executable)? != execution.executable_identity_digest
        || file_identity_digest(&execution.held_cwd)? != execution.cwd_identity_digest
        || executable.identity_digest != execution.executable_identity_digest
        || cwd.identity_digest != execution.cwd_identity_digest
        || !same_path(
            &executable.resolved_path,
            Path::new(&execution.normalized.executable),
        )
        || !same_path(&cwd.resolved_path, Path::new(&execution.normalized.cwd))
    {
        return Err(ErrorData::new(
            "preparation.identity_changed",
            "executable or cwd identity changed after approval",
            "activate",
        ));
    }
    if hash_file(&execution.held_executable)? != execution.executable_content_sha256
        || hash_file(&executable.file)? != execution.executable_content_sha256
    {
        return Err(ErrorData::new(
            "preparation.executable_changed",
            "executable bytes changed after approval",
            "activate",
        ));
    }
    Ok(())
}

fn target_environment(
    policy: &PreparedPolicy,
    execution: &PreparedExecution,
) -> Vec<(String, String)> {
    let mut values = execution
        .normalized
        .environment
        .iter()
        .map(|(name, value)| (name.clone(), value.value.clone()))
        .collect::<Vec<_>>();
    values.retain(|(name, _)| !matches!(name.as_str(), "HOME" | "TMPDIR" | "TEMP" | "TMP"));
    values.push((
        "HOME".into(),
        policy.private_home.to_string_lossy().into_owned(),
    ));
    #[cfg(target_os = "windows")]
    {
        values.push((
            "TEMP".into(),
            policy.temporary.to_string_lossy().into_owned(),
        ));
        values.push((
            "TMP".into(),
            policy.temporary.to_string_lossy().into_owned(),
        ));
    }
    #[cfg(target_os = "macos")]
    values.push((
        "TMPDIR".into(),
        policy.temporary.to_string_lossy().into_owned(),
    ));
    values
}

#[cfg(target_os = "windows")]
fn platform_spawn(
    policy: &PreparedPolicy,
    execution: &PreparedExecution,
) -> Result<SpawnedProcess, ErrorData> {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::FromRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    // SAFETY: caller must take ownership of both returned handles and close or transfer each once.
    unsafe fn pipe() -> io::Result<(HANDLE, HANDLE)> {
        // SAFETY: SECURITY_ATTRIBUTES is plain C data and zero initialization is valid.
        let mut attributes: SECURITY_ATTRIBUTES = unsafe { zeroed() };
        attributes.nLength = size_of::<SECURITY_ATTRIBUTES>() as u32;
        attributes.bInheritHandle = 1;
        let mut read: HANDLE = null_mut();
        let mut write: HANDLE = null_mut();
        // SAFETY: both output pointers and security attributes are fully initialized.
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((read, write))
    }

    // SAFETY: every successful pair is tracked in `all` and either closed or transferred.
    let (stdin_read, stdin_write) =
        unsafe { pipe() }.map_err(|error| os_error("spawn.stdin_pipe", &error, "spawn"))?;
    // SAFETY: ownership follows the same exact cleanup table as the stdin pair.
    let (stdout_read, stdout_write) =
        unsafe { pipe() }.map_err(|error| os_error("spawn.stdout_pipe", &error, "spawn"))?;
    // SAFETY: ownership follows the same exact cleanup table as the other pairs.
    let (stderr_read, stderr_write) =
        unsafe { pipe() }.map_err(|error| os_error("spawn.stderr_pipe", &error, "spawn"))?;
    let all = [
        stdin_read,
        stdin_write,
        stdout_read,
        stdout_write,
        stderr_read,
        stderr_write,
    ];
    for parent in [stdin_write, stdout_read, stderr_read] {
        // SAFETY: parent endpoint is live and must not be inherited by the target.
        if unsafe { SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) } == 0 {
            for handle in all {
                // SAFETY: on setup failure every raw handle in `all` remains owned here.
                unsafe { CloseHandle(handle) };
            }
            return Err(os_error(
                "spawn.handle_inheritance",
                &io::Error::last_os_error(),
                "spawn",
            ));
        }
    }
    let environment = target_environment(policy, execution);
    let launch_result = {
        let authority = policy.authority.lock().map_err(|_| lock_error())?;
        let session = authority.session.as_ref().ok_or_else(|| {
            ErrorData::new(
                "spawn.appcontainer",
                "AppContainer authority was cleaned",
                "spawn",
            )
        })?;
        session.launch_suspended(&sandbox_launcher_windows::ProcessLaunchSpec {
            executable: Path::new(&execution.normalized.executable),
            args: &execution.normalized.args,
            cwd: Path::new(&execution.normalized.cwd),
            environment: &environment,
            inherited_handles: &[stdin_read, stdout_write, stderr_write],
            limits: sandbox_launcher_windows::JobLimits {
                memory_bytes: Some(execution.normalized.resources.memory_bytes),
                max_processes: u32::try_from(execution.normalized.resources.max_processes).ok(),
            },
        })
    };
    // Target-only endpoints are never retained by the trusted supervisor.
    for handle in [stdin_read, stdout_write, stderr_write] {
        // SAFETY: CreateProcessW has consumed inheritance metadata; these parent copies are owned.
        unsafe { CloseHandle(handle) };
    }
    let process = match launch_result {
        Ok(process) => process,
        Err(error) => {
            for handle in [stdin_write, stdout_read, stderr_read] {
                // SAFETY: launch failed before these parent endpoints were transferred.
                unsafe { CloseHandle(handle) };
            }
            return Err(os_error("spawn.appcontainer_process", &error, "spawn"));
        }
    };
    // SAFETY: ownership of each remaining parent endpoint is transferred exactly once to File.
    let stdin = unsafe { File::from_raw_handle(stdin_write.cast()) };
    let stdout = unsafe { File::from_raw_handle(stdout_read.cast()) };
    let stderr = unsafe { File::from_raw_handle(stderr_read.cast()) };
    Ok(SpawnedProcess {
        process,
        stdin,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "windows")]
fn platform_try_wait(process: &mut PlatformProcess) -> io::Result<Option<PlatformExit>> {
    process
        .try_wait()
        .map(|status| status.map(|code| PlatformExit::Code(code as i32)))
}

#[cfg(target_os = "windows")]
fn platform_terminate(process: &mut PlatformProcess, _grace: Duration) -> io::Result<PlatformExit> {
    process.terminate(137)?;
    process.wait().map(|code| PlatformExit::Code(code as i32))
}

#[cfg(target_os = "windows")]
fn platform_cleanup_tree(process: &mut PlatformProcess) -> io::Result<()> {
    process.terminate_descendants()
}

#[cfg(target_os = "macos")]
fn platform_spawn(
    policy: &PreparedPolicy,
    execution: &PreparedExecution,
) -> Result<SpawnedProcess, ErrorData> {
    use std::os::fd::FromRawFd;

    fn pipe(label: &str) -> Result<[libc::c_int; 2], ErrorData> {
        let mut descriptors = [-1; 2];
        // SAFETY: array contains two writable integer slots.
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(os_error(label, &io::Error::last_os_error(), "spawn"));
        }
        Ok(descriptors)
    }

    let stdin_pipe = pipe("spawn.stdin_pipe")?;
    let stdout_pipe = pipe("spawn.stdout_pipe")?;
    let stderr_pipe = pipe("spawn.stderr_pipe")?;
    let grants = policy
        .grants
        .iter()
        .map(|grant| sandbox_launcher_macos::Grant {
            resolved_host_path: PathBuf::from(&grant.resolved_host_path),
            target_path: PathBuf::from(&grant.target_path),
            access: if grant.access == "read-write" {
                sandbox_launcher_macos::GrantAccess::ReadWrite
            } else {
                sandbox_launcher_macos::GrantAccess::Read
            },
        })
        .collect::<Vec<_>>();
    let masks = policy
        .normalized
        .masks
        .iter()
        .map(|mask| PathBuf::from(&mask.target_path))
        .collect::<Vec<_>>();
    let seatbelt = sandbox_launcher_macos::SeatbeltPolicy::generate_with_masks(
        &grants,
        &masks,
        policy.private_home.clone(),
        policy.temporary.clone(),
        if policy.normalized.network == "none" {
            sandbox_launcher_macos::NetworkMode::None
        } else {
            sandbox_launcher_macos::NetworkMode::Unrestricted
        },
    )
    .map_err(|error| os_error("spawn.seatbelt_profile", &error, "spawn"))?;
    let environment = target_environment(policy, execution);
    let launch =
        sandbox_launcher_macos::Process::spawn(&sandbox_launcher_macos::ProcessLaunchSpec {
            launcher_executable: &std::env::current_exe()
                .map_err(|error| os_error("spawn.launcher_path", &error, "spawn"))?,
            executable: Path::new(&execution.normalized.executable),
            args: &execution.normalized.args,
            cwd: Path::new(&execution.normalized.cwd),
            environment: &environment,
            stdin_fd: stdin_pipe[0],
            stdout_fd: stdout_pipe[1],
            stderr_fd: stderr_pipe[1],
            policy: &seatbelt,
            resources: sandbox_launcher_macos::ResourceLimits {
                cpu_time_ms: execution.normalized.resources.cpu_time_ms,
                max_file_bytes: execution.normalized.resources.max_single_file_bytes,
                max_processes: Some(execution.normalized.resources.max_processes),
                max_open_files: execution.normalized.resources.max_open_files_per_process,
            },
        });
    for fd in [stdin_pipe[0], stdout_pipe[1], stderr_pipe[1]] {
        // SAFETY: the launcher duplicated these child endpoints or failed atomically.
        unsafe { libc::close(fd) };
    }
    let process = match launch {
        Ok(process) => process,
        Err(error) => {
            for fd in [stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]] {
                // SAFETY: launch failed before ownership of these parent endpoints was transferred.
                unsafe { libc::close(fd) };
            }
            return Err(os_error("spawn.seatbelt_process", &error, "spawn"));
        }
    };
    // SAFETY: ownership of the three remaining parent pipe endpoints is transferred once.
    let stdin = unsafe { File::from_raw_fd(stdin_pipe[1]) };
    let stdout = unsafe { File::from_raw_fd(stdout_pipe[0]) };
    let stderr = unsafe { File::from_raw_fd(stderr_pipe[0]) };
    Ok(SpawnedProcess {
        process,
        stdin,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "macos")]
fn platform_try_wait(process: &mut PlatformProcess) -> io::Result<Option<PlatformExit>> {
    process.try_wait().map(|status| status.map(mac_status))
}

#[cfg(target_os = "macos")]
fn platform_terminate(process: &mut PlatformProcess, grace: Duration) -> io::Result<PlatformExit> {
    process.terminate(grace).map(mac_status)
}

#[cfg(target_os = "macos")]
fn platform_cleanup_tree(process: &mut PlatformProcess) -> io::Result<()> {
    process.terminate_descendants()
}

#[cfg(target_os = "macos")]
fn mac_status(status: sandbox_launcher_macos::ExitStatus) -> PlatformExit {
    if let Some(code) = status.exit_code {
        PlatformExit::Code(code)
    } else {
        PlatformExit::Signal(status.signal.unwrap_or(0))
    }
}

#[cfg(target_os = "macos")]
fn signal_termination(signal: i32) -> Value {
    let name = match signal {
        libc::SIGKILL => "SIGKILL",
        libc::SIGTERM => "SIGTERM",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGABRT => "SIGABRT",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        _ => "UNKNOWN",
    };
    if signal == libc::SIGXCPU {
        return json!({"reason": "cpu-limit"});
    }
    if signal == libc::SIGXFSZ {
        return json!({"reason": "single-file-size-limit"});
    }
    json!({"reason": "signal", "signal": name})
}

fn ensure_empty(state: &RuntimeState) -> Result<(), ErrorData> {
    if matches!(state, RuntimeState::Empty) {
        Ok(())
    } else {
        Err(ErrorData::new(
            "preparation.state",
            "runtime already owns state",
            "prepare",
        ))
    }
}

fn session_mut(state: &mut RuntimeState) -> Result<&mut Session, ErrorData> {
    match state {
        RuntimeState::Session(session) => Ok(session),
        _ => Err(ErrorData::new(
            "preparation.state",
            "no session exists",
            "prepare",
        )),
    }
}

fn active_session<'a>(state: &'a mut RuntimeState, id: &str) -> Result<&'a mut Session, ErrorData> {
    let session = session_mut(state)?;
    if !session.active || session.id != id {
        return Err(ErrorData::new(
            "preparation.state",
            "active session unavailable",
            "prepare",
        ));
    }
    Ok(session)
}

fn running(state: &RuntimeState) -> Result<&Arc<Running>, ErrorData> {
    match state {
        RuntimeState::Session(Session {
            running: Some(running),
            ..
        }) if running.alive.load(Ordering::Acquire) => Ok(running),
        _ => Err(ErrorData::new(
            "preparation.state",
            "no process is running",
            "execute",
        )),
    }
}

fn clear_finished(session: &mut Session) {
    if session
        .running
        .as_ref()
        .is_some_and(|value| !value.alive.load(Ordering::Acquire))
    {
        session.running = None;
    }
}

fn validate_run(prepared: &PreparedRun, message: &StartRunMessage) -> Result<(), ErrorData> {
    if prepared.id != message.id {
        return Err(ErrorData::new(
            "preparation.state",
            "prepared run id mismatch",
            "activate",
        ));
    }
    if Instant::now() >= prepared.deadline {
        return Err(ErrorData::new(
            "preparation_expired.run",
            "prepared run expired",
            "activate",
        ));
    }
    if prepared.policy.digest != message.policy_digest
        || prepared.execution.digest != message.execution_digest
    {
        return Err(ErrorData::new(
            "digest_mismatch.prepared",
            "prepared run digest mismatch",
            "activate",
        ));
    }
    Ok(())
}

fn validate_process(
    policy: &PreparedPolicy,
    prepared: &PreparedProcess,
    message: &StartProcessMessage,
) -> Result<(), ErrorData> {
    if prepared.id != message.id || Instant::now() >= prepared.deadline {
        return Err(ErrorData::new(
            "preparation_expired.process",
            "prepared process unavailable or expired",
            "activate",
        ));
    }
    if policy.digest != message.policy_digest
        || prepared.execution.digest != message.execution_digest
    {
        return Err(ErrorData::new(
            "digest_mismatch.prepared",
            "prepared process digest mismatch",
            "activate",
        ));
    }
    Ok(())
}

fn process_started(
    writer: &ProtocolWriter,
    request_id: &str,
    running: &Running,
) -> Result<(), ErrorData> {
    writer.control(
        MessageType::ProcessStarted,
        &json!({
            "requestId": request_id,
            "id": running.id,
            "identity": {"kind": "opaque"},
        }),
    )
}

fn send_stdin_credit(writer: &ProtocolWriter) -> Result<(), ErrorData> {
    writer.control(
        MessageType::StreamCredit,
        &StreamCreditMessage {
            stream: "stdin".into(),
            bytes: INITIAL_STREAM_CREDIT,
        },
    )
}

fn close_stdin(running: &Running) -> Result<(), ErrorData> {
    running
        .stdin
        .send(None)
        .map_err(|_| ErrorData::new("runtime.stdin", "stdin pump is closed", "execute"))
}

fn terminate_and_wait(running: Option<&Arc<Running>>) {
    let Some(running) = running else {
        return;
    };
    if running.alive.load(Ordering::Acquire) {
        let _ = running
            .control
            .send(Control::Terminate("caller-request".into()));
        let deadline = Instant::now() + Duration::from_secs(15);
        while running.alive.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn cleanup_state(state: &mut RuntimeState) {
    if let RuntimeState::Session(session) = state {
        terminate_and_wait(session.running.as_ref());
        cleanup_authority(&session.policy.authority);
    }
    *state = RuntimeState::Empty;
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

fn request_id(frame: &Frame) -> Option<String> {
    if frame.message_type.is_binary() {
        return None;
    }
    serde_json::from_slice::<Value>(&frame.payload)
        .ok()
        .and_then(|value| {
            value
                .get("requestId")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

fn request_id_value(value: &Value) -> Result<String, ErrorData> {
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

fn unique_request(ids: &mut HashSet<String>, id: &str) -> Result<(), ErrorData> {
    if ids.len() > 65_536 || !ids.insert(id.to_owned()) {
        return Err(ErrorData::new(
            "protocol.request_id",
            "requestId is duplicate or limit exceeded",
            "validate",
        ));
    }
    Ok(())
}

fn parse<T: for<'de> serde::Deserialize<'de>>(frame: &Frame) -> Result<T, ErrorData> {
    frame
        .parse_control()
        .map_err(|error| ErrorData::new("protocol.control", error.to_string(), "validate"))
}

fn create_state_root() -> Result<PathBuf, ErrorData> {
    let root = std::env::temp_dir().join(format!("sandbox-state-{}", new_id("portable")));
    fs::create_dir(&root).map_err(|error| os_error("preparation.state", &error, "prepare"))?;
    Ok(root)
}

#[cfg(target_os = "windows")]
fn recover_abandoned_windows_authority() -> Result<(), ErrorData> {
    let entries = fs::read_dir(std::env::temp_dir())
        .map_err(|error| os_error("recovery.scan", &error, "cleanup"))?;
    for entry in entries {
        let entry = entry.map_err(|error| os_error("recovery.scan", &error, "cleanup"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("sandbox-appcontainer-")
            || !entry
                .file_type()
                .map_err(|error| os_error("recovery.scan", &error, "cleanup"))?
                .is_dir()
        {
            continue;
        }
        let journal = entry.path().join("acl-journal.json");
        if !journal.is_file() {
            continue;
        }
        match sandbox_launcher_windows::recover_acl_journal(&journal) {
            Ok(report) if report.completed() => {}
            Ok(report) => {
                return Err(ErrorData::new(
                    "cleanup.recovery",
                    report.failures.join("; "),
                    "cleanup",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(os_error("cleanup.recovery", &error, "cleanup")),
        }
    }
    Ok(())
}

fn host_memory() -> u64 {
    // Conservative resolution input on preview backends. Actual memory enforcement is separately
    // reported, and explicit limits remain authoritative.
    8 * 1024 * 1024 * 1024
}

fn expiration(ttl_ms: u64) -> (Instant, u64) {
    (
        Instant::now() + Duration::from_millis(ttl_ms),
        epoch_ms().saturating_add(ttl_ms),
    )
}

fn epoch_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn new_id(prefix: &str) -> String {
    format!(
        "{prefix}-{:x}-{:x}",
        epoch_ms(),
        IDS.fetch_add(1, Ordering::Relaxed)
    )
}

fn cleanup_failure(code: &str, resource: &str, message: &str) -> Value {
    json!({"code": code, "resource": resource, "message": bounded(message)})
}

fn protocol_error(error: ProtocolError) -> ErrorData {
    ErrorData::new("protocol.runtime", error.to_string(), "execute")
}

fn os_error(code: &str, error: &io::Error, phase: &str) -> ErrorData {
    let mut data = ErrorData::new(code, bounded(&error.to_string()), phase);
    data.cause_code = error.raw_os_error().map(|value| value.to_string());
    data
}

fn lock_error() -> ErrorData {
    ErrorData::new(
        "runtime.lock",
        "runtime synchronization lock poisoned",
        "execute",
    )
}

fn bounded(value: &str) -> String {
    value
        .chars()
        .take(1024)
        .filter(|character| !character.is_control() || *character == ' ')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{HOST_PLATFORM, TARGET_OPERATING_SYSTEM};

    #[test]
    fn platform_names_match_the_public_node_contract() {
        #[cfg(target_os = "windows")]
        {
            assert_eq!(HOST_PLATFORM, "win32");
            assert_eq!(TARGET_OPERATING_SYSTEM, "windows");
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(HOST_PLATFORM, "darwin");
            assert_eq!(TARGET_OPERATING_SYSTEM, "macos");
        }
    }
}
