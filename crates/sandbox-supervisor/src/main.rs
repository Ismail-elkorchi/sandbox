#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::result_large_err)]

#[cfg(target_os = "linux")]
mod linux {

    use sandbox_launcher_linux::{
        KernelProbeResult, LauncherEvent, LauncherFinalStatus, LauncherStatus, probe_main,
        read_launcher_event, read_launcher_status, receive_managed_listener_fds, send_launch_spec,
        send_launcher_close_stdin, send_launcher_stdin, send_launcher_terminate,
    };
    use sandbox_network_broker::{BrokerHandle, NetworkViolation};
    use sandbox_platform::{
        Cgroup, PreparedLinuxExecution, PreparedLinuxPolicy, ProbeCapabilities, execution_summary,
        host_physical_memory, prepare_execution, prepare_policy, probe_cgroup_delegation,
    };
    use sandbox_policy::{
        ActivateSessionMessage, ErrorData, IdMessage, PrepareProcessMessage, PrepareRunMessage,
        PrepareSessionMessage, StartProcessMessage, StartRunMessage, TerminateMessage,
        normalize_process, normalize_run, normalize_session,
    };
    use sandbox_protocol::{
        Frame, Hello, INITIAL_STREAM_CREDIT, MessageType, PROTOCOL_MAJOR, PROTOCOL_MINOR,
        ProtocolError, StreamCreditMessage, read_frame, write_frame,
    };
    use serde::Serialize;
    use serde_json::{Value, json};
    use std::collections::HashSet;
    use std::io::{self, Read};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const MAX_OUTSTANDING_CREDIT: u64 = 16 * 1024 * 1024;
    const MAX_RECORDED_VIOLATIONS: usize = 1024;
    static IDS: AtomicU64 = AtomicU64::new(1);

    pub fn run() {
        let mut arguments = std::env::args_os();
        let _program = arguments.next();
        match arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .as_deref()
        {
            Some("--linux-launcher") => std::process::exit(sandbox_launcher_linux::launcher_main()),
            Some("--linux-probe") => std::process::exit(probe_main()),
            Some(_) => {
                eprintln!("invalid internal runtime mode");
                std::process::exit(2);
            }
            None => {
                if let Err(error) = supervisor_main() {
                    eprintln!(
                        "sandbox runtime emergency failure: {}",
                        bounded(&error.to_string())
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    #[derive(Clone)]
    struct ProtocolWriter {
        output: Arc<Mutex<io::Stdout>>,
    }

    struct ProtocolSequence<'a> {
        output: MutexGuard<'a, io::Stdout>,
    }

    impl ProtocolWriter {
        fn sequence(&self) -> Result<ProtocolSequence<'_>, ProtocolError> {
            Ok(ProtocolSequence {
                output: self.output.lock().map_err(|_| poisoned())?,
            })
        }

        fn control<T: Serialize>(
            &self,
            message_type: MessageType,
            value: &T,
        ) -> Result<(), ProtocolError> {
            self.sequence()?.control(message_type, value)
        }

        fn binary(&self, message_type: MessageType, value: Vec<u8>) -> Result<(), ProtocolError> {
            let frame = Frame::binary(message_type, value)?;
            let mut output = self.output.lock().map_err(|_| poisoned())?;
            write_frame(&mut *output, &frame)
        }

        fn error(&self, request_id: Option<&str>, error: &ErrorData) {
            let _ = self.control(
                MessageType::Error,
                &json!({"requestId": request_id, "error": error}),
            );
        }
    }

    impl ProtocolSequence<'_> {
        fn control<T: Serialize>(
            &mut self,
            message_type: MessageType,
            value: &T,
        ) -> Result<(), ProtocolError> {
            let frame = Frame::control(message_type, value)?;
            write_frame(&mut *self.output, &frame)
        }
    }

    fn poisoned() -> ProtocolError {
        ProtocolError::Io(io::Error::other("protocol writer lock poisoned"))
    }

    enum InputEvent {
        Frame(Frame),
        Eof,
        Error(String),
    }

    struct PreparedRun {
        id: String,
        policy: PreparedLinuxPolicy,
        execution: PreparedLinuxExecution,
        deadline: Instant,
    }

    struct PreparedProcess {
        id: String,
        execution: PreparedLinuxExecution,
        deadline: Instant,
    }

    struct SessionState {
        id: String,
        policy: PreparedLinuxPolicy,
        deadline: Option<Instant>,
        active: bool,
        prepared_process: Option<PreparedProcess>,
        running: Option<Arc<RunningState>>,
    }

    enum RuntimeState {
        Empty,
        PreparedRun(PreparedRun),
        Session(SessionState),
    }

    struct OutputCredits {
        values: Mutex<(u64, u64)>,
        changed: Condvar,
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
                    "invalid stream credit amount",
                    "execute",
                ));
            }
            let mut values = self.values.lock().map_err(|_| {
                ErrorData::new("runtime.lock", "stream credit lock poisoned", "execute")
            })?;
            let value = match stream {
                "stdout" => &mut values.0,
                "stderr" => &mut values.1,
                _ => {
                    return Err(ErrorData::new(
                        "protocol.credit_stream",
                        "invalid output credit stream",
                        "execute",
                    ));
                }
            };
            *value = value
                .checked_add(amount)
                .filter(|total| *total <= MAX_OUTSTANDING_CREDIT)
                .ok_or_else(|| {
                    ErrorData::new(
                        "protocol.credit_overflow",
                        "stream credit exceeds the bounded window",
                        "execute",
                    )
                })?;
            self.changed.notify_all();
            Ok(())
        }

        fn reserve(
            &self,
            stream: MessageType,
            maximum: usize,
            alive: &AtomicBool,
        ) -> Option<usize> {
            let mut values = self.values.lock().ok()?;
            loop {
                let available = if stream == MessageType::Stdout {
                    &mut values.0
                } else {
                    &mut values.1
                };
                if *available > 0 {
                    let amount = maximum.min(usize::try_from(*available).unwrap_or(maximum));
                    *available -= amount as u64;
                    return Some(amount);
                }
                if !alive.load(Ordering::Acquire) {
                    return None;
                }
                values = self.changed.wait(values).ok()?;
            }
        }

        fn refund(&self, stream: MessageType, amount: usize) {
            if amount == 0 {
                return;
            }
            if let Ok(mut values) = self.values.lock() {
                let value = if stream == MessageType::Stdout {
                    &mut values.0
                } else {
                    &mut values.1
                };
                *value = value
                    .saturating_add(amount as u64)
                    .min(MAX_OUTSTANDING_CREDIT);
                self.changed.notify_all();
            }
        }
    }

    struct RunningState {
        id: String,
        policy_digest: String,
        execution_digest: String,
        enforcement: sandbox_policy::EnforcementReport,
        control: Mutex<UnixStream>,
        launcher_pid: u32,
        alive: AtomicBool,
        stdin_credit: Mutex<u64>,
        credits: OutputCredits,
        termination_reason: Mutex<Option<String>>,
        stdout_bytes: AtomicU64,
        stderr_bytes: AtomicU64,
        total_output: AtomicU64,
        output_limit: u64,
        started: Instant,
        final_status: Mutex<Option<LauncherFinalStatus>>,
        launcher_event_error: Mutex<Option<String>>,
        hard_kill_armed: AtomicBool,
        termination_grace_ms: u64,
        violations: Arc<Mutex<Vec<Value>>>,
    }

    fn supervisor_main() -> Result<(), Box<dyn std::error::Error>> {
        let capabilities = probe_capabilities();
        let writer = ProtocolWriter {
            output: Arc::new(Mutex::new(io::stdout())),
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut input = io::stdin();
            loop {
                match read_frame(&mut input) {
                    Ok(Some(frame)) => {
                        if sender.send(InputEvent::Frame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(InputEvent::Eof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(InputEvent::Error(bounded(&error.to_string())));
                        return;
                    }
                }
            }
        });

        let mut state = RuntimeState::Empty;
        let mut request_ids = HashSet::new();
        let mut hello_complete = false;
        loop {
            let timeout = next_timeout(&state).unwrap_or(Duration::from_secs(3600));
            match receiver.recv_timeout(timeout) {
                Ok(InputEvent::Frame(frame)) => {
                    if let Err(error) = handle_frame(
                        frame,
                        &writer,
                        &capabilities,
                        &mut state,
                        &mut request_ids,
                        &mut hello_complete,
                    ) {
                        writer.error(None, &error);
                        cleanup_state(&state);
                        return Err(error.message.into());
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
        capabilities: &ProbeCapabilities,
        state: &mut RuntimeState,
        request_ids: &mut HashSet<String>,
        hello_complete: &mut bool,
    ) -> Result<(), ErrorData> {
        if !*hello_complete {
            if frame.message_type != MessageType::Hello {
                return Err(ErrorData::new(
                    "protocol.hello_required",
                    "HELLO must be the first message",
                    "validate",
                ));
            }
            let hello: Hello = parse(&frame)?;
            if hello.protocol_major != PROTOCOL_MAJOR {
                return Err(ErrorData::new(
                    "protocol.major_mismatch",
                    "protocol major version mismatch",
                    "validate",
                ));
            }
            *hello_complete = true;
            writer
                .control(
                    MessageType::HelloAck,
                    &json!({
                        "protocolMajor": PROTOCOL_MAJOR,
                        "protocolMinor": PROTOCOL_MINOR,
                        "runtimeVersion": env!("CARGO_PKG_VERSION"),
                        "backendVersions": {"linux-namespace-v1": env!("CARGO_PKG_VERSION")},
                    }),
                )
                .map_err(protocol_data)?;
            return Ok(());
        }

        match frame.message_type {
            MessageType::Probe => {
                let value: Value = parse(&frame)?;
                let request_id = request_id_from_value(&value)?;
                unique_request(request_ids, &request_id)?;
                writer
                .control(
                    MessageType::ProbeResult,
                    &json!({
                        "requestId": request_id,
                        "support": {
                            "protocol": {"major": PROTOCOL_MAJOR, "minor": PROTOCOL_MINOR},
                            "packageVersion": env!("CARGO_PKG_VERSION"),
                            "host": {"platform": "linux", "architecture": std::env::consts::ARCH},
                            "backends": [{
                                "id": "linux-namespace-v1",
                                "isolation": "process",
                                "stability": "stable",
                                "available": capabilities.backend_available("none"),
                                "capabilities": capabilities,
                            }],
                        }
                    }),
                )
                .map_err(protocol_data)?;
            }
            MessageType::PrepareRun => {
                ensure_empty(state)?;
                let message: PrepareRunMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let memory = host_physical_memory()
                    .map_err(|error| runtime_os("preparation.host_memory", &error, "prepare"))?;
                let (normalized_policy, normalized_execution) =
                    normalize_run(message.options, memory).map_err(|error| *error.0)?;
                let policy = prepare_policy(normalized_policy, capabilities)?;
                let execution = prepare_execution(&policy, normalized_execution)?;
                let id = new_id("run");
                let (deadline, expires_at_ms) = expiration(policy.normalized.prepared_ttl_ms);
                writer
                    .control(
                        MessageType::RunPrepared,
                        &json!({
                            "requestId": message.request_id,
                            "id": id,
                            "policyDigest": &policy.policy_digest,
                            "executionDigest": &execution.execution_digest,
                            "summary": policy.run_summary(&execution),
                            "enforcement": &policy.enforcement,
                            "expiresAtMs": expires_at_ms,
                        }),
                    )
                    .map_err(protocol_data)?;
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
                            "no prepared one-shot run exists",
                            "activate",
                        ));
                    }
                };
                validate_prepared_run(&prepared, &message)?;
                // The target can emit output as soon as it is spawned. Keep every cloned
                // publisher behind this writer lock until ProcessStarted is serialized.
                let mut publication = writer.sequence().map_err(protocol_data)?;
                let running = spawn_process(
                    &prepared.policy,
                    &prepared.execution,
                    capabilities,
                    writer.clone(),
                    Some(prepared.policy.state_path()),
                )?;
                *state = RuntimeState::Session(SessionState {
                    id: String::new(),
                    policy: prepared.policy,
                    deadline: None,
                    active: false,
                    prepared_process: None,
                    running: Some(Arc::clone(&running)),
                });
                publication
                    .control(
                        MessageType::ProcessStarted,
                        &process_started(&message.request_id, &running),
                    )
                    .map_err(protocol_data)?;
                drop(publication);
                send_stdin_credit(writer)?;
                if prepared.execution.normalized.stdin == "closed" {
                    close_target_stdin(&running)?;
                }
                set_watchdog_duration(
                    &running,
                    prepared.execution.normalized.resources.wall_time_ms,
                );
            }
            MessageType::CancelPreparedRun => {
                let message: IdMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let cancelled = matches!(state, RuntimeState::PreparedRun(prepared) if prepared.id == message.id);
                if cancelled {
                    *state = RuntimeState::Empty;
                }
                writer.control(MessageType::Event, &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id})).map_err(protocol_data)?;
            }
            MessageType::PrepareSession => {
                ensure_empty(state)?;
                let message: PrepareSessionMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let memory = host_physical_memory()
                    .map_err(|error| runtime_os("preparation.host_memory", &error, "prepare"))?;
                let normalized =
                    normalize_session(message.options, memory).map_err(|error| *error.0)?;
                let policy = prepare_policy(normalized, capabilities)?;
                let id = new_id("session");
                let (deadline, expires_at_ms) = expiration(policy.normalized.prepared_ttl_ms);
                writer
                    .control(
                        MessageType::SessionPrepared,
                        &json!({
                            "requestId": message.request_id,
                            "id": id,
                            "policyDigest": &policy.policy_digest,
                            "summary": policy.session_summary(),
                            "enforcement": &policy.enforcement,
                            "expiresAtMs": expires_at_ms,
                        }),
                    )
                    .map_err(protocol_data)?;
                *state = RuntimeState::Session(SessionState {
                    id,
                    policy,
                    deadline: Some(deadline),
                    active: false,
                    prepared_process: None,
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
                        "prepared session is unavailable",
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
                if session.policy.policy_digest != message.policy_digest {
                    return Err(ErrorData::new(
                        "digest_mismatch.policy",
                        "policy digest does not match the prepared session",
                        "activate",
                    ));
                }
                session.active = true;
                session.deadline = None;
                writer
                    .control(
                        MessageType::SessionActive,
                        &json!({
                            "requestId": message.request_id,
                            "id": session.id,
                            "policyDigest": &session.policy.policy_digest,
                            "enforcement": &session.policy.enforcement,
                        }),
                    )
                    .map_err(protocol_data)?;
            }
            MessageType::CancelPreparedSession => {
                let message: IdMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let cancelled = matches!(state, RuntimeState::Session(session) if !session.active && session.id == message.id);
                if cancelled {
                    *state = RuntimeState::Empty;
                }
                writer.control(MessageType::Event, &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id})).map_err(protocol_data)?;
            }
            MessageType::PrepareProcess => {
                let message: PrepareProcessMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let session = active_session_mut(state, &message.session_id)?;
                clear_finished_process(session);
                if session.running.is_some() || session.prepared_process.is_some() {
                    return Err(ErrorData::new(
                        "preparation.busy",
                        "the session already has an active or prepared process",
                        "prepare",
                    ));
                }
                let normalized =
                    normalize_process(message.process, &session.policy.normalized.resources)
                        .map_err(|error| *error.0)?;
                let execution = prepare_execution(&session.policy, normalized)?;
                let id = new_id("process");
                let (deadline, expires_at_ms) =
                    expiration(session.policy.normalized.prepared_ttl_ms);
                writer
                    .control(
                        MessageType::ProcessPrepared,
                        &json!({
                            "requestId": message.request_id,
                            "id": id,
                            "policyDigest": &session.policy.policy_digest,
                            "executionDigest": &execution.execution_digest,
                            "summary": execution_summary(&execution),
                            "expiresAtMs": expires_at_ms,
                        }),
                    )
                    .map_err(protocol_data)?;
                session.prepared_process = Some(PreparedProcess {
                    id,
                    execution,
                    deadline,
                });
            }
            MessageType::StartPreparedProcess => {
                let message: StartProcessMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let session = session_mut(state)?;
                if !session.active {
                    return Err(ErrorData::new(
                        "preparation.state",
                        "session is not active",
                        "activate",
                    ));
                }
                clear_finished_process(session);
                if session.running.is_some() {
                    return Err(ErrorData::new(
                        "preparation.busy",
                        "session process is already running",
                        "activate",
                    ));
                }
                let prepared = session.prepared_process.take().ok_or_else(|| {
                    ErrorData::new(
                        "preparation.state",
                        "no prepared session process exists",
                        "activate",
                    )
                })?;
                validate_prepared_process(&session.policy, &prepared, &message)?;
                // The target can emit output as soon as it is spawned. Keep every cloned
                // publisher behind this writer lock until ProcessStarted is serialized.
                let mut publication = writer.sequence().map_err(protocol_data)?;
                let running = spawn_process(
                    &session.policy,
                    &prepared.execution,
                    capabilities,
                    writer.clone(),
                    None,
                )?;
                session.running = Some(Arc::clone(&running));
                publication
                    .control(
                        MessageType::ProcessStarted,
                        &process_started(&message.request_id, &running),
                    )
                    .map_err(protocol_data)?;
                drop(publication);
                send_stdin_credit(writer)?;
                if prepared.execution.normalized.stdin == "closed" {
                    close_target_stdin(&running)?;
                }
                set_watchdog_duration(
                    &running,
                    prepared.execution.normalized.resources.wall_time_ms,
                );
            }
            MessageType::CancelPreparedProcess => {
                let message: IdMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                if let Ok(session) = session_mut(state)
                    && session
                        .prepared_process
                        .as_ref()
                        .is_some_and(|prepared| prepared.id == message.id)
                {
                    session.prepared_process = None;
                }
                writer.control(MessageType::Event, &json!({"requestId": message.request_id, "kind": "cancelled", "id": message.id})).map_err(protocol_data)?;
            }
            MessageType::Stdin => {
                let running = running_state(state)?;
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
                let mut control = running.control.lock().map_err(|_| lock_error())?;
                send_launcher_stdin(&mut control, &frame.payload)
                    .map_err(|error| runtime_os("runtime.stdin", &error, "execute"))?;
                drop(control);
            }
            MessageType::CloseStdin => {
                let message: IdMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let running = running_state(state)?;
                if running.id != message.id {
                    return Err(ErrorData::new(
                        "protocol.process_id",
                        "stdin close process id mismatch",
                        "execute",
                    ));
                }
                close_target_stdin(running)?;
                writer.control(MessageType::Event, &json!({"requestId": message.request_id, "kind": "stdin-closed", "id": message.id})).map_err(protocol_data)?;
            }
            MessageType::StreamCredit => {
                let message: StreamCreditMessage = parse(&frame)?;
                let running = running_state(state)?;
                running.credits.grant(&message.stream, message.bytes)?;
            }
            MessageType::Terminate => {
                let message: TerminateMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let running = running_state(state)?;
                if running.id != message.id {
                    return Err(ErrorData::new(
                        "protocol.process_id",
                        "termination process id mismatch",
                        "terminate",
                    ));
                }
                request_termination(running, &message.reason)?;
                writer.control(MessageType::Event, &json!({"requestId": message.request_id, "kind": "termination-started", "reason": message.reason})).map_err(protocol_data)?;
            }
            MessageType::CloseSession => {
                let message: IdMessage = parse(&frame)?;
                unique_request(request_ids, &message.request_id)?;
                let mut cleanup_failures = Vec::new();
                if let RuntimeState::Session(session) = state {
                    if !session.id.is_empty() && session.id != message.id {
                        return Err(ErrorData::new(
                            "protocol.session_id",
                            "session close id mismatch",
                            "cleanup",
                        ));
                    }
                    if let Some(running) = &session.running
                        && running.alive.load(Ordering::Acquire)
                    {
                        if let Err(error) = request_termination(running, "caller-request") {
                            cleanup_failures.push(cleanup_failure(
                                "cleanup.termination_request",
                                "target-process-tree",
                                &error.message,
                            ));
                            if let Err(error) = force_kill(running) {
                                cleanup_failures.push(cleanup_failure(
                                    "cleanup.force_kill",
                                    "target-process-tree",
                                    &error.to_string(),
                                ));
                            }
                        }
                        wait_for_exit(running, Duration::from_secs(15));
                        if running.alive.load(Ordering::Acquire) {
                            cleanup_failures.push(cleanup_failure(
                                "cleanup.tree_unconfirmed",
                                "target-process-tree",
                                "target process-tree death was not confirmed",
                            ));
                        }
                    }
                }
                if let RuntimeState::Session(session) = state
                    && let Err(error) = session.policy.cleanup_state()
                {
                    cleanup_failures.push(cleanup_failure(
                        "cleanup.state",
                        "state-directory",
                        &error.to_string(),
                    ));
                }
                *state = RuntimeState::Empty;
                let completed = cleanup_failures.is_empty();
                writer
                    .control(
                        MessageType::SessionClosed,
                        &json!({
                            "requestId": message.request_id,
                            "id": message.id,
                            "cleanup": {
                                "completed": completed,
                                "failures": cleanup_failures,
                            },
                        }),
                    )
                    .map_err(protocol_data)?;
            }
            MessageType::Shutdown => {
                let value: Value = parse(&frame)?;
                let request_id = request_id_from_value(&value)?;
                unique_request(request_ids, &request_id)?;
                cleanup_state(state);
                writer
                    .control(
                        MessageType::RuntimeMetrics,
                        &json!({"requestId": request_id, "shutdown": true}),
                    )
                    .map_err(protocol_data)?;
                std::process::exit(0);
            }
            _ => {
                return Err(ErrorData::new(
                    "protocol.direction",
                    "message is invalid in the Node-to-runtime direction",
                    "validate",
                ));
            }
        }
        Ok(())
    }

    fn spawn_process(
        policy: &PreparedLinuxPolicy,
        execution: &PreparedLinuxExecution,
        capabilities: &ProbeCapabilities,
        writer: ProtocolWriter,
        cleanup_state_path: Option<std::path::PathBuf>,
    ) -> Result<Arc<RunningState>, ErrorData> {
        let bundle = policy.launch_bundle(execution)?;
        let executable = std::env::current_exe()
            .map_err(|error| runtime_os("spawn.runtime_path", &error, "spawn"))?;
        let (mut supervisor_control, launcher_control) =
            UnixStream::pair().map_err(|error| runtime_os("spawn.control", &error, "spawn"))?;
        let launcher_input = launcher_control
            .try_clone()
            .map_err(|error| runtime_os("spawn.control_clone", &error, "spawn"))?;
        let launcher_input: OwnedFd = launcher_input.into();
        drop(launcher_control);
        let child = Command::new(executable)
            .arg("--linux-launcher")
            .env_clear()
            .stdin(Stdio::from(launcher_input))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| runtime_os("spawn.launcher", &error, "spawn"))?;
        let mut guard = LaunchGuard::new(child);
        let launch_result = (|| -> Result<Arc<RunningState>, ErrorData> {
            let cgroup = if capabilities.cgroup_memory || capabilities.cgroup_processes {
                match Cgroup::create(
                    guard.child_mut().id(),
                    capabilities
                        .cgroup_memory
                        .then_some(execution.normalized.resources.memory_bytes),
                    capabilities
                        .cgroup_processes
                        .then_some(execution.normalized.resources.max_processes),
                ) {
                    Ok(cgroup) => Some(cgroup),
                    Err(error) => {
                        return Err(runtime_os("setup.cgroup", &error, "spawn"));
                    }
                }
            } else {
                None
            };
            guard.set_cgroup(cgroup);
            send_launch_spec(&mut supervisor_control, &bundle.spec, &bundle.files)
                .map_err(|error| runtime_os("spawn.launch_request", &error, "spawn"))?;
            drop(bundle.files);
            supervisor_control
                .set_read_timeout(Some(Duration::from_secs(30)))
                .map_err(|error| runtime_os("spawn.setup_timeout", &error, "spawn"))?;
            let managed_listeners = if policy.normalized.network == "managed" {
                Some(
                    receive_managed_listener_fds(&supervisor_control)
                        .map_err(|error| runtime_os("setup.managed_listeners", &error, "spawn"))?,
                )
            } else {
                None
            };
            let status = read_launcher_status(&mut supervisor_control)
                .map_err(|error| runtime_os("setup.launcher_status", &error, "spawn"))?;
            supervisor_control
                .set_read_timeout(None)
                .map_err(|error| runtime_os("spawn.control_timeout", &error, "spawn"))?;
            if let LauncherStatus::SetupError(error) = status {
                return Err(ErrorData::new(error.code.as_str(), error.message, "spawn"));
            }

            let status_control = supervisor_control
                .try_clone()
                .map_err(|error| runtime_os("spawn.status_control", &error, "spawn"))?;
            let stdout = guard.child_mut().stdout.take().ok_or_else(|| {
                ErrorData::new("spawn.stdout", "launcher stdout pipe is missing", "spawn")
            })?;
            let stderr = guard.child_mut().stderr.take().ok_or_else(|| {
                ErrorData::new("spawn.stderr", "launcher stderr pipe is missing", "spawn")
            })?;
            let process_id = new_id("target");
            let violations = Arc::new(Mutex::new(Vec::new()));
            let broker = if let Some(listeners) = managed_listeners {
                let event_writer = writer.clone();
                let event_process_id = process_id.clone();
                let event_violations = Arc::clone(&violations);
                Some(
                    BrokerHandle::start(
                        listeners,
                        policy.normalized.managed_network_rules.clone(),
                        move |violation: NetworkViolation| {
                            let value = json!({
                                "id": new_id("violation"),
                                "kind": "network-denied",
                                "processId": event_process_id,
                                "timestampMs": epoch_ms(),
                                "mechanism": "managed-network-broker",
                                "details": {
                                    "destination": violation.destination,
                                    "port": violation.port,
                                    "transport": "tcp",
                                    "ruleReason": violation.rule_reason,
                                },
                            });
                            let recorded = event_violations.lock().is_ok_and(|mut values| {
                                if values.len() >= MAX_RECORDED_VIOLATIONS {
                                    false
                                } else {
                                    values.push(value.clone());
                                    true
                                }
                            });
                            if recorded {
                                let _ = event_writer.control(
                                    MessageType::Event,
                                    &json!({"kind": "violation", "violation": value}),
                                );
                            }
                        },
                    )
                    .map_err(|error| runtime_os("setup.network_broker", &error, "spawn"))?,
                )
            } else {
                None
            };
            let running = Arc::new(RunningState {
                id: process_id,
                policy_digest: policy.policy_digest.clone(),
                execution_digest: execution.execution_digest.clone(),
                enforcement: policy.enforcement.clone(),
                control: Mutex::new(supervisor_control),
                launcher_pid: guard.child_mut().id(),
                alive: AtomicBool::new(true),
                stdin_credit: Mutex::new(INITIAL_STREAM_CREDIT),
                credits: OutputCredits::new(),
                termination_reason: Mutex::new(None),
                stdout_bytes: AtomicU64::new(0),
                stderr_bytes: AtomicU64::new(0),
                total_output: AtomicU64::new(0),
                output_limit: execution.normalized.resources.max_output_bytes,
                started: Instant::now(),
                final_status: Mutex::new(None),
                launcher_event_error: Mutex::new(None),
                hard_kill_armed: AtomicBool::new(false),
                termination_grace_ms: execution.normalized.resources.termination_grace_ms,
                violations,
            });
            let status_thread =
                spawn_launcher_event_reader(status_control, Arc::clone(&running), writer.clone());
            let stdout_thread = spawn_output_reader(
                stdout,
                MessageType::Stdout,
                execution.normalized.stdout.clone(),
                Arc::clone(&running),
                writer.clone(),
            );
            let stderr_thread = spawn_output_reader(
                stderr,
                MessageType::Stderr,
                execution.normalized.stderr.clone(),
                Arc::clone(&running),
                writer.clone(),
            );
            let (child, cgroup) = guard.handoff();
            spawn_exit_watcher(
                child,
                Arc::clone(&running),
                writer,
                ExitResources {
                    cgroup,
                    stdout_thread,
                    stderr_thread,
                    status_thread,
                    cleanup_state_path,
                    broker,
                },
            );
            Ok(running)
        })();
        match launch_result {
            Ok(running) => Ok(running),
            Err(mut error) => {
                let cleanup_failures = guard.cleanup();
                if !cleanup_failures.is_empty() {
                    error.message = bounded(&format!(
                        "{}; launch cleanup failed: {}",
                        error.message,
                        cleanup_failures.join("; ")
                    ));
                }
                Err(error)
            }
        }
    }

    struct LaunchGuard {
        child: Option<Child>,
        cgroup: Option<Cgroup>,
    }

    impl LaunchGuard {
        fn new(child: Child) -> Self {
            Self {
                child: Some(child),
                cgroup: None,
            }
        }

        fn child_mut(&mut self) -> &mut Child {
            self.child.as_mut().expect("launch guard owns its child")
        }

        fn set_cgroup(&mut self, cgroup: Option<Cgroup>) {
            self.cgroup = cgroup;
        }

        fn handoff(&mut self) -> (Child, Option<Cgroup>) {
            let child = self.child.take().expect("launch guard owns its child");
            (child, self.cgroup.take())
        }

        fn cleanup(&mut self) -> Vec<String> {
            let mut failures = Vec::new();
            if let Some(cgroup) = self.cgroup.as_ref()
                && let Err(error) = cgroup.kill()
                && error.kind() != io::ErrorKind::NotFound
            {
                failures.push(format!("cgroup kill: {error}"));
            }
            if let Some(child) = self.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        if let Err(error) = child.kill()
                            && error.kind() != io::ErrorKind::InvalidInput
                        {
                            failures.push(format!("launcher kill: {error}"));
                        }
                    }
                    Err(error) => failures.push(format!("launcher status: {error}")),
                }
                if let Err(error) = child.wait() {
                    failures.push(format!("launcher wait: {error}"));
                }
            }
            self.child = None;
            if let Some(cgroup) = self.cgroup.as_mut() {
                let report = cgroup.cleanup();
                failures.extend(report.failures);
                if !report.removed {
                    failures.push("cgroup removal was not confirmed".into());
                }
            }
            self.cgroup = None;
            failures
        }
    }

    impl Drop for LaunchGuard {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    fn spawn_launcher_event_reader(
        mut control: UnixStream,
        running: Arc<RunningState>,
        writer: ProtocolWriter,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            loop {
                match read_launcher_event(&mut control) {
                    Ok(LauncherEvent::StdinCredit(bytes)) => {
                        let updated = running.stdin_credit.lock().ok().and_then(|mut credit| {
                            *credit = credit.checked_add(bytes)?;
                            (*credit <= INITIAL_STREAM_CREDIT).then_some(())
                        });
                        if updated.is_none()
                            || writer
                                .control(
                                    MessageType::StreamCredit,
                                    &StreamCreditMessage {
                                        stream: "stdin".into(),
                                        bytes,
                                    },
                                )
                                .is_err()
                        {
                            let _ = force_kill(&running);
                            return;
                        }
                    }
                    Ok(LauncherEvent::Final(status)) => {
                        if let Ok(mut slot) = running.final_status.lock() {
                            *slot = Some(status);
                        }
                        return;
                    }
                    Ok(LauncherEvent::RuntimeError(error)) => {
                        if let Ok(mut slot) = running.launcher_event_error.lock() {
                            *slot = Some(format!("{}: {}", error.code, error.message));
                        }
                        return;
                    }
                    Err(error) => {
                        if let Ok(mut slot) = running.launcher_event_error.lock() {
                            *slot = Some(error.to_string());
                        }
                        return;
                    }
                }
            }
        })
    }

    fn spawn_output_reader(
        mut reader: impl Read + Send + 'static,
        stream: MessageType,
        mode: String,
        running: Arc<RunningState>,
        writer: ProtocolWriter,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut buffer = vec![0_u8; sandbox_protocol::MAX_STREAM_PAYLOAD];
            loop {
                let maximum = if mode == "discard" {
                    buffer.len()
                } else {
                    match running
                        .credits
                        .reserve(stream, buffer.len(), &running.alive)
                    {
                        Some(value) => value,
                        None => return,
                    }
                };
                let count = match reader.read(&mut buffer[..maximum]) {
                    Ok(0) => return,
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        if mode != "discard" {
                            running.credits.refund(stream, maximum);
                        }
                        continue;
                    }
                    Err(_) => return,
                };
                if mode != "discard" && count < maximum {
                    running.credits.refund(stream, maximum - count);
                }
                let counter = if stream == MessageType::Stdout {
                    &running.stdout_bytes
                } else {
                    &running.stderr_bytes
                };
                counter.fetch_add(count as u64, Ordering::Relaxed);
                let previous = running
                    .total_output
                    .fetch_add(count as u64, Ordering::AcqRel);
                let deliverable = usize::try_from(running.output_limit.saturating_sub(previous))
                    .unwrap_or(usize::MAX)
                    .min(count);
                if mode != "discard"
                    && deliverable > 0
                    && writer
                        .binary(stream, buffer[..deliverable].to_vec())
                        .is_err()
                {
                    let _ = force_kill(&running);
                    return;
                }
                if previous.saturating_add(count as u64) > running.output_limit {
                    let _ = request_termination(&running, "output-limit");
                    return;
                }
            }
        })
    }

    struct ExitResources {
        cgroup: Option<Cgroup>,
        stdout_thread: thread::JoinHandle<()>,
        stderr_thread: thread::JoinHandle<()>,
        status_thread: thread::JoinHandle<()>,
        cleanup_state_path: Option<std::path::PathBuf>,
        broker: Option<BrokerHandle>,
    }

    fn spawn_exit_watcher(
        mut child: Child,
        running: Arc<RunningState>,
        writer: ProtocolWriter,
        resources: ExitResources,
    ) {
        thread::spawn(move || {
            let ExitResources {
                mut cgroup,
                stdout_thread,
                stderr_thread,
                status_thread,
                cleanup_state_path,
                broker,
            } = resources;
            let status = child.wait();
            running.alive.store(false, Ordering::Release);
            running.credits.changed.notify_all();
            let mut cleanup_failures = Vec::new();
            if stdout_thread.join().is_err() {
                cleanup_failures.push(cleanup_failure(
                    "cleanup.output_thread",
                    "stdout-reader",
                    "stdout reader panicked",
                ));
            }
            if stderr_thread.join().is_err() {
                cleanup_failures.push(cleanup_failure(
                    "cleanup.output_thread",
                    "stderr-reader",
                    "stderr reader panicked",
                ));
            }
            if status_thread.join().is_err() {
                cleanup_failures.push(cleanup_failure(
                    "cleanup.status_thread",
                    "launcher-status-reader",
                    "launcher status reader panicked",
                ));
            }
            let final_status = running
                .final_status
                .lock()
                .ok()
                .and_then(|status| status.clone());
            if let Some(final_status) = &final_status {
                for failure in &final_status.cleanup_failures {
                    cleanup_failures.push(cleanup_failure(
                        "cleanup.namespace",
                        "target-tree",
                        failure,
                    ));
                }
                if !final_status.tree_reaped {
                    cleanup_failures.push(cleanup_failure(
                        "cleanup.tree_unconfirmed",
                        "target-tree",
                        "namespace init did not confirm that every descendant was reaped",
                    ));
                }
            } else {
                let message = running
                    .launcher_event_error
                    .lock()
                    .ok()
                    .and_then(|error| error.clone())
                    .unwrap_or_else(|| "launcher returned no structured final status".into());
                cleanup_failures.push(cleanup_failure(
                    "cleanup.status_missing",
                    "launcher",
                    &message,
                ));
            }
            let broker_report = broker.map(BrokerHandle::stop).unwrap_or_default();
            for failure in broker_report.cleanup_failures {
                cleanup_failures.push(cleanup_failure(
                    "cleanup.network_broker",
                    "managed-network-broker",
                    &failure,
                ));
            }
            let termination = determine_termination(
                status.as_ref().ok(),
                final_status.as_ref(),
                &running,
                cgroup.as_ref(),
            );
            let peak_memory = cgroup.as_ref().and_then(Cgroup::peak_memory);
            if let Some(cgroup) = cgroup.as_mut() {
                let report = cgroup.cleanup();
                for failure in report.failures {
                    cleanup_failures.push(cleanup_failure("cleanup.cgroup", "cgroup", &failure));
                }
                if !report.removed {
                    cleanup_failures.push(cleanup_failure(
                        "cleanup.cgroup_unconfirmed",
                        "cgroup",
                        "cgroup removal was not confirmed",
                    ));
                }
            }
            if let Some(path) = cleanup_state_path
                && let Err(error) = std::fs::remove_dir_all(&path)
                && error.kind() != io::ErrorKind::NotFound
            {
                cleanup_failures.push(cleanup_failure(
                    "cleanup.state",
                    "state-directory",
                    &error.to_string(),
                ));
            }
            let cleanup_completed = cleanup_failures.is_empty();
            let mut violations = running
                .violations
                .lock()
                .map(|values| values.clone())
                .unwrap_or_default();
            let omitted_violations = broker_report
                .violations
                .saturating_sub(violations.len() as u64);
            if omitted_violations > 0 {
                violations.push(json!({
                    "id": new_id("violation"),
                    "kind": "network-denied-events-truncated",
                    "processId": &running.id,
                    "timestampMs": epoch_ms(),
                    "mechanism": "managed-network-broker",
                    "details": {
                        "omittedCount": omitted_violations,
                        "recordedCount": violations.len(),
                    },
                }));
            }
            let result = json!({
                "processId": &running.id,
                "policyDigest": &running.policy_digest,
                "executionDigest": &running.execution_digest,
                "termination": termination,
                "enforcement": &running.enforcement,
                "violations": violations,
                "usage": {
                    "wallTimeMs": u64::try_from(running.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    "peakMemoryBytes": peak_memory,
                    "stdoutBytes": running.stdout_bytes.load(Ordering::Relaxed),
                    "stderrBytes": running.stderr_bytes.load(Ordering::Relaxed),
                    "networkConnections": broker_report.connections,
                },
                "cleanup": {"completed": cleanup_completed, "failures": cleanup_failures},
            });
            let _ = writer.control(MessageType::ProcessExit, &result);
        });
    }

    fn cleanup_failure(code: &str, resource: &str, message: &str) -> Value {
        json!({
            "code": code,
            "resource": resource,
            "message": bounded(message),
        })
    }

    fn set_watchdog_duration(running: &Arc<RunningState>, duration_ms: u64) {
        let running = Arc::clone(running);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(duration_ms));
            if running.alive.load(Ordering::Acquire) {
                let _ = request_termination(&running, "timeout");
            }
        });
    }

    fn determine_termination(
        status: Option<&ExitStatus>,
        final_status: Option<&LauncherFinalStatus>,
        running: &RunningState,
        cgroup: Option<&Cgroup>,
    ) -> Value {
        if cgroup
            .and_then(Cgroup::events)
            .is_some_and(|events| counter_is_positive(&events, "oom_kill"))
        {
            return json!({"reason": "memory-limit"});
        }
        if cgroup
            .and_then(Cgroup::process_events)
            .is_some_and(|events| counter_is_positive(&events, "max"))
        {
            return json!({"reason": "process-limit"});
        }
        if let Ok(reason) = running.termination_reason.lock()
            && let Some(reason) = reason.as_deref()
        {
            return match reason {
                "timeout" => json!({"reason": "timeout"}),
                "cancelled" => json!({"reason": "cancelled"}),
                "output-limit" => json!({"reason": "output-limit"}),
                "process-limit" => json!({"reason": "process-limit"}),
                _ => json!({"reason": "signal", "signal": "SIGTERM"}),
            };
        }
        if let Some(final_status) = final_status {
            if let Some(signal) = final_status.signal {
                return match signal {
                    libc::SIGXCPU => json!({"reason": "cpu-limit"}),
                    libc::SIGXFSZ => json!({"reason": "single-file-size-limit"}),
                    signal => json!({"reason": "signal", "signal": signal_name(signal)}),
                };
            }
            if let Some(code) = final_status.exit_code {
                return json!({"reason": "exit", "code": code});
            }
        }
        match status {
            Some(status) => match status.code() {
                Some(code) if code != 125 => json!({"reason": "exit", "code": code}),
                Some(_) => json!({
                    "reason": "runtime-failure",
                    "error": ErrorData::new("runtime_failed.launcher", "launcher exited without structured target status", "execute"),
                }),
                None => {
                    use std::os::unix::process::ExitStatusExt;
                    json!({"reason": "signal", "signal": signal_name(status.signal().unwrap_or(0))})
                }
            },
            None => json!({
                "reason": "runtime-failure",
                "error": ErrorData::new("runtime_crashed.launcher", "launcher wait failed", "execute"),
            }),
        }
    }

    fn counter_is_positive(contents: &str, name: &str) -> bool {
        contents.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some(name)
                && fields
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_some_and(|value| value > 0)
                && fields.next().is_none()
        })
    }

    fn request_termination(running: &Arc<RunningState>, reason: &str) -> Result<(), ErrorData> {
        if !running.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        {
            let mut current = running
                .termination_reason
                .lock()
                .map_err(|_| lock_error())?;
            if current.is_none() {
                *current = Some(reason.into());
            }
        }
        match running.control.try_lock() {
            Ok(mut control) => {
                send_launcher_terminate(&mut control)
                    .map_err(|error| runtime_os("termination.control", &error, "terminate"))?;
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(lock_error()),
        }
        arm_hard_kill(running);
        Ok(())
    }

    fn arm_hard_kill(running: &Arc<RunningState>) {
        if running.hard_kill_armed.swap(true, Ordering::AcqRel) {
            return;
        }
        let running = Arc::clone(running);
        let delay = Duration::from_millis(running.termination_grace_ms.saturating_add(1_000));
        thread::spawn(move || {
            thread::sleep(delay);
            if running.alive.load(Ordering::Acquire) {
                let _ = force_kill(&running);
            }
        });
    }

    fn force_kill(running: &RunningState) -> io::Result<()> {
        // SAFETY: launcher_pid is the positive PID returned by Child::id; kill does not dereference memory.
        let result = unsafe { libc::kill(running.launcher_pid as libc::pid_t, libc::SIGKILL) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn close_target_stdin(running: &RunningState) -> Result<(), ErrorData> {
        let mut control = running.control.lock().map_err(|_| lock_error())?;
        send_launcher_close_stdin(&mut control)
            .map_err(|error| runtime_os("runtime.stdin_close", &error, "execute"))
    }

    fn wait_for_exit(running: &RunningState, maximum: Duration) {
        let start = Instant::now();
        while running.alive.load(Ordering::Acquire) && start.elapsed() < maximum {
            thread::sleep(Duration::from_millis(5));
        }
        if running.alive.load(Ordering::Acquire) {
            let _ = force_kill(running);
        }
    }

    fn cleanup_state(state: &RuntimeState) {
        if let RuntimeState::Session(session) = state
            && let Some(running) = &session.running
            && running.alive.load(Ordering::Acquire)
        {
            let _ = force_kill(running);
            wait_for_exit(running, Duration::from_secs(5));
        }
    }

    fn process_started(request_id: &str, running: &RunningState) -> Value {
        json!({
            "requestId": request_id,
            "id": &running.id,
            "identity": {"kind": "opaque"},
        })
    }

    fn send_stdin_credit(writer: &ProtocolWriter) -> Result<(), ErrorData> {
        writer
            .control(
                MessageType::StreamCredit,
                &StreamCreditMessage {
                    stream: "stdin".into(),
                    bytes: INITIAL_STREAM_CREDIT,
                },
            )
            .map_err(protocol_data)
    }

    fn validate_prepared_run(
        prepared: &PreparedRun,
        message: &StartRunMessage,
    ) -> Result<(), ErrorData> {
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
        if prepared.policy.policy_digest != message.policy_digest
            || prepared.execution.execution_digest != message.execution_digest
        {
            return Err(ErrorData::new(
                "digest_mismatch.prepared_run",
                "prepared run digests do not match",
                "activate",
            ));
        }
        Ok(())
    }

    fn validate_prepared_process(
        policy: &PreparedLinuxPolicy,
        prepared: &PreparedProcess,
        message: &StartProcessMessage,
    ) -> Result<(), ErrorData> {
        if prepared.id != message.id {
            return Err(ErrorData::new(
                "preparation.state",
                "prepared process id mismatch",
                "activate",
            ));
        }
        if Instant::now() >= prepared.deadline {
            return Err(ErrorData::new(
                "preparation_expired.process",
                "prepared process expired",
                "activate",
            ));
        }
        if policy.policy_digest != message.policy_digest
            || prepared.execution.execution_digest != message.execution_digest
        {
            return Err(ErrorData::new(
                "digest_mismatch.prepared_process",
                "prepared process digests do not match",
                "activate",
            ));
        }
        Ok(())
    }

    fn ensure_empty(state: &RuntimeState) -> Result<(), ErrorData> {
        if matches!(state, RuntimeState::Empty) {
            Ok(())
        } else {
            Err(ErrorData::new(
                "preparation.busy",
                "runtime already owns a prepared or active object",
                "prepare",
            ))
        }
    }

    fn session_mut(state: &mut RuntimeState) -> Result<&mut SessionState, ErrorData> {
        match state {
            RuntimeState::Session(session) => Ok(session),
            _ => Err(ErrorData::new(
                "preparation.state",
                "session does not exist",
                "activate",
            )),
        }
    }

    fn active_session_mut<'a>(
        state: &'a mut RuntimeState,
        id: &str,
    ) -> Result<&'a mut SessionState, ErrorData> {
        let session = session_mut(state)?;
        if !session.active || session.id != id {
            return Err(ErrorData::new(
                "preparation.state",
                "active session id mismatch",
                "prepare",
            ));
        }
        Ok(session)
    }

    fn running_state(state: &RuntimeState) -> Result<&Arc<RunningState>, ErrorData> {
        match state {
            RuntimeState::Session(session) => session
                .running
                .as_ref()
                .filter(|running| running.alive.load(Ordering::Acquire))
                .ok_or_else(|| {
                    ErrorData::new(
                        "runtime.no_process",
                        "no target process is running",
                        "execute",
                    )
                }),
            _ => Err(ErrorData::new(
                "runtime.no_process",
                "no target process is running",
                "execute",
            )),
        }
    }

    fn clear_finished_process(session: &mut SessionState) {
        if session
            .running
            .as_ref()
            .is_some_and(|running| !running.alive.load(Ordering::Acquire))
        {
            session.running = None;
        }
    }

    fn next_timeout(state: &RuntimeState) -> Option<Duration> {
        let deadline = match state {
            RuntimeState::PreparedRun(prepared) => Some(prepared.deadline),
            RuntimeState::Session(session) if !session.active => session.deadline,
            RuntimeState::Session(session) => session
                .prepared_process
                .as_ref()
                .map(|prepared| prepared.deadline),
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
                    .prepared_process
                    .as_ref()
                    .is_some_and(|prepared| now >= prepared.deadline) =>
            {
                if let Some(prepared) = session.prepared_process.take() {
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

    fn probe_capabilities() -> ProbeCapabilities {
        let mut errors = Vec::new();
        let kernel = std::env::current_exe()
            .and_then(|executable| {
                Command::new(executable)
                    .arg("--linux-probe")
                    .env_clear()
                    .output()
            })
            .map_err(|error| error.to_string())
            .and_then(|output| {
                if output.status.success() {
                    serde_json::from_slice::<KernelProbeResult>(&output.stdout)
                        .map_err(|error| error.to_string())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).into_owned())
                }
            });
        let kernel = match kernel {
            Ok(kernel) => kernel,
            Err(error) => {
                errors.push(format!("kernel probe failed: {}", bounded(&error)));
                KernelProbeResult {
                    namespaces: false,
                    network_namespace: false,
                    mount_setattr: false,
                    landlock_abi: 0,
                    seccomp: false,
                    execveat: false,
                    errors: Vec::new(),
                }
            }
        };
        errors.extend(kernel.errors.iter().map(|error| bounded(error)));
        let (cgroup_memory, cgroup_processes) = probe_cgroup_delegation();
        ProbeCapabilities {
            namespaces: kernel.namespaces,
            network_namespace: kernel.network_namespace,
            mount_setattr: kernel.mount_setattr,
            landlock_abi: kernel.landlock_abi,
            seccomp: kernel.seccomp,
            execveat: kernel.execveat,
            cgroup_memory,
            cgroup_processes,
            errors,
        }
    }

    fn parse<T: for<'de> serde::Deserialize<'de>>(frame: &Frame) -> Result<T, ErrorData> {
        frame.parse_control().map_err(protocol_data)
    }

    fn request_id_from_value(value: &Value) -> Result<String, ErrorData> {
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
        if id.is_empty() || id.len() > 256 {
            return Err(ErrorData::new(
                "protocol.request_id",
                "requestId is missing or invalid",
                "validate",
            ));
        }
        if !ids.insert(id.into()) {
            return Err(ErrorData::new(
                "protocol.duplicate_request",
                "duplicate request identifier",
                "validate",
            ));
        }
        if ids.len() > 100_000 {
            return Err(ErrorData::new(
                "protocol.request_limit",
                "runtime request identifier limit exceeded",
                "validate",
            ));
        }
        Ok(())
    }

    fn expiration(ttl_ms: u64) -> (Instant, u64) {
        let expires_at_ms = epoch_ms().saturating_add(ttl_ms);
        (
            Instant::now() + Duration::from_millis(ttl_ms),
            expires_at_ms,
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

    fn protocol_data(error: ProtocolError) -> ErrorData {
        ErrorData::new("protocol.runtime", error.to_string(), "execute")
    }

    fn runtime_os(code: &str, error: &io::Error, phase: &str) -> ErrorData {
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

    fn signal_name(signal: i32) -> &'static str {
        match signal {
            libc::SIGTERM => "SIGTERM",
            libc::SIGKILL => "SIGKILL",
            libc::SIGSEGV => "SIGSEGV",
            libc::SIGABRT => "SIGABRT",
            libc::SIGXCPU => "SIGXCPU",
            libc::SIGXFSZ => "SIGXFSZ",
            libc::SIGPIPE => "SIGPIPE",
            _ => "UNKNOWN",
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn main() {
    sandbox_platform_portable::runtime_main();
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn main() {
    eprintln!("unsupported sandbox runtime host");
    std::process::exit(2);
}
