use sandsurf_host::api::{HostRequest, HostResponse};
use sandsurf_host::service::{HostError, host_call, serve_host, serve_machine_guardian};
use sandsurf_protocol::MachineId;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

const MAX_BRIDGE_BYTES: usize =
    sandsurf_protocol::MAX_RPC_DATA_BYTES + sandsurf_protocol::MAX_CONTROL_BYTES + 4;
const MAX_BRIDGE_PENDING: usize = 64;
const BRIDGE_WORKERS: usize = 8;
const BRIDGE_VERSION: u16 = 1;

fn main() {
    if let Err(error) = run() {
        eprintln!("sandsurf-host: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("missing Sandsurf host mode")?;
    #[cfg(target_os = "macos")]
    let (mode, native_worker) = if mode == "--broker-worker" {
        let role = sandsurf_native::resource_broker::WorkerKind::parse(
            &arguments
                .next()
                .and_then(|v| v.into_string().ok())
                .ok_or("missing owned worker role")?,
        )?;
        let mode = role
            .host_mode()
            .ok_or("VM workers must use the installed VMM executable")?;
        let budget = sandsurf_native::resource_broker::macos::enter_worker()?;
        (mode.to_owned(), Some((role, budget)))
    } else {
        (mode, None)
    };
    #[cfg(target_os = "linux")]
    if mode == "--linux-network-sockets" {
        if arguments.next().is_some() {
            return Err("native socket owner accepts no arguments".into());
        }
        sandsurf_native::network_sockets::serve()?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-vmm-launcher" {
        std::process::exit(sandsurf_machine::launcher::vmm_launcher_main());
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-vmm-isolated" {
        std::process::exit(sandsurf_machine::launcher::vmm_isolated_main(
            arguments.next(),
        ));
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-kernel-probe" {
        std::process::exit(sandsurf_machine::launcher::probe_main());
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-namespace-probe" {
        std::process::exit(sandsurf_machine::launcher::namespace_probe_main());
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-network-namespace-probe" {
        std::process::exit(sandsurf_machine::launcher::network_namespace_probe_main());
    }
    let values = arguments.collect::<Vec<_>>();
    let directory = argument(&values, "--directory")?;
    #[cfg(windows)]
    match mode.as_str() {
        "serve" => windows_pool(sandsurf_native::service_pool::ServicePool::Api)?,
        "supervise" => windows_pool(sandsurf_native::service_pool::ServicePool::Supervisor)?,
        _ => {}
    };
    match mode.as_str() {
        "storage-path" => {
            let machine: MachineId = text_argument(&values, "--machine")?.try_into()?;
            if !directory.is_absolute() {
                return Err("storage directory must be absolute".into());
            }
            println!(
                "{}",
                directory
                    .join("machines")
                    .join(sandsurf_native::storage::object_name(machine.as_str()))
                    .display()
            );
        }
        "storage-volume" => {
            let root = if values.iter().any(|value| value == "--machine") {
                let machine: MachineId = text_argument(&values, "--machine")?.try_into()?;
                directory
                    .join("machines")
                    .join(sandsurf_native::storage::object_name(machine.as_str()))
            } else {
                directory
            };
            match sandsurf_native::volume::inspect(&root) {
                Ok(volume) => println!(
                    "{}",
                    serde_json::json!({"formatVersion":1,"path":root,"kind":"bounded","device":volume.device,"bytes":volume.bytes})
                ),
                Err(error) => {
                    println!(
                        "{}",
                        serde_json::json!({"formatVersion":1,"path":root,"kind":"unsupported","reason":error.to_string()})
                    );
                    std::process::exit(2);
                }
            }
        }
        "image-worker" => {
            let pool = directory.join("image-workers/.lease");
            #[cfg(target_os = "linux")]
            let lease = {
                if !sandsurf_native::service_pool::ServicePool::Images.current(&directory)? {
                    return Err("image worker outside its owned unit".into());
                }
                sandsurf_native::storage::disk_lease(&pool)?
            };
            #[cfg(target_os = "macos")]
            let lease = {
                if native_worker.map(|v| v.0)
                    != Some(sandsurf_native::resource_broker::WorkerKind::Images)
                {
                    return Err("image worker requires the installed native owner".into());
                }
                sandsurf_native::resource_broker::macos::receive_image_lease(&pool)?
            };
            #[cfg(windows)]
            let lease = sandsurf_native::owned_windows::OwnedWorker::receive_image_lease(
                text_argument(&values, "--owned-lease")?.parse()?,
                &pool,
            )?;
            sandsurf_host::image_worker::serve(
                &directory,
                text_argument(&values, "--operation")?.try_into()?,
                lease,
            )?;
        }
        "serve" => {
            #[cfg(target_os = "linux")]
            if !managed_pool(
                &directory,
                sandsurf_native::service_pool::ServicePool::Api,
                "serve",
            )? {
                return Ok(());
            }
            #[cfg(target_os = "macos")]
            if !managed_pool(
                &directory,
                sandsurf_native::service_pool::ServicePool::Api,
                native_worker,
            )? {
                return Ok(());
            }
            serve_host(&directory, std::env::current_exe()?)?;
        }
        "supervise" => {
            #[cfg(target_os = "linux")]
            if !managed_pool(
                &directory,
                sandsurf_native::service_pool::ServicePool::Supervisor,
                "supervise",
            )? {
                return Ok(());
            }
            #[cfg(target_os = "macos")]
            if !managed_pool(
                &directory,
                sandsurf_native::service_pool::ServicePool::Supervisor,
                native_worker,
            )? {
                return Ok(());
            }
            sandsurf_host::supervision::serve(&directory, std::env::current_exe()?)?;
        }
        "supervisor-status" => {
            match sandsurf_host::supervision::call(
                &directory,
                sandsurf_host::supervision::Request::Inspect,
            ) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    std::process::exit(2)
                }
                Err(error) => return Err(error.into()),
            }
        }
        "stop-supervisor" => sandsurf_host::supervision::call(
            &directory,
            sandsurf_host::supervision::Request::Shutdown,
        )?,
        #[cfg(target_os = "windows")]
        "service" => {
            let service_name = text_argument(&values, "--service-name")?;
            let role = match text_argument(&values, "--role")?.as_str() {
                "host" => windows_service::Role::Host,
                "supervisor" => windows_service::Role::Supervisor,
                _ => return Err("invalid native service role".into()),
            };
            windows_service::run(directory, service_name, std::env::current_exe()?, role)?;
        }
        "qualification-requirements" => {
            println!(
                "{}",
                serde_json::to_string(&sandsurf_host::qualification::requirements())?
            );
        }
        "qualification-config" => {
            #[cfg(target_os = "linux")]
            {
                let machine: MachineId = text_argument(&values, "--machine")?.try_into()?;
                let machine_root = directory
                    .join("machines")
                    .join(sandsurf_native::storage::object_name(machine.as_str()));
                let config = sandsurf_host::linux::read_config(
                    &machine_root.join("guardian/config.json"),
                    &machine,
                )?;
                println!(
                    "{}",
                    serde_json::to_string(&sandsurf_host::linux::qualification_configuration(
                        &config,
                        &machine_root
                    )?)?
                );
            }
            #[cfg(not(target_os = "linux"))]
            return Err("native hardware qualification is unavailable on this platform".into());
        }
        "qualification-accept" => {
            let run_path = argument(&values, "--run")?;
            let file = sandsurf_native::local::open_private_file(
                &run_path,
                sandsurf_native::PrivateFileAccess::ReadOnly,
            )?;
            let mut bytes = Vec::new();
            file.take(65537).read_to_end(&mut bytes)?;
            if bytes.len() > 65536 {
                return Err("hardware run record exceeds bound".into());
            }
            let run = serde_json::from_slice(&bytes)?;
            let evidence = argument(&values, "--evidence")?;
            let operator = text_argument(&values, "--operator")?;
            let record =
                sandsurf_host::qualification::accept_linux(&directory, run, &evidence, &operator)?;
            println!("{}", serde_json::to_string(&record)?);
        }
        "guardian" => {
            #[cfg(target_os = "macos")]
            if native_worker.is_none_or(|(kind, _)| {
                kind != sandsurf_native::resource_broker::WorkerKind::Guardian
            }) {
                return Err("guardian requires its owned resource-broker entry".into());
            }
            let machine: MachineId = argument(&values, "--machine")?
                .into_os_string()
                .into_string()
                .map_err(|_| "machine identity is not UTF-8")?
                .try_into()?;
            serve_machine_guardian(&directory, machine)?;
        }
        "bridge" => run_bridge(&directory)?,
        "event-stream" | "console-stream" => {
            let machine: MachineId = argument(&values, "--machine")?
                .into_os_string()
                .into_string()
                .map_err(|_| "machine identity is not UTF-8")?
                .try_into()?;
            let after = argument(&values, "--after")?
                .to_str()
                .ok_or("invalid event cursor")?
                .parse::<u64>()?
                .try_into()?;
            let maximum = argument(&values, "--maximum")?
                .to_str()
                .ok_or("invalid event page size")?
                .parse::<u32>()?;
            let endpoint = match host_call(
                &directory,
                HostRequest::OpenObservationStream {
                    machine_id: machine.clone(),
                },
            )? {
                HostResponse::ObservationStream { endpoint } => endpoint,
                HostResponse::Rejected { category, message } => {
                    return Err(
                        format!("observation stream rejected ({category}): {message}").into(),
                    );
                }
                _ => return Err("host returned an invalid observation stream endpoint".into()),
            };
            let subscription = if mode == "console-stream" {
                sandsurf_protocol::GuardianRequest::SubscribeConsole {
                    machine_id: machine,
                    generation: text_argument(&values, "--generation")?
                        .parse::<u64>()?
                        .try_into()?,
                    after,
                    maximum,
                }
            } else {
                sandsurf_protocol::GuardianRequest::SubscribeEvents {
                    machine_id: machine,
                    after,
                    maximum: maximum.try_into()?,
                }
            };
            let mut stream =
                sandsurf_host::guardian::ObservationStream::open(&endpoint, subscription)?;
            observation_bridge_loop(&mut io::stdin(), &mut io::stdout(), &mut || {
                stream.read_page()
            })?;
        }
        _ => return Err("invalid Sandsurf host mode".into()),
    }
    Ok(())
}

#[cfg(windows)]
fn windows_pool(pool: sandsurf_native::service_pool::ServicePool) -> io::Result<()> {
    sandsurf_native::process_budget::windows::JobEnvelope::install_factory_current(
        pool.worker_kind(),
        pool.process_budget(),
    )
}

#[cfg(target_os = "macos")]
fn managed_pool(
    directory: &Path,
    pool: sandsurf_native::service_pool::ServicePool,
    worker: Option<(
        sandsurf_native::resource_broker::WorkerKind,
        sandsurf_native::process_budget::ProcessBudget,
    )>,
) -> io::Result<bool> {
    if let Some((kind, budget)) = worker {
        if kind != pool.worker_kind()
            || budget != sandsurf_native::resource_broker::worker_budget(pool.process_budget())?
        {
            return Err(io::Error::other(
                "native service pool budget differs from host admission",
            ));
        }
        return Ok(true);
    }
    sandsurf_native::local::ensure_private_directory(directory)?;
    let root = sandsurf_native::local::canonical_private_directory(directory)?;
    let endpoint = root.join(match pool {
        sandsurf_native::service_pool::ServicePool::Api => "api",
        sandsurf_native::service_pool::ServicePool::Supervisor => "supervision",
        sandsurf_native::service_pool::ServicePool::Images => {
            return Err(io::Error::other(
                "image workers do not publish service endpoints",
            ));
        }
    });
    let mut owned = sandsurf_native::resource_broker::macos::launch(
        pool.worker_kind(),
        pool.process_budget(),
        &["--directory".into(), root.clone().into_os_string()],
        std::process::Stdio::null(),
        std::process::Stdio::inherit(),
        std::process::Stdio::inherit(),
    )?;
    // The broker receipt proves native resource admission, not that this
    // worker acquired the exclusive service endpoint. Never accept an older
    // endpoint owner's response as readiness of a newly launched worker.
    if let Err(error) = wait_service_owner(&endpoint, owned.process_id(), || {
        owned.try_wait().map(|exit| exit.is_none())
    }) {
        owned.terminate()?;
        return Err(error);
    }
    drop(owned);
    Ok(false)
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn wait_service_owner(
    endpoint: &Path,
    original: u32,
    mut running: impl FnMut() -> io::Result<bool>,
) -> io::Result<()> {
    use sandsurf_native::local::LocalConnection;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if !running()? {
            return Err(io::Error::other(
                "native service exited before endpoint admission",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native service did not acquire its endpoint",
            ));
        }
        match LocalConnection::connect(endpoint, remaining.min(Duration::from_millis(200))) {
            Ok(connection) => {
                if connection.peer_process()? != original {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "service endpoint belongs to another owner",
                    ));
                }
                if !running()? {
                    return Err(io::Error::other(
                        "native service exited during endpoint admission",
                    ));
                }
                return Ok(());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(Duration::from_millis(10).min(remaining));
    }
}

#[cfg(target_os = "linux")]
fn managed_pool(
    directory: &Path,
    pool: sandsurf_native::service_pool::ServicePool,
    mode: &str,
) -> io::Result<bool> {
    sandsurf_native::local::ensure_private_directory(directory)?;
    let root = sandsurf_native::local::canonical_private_directory(directory)?;
    if pool.current(&root)? {
        return Ok(true);
    }
    let unit = pool.unit(&root)?;
    let mut start = std::process::Command::new("systemd-run");
    start.args([
        "--user",
        "--quiet",
        "--collect",
        "--service-type=exec",
        "--unit",
        &unit,
    ]);
    for property in pool.properties() {
        start.arg(format!("--property={property}"));
    }
    start
        .arg(std::env::current_exe()?)
        .arg(mode)
        .arg("--directory")
        .arg(root);
    sandsurf_native::resources::run_bounded(start)?;
    Ok(false)
}

fn run_bridge(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = io::stdin();
    let mut output = io::stdout();
    bridge_loop(directory, &mut input, &mut output)
}

fn observation_bridge_loop(
    input: &mut impl Read,
    output: &mut impl Write,
    next: &mut impl FnMut() -> sandsurf_host::guardian::Result<sandsurf_protocol::RuntimeResponse>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let response = next()?;
        let cursor = match &response {
            sandsurf_protocol::RuntimeResponse::Events { page } => page.cursor,
            sandsurf_protocol::RuntimeResponse::Console { page } => page.cursor,
            _ => return Err("invalid observation bridge response".into()),
        };
        let (response, binary) = HostResponse::Runtime { response }.into_wire_parts()?;
        let data = binary
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let bytes = bridge_payload(1, &response, &data);
        if bytes.len() > MAX_BRIDGE_BYTES {
            return Err("observation page exceeds bridge bound".into());
        }
        output.write_all(&u32::try_from(bytes.len())?.to_le_bytes())?;
        output.write_all(&bytes)?;
        output.flush()?;
        // Credit acknowledges transport progress only, not receipt acceptance
        // or permission to release retained output. EOF detaches the observer.
        let mut credit = [0_u8; 8];
        if input.read(&mut credit[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut credit[1..])?;
        if u64::from_le_bytes(credit) != cursor.get() {
            return Err("observation bridge credit differs from delivered cursor".into());
        }
    }
}

fn bridge_loop(
    directory: &Path,
    input: &mut (impl Read + Send),
    output: &mut (impl Write + Send),
) -> Result<(), Box<dyn std::error::Error>> {
    bridge_loop_with_handler(input, output, &|request| host_call(directory, request))
}

fn bridge_loop_with_handler(
    input: &mut (impl Read + Send),
    output: &mut (impl Write + Send),
    handler: &(impl Fn(HostRequest) -> Result<HostResponse, HostError> + Sync),
) -> Result<(), Box<dyn std::error::Error>> {
    std::thread::scope(|scope| {
        let (jobs, receiver) = mpsc::sync_channel::<Vec<u8>>(MAX_BRIDGE_PENDING);
        let receiver = Arc::new(Mutex::new(receiver));
        let (responses, completed) = mpsc::sync_channel::<Vec<u8>>(MAX_BRIDGE_PENDING);
        for _ in 0..BRIDGE_WORKERS {
            let receiver = Arc::clone(&receiver);
            let responses = responses.clone();
            scope.spawn(move || {
                loop {
                    let job = receiver.lock().expect("bridge receiver poisoned").recv();
                    let Ok(job) = job else { break };
                    if responses.send(bridge_response(handler, &job)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(responses);
        let writer = scope.spawn(move || -> io::Result<()> {
            for bytes in completed {
                let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
                if bytes.is_empty() || bytes.len() > MAX_BRIDGE_BYTES {
                    return Err(io::Error::other("bridge response exceeds its byte bound"));
                }
                output.write_all(&length.to_le_bytes())?;
                output.write_all(&bytes)?;
                output.flush()?;
            }
            Ok(())
        });
        let read_result = bridge_read(input, &jobs);
        drop(jobs);
        let write_result = writer.join().expect("bridge writer panicked");
        read_result?;
        write_result?;
        Ok(())
    })
}

fn bridge_read(input: &mut impl Read, jobs: &mpsc::SyncSender<Vec<u8>>) -> io::Result<()> {
    loop {
        let mut length = [0_u8; 4];
        if input.read(&mut length[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut length[1..])?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_BRIDGE_BYTES {
            return Err(io::Error::other("bridge request exceeds its byte bound"));
        }
        let mut bytes = vec![0_u8; length];
        input.read_exact(&mut bytes)?;
        jobs.send(bytes)
            .map_err(|_| io::Error::other("bridge workers stopped"))?;
    }
}

fn parse_bridge_request(
    bytes: &[u8],
) -> Result<(u64, u16, HostRequest), Box<dyn std::error::Error>> {
    let header: [u8; 4] = bytes
        .get(..4)
        .ok_or("bridge metadata length missing")?
        .try_into()?;
    let length = u32::from_le_bytes(header) as usize;
    if length > sandsurf_protocol::MAX_CONTROL_BYTES {
        return Err("bridge metadata exceeds control bound".into());
    }
    let json = bytes
        .get(4..4 + length)
        .ok_or("bridge metadata is incomplete")?;
    let (id, version, mut wire): (u64, u16, sandsurf_protocol::RequestEnvelope<HostRequest>) =
        serde_json::from_slice(json)?;
    let binary = &bytes[4 + length..];
    let data = if let Some(metadata) = wire.descriptor()? {
        let mut position = 0;
        let mut chunks = Vec::with_capacity(metadata.len());
        for chunk in metadata {
            let end = position + chunk.length as usize;
            chunks.push(
                binary
                    .get(position..end)
                    .ok_or("bridge data is incomplete")?
                    .to_vec(),
            );
            position = end;
        }
        if position != binary.len() {
            return Err("bridge data coverage differs from descriptor".into());
        }
        Some(chunks)
    } else {
        if !binary.is_empty() {
            return Err("bridge data is unexpected".into());
        }
        None
    };
    Ok((id, version, wire.assemble(data)?))
}

fn bridge_response(
    handler: &impl Fn(HostRequest) -> Result<HostResponse, HostError>,
    bytes: &[u8],
) -> Vec<u8> {
    let parsed = parse_bridge_request(bytes);
    let id = parsed.as_ref().map_or(0, |value| value.0);
    let response = match parsed {
        Ok((id, BRIDGE_VERSION, request)) if id > 0 && id <= 9_007_199_254_740_991 => {
            match handler(request) {
                Ok(response) => response,
                Err(error) => HostResponse::Rejected {
                    category: if matches!(error, HostError::EndpointUnavailable(_)) {
                        "unavailable"
                    } else {
                        "transport"
                    }
                    .into(),
                    message: error.to_string(),
                },
            }
        }
        Ok(_) => HostResponse::Rejected {
            category: "protocol".into(),
            message: "bridge version or request identity mismatch".into(),
        },
        Err(error) => HostResponse::Rejected {
            category: "protocol".into(),
            message: format!("invalid bridge request: {error}"),
        },
    };
    let (response, data) = match response.into_wire_parts() {
        Ok((response, bytes)) => (
            response,
            bytes
                .unwrap_or_default()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        ),
        Err(error) => (
            HostResponse::Rejected {
                category: "protocol".into(),
                message: error.to_string(),
            },
            Vec::new(),
        ),
    };
    let result = bridge_payload(id, &response, &data);
    if result.len() <= MAX_BRIDGE_BYTES {
        result
    } else {
        bridge_payload(
            id,
            &HostResponse::Rejected {
                category: "protocol".into(),
                message: "bridge response exceeds its byte bound".into(),
            },
            &[],
        )
    }
}

fn bridge_payload(id: u64, response: &HostResponse, data: &[u8]) -> Vec<u8> {
    let json =
        serde_json::to_vec(&(id, BRIDGE_VERSION, response)).expect("bridge response serialization");
    let mut payload = Vec::with_capacity(4 + json.len() + data.len());
    payload.extend_from_slice(
        &u32::try_from(json.len())
            .expect("bounded JSON")
            .to_le_bytes(),
    );
    payload.extend_from_slice(&json);
    payload.extend_from_slice(data);
    payload
}

fn text_argument(values: &[std::ffi::OsString], name: &str) -> Result<String, &'static str> {
    argument(values, name)?
        .into_os_string()
        .into_string()
        .map_err(|_| "required argument must be UTF-8")
}

#[cfg(target_os = "windows")]
mod windows_service {
    use super::*;
    use std::ptr::{null, null_mut};
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    };
    use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
        SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
        StartServiceCtrlDispatcherW,
    };

    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    static EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
    static SERVICE_NAME: OnceLock<Vec<u16>> = OnceLock::new();
    static STATUS: OnceLock<usize> = OnceLock::new();
    static FAILED: AtomicBool = AtomicBool::new(false);
    #[derive(Clone, Copy)]
    pub(super) enum Role {
        Host,
        Supervisor,
    }
    static ROLE: OnceLock<Role> = OnceLock::new();

    pub(super) fn run(
        directory: PathBuf,
        service_name: String,
        executable: PathBuf,
        role: Role,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if service_name.is_empty() || service_name.encode_utf16().count() > 256 {
            return Err("Windows service name is malformed".into());
        }
        DIRECTORY
            .set(directory)
            .map_err(|_| "Windows service directory was already initialized")?;
        EXECUTABLE
            .set(executable)
            .map_err(|_| "Windows service executable was already initialized")?;
        ROLE.set(role)
            .map_err(|_| "Windows service role was already initialized")?;
        let mut name = service_name.encode_utf16().collect::<Vec<_>>();
        name.push(0);
        SERVICE_NAME
            .set(name)
            .map_err(|_| "Windows service name was already initialized")?;
        let entries = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: SERVICE_NAME
                    .get()
                    .expect("service name")
                    .as_ptr()
                    .cast_mut(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: entries is a terminated service table that remains live while
        // the dispatcher blocks, and service_main has the required ABI.
        if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        if FAILED.load(Ordering::Acquire) {
            return Err(
                "Windows service failed; see its native service status and diagnostics".into(),
            );
        }
        Ok(())
    }

    // SAFETY: this exact ABI and parameter layout are required by the SCM
    // service-table callback contract; the callback does not dereference them.
    unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
        let name = SERVICE_NAME.get().map_or(null(), |value| value.as_ptr());
        // SAFETY: SCM invokes this callback after the service table has been accepted;
        // name is its stable NUL-terminated service name.
        let handle = unsafe { RegisterServiceCtrlHandlerW(name, Some(control_handler)) };
        if handle.is_null() || STATUS.set(handle as usize).is_err() {
            FAILED.store(true, Ordering::Release);
            return;
        }
        report(SERVICE_START_PENDING, 0, 10_000, 0);
        let directory = DIRECTORY.get().expect("service directory");
        let executable = EXECUTABLE.get().expect("service executable").clone();
        let pool = match ROLE.get().expect("service role") {
            Role::Host => sandsurf_native::service_pool::ServicePool::Api,
            Role::Supervisor => sandsurf_native::service_pool::ServicePool::Supervisor,
        };
        if let Err(error) = super::windows_pool(pool) {
            eprintln!("sandsurf service resource envelope: {error}");
            FAILED.store(true, Ordering::Release);
            report(SERVICE_STOPPED, 0, 0, 1);
            return;
        }
        report(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0);
        let result = match ROLE.get().expect("service role") {
            Role::Host => serve_host(directory, executable),
            Role::Supervisor => {
                sandsurf_host::supervision::serve(directory, executable).map_err(HostError::Io)
            }
        };
        if let Err(error) = result {
            eprintln!("sandsurf-host service: {error}");
            FAILED.store(true, Ordering::Release);
            report(SERVICE_STOPPED, 0, 0, 1);
        } else {
            report(SERVICE_STOPPED, 0, 0, 0);
        }
    }

    // SAFETY: this exact ABI is required by RegisterServiceCtrlHandlerW and the
    // callback receives its scalar control code directly from the SCM.
    unsafe extern "system" fn control_handler(control: u32) {
        if control != SERVICE_CONTROL_STOP {
            return;
        }
        report(SERVICE_STOP_PENDING, 0, 10_000, 0);
        if let Some(directory) = DIRECTORY.get().cloned() {
            std::thread::spawn(move || match ROLE.get().expect("service role") {
                Role::Host => {
                    let _ = host_call(&directory, HostRequest::StopService);
                }
                Role::Supervisor => {
                    let _ = sandsurf_host::supervision::call(
                        &directory,
                        sandsurf_host::supervision::Request::Shutdown,
                    );
                }
            });
        }
    }

    fn report(state: u32, accepted: u32, wait_hint: u32, failure: u32) {
        let Some(raw) = STATUS.get().copied() else {
            return;
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: if failure == 0 {
                NO_ERROR
            } else {
                ERROR_SERVICE_SPECIFIC_ERROR
            },
            dwServiceSpecificExitCode: failure,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        // SAFETY: STATUS contains the live handle returned for this service and
        // status is initialized for the duration of the call.
        let _ = unsafe { SetServiceStatus(raw as SERVICE_STATUS_HANDLE, &status) };
    }
}

fn argument(values: &[std::ffi::OsString], name: &str) -> Result<PathBuf, &'static str> {
    let index = values
        .iter()
        .position(|value| value == name)
        .ok_or("required argument is missing")?;
    values
        .get(index + 1)
        .cloned()
        .map(PathBuf::from)
        .ok_or("required argument value is missing")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn service_admission_requires_the_retained_original_endpoint_owner() {
        use sandsurf_native::local::{LocalListener, create_private_directory};
        let root = std::env::temp_dir().join(format!(
            "ss-startup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_private_directory(&root).unwrap();
        let listener = LocalListener::bind(&root).unwrap();
        std::thread::scope(|scope| {
            let (finished, observations) = std::sync::mpsc::channel();
            let listening = &listener;
            let accept = scope.spawn(move || {
                let mut connections = Vec::new();
                for _ in 0..3 {
                    connections.push(listening.accept(std::time::Duration::from_secs(2)).unwrap());
                }
                // Darwin correctly refuses LOCAL_PEERPID once the server closes
                // the connection. Keep the observed owners live, as the actual
                // service does, until all admission checks have completed.
                observations
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                drop(connections);
            });
            wait_service_owner(&root, std::process::id(), || Ok(true)).unwrap();
            assert_eq!(
                wait_service_owner(&root, std::process::id() + 1, || Ok(true))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AlreadyExists,
                "an older service is not admission of a new worker"
            );
            let mut checks = 0;
            assert!(
                wait_service_owner(&root, std::process::id(), || {
                    checks += 1;
                    Ok(checks == 1)
                })
                .is_err(),
                "exit during publication must not report success"
            );
            finished.send(()).unwrap();
            accept.join().unwrap();
        });
        assert!(wait_service_owner(&root, std::process::id(), || Ok(false)).is_err());
        listener.close().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn event_bridge_is_credit_driven_and_eof_only_detaches() {
        let mut credits = 1_u64.to_le_bytes().as_slice().to_vec();
        let mut output = Vec::new();
        let mut reads = 0;
        observation_bridge_loop(&mut credits.as_slice(), &mut output, &mut || {
            reads += 1;
            Ok(sandsurf_protocol::RuntimeResponse::Events {
                page: sandsurf_protocol::RuntimeEventPage {
                    cursor: sandsurf_protocol::Counter::ONE,
                    available: sandsurf_protocol::Counter::ONE,
                    events: Vec::new(),
                },
            })
        })
        .unwrap();
        assert_eq!(reads, 2);
        let mut bytes = output.as_slice();
        for _ in 0..2 {
            let mut length = [0; 4];
            bytes.read_exact(&mut length).unwrap();
            let mut frame = vec![0; u32::from_le_bytes(length) as usize];
            bytes.read_exact(&mut frame).unwrap();
            let (id, version, response, binary) = decode_response(&frame);
            assert_eq!((id, version), (1, BRIDGE_VERSION));
            assert!(matches!(
                response,
                HostResponse::Runtime {
                    response: sandsurf_protocol::RuntimeResponse::Events { .. }
                }
            ));
            assert!(binary.is_empty());
        }
        assert!(bytes.is_empty());
        for bad in [2_u64.to_le_bytes().to_vec(), vec![1]] {
            reads = 0;
            credits = bad;
            assert!(
                observation_bridge_loop(&mut credits.as_slice(), &mut Vec::new(), &mut || {
                    reads += 1;
                    Ok(sandsurf_protocol::RuntimeResponse::Events {
                        page: sandsurf_protocol::RuntimeEventPage {
                            cursor: sandsurf_protocol::Counter::ONE,
                            available: sandsurf_protocol::Counter::ONE,
                            events: Vec::new(),
                        },
                    })
                })
                .is_err()
            );
            assert_eq!(reads, 1, "invalid credit cannot request another page");
        }
    }

    #[test]
    fn console_bridge_keeps_binary_bytes_and_eof_never_requests_another_page() {
        let mut output = Vec::new();
        let mut reads = 0;
        observation_bridge_loop(&mut [].as_slice(), &mut output, &mut || {
            reads += 1;
            Ok(sandsurf_protocol::RuntimeResponse::Console {
                page: sandsurf_protocol::ConsolePage {
                    generation: sandsurf_protocol::Counter::ONE,
                    after: sandsurf_protocol::Counter::ZERO,
                    cursor: 3.try_into().unwrap(),
                    available: 3.try_into().unwrap(),
                    bytes: vec![0, 128, 255],
                    loss: None,
                    open: true,
                    capture_failed: false,
                },
            })
        })
        .unwrap();
        assert_eq!(reads, 1);
        let length = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
        assert_eq!(length, output.len() - 4);
        let (_, _, response, binary) = decode_response(&output[4..]);
        assert_eq!(binary, [0, 128, 255]);
        assert!(matches!(
            response,
            HostResponse::Runtime {
                response: sandsurf_protocol::RuntimeResponse::ConsoleMetadata { .. }
            }
        ));
    }

    fn decode_response(bytes: &[u8]) -> (u64, u16, HostResponse, &[u8]) {
        let json_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let (id, version, response) = serde_json::from_slice(&bytes[4..4 + json_len]).unwrap();
        (id, version, response, &bytes[4 + json_len..])
    }

    fn request(bytes: &[u8]) -> Vec<u8> {
        let (id, version, request): (u64, u16, HostRequest) =
            serde_json::from_slice(bytes).unwrap();
        let (wire, data) = sandsurf_protocol::RequestEnvelope::split(request).unwrap();
        let json = serde_json::to_vec(&(id, version, wire)).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
        payload.extend_from_slice(&json);
        payload.extend(data.unwrap_or_default().into_iter().flatten());
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend(payload);
        frame
    }

    #[test]
    fn bridge_reuses_one_process_for_bounded_requests() {
        let mut input =
            request(&serde_json::to_vec(&(1_u64, BRIDGE_VERSION, HostRequest::Inspect)).unwrap());
        input.extend_from_slice(&request(
            &serde_json::to_vec(&(2_u64, BRIDGE_VERSION, HostRequest::Inspect)).unwrap(),
        ));
        let mut output = Vec::new();
        let missing = std::env::temp_dir().join(format!(
            "sandsurf-host-endpoint-absent-{}",
            std::process::id()
        ));
        bridge_loop(&missing, &mut input.as_slice(), &mut output).unwrap();
        let mut cursor = output.as_slice();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let mut length = [0_u8; 4];
            cursor.read_exact(&mut length).unwrap();
            let mut bytes = vec![0_u8; u32::from_le_bytes(length) as usize];
            cursor.read_exact(&mut bytes).unwrap();
            let (id, version, response, data) = decode_response(&bytes);
            assert!(data.is_empty());
            assert_eq!(version, BRIDGE_VERSION);
            ids.push(id);
            assert!(
                matches!(
                    &response,
                    HostResponse::Rejected { category, .. } if category == "unavailable"
                ),
                "bridge should report an absent host endpoint as unavailable: {response:?}"
            );
        }
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
        assert!(cursor.is_empty());
    }

    #[test]
    fn bridge_routes_out_of_order_responses_by_request_identity() {
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::Duration;

        struct GateWriter {
            bytes: Vec<u8>,
            gate: Arc<(Mutex<bool>, Condvar)>,
        }
        impl Write for GateWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                let (lock, wake) = &*self.gate;
                *lock.lock().unwrap() = true;
                wake.notify_all();
                Ok(())
            }
        }

        let mut input =
            request(&serde_json::to_vec(&(1_u64, BRIDGE_VERSION, HostRequest::Inspect)).unwrap());
        input.extend_from_slice(&request(
            &serde_json::to_vec(&(2_u64, BRIDGE_VERSION, HostRequest::StopService)).unwrap(),
        ));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let mut output = GateWriter {
            bytes: Vec::new(),
            gate: Arc::clone(&gate),
        };
        bridge_loop_with_handler(
            &mut input.as_slice(),
            &mut output,
            &|request| match request {
                HostRequest::Inspect => {
                    let (lock, wake) = &*gate;
                    let released = lock.lock().unwrap();
                    let (released, timeout) = wake
                        .wait_timeout_while(released, Duration::from_secs(3), |value| !*value)
                        .unwrap();
                    assert!(
                        !timeout.timed_out() && *released,
                        "second request did not run concurrently"
                    );
                    Ok(HostResponse::Complete)
                }
                HostRequest::StopService => Ok(HostResponse::Complete),
                _ => panic!("unexpected bridge request"),
            },
        )
        .unwrap();
        let mut cursor = output.bytes.as_slice();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let mut length = [0_u8; 4];
            cursor.read_exact(&mut length).unwrap();
            let mut bytes = vec![0_u8; u32::from_le_bytes(length) as usize];
            cursor.read_exact(&mut bytes).unwrap();
            let (id, version, response, data) = decode_response(&bytes);
            assert!(data.is_empty());
            assert_eq!(version, BRIDGE_VERSION);
            assert!(matches!(response, HostResponse::Complete));
            ids.push(id);
        }
        assert_eq!(ids, [2, 1]);
        assert!(cursor.is_empty());
    }

    #[test]
    fn bridge_sends_full_binary_output_without_json_byte_expansion() {
        use sandsurf_protocol::{
            Counter, EvidenceChunk, EvidencePage, RuntimeResponse, Stream, bytes_digest,
        };
        let bytes = vec![255; 64 * 1024];
        let digest = bytes_digest(&bytes);
        let boundary = Counter::try_from(bytes.len() as u64).unwrap();
        let page = EvidencePage {
            after: Counter::ZERO,
            cursor: boundary,
            available: boundary,
            chunks: vec![EvidenceChunk {
                sequence: Counter::ONE,
                offset: Counter::ZERO,
                stream: Stream::Stdout,
                bytes: bytes.clone(),
                bytes_digest: digest.clone(),
                chain_digest: digest,
            }],
        };
        let input =
            request(&serde_json::to_vec(&(1_u64, BRIDGE_VERSION, HostRequest::Inspect)).unwrap());
        let mut output = Vec::new();
        bridge_loop_with_handler(&mut input.as_slice(), &mut output, &|_| {
            Ok(HostResponse::Runtime {
                response: RuntimeResponse::Output { page: page.clone() },
            })
        })
        .unwrap();
        let mut outer = [0; 4];
        output.as_slice().read_exact(&mut outer).unwrap();
        assert_eq!(u32::from_le_bytes(outer) as usize, output.len() - 4);
        let (id, version, response, raw) = decode_response(&output[4..]);
        assert_eq!((id, version), (1, BRIDGE_VERSION));
        let HostResponse::Runtime {
            response: RuntimeResponse::OutputMetadata { page },
        } = response
        else {
            panic!("bridge did not return binary output metadata");
        };
        assert_eq!(
            page.with_binary_parts(vec![raw.to_vec()]).unwrap().chunks[0].bytes,
            bytes
        );
    }

    #[test]
    fn bridge_accepts_a_complete_mebibyte_secret_without_json_expansion() {
        let secret = vec![255; 1024 * 1024];
        let input = request(
            &serde_json::to_vec(&(
                7_u64,
                BRIDGE_VERSION,
                HostRequest::PutSecret {
                    secret_id: "credential".try_into().unwrap(),
                    version: "version-a".try_into().unwrap(),
                    bytes: secret.clone(),
                    operation_id: "publish-credential".try_into().unwrap(),
                    approval_id: "approve-credential".try_into().unwrap(),
                },
            ))
            .unwrap(),
        );
        assert!(input.len() < secret.len() + 4096);
        let mut output = Vec::new();
        bridge_loop_with_handler(&mut input.as_slice(), &mut output, &|request| {
            let HostRequest::PutSecret { bytes, .. } = request else {
                panic!("wrong request")
            };
            assert_eq!(bytes, secret);
            Ok(HostResponse::Complete)
        })
        .unwrap();
        let (id, _, response, data) = decode_response(&output[4..]);
        assert_eq!(id, 7);
        assert!(matches!(response, HostResponse::Complete));
        assert!(data.is_empty());
        let mut corrupt = input[4..].to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(parse_bridge_request(&corrupt).is_err());
    }

    #[test]
    fn bridge_file_and_artifact_reads_keep_dense_bytes_outside_control_json() {
        use sandsurf_protocol::{
            Counter, FileRange, FileReadObservation, FilesystemResponse, GuestServiceResponse,
            bytes_digest,
        };
        let bytes = vec![255; 64 * 1024];
        let request =
            request(&serde_json::to_vec(&(1_u64, BRIDGE_VERSION, HostRequest::Inspect)).unwrap());
        for response in [
            HostResponse::HostBlob {
                offset: Counter::ZERO,
                eof: true,
                digest: bytes_digest(&bytes),
                bytes: bytes.clone(),
            },
            HostResponse::Guest {
                response: GuestServiceResponse::File {
                    response: FilesystemResponse::Read {
                        range: FileRange {
                            offset: 0,
                            eof: true,
                            bytes: bytes.clone(),
                            observation: FileReadObservation {
                                size: bytes.len() as u64,
                                token: bytes_digest(&bytes),
                            },
                        },
                    },
                },
            },
        ] {
            let encoded = bridge_response(&|_| Ok(response.clone()), &request[4..]);
            let (_, _, wire, raw) = decode_response(&encoded);
            assert_eq!(raw, bytes);
            assert!(encoded.len() < bytes.len() + 1024);
            assert_eq!(wire.with_wire_bytes(vec![raw.to_vec()]).unwrap(), response);
        }
    }

    #[test]
    fn bridge_rejects_unbounded_frames_before_allocating() {
        let input = u32::try_from(MAX_BRIDGE_BYTES + 1).unwrap().to_le_bytes();
        assert!(bridge_loop(Path::new("/absent"), &mut input.as_slice(), &mut Vec::new()).is_err());
    }
}
