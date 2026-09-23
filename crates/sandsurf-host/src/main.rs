use sandsurf_host::api::{HostRequest, HostResponse};
use sandsurf_host::service::{HostError, host_call, serve_host, serve_sandbox_guardian};
use sandsurf_protocol::{RuntimeResponse, SandboxId};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

const MAX_BRIDGE_BYTES: usize = 1024 * 1024;
const MAX_BRIDGE_PENDING: usize = 64;
const BRIDGE_WORKERS: usize = 8;
const BRIDGE_VERSION: u16 = 2;

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
    #[cfg(target_os = "linux")]
    if mode == "--linux-vmm-launcher" {
        std::process::exit(sandbox_launcher_linux::vmm_launcher_main());
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-vmm-isolated" {
        std::process::exit(sandbox_launcher_linux::vmm_isolated_main(arguments.next()));
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-kernel-probe" {
        std::process::exit(sandbox_launcher_linux::probe_main());
    }
    #[cfg(target_os = "linux")]
    if mode == "--linux-namespace-probe" {
        std::process::exit(sandbox_launcher_linux::namespace_probe_main());
    }
    let values = arguments.collect::<Vec<_>>();
    let directory = argument(&values, "--directory")?;
    match mode.as_str() {
        "serve" => serve_host(&directory, std::env::current_exe()?)?,
        #[cfg(target_os = "windows")]
        "service" => {
            let service_name = text_argument(&values, "--service-name")?;
            windows_service::run(directory, service_name, std::env::current_exe()?)?;
        }
        "guardian" => {
            let sandbox: SandboxId = argument(&values, "--sandbox")?
                .into_os_string()
                .into_string()
                .map_err(|_| "sandbox identity is not UTF-8")?
                .try_into()?;
            serve_sandbox_guardian(&directory, sandbox)?;
        }
        "bridge" => run_bridge(&directory)?,
        _ => return Err("invalid Sandsurf host mode".into()),
    }
    Ok(())
}

fn run_bridge(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = io::stdin();
    let mut output = io::stdout();
    bridge_loop(directory, &mut input, &mut output)
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

fn bridge_response(
    handler: &impl Fn(HostRequest) -> Result<HostResponse, HostError>,
    bytes: &[u8],
) -> Vec<u8> {
    let parsed = serde_json::from_slice::<(u64, u16, HostRequest)>(bytes);
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
    let (response, data) = match response {
        HostResponse::Runtime {
            response: RuntimeResponse::Output { page },
        } => match page.into_binary_parts() {
            Ok((page, chunks)) => (
                HostResponse::Runtime {
                    response: RuntimeResponse::OutputMetadata { page },
                },
                chunks.into_iter().flatten().collect::<Vec<_>>(),
            ),
            Err(error) => (
                HostResponse::Rejected {
                    category: "protocol".into(),
                    message: error.to_string(),
                },
                Vec::new(),
            ),
        },
        response => (response, Vec::new()),
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

#[cfg(target_os = "windows")]
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
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::NO_ERROR;
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

    pub(super) fn run(
        directory: PathBuf,
        service_name: String,
        executable: PathBuf,
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
            return;
        }
        report(SERVICE_START_PENDING, 0, 10_000);
        report(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0);
        let result = serve_host(
            DIRECTORY.get().expect("service directory"),
            EXECUTABLE.get().expect("service executable").clone(),
        );
        report(SERVICE_STOPPED, 0, 0);
        if let Err(error) = result {
            eprintln!("sandsurf-host service: {error}");
        }
    }

    // SAFETY: this exact ABI is required by RegisterServiceCtrlHandlerW and the
    // callback receives its scalar control code directly from the SCM.
    unsafe extern "system" fn control_handler(control: u32) {
        if control != SERVICE_CONTROL_STOP {
            return;
        }
        report(SERVICE_STOP_PENDING, 0, 10_000);
        if let Some(directory) = DIRECTORY.get().cloned() {
            std::thread::spawn(move || {
                let _ = host_call(&directory, HostRequest::StopService);
            });
        }
    }

    fn report(state: u32, accepted: u32, wait_hint: u32) {
        let Some(raw) = STATUS.get().copied() else {
            return;
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
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

    fn decode_response(bytes: &[u8]) -> (u64, u16, HostResponse, &[u8]) {
        let json_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let (id, version, response) = serde_json::from_slice(&bytes[4..4 + json_len]).unwrap();
        (id, version, response, &bytes[4 + json_len..])
    }

    fn request(bytes: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(bytes);
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
        use sandsurf_protocol::{Counter, EvidenceChunk, EvidencePage, Stream, bytes_digest};
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
    fn bridge_rejects_unbounded_frames_before_allocating() {
        let input = u32::try_from(MAX_BRIDGE_BYTES + 1).unwrap().to_le_bytes();
        assert!(bridge_loop(Path::new("/absent"), &mut input.as_slice(), &mut Vec::new()).is_err());
    }
}
