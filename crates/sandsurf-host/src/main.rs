use sandsurf_host::api::{HOST_API_VERSION, HostRequest, HostResponse};
use sandsurf_host::service::{HostError, host_call, serve_host, serve_sandbox_guardian};
use sandsurf_protocol::SandboxId;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MAX_BRIDGE_BYTES: usize = 1024 * 1024;

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
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    bridge_loop(directory, &mut input, &mut output)
}

fn bridge_loop(
    directory: &Path,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let mut length = [0_u8; 4];
        if input.read(&mut length[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut length[1..])?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_BRIDGE_BYTES {
            return Err("bridge request exceeds its byte bound".into());
        }
        let mut bytes = vec![0_u8; length];
        input.read_exact(&mut bytes)?;
        let response = match serde_json::from_slice::<(u16, HostRequest)>(&bytes) {
            Ok((HOST_API_VERSION, request)) => match host_call(directory, request) {
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
            },
            Ok(_) => HostResponse::Rejected {
                category: "protocol".into(),
                message: "host API version mismatch".into(),
            },
            Err(error) => HostResponse::Rejected {
                category: "protocol".into(),
                message: format!("invalid bridge request: {error}"),
            },
        };
        let bytes = serde_json::to_vec(&(HOST_API_VERSION, response))?;
        let length = u32::try_from(bytes.len())?;
        if bytes.is_empty() || bytes.len() > MAX_BRIDGE_BYTES {
            return Err("bridge response exceeds its byte bound".into());
        }
        output.write_all(&length.to_le_bytes())?;
        output.write_all(&bytes)?;
        output.flush()?;
    }
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

    fn request(bytes: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(bytes);
        frame
    }

    #[test]
    fn bridge_reuses_one_process_for_bounded_requests() {
        let message = serde_json::to_vec(&(HOST_API_VERSION, HostRequest::Inspect)).unwrap();
        let mut input = request(&message);
        input.extend_from_slice(&request(&message));
        let mut output = Vec::new();
        let missing = Path::new("/this-sandsurf-host-endpoint-does-not-exist");
        bridge_loop(missing, &mut input.as_slice(), &mut output).unwrap();
        let mut cursor = output.as_slice();
        for _ in 0..2 {
            let mut length = [0_u8; 4];
            cursor.read_exact(&mut length).unwrap();
            let mut bytes = vec![0_u8; u32::from_le_bytes(length) as usize];
            cursor.read_exact(&mut bytes).unwrap();
            let (_, response): (u16, HostResponse) = serde_json::from_slice(&bytes).unwrap();
            assert!(matches!(
                response,
                HostResponse::Rejected { category, .. } if category == "unavailable"
            ));
        }
        assert!(cursor.is_empty());
    }

    #[test]
    fn bridge_rejects_unbounded_frames_before_allocating() {
        let input = u32::try_from(MAX_BRIDGE_BYTES + 1).unwrap().to_le_bytes();
        assert!(bridge_loop(Path::new("/absent"), &mut input.as_slice(), &mut Vec::new()).is_err());
    }
}
