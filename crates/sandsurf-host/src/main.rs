use sandsurf_host::api::{HOST_API_VERSION, HostRequest};
use sandsurf_host::service::{host_call, serve_host, serve_sandbox_guardian};
use sandsurf_protocol::SandboxId;
use std::io::{self, Read};
use std::path::PathBuf;

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
        "request" => {
            let mut bytes = Vec::new();
            io::stdin().take(1024 * 1024).read_to_end(&mut bytes)?;
            let (version, request): (u16, HostRequest) = serde_json::from_slice(&bytes)?;
            if version != HOST_API_VERSION {
                return Err("host API version mismatch".into());
            }
            serde_json::to_writer(
                io::stdout(),
                &(HOST_API_VERSION, host_call(&directory, request)?),
            )?;
        }
        _ => return Err("invalid Sandsurf host mode".into()),
    }
    Ok(())
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
                lpServiceName: SERVICE_NAME.get().expect("service name").as_ptr().cast_mut(),
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
