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
