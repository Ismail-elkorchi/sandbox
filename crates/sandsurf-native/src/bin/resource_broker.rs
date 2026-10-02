fn main() {
    #[cfg(target_os = "macos")]
    match sandsurf_native::resource_broker::macos::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("sandsurf-resource-broker: {error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("sandsurf-resource-broker is a Darwin native worker owner");
        std::process::exit(1);
    }
}
