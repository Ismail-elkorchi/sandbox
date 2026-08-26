#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    if let Ok(path) = std::str::from_utf8(data)
        && Path::new(path).is_absolute()
    {
        let _ = sandbox_platform::prepare_host_path(Path::new(path), true);
        let _ = sandbox_platform::prepare_host_path(Path::new(path), false);
    }
});
