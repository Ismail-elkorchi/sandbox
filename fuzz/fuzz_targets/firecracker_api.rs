#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(target_os = "linux")]
    if data.len() <= 1024 * 1024 {
        for status in [200, 204] {
            let _ = sandsurf_machine::firecracker::read_api_response(std::io::Cursor::new(data), status);
        }
    }
});
