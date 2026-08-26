#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_policy::normalize_target_path;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = normalize_target_path(path);
    }
});
