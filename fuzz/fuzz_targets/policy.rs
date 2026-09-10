#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_policy::{SessionOptions, normalize_run, normalize_session};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(options) = serde_json::from_slice::<SessionOptions>(data) {
        let _ = normalize_session(options);
    }
    if let Ok(options) = serde_json::from_slice(data) {
        let _ = normalize_run(options);
    }
});
