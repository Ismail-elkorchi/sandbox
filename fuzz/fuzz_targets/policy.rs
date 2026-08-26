#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_policy::{
    ProcessOptions, ResourceLimits, SessionOptions, normalize_process, normalize_run,
    normalize_session,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(options) = serde_json::from_slice::<SessionOptions>(data) {
        let _ = normalize_session(options, 8 * 1024 * 1024 * 1024);
    }
    if let Ok(options) = serde_json::from_slice(data) {
        let _ = normalize_run(options, 8 * 1024 * 1024 * 1024);
    }
    if let Ok(options) = serde_json::from_slice::<ProcessOptions>(data) {
        let limits = ResourceLimits {
            wall_time_ms: 60_000,
            cpu_time_ms: Some(60_000),
            memory_bytes: 512 * 1024 * 1024,
            max_processes: 64,
            max_open_files_per_process: Some(256),
            max_single_file_bytes: Some(64 * 1024 * 1024),
            max_output_bytes: 8 * 1024 * 1024,
            termination_grace_ms: 1_000,
        };
        let _ = normalize_process(options, &limits);
    }
});
