#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(values) = serde_json::from_slice::<Vec<(String, String)>>(data) {
        let _ = sandbox_launcher_windows::encode_windows_environment(&values);
    }
});
