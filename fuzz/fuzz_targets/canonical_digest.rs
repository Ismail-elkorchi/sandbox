#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = sandbox_digest::identity_digest(&value);
        let _ = sandbox_digest::policy_digest(&value);
        let _ = sandbox_digest::execution_digest(&value);
    }
});
