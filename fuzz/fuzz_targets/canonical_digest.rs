#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = sandsurf_format::identity_digest(&value);
        let _ = sandsurf_format::sandsurf_digest(sandsurf_format::SandsurfDomain::Network, &value);
        let _ = sandsurf_format::sandsurf_digest(sandsurf_format::SandsurfDomain::Operation, &value);
    }
});
