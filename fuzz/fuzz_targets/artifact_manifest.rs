#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_vm::{ArtifactBundle, validate_artifact_bundle};

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 * 1024 {
        return;
    }
    if let Ok(bundle) = serde_json::from_slice::<ArtifactBundle>(data) {
        let _ = validate_artifact_bundle(&bundle, 16 * 1024 * 1024);
    }
});
