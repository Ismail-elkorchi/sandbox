#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_image::ImageManifest;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(manifest) = serde_json::from_slice::<ImageManifest>(data) {
        let _ = sandbox_image::validate_image_manifest(&manifest);
    }
});
