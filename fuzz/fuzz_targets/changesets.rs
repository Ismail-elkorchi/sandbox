#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_vm::{ChangeSet, validate_change_set};

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 * 1024 {
        return;
    }
    if let Ok(change_set) = serde_json::from_slice::<ChangeSet>(data) {
        let _ = validate_change_set(&change_set);
    }
});
