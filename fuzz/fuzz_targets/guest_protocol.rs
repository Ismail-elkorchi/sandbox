#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_guest::{GuestRequest, GuestResponse};

fuzz_target!(|data: &[u8]| {
    if data.len() > sandbox_guest::MAX_GUEST_FRAME {
        return;
    }
    let _ = serde_json::from_slice::<GuestRequest>(data);
    let _ = serde_json::from_slice::<GuestResponse>(data);
});
