#![no_main]

use libfuzzer_sys::fuzz_target;
use sandsurf_protocol::{GuestServiceRequest, GuestServiceResponse, MAX_CONTROL_BYTES};

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_CONTROL_BYTES {
        return;
    }
    let _ = serde_json::from_slice::<GuestServiceRequest>(data);
    let _ = serde_json::from_slice::<GuestServiceResponse>(data);
});
