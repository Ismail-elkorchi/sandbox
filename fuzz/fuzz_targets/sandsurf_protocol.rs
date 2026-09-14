#![no_main]

use libfuzzer_sys::fuzz_target;
use sandsurf_protocol::{Frame, MAX_CONTROL_BYTES, Mutation, Receipt, ReleaseRequest};

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    for _ in 0..64 {
        match Frame::read(&mut input) {
            Ok(Some(frame)) => {
                let _ = serde_json::from_slice::<Mutation>(&frame.payload);
                let _ = serde_json::from_slice::<ReleaseRequest>(&frame.payload);
            }
            Ok(None) | Err(_) => break,
        }
    }
    if data.len() <= MAX_CONTROL_BYTES {
        let _ = serde_json::from_slice::<Mutation>(data);
        let _ = serde_json::from_slice::<Receipt>(data);
        let _ = serde_json::from_slice::<ReleaseRequest>(data);
    }
});
