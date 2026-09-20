#![no_main]

use libfuzzer_sys::fuzz_target;
use sandsurf_protocol::{
    AuthorizedLifecycle, AuthorizedLoss, AuthorizedMutation, Frame, GuardianRequest,
    GuardianResponse, MAX_CONTROL_BYTES, Mutation, Receipt, ReleaseRequest,
};

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    for _ in 0..64 {
        match Frame::read(&mut input) {
            Ok(Some(frame)) => {
                let _ = serde_json::from_slice::<Mutation>(&frame.payload);
                let _ = serde_json::from_slice::<ReleaseRequest>(&frame.payload);
                let _ = serde_json::from_slice::<GuardianRequest>(&frame.payload);
                let _ = serde_json::from_slice::<GuardianResponse>(&frame.payload);
            }
            Ok(None) | Err(_) => break,
        }
    }
    if data.len() <= MAX_CONTROL_BYTES {
        let _ = serde_json::from_slice::<Mutation>(data);
        let _ = serde_json::from_slice::<Receipt>(data);
        let _ = serde_json::from_slice::<ReleaseRequest>(data);
        let _ = serde_json::from_slice::<AuthorizedMutation>(data);
        let _ = serde_json::from_slice::<AuthorizedLifecycle>(data);
        let _ = serde_json::from_slice::<AuthorizedLoss>(data);
        let _ = serde_json::from_slice::<GuardianRequest>(data);
        let _ = serde_json::from_slice::<GuardianResponse>(data);
    }
});
