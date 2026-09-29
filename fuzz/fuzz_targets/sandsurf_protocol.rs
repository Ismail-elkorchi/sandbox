#![no_main]

use libfuzzer_sys::fuzz_target;
use sandsurf_protocol::{
    AuthorizedLifecycle, AuthorizedLoss, Frame, GuardianRequest, GuardianResponse,
    GuestCommand, Receipt, ReleaseRequest, RequestEnvelope, MAX_CONTROL_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let mut input = data;
    for _ in 0..64 {
        match Frame::read(&mut input) {
            Ok(Some(frame)) => {
                let _ = serde_json::from_slice::<GuestCommand>(&frame.payload);
                let _ = serde_json::from_slice::<ReleaseRequest>(&frame.payload);
                let _ = serde_json::from_slice::<GuardianRequest>(&frame.payload);
                let _ = serde_json::from_slice::<GuardianResponse>(&frame.payload);
            }
            Ok(None) | Err(_) => break,
        }
    }
    if data.len() <= MAX_CONTROL_BYTES {
        let _ = serde_json::from_slice::<GuestCommand>(data);
        let _ = serde_json::from_slice::<Receipt>(data);
        let _ = serde_json::from_slice::<ReleaseRequest>(data);
        if let Ok(mut admission) = serde_json::from_slice::<RequestEnvelope<GuestCommand>>(data) {
            let _ = admission.validate_admission();
        }
        let _ = serde_json::from_slice::<AuthorizedLifecycle>(data);
        let _ = serde_json::from_slice::<AuthorizedLoss>(data);
        let _ = serde_json::from_slice::<GuardianRequest>(data);
        let _ = serde_json::from_slice::<GuardianResponse>(data);
    }
});
