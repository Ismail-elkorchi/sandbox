#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_policy::{NetworkPolicy, SessionOptions, normalize_session};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let Ok(network) = serde_json::from_slice::<NetworkPolicy>(data) else {
        return;
    };
    let mut options: SessionOptions = match serde_json::from_str(
        r#"{"isolation":{"kind":"process"},"policy":{"filesystem":{"runtime":{"kind":"empty"},"grants":[]},"network":{"mode":"none"},"process":{"hostProcesses":"deny","hostIpc":"deny"}},"requirements":{"boundary":"os-process","required":[]}}"#,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };
    options.policy.network = network;
    let _ = normalize_session(options, 8 * 1024 * 1024 * 1024);
});
