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
        r#"{"isolation":{"kind":"process"},"policy":{"filesystem":{"kind":"isolated","resources":[]},"network":{"mode":"none"},"process":{"visibility":"session","control":"session","termination":{"scope":"descendant-tree","graceMs":100}},"ipc":{"visibility":"session"}},"requirements":{}}"#,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };
    options.policy.network = network;
    let _ = normalize_session(options);
});
