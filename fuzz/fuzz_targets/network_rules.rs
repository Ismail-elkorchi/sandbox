#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_policy::{ManagedNetworkRule, normalize_managed_network_rules};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(rules) = serde_json::from_slice::<Vec<ManagedNetworkRule>>(data) {
        let _ = normalize_managed_network_rules(&rules);
    }
});
