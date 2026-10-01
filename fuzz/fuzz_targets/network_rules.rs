#![no_main]

use libfuzzer_sys::fuzz_target;
use sandsurf_network::policy::PacketPolicy;
use sandsurf_protocol::NetworkPolicy;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(policy) = serde_json::from_slice::<NetworkPolicy>(data) {
        let _ = PacketPolicy::compile(&policy, Vec::new());
    }
});
