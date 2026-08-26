#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 1024 {
        let _ = sandbox_network_broker::parse_socks5_request(data);
    }
});
