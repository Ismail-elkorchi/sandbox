#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 64 * 1024 {
        let _ = sandbox_network_broker::parse_http_connect_request(data);
        if let Ok(text) = std::str::from_utf8(data) {
            let _ = sandbox_network_broker::parse_absolute_http_uri(text);
        }
    }
});
