#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4096 {
        let _ = sandsurf_network::parse_dns_question(data);
    }
});
