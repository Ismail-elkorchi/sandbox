#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sandsurf_network::packet::parse(data, &sandsurf_network::LinkIdentity { guest_mac: [2, 0, 0, 0, 0, 2] });
});
