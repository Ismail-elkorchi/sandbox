#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_protocol::read_frame;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut input = Cursor::new(data);
    for _ in 0..64 {
        match read_frame(&mut input) {
            Ok(Some(frame)) => {
                if !frame.message_type.is_binary() {
                    let _ = frame.parse_control::<serde_json::Value>();
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
});
