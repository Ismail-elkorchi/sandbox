#![no_main]

use libfuzzer_sys::fuzz_target;
use sandbox_protocol::{Frame, MessageType};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let frame = Frame {
        message_type: MessageType::Hello,
        flags: 0,
        payload: data.to_vec(),
    };
    let _ = frame.parse_control::<serde_json::Value>();
});
