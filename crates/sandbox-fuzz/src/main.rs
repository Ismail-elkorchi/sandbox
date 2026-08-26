#![deny(unsafe_code)]

use sandbox_policy::{SessionOptions, normalize_session, normalize_target_path};
use sandbox_protocol::{HEADER_LEN, MAGIC, MAX_CONTROL_PAYLOAD, MessageType, read_frame};
use std::io::Cursor;

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(25_000)
        .clamp(1, 1_000_000);
    let mut random = XorShift64(0x4d59_5df4_d0f3_3173);
    for index in 0..iterations {
        fuzz_protocol(&mut random, index);
        fuzz_policy(&mut random, index);
        fuzz_path(&mut random, index);
    }
    println!("sandbox fuzz smoke completed {iterations} iterations per target");
}

fn fuzz_protocol(random: &mut XorShift64, index: usize) {
    let mut bytes = vec![0_u8; random.length(4096)];
    random.fill(&mut bytes);
    if index.is_multiple_of(3) {
        bytes.resize(HEADER_LEN, 0);
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = if index.is_multiple_of(2) {
            MessageType::Hello as u8
        } else {
            MessageType::Stdin as u8
        };
        let declared = if index.is_multiple_of(5) {
            MAX_CONTROL_PAYLOAD as u32 + random.next_u32()
        } else {
            random.next_u32()
        };
        bytes[8..12].copy_from_slice(&declared.to_be_bytes());
    }
    let _ = read_frame(&mut Cursor::new(bytes));
}

fn fuzz_policy(random: &mut XorShift64, index: usize) {
    let mut bytes = vec![0_u8; random.length(8192)];
    random.fill(&mut bytes);
    if index.is_multiple_of(4) {
        bytes.splice(0..0, br#"{"isolation":{"kind":"process"},"policy":{"filesystem":{"runtime":{"kind":"system"},"grants":[]},"network":{"mode":"none"},"process":{"hostProcesses":"deny","hostIpc":"deny"}},"requirements":{"boundary":"os-process","required":[]}}"#.iter().copied());
    }
    if let Ok(options) = serde_json::from_slice::<SessionOptions>(&bytes) {
        let _ = normalize_session(options, 8 * 1024 * 1024 * 1024);
    }
}

fn fuzz_path(random: &mut XorShift64, index: usize) {
    let mut bytes = vec![0_u8; random.length(2048)];
    random.fill(&mut bytes);
    if index.is_multiple_of(2) {
        bytes.insert(0, b'/');
    }
    let value = String::from_utf8_lossy(&bytes);
    let _ = normalize_target_path(&value);
}

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }

    fn length(&mut self, maximum: usize) -> usize {
        (self.next() as usize) % (maximum + 1)
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next() as u8;
        }
    }
}
