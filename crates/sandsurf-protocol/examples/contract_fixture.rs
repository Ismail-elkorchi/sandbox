//! Source-built cross-language qualification helper; not a runtime or SDK backend.
use sandsurf_protocol::*;
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let mode = arguments.get(1).ok_or("mode missing")?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_CONTROL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err("fixture input exceeds bound".into());
    }
    match mode.as_str() {
        "frame" => {
            let mut reader = &bytes[..];
            let frame = Frame::read(&mut reader)?.ok_or("missing frame")?;
            if !reader.is_empty() {
                return Err("trailing frame bytes".into());
            }
            frame.write(&mut std::io::stdout())?;
        }
        "mutation" => {
            let value: Mutation = serde_json::from_slice(&bytes)?;
            serde_json::to_writer(std::io::stdout(), &value)?;
        }
        "release" => {
            let value: ReleaseRequest = serde_json::from_slice(&bytes)?;
            serde_json::to_writer(std::io::stdout(), &value)?;
        }
        "digest" => {
            let domain = match arguments.get(2).map(String::as_str) {
                Some("sandbox") => Domain::Sandbox,
                Some("grant") => Domain::Grant,
                Some("operation") => Domain::Operation,
                Some("receipt") => Domain::Receipt,
                Some("output") => Domain::Output,
                Some("release") => Domain::Release,
                Some("image") => Domain::Image,
                Some("checkpoint") => Domain::Checkpoint,
                Some("transfer") => Domain::Transfer,
                _ => return Err("unknown domain".into()),
            };
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            std::io::stdout().write_all(digest(domain, &value)?.as_str().as_bytes())?;
        }
        _ => return Err("unknown fixture mode".into()),
    }
    Ok(())
}
