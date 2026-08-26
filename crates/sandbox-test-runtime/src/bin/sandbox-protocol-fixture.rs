#![deny(unsafe_code)]

use sandbox_protocol::{Frame, MessageType, read_frame, write_frame};
use serde_json::{Value, json};
use std::error::Error;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn Error>> {
    let mode = std::env::current_exe()?
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or("fixture executable has no UTF-8 file name")?
        .to_owned();
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();

    while let Some(frame) = read_frame(&mut input)? {
        let body: Value = if frame.message_type.is_binary() {
            Value::Null
        } else {
            frame.parse_control()?
        };
        match frame.message_type {
            MessageType::Hello => {
                let acknowledgement = Frame::control(
                    MessageType::HelloAck,
                    &json!({ "protocolMajor": 1, "protocolMinor": 0 }),
                )?;
                write_frame(&mut output, &acknowledgement)?;
                if mode == "duplicate-hello" {
                    write_frame(&mut output, &acknowledgement)?;
                }
            }
            MessageType::Probe => handle_probe(&mode, &body, &mut output)?,
            MessageType::StartPreparedRun => handle_start(&mode, &body, &mut output)?,
            MessageType::Shutdown => {
                respond(&mut output, MessageType::RuntimeMetrics, &body, json!({}))?;
                return Ok(());
            }
            _ => {}
        }
    }
    Ok(())
}

fn handle_probe(mode: &str, body: &Value, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    match mode {
        "output-before-start" => {
            write_frame(output, &Frame::binary(MessageType::Stdout, b"x".to_vec())?)?
        }
        "exit-before-start" => {
            write_frame(
                output,
                &Frame::control(MessageType::ProcessExit, &json!({}))?,
            )?;
        }
        "credit-before-start" => write_frame(
            output,
            &Frame::control(
                MessageType::StreamCredit,
                &json!({ "stream": "stdin", "bytes": 1 }),
            )?,
        )?,
        _ => {
            let response = response_frame(
                MessageType::ProbeResult,
                body,
                json!({
                    "support": {
                        "protocol": { "major": 1, "minor": 0 },
                        "packageVersion": "test",
                        "host": { "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH },
                        "backends": []
                    }
                }),
            )?;
            write_frame(output, &response)?;
            if mode == "duplicate-response" {
                write_frame(output, &response)?;
            }
        }
    }
    Ok(())
}

fn handle_start(mode: &str, body: &Value, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    respond(
        output,
        MessageType::ProcessStarted,
        body,
        json!({ "id": "target", "identity": { "kind": "opaque" } }),
    )?;
    match mode {
        "output-after-exit" => {
            write_frame(
                output,
                &Frame::control(MessageType::ProcessExit, &json!({}))?,
            )?;
            write_frame(
                output,
                &Frame::binary(MessageType::Stdout, b"late".to_vec())?,
            )?;
        }
        "credit-overflow" => {
            for bytes in [16 * 1024 * 1024, 1] {
                write_frame(
                    output,
                    &Frame::control(
                        MessageType::StreamCredit,
                        &json!({ "stream": "stdin", "bytes": bytes }),
                    )?,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn respond(
    output: &mut impl Write,
    message_type: MessageType,
    request: &Value,
    fields: Value,
) -> Result<(), Box<dyn Error>> {
    write_frame(output, &response_frame(message_type, request, fields)?)?;
    Ok(())
}

fn response_frame(
    message_type: MessageType,
    request: &Value,
    mut fields: Value,
) -> Result<Frame, Box<dyn Error>> {
    let request_id = request
        .get("requestId")
        .and_then(Value::as_str)
        .ok_or("request is missing requestId")?;
    fields
        .as_object_mut()
        .ok_or("response fields must be an object")?
        .insert("requestId".to_owned(), Value::String(request_id.to_owned()));
    Ok(Frame::control(message_type, &fields)?)
}
