#![deny(unsafe_code)]

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

const FORMAT_DOMAIN: &[u8] = b"SBX-DIGEST-1";
const POLICY_DOMAIN: &[u8] = b"POLICY";
const EXECUTION_DOMAIN: &[u8] = b"EXECUTION";

#[derive(Debug)]
pub enum DigestError {
    Serialization(serde_json::Error),
    FloatingPointUnsupported,
    LengthOverflow,
}

impl Display for DigestError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(error) => write!(formatter, "digest serialization failed: {error}"),
            Self::FloatingPointUnsupported => {
                formatter.write_str("floating point values are not canonical digest inputs")
            }
            Self::LengthOverflow => {
                formatter.write_str("canonical value exceeds the digest format length limit")
            }
        }
    }
}

impl std::error::Error for DigestError {}

pub fn policy_digest<T: Serialize>(value: &T) -> Result<String, DigestError> {
    digest(POLICY_DOMAIN, value)
}

pub fn execution_digest<T: Serialize>(value: &T) -> Result<String, DigestError> {
    digest(EXECUTION_DOMAIN, value)
}

pub fn identity_digest<T: Serialize>(value: &T) -> Result<String, DigestError> {
    digest(b"IDENTITY", value)
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, DigestError> {
    let value = serde_json::to_value(value).map_err(DigestError::Serialization)?;
    let mut bytes = Vec::new();
    put_bytes(&mut bytes, FORMAT_DOMAIN)?;
    put_bytes(&mut bytes, domain)?;
    encode_value(&value, &mut bytes)?;
    let output = Sha256::digest(bytes);
    Ok(to_hex(&output))
}

fn put_len(output: &mut Vec<u8>, length: usize) -> Result<(), DigestError> {
    let length = u32::try_from(length).map_err(|_| DigestError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DigestError> {
    put_len(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_value(value: &Value, output: &mut Vec<u8>) -> Result<(), DigestError> {
    match value {
        Value::Null => output.push(0x00),
        Value::Bool(value) => {
            output.push(0x01);
            output.push(u8::from(*value));
        }
        Value::Number(value) => {
            output.push(0x02);
            if let Some(number) = value.as_u64() {
                output.push(0x00);
                output.extend_from_slice(&number.to_be_bytes());
            } else if let Some(number) = value.as_i64() {
                output.push(0x01);
                output.extend_from_slice(&number.to_be_bytes());
            } else {
                return Err(DigestError::FloatingPointUnsupported);
            }
        }
        Value::String(value) => {
            output.push(0x03);
            put_bytes(output, value.as_bytes())?;
        }
        Value::Array(values) => {
            output.push(0x04);
            put_len(output, values.len())?;
            for value in values {
                encode_value(value, output)?;
            }
        }
        Value::Object(values) => {
            output.push(0x05);
            put_len(output, values.len())?;
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (key, value) in entries {
                put_bytes(output, key.as_bytes())?;
                encode_value(value, output)?;
            }
        }
    }
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn map_key_order_does_not_change_digest() {
        let first = json!({"z": 1, "a": [true, null, "x"]});
        let second = json!({"a": [true, null, "x"], "z": 1});
        assert_eq!(
            policy_digest(&first).expect("digest"),
            policy_digest(&second).expect("digest")
        );
    }

    #[test]
    fn digest_domains_are_distinct() {
        let value = json!({"a": 1});
        assert_ne!(
            policy_digest(&value).expect("policy"),
            execution_digest(&value).expect("execution")
        );
    }
}
