//! Boot channel binding, not guest integrity evidence. Root in the guest can
//! read this capability and replace the management service. All adapters use
//! the same sector-aligned record; there is no legacy short-record reader.
use crate::{AUTHENTICATION_MAGIC, BootCapability, Counter, Digest, Invalid, MachineId};
use zeroize::Zeroizing;

pub const BOOT_RECORD_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct BootIdentity {
    pub machine_id: MachineId,
    pub generation: Counter,
    pub boot_digest: Digest,
    pub capability: BootCapability,
}

impl BootIdentity {
    pub fn encode(&self) -> Result<Zeroizing<[u8; BOOT_RECORD_BYTES]>, Invalid> {
        if self.generation == Counter::ZERO {
            return Err(Invalid("boot generation must be positive"));
        }
        let capability = Zeroizing::new(self.capability.secret_bytes());
        if capability.iter().all(|byte| *byte == 0) {
            return Err(Invalid("boot capability is empty"));
        }
        let machine = self.machine_id.as_str().as_bytes();
        let mut bytes = Zeroizing::new([0; BOOT_RECORD_BYTES]);
        bytes[..8].copy_from_slice(AUTHENTICATION_MAGIC);
        bytes[8..10].copy_from_slice(&(machine.len() as u16).to_be_bytes());
        bytes[10..10 + machine.len()].copy_from_slice(machine);
        let offset = 10 + machine.len();
        bytes[offset..offset + 8].copy_from_slice(&self.generation.get().to_be_bytes());
        for (index, pair) in self
            .boot_digest
            .as_str()
            .as_bytes()
            .chunks_exact(2)
            .enumerate()
        {
            // Digest's constructor already guarantees lowercase hexadecimal.
            let nibble = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            bytes[offset + 8 + index] = nibble(pair[0]) * 16 + nibble(pair[1]);
        }
        bytes[offset + 40..offset + 72].copy_from_slice(&capability[..]);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Invalid> {
        if bytes.len() != BOOT_RECORD_BYTES || &bytes[..8] != AUTHENTICATION_MAGIC {
            return Err(Invalid("boot record has invalid size or identity"));
        }
        let size = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
        if !(1..=128).contains(&size) {
            return Err(Invalid("boot machine identity exceeds its bound"));
        }
        let machine_id = std::str::from_utf8(&bytes[10..10 + size])
            .map_err(|_| Invalid("boot machine identity is not UTF-8"))?
            .try_into()?;
        let offset = 10 + size;
        let generation = Counter::try_from(u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("bounded generation"),
        ))?;
        if generation == Counter::ZERO || bytes[offset + 72..].iter().any(|byte| *byte != 0) {
            return Err(Invalid("boot generation or reserved padding is invalid"));
        }
        let digest: String = bytes[offset + 8..offset + 40]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let capability = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[offset + 40..offset + 72]).expect("bounded capability"),
        );
        if capability.iter().all(|byte| *byte == 0) {
            return Err(Invalid("boot capability is empty"));
        }
        Ok(Self {
            machine_id,
            generation,
            boot_digest: digest.try_into()?,
            capability: BootCapability::from_bytes(*capability),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> BootIdentity {
        BootIdentity {
            machine_id: "machine-1".try_into().unwrap(),
            generation: Counter::ONE,
            boot_digest: crate::bytes_digest(b"boot"),
            capability: BootCapability::from_bytes([3; 32]),
        }
    }

    #[test]
    fn one_sector_aligned_roundtrip_and_redacted_debug() {
        let expected = identity();
        let bytes = expected.encode().unwrap();
        assert_eq!(bytes.len(), 4096);
        let actual = BootIdentity::decode(&bytes[..]).unwrap();
        assert_eq!(actual.machine_id, expected.machine_id);
        assert_eq!(actual.generation, expected.generation);
        assert_eq!(actual.boot_digest, expected.boot_digest);
        assert_eq!(
            actual.capability.secret_bytes(),
            expected.capability.secret_bytes()
        );
        assert!(format!("{actual:?}").contains("[REDACTED]"));
    }

    #[test]
    fn malformed_and_short_records_have_no_compatibility_reader() {
        let bytes = identity().encode().unwrap();
        for size in [0, 8, 512, 4095] {
            assert!(BootIdentity::decode(&bytes[..size]).is_err());
        }
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(BootIdentity::decode(&longer).is_err());
        for (index, value) in [(0, 0), (8, 255), (10, b'/'), (4095, 1)] {
            let mut changed = bytes.clone();
            changed[index] = value;
            assert!(BootIdentity::decode(&changed[..]).is_err());
        }
        let mut changed = bytes.clone();
        changed[19..27].fill(0);
        assert!(BootIdentity::decode(&changed[..]).is_err());
        changed = bytes.clone();
        changed[59..91].fill(0);
        assert!(BootIdentity::decode(&changed[..]).is_err());
    }

    #[test]
    fn maximum_identity_and_invalid_writer_state() {
        let mut value = identity();
        value.machine_id = "x".repeat(128).try_into().unwrap();
        assert!(BootIdentity::decode(&value.encode().unwrap()[..]).is_ok());
        value.generation = Counter::ZERO;
        assert!(value.encode().is_err());
        value.generation = Counter::ONE;
        value.capability = BootCapability::from_bytes([0; 32]);
        assert!(value.encode().is_err());
    }
}
