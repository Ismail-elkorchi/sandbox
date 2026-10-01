//! Native serial bytes are guest-controlled. Cursors describe host capture,
//! independently of management availability and managed execution output.
use crate::{Counter, Digest, Invalid, MAX_STREAM_BYTES};
use serde::{Deserialize, Serialize};

pub const MAX_CONSOLE_INPUT_BYTES: usize = 4096;
pub const MAX_CONSOLE_PAGE_BYTES: usize = MAX_STREAM_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsolePage {
    pub generation: Counter,
    pub after: Counter,
    pub cursor: Counter,
    pub available: Counter,
    pub bytes: Vec<u8>,
    pub loss: Option<ConsoleLoss>,
    /// False means native EOF was durably recorded. An interrupted capture
    /// remains explicit; an absent management service does not end this stream.
    pub open: bool,
    pub capture_failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsoleLoss {
    pub from: Counter,
    pub to: Counter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsolePageMetadata {
    pub generation: Counter,
    pub after: Counter,
    pub cursor: Counter,
    pub available: Counter,
    pub length: u32,
    pub digest: Digest,
    pub loss: Option<ConsoleLoss>,
    pub open: bool,
    pub capture_failed: bool,
}

impl ConsolePageMetadata {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.generation == Counter::ZERO
            || self.length as usize > MAX_CONSOLE_PAGE_BYTES
            || self.after > self.cursor
            || self.cursor > self.available
        {
            return Err(Invalid("invalid console page boundary"));
        }
        let retained_end = self.after.checked_add(self.length as u64)?;
        match &self.loss {
            Some(loss)
                if loss.from == retained_end && loss.to == self.cursor && loss.from < loss.to => {}
            None if retained_end == self.cursor => {}
            _ => return Err(Invalid("console page coverage is incomplete")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_loss_must_cover_exactly_the_gap_after_retained_bytes() {
        let mut page = ConsolePageMetadata {
            generation: Counter::ONE,
            after: Counter::ZERO,
            cursor: 9.try_into().unwrap(),
            available: 9.try_into().unwrap(),
            length: 3,
            digest: crate::bytes_digest(b"abc"),
            loss: Some(ConsoleLoss {
                from: 3.try_into().unwrap(),
                to: 9.try_into().unwrap(),
            }),
            open: true,
            capture_failed: false,
        };
        assert!(page.validate().is_ok());
        page.loss.as_mut().unwrap().from = Counter::ONE;
        assert!(page.validate().is_err());
        page.loss = None;
        assert!(page.validate().is_err());
    }

    #[test]
    fn console_wire_bytes_are_binary_exact_and_digest_bound() {
        let response = crate::RuntimeResponse::Console {
            page: ConsolePage {
                generation: Counter::ONE,
                after: Counter::ZERO,
                cursor: 3.try_into().unwrap(),
                available: 3.try_into().unwrap(),
                bytes: vec![0, 255, 128],
                loss: None,
                open: true,
                capture_failed: false,
            },
        };
        let (wire, bytes) = response.clone().into_wire_parts().unwrap();
        assert_eq!(wire.binary_descriptor().unwrap().unwrap()[0].length, 3);
        assert_eq!(
            wire.clone().with_wire_bytes(bytes.unwrap()).unwrap(),
            response
        );
        assert!(wire.with_wire_bytes(vec![vec![0, 255, 127]]).is_err());
    }
}
