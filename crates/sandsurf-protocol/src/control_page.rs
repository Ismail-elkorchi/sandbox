//! Allocation-bounded control collections. Count limits are independent of
//! encoded byte limits; neither pagination nor recovery may collect history
//! first and discover that it cannot be transmitted afterwards.
use crate::{Invalid, MAX_CONTROL_BYTES};
use serde::Serialize;
use std::io::{self, Write};

/// Leaves room for the collection's response/authentication envelope. This is
/// a serialization mechanism, not a wire type or another state owner.
pub struct ControlPage<T> {
    values: Vec<T>,
    bytes: usize,
    limit: usize,
}

impl<T: Serialize> Default for ControlPage<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            bytes: 2,
            limit: MAX_CONTROL_BYTES - 4096,
        }
    }
}

impl<T: Serialize> ControlPage<T> {
    pub fn with_envelope_bytes(reserved: usize) -> Result<Self, Invalid> {
        if !(4096..MAX_CONTROL_BYTES - 2).contains(&reserved) {
            return Err(Invalid("invalid control envelope reservation"));
        }
        Ok(Self {
            limit: MAX_CONTROL_BYTES - reserved,
            ..Self::default()
        })
    }

    /// False leaves the next identity outside this page. An oversized first
    /// record fails explicitly rather than producing an empty non-progressing
    /// page. Counting serialization does not allocate a second metadata copy.
    pub fn push(&mut self, value: T) -> Result<bool, Invalid> {
        let mut count = Count { bytes: 0 };
        serde_json::to_writer(&mut count, &value)
            .map_err(|_| Invalid("control page record is invalid or exceeds its byte bound"))?;
        let bytes = self
            .bytes
            .checked_add(count.bytes + usize::from(!self.values.is_empty()))
            .ok_or(Invalid("control page byte count overflow"))?;
        if bytes > self.limit {
            return if self.values.is_empty() {
                Err(Invalid("control page cannot fit its first record"))
            } else {
                Ok(false)
            };
        }
        self.bytes = bytes;
        self.values.push(value);
        Ok(true)
    }

    pub fn into_values(self) -> Vec<T> {
        self.values
    }
}

struct Count {
    bytes: usize,
}
impl Write for Count {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(value.len())
            .filter(|bytes| *bytes <= MAX_CONTROL_BYTES)
            .ok_or_else(|| io::Error::other("control metadata exceeds bound"))?;
        Ok(value.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_count_encoded_bytes_before_aggregating_and_leave_the_next_identity() {
        let value = "\0".repeat(16000);
        let mut page = ControlPage::default();
        assert!(page.push(value.clone()).unwrap());
        assert!(page.push(value.clone()).unwrap());
        assert!(!page.push(value).unwrap());
        let values = page.into_values();
        assert_eq!(values.len(), 2);
        assert!(serde_json::to_vec(&values).unwrap().len() <= MAX_CONTROL_BYTES - 4096);
    }

    #[test]
    fn oversized_single_records_fail_without_an_empty_success_page() {
        let mut page = ControlPage::default();
        assert!(page.push("x".repeat(MAX_CONTROL_BYTES)).is_err());
        assert!(page.push("y".repeat(MAX_CONTROL_BYTES - 4096)).is_err());
        assert!(page.push("accepted".to_owned()).unwrap());
        assert_eq!(page.into_values(), vec!["accepted"]);
    }
}
