//! Durable native serial capture, independent of guest management. The host
//! reserves a bounded prefix and explicitly reports every observed excess byte.
use crate::guardian::{Error, Result};
use sandsurf_machine::NativeConsole;
use sandsurf_protocol::{
    ConsoleLoss, ConsolePage, Counter, MAX_CONSOLE_INPUT_BYTES, MAX_CONSOLE_PAGE_BYTES,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Independent of execution output: at most 32 MiB plus 64 small manifests.
const MAX_STREAMS: usize = 64;
const RETAINED_BYTES: u64 = 512 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Boundary {
    retained: u64,
    available: u64,
    open: bool,
    capture_failed: bool,
}
struct Attachment {
    generation: Counter,
    input: Box<dyn Write + Send>,
}
pub(crate) struct ConsoleStore {
    root: PathBuf,
    attachment: Option<Attachment>,
    input_budget: Budget,
    read_budget: Budget,
}
struct Budget {
    since: Instant,
    remaining: usize,
    capacity: usize,
}
impl Budget {
    fn new(capacity: usize) -> Self {
        Self {
            since: Instant::now(),
            remaining: capacity,
            capacity,
        }
    }
    fn admit(&mut self, bytes: usize) -> Result<()> {
        if self.since.elapsed() >= Duration::from_secs(1) {
            self.since = Instant::now();
            self.remaining = self.capacity;
        }
        if bytes > self.remaining {
            return Err(Error::Unsupported(
                "native console host stream budget exhausted",
            ));
        }
        self.remaining -= bytes;
        Ok(())
    }
}
impl ConsoleStore {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.join("console"),
            attachment: None,
            input_budget: Budget::new(32 * 1024),
            read_budget: Budget::new(1024 * 1024),
        }
    }
    pub fn attach(&mut self, generation: Counter, console: NativeConsole) -> Result<()> {
        let NativeConsole { input, output } = console;
        // Output ownership is always handed to a drain, even when retention
        // cannot be admitted. Closing the reader could signal the VMM instead.
        self.attachment = Some(Attachment { generation, input });
        let reservation = self.reserve(generation);
        match reservation {
            Ok((base, data, boundary)) => {
                std::thread::Builder::new()
                    .name("sandsurf-native-console".into())
                    .spawn(move || {
                        capture(output, data, base, boundary);
                    })?;
                Ok(())
            }
            Err(error) => {
                std::thread::Builder::new()
                    .name("sandsurf-console-unavailable".into())
                    .spawn(move || {
                        let mut output = output;
                        let _ = std::io::copy(&mut output, &mut std::io::sink());
                    })?;
                Err(error)
            }
        }
    }
    fn reserve(&self, generation: Counter) -> Result<(PathBuf, File, Boundary)> {
        sandsurf_native::local::ensure_private_directory(&self.root)?;
        let mut streams = 0;
        for entry in fs::read_dir(&self.root)? {
            if entry?.path().extension().is_some_and(|ext| ext == "bytes") {
                streams += 1;
            }
        }
        if streams >= MAX_STREAMS {
            return Err(Error::Unsupported(
                "native console archive stream reservation exhausted",
            ));
        }
        let base = self.root.join(generation.get().to_string());
        // No append or replacement of another generation's retained history.
        let data = sandsurf_native::local::create_private_file(&base.with_extension("bytes"))?;
        let boundary = Boundary {
            retained: 0,
            available: 0,
            open: true,
            capture_failed: false,
        };
        if let Err(error) = publish(&base, &boundary) {
            drop(data);
            let _ = fs::remove_file(base.with_extension("bytes"));
            let _ = fs::remove_file(base.with_extension("pending"));
            return Err(error);
        }
        Ok((base, data, boundary))
    }
    pub fn detach(&mut self) {
        self.attachment = None;
    }
    pub fn write(&mut self, generation: Counter, bytes: &[u8]) -> Result<u32> {
        if bytes.is_empty() || bytes.len() > MAX_CONSOLE_INPUT_BYTES {
            return Err(Error::Protocol(
                "native console input is empty or oversized",
            ));
        }
        self.input_budget.admit(bytes.len())?;
        let attachment = self
            .attachment
            .as_mut()
            .filter(|value| value.generation == generation)
            .ok_or(Error::Unsupported(
                "native console attachment is unavailable",
            ))?;
        // One nonblocking write with a reported accepted prefix. Ambiguous
        // transport must never cause automatic input replay.
        match attachment.input.write(bytes) {
            Ok(count) => Ok(count as u32),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(error.into()),
        }
    }
    pub fn read(
        &mut self,
        generation: Counter,
        after: Counter,
        maximum: u32,
    ) -> Result<ConsolePage> {
        if generation == Counter::ZERO || maximum == 0 || maximum as usize > MAX_CONSOLE_PAGE_BYTES
        {
            return Err(Error::Protocol("invalid native console read bound"));
        }
        self.read_budget.admit(maximum as usize)?;
        let base = self.root.join(generation.get().to_string());
        let manifest = match sandsurf_native::local::open_private_file(
            &base.with_extension("json"),
            sandsurf_native::PrivateFileAccess::ReadOnly,
        ) {
            Ok(file) => file,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && after == Counter::ZERO
                    && self
                        .attachment
                        .as_ref()
                        .is_some_and(|value| value.generation == generation) =>
            {
                return Ok(ConsolePage {
                    generation,
                    after,
                    cursor: after,
                    available: after,
                    bytes: vec![],
                    loss: None,
                    open: true,
                    capture_failed: true,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let boundary: Boundary = serde_json::from_reader(manifest.take(4097))?;
        if boundary.retained > RETAINED_BYTES
            || boundary.retained > boundary.available
            || boundary.available > Counter::MAX
            || after.get() > boundary.available
        {
            return Err(Error::Protocol("invalid native console durable boundary"));
        }
        let count = boundary
            .retained
            .saturating_sub(after.get())
            .min(maximum as u64) as usize;
        let mut bytes = vec![0; count];
        if count != 0 {
            let mut file = sandsurf_native::local::open_private_file(
                &base.with_extension("bytes"),
                sandsurf_native::PrivateFileAccess::ReadOnly,
            )?;
            file.seek(SeekFrom::Start(after.get()))?;
            file.read_exact(&mut bytes)?;
        }
        let end = after.get() + count as u64;
        let loss = (end >= boundary.retained && end < boundary.available).then(|| ConsoleLoss {
            from: end.try_into().expect("bounded cursor"),
            to: boundary.available.try_into().expect("bounded cursor"),
        });
        let cursor = loss.as_ref().map_or(end, |loss| loss.to.get());
        let attached = self
            .attachment
            .as_ref()
            .is_some_and(|value| value.generation == generation);
        Ok(ConsolePage {
            generation,
            after,
            cursor: cursor.try_into().expect("bounded cursor"),
            available: boundary.available.try_into().expect("bounded cursor"),
            bytes,
            loss,
            open: boundary.open && attached,
            capture_failed: boundary.capture_failed || (boundary.open && !attached),
        })
    }
}
fn publish(base: &Path, boundary: &Boundary) -> Result<()> {
    let temporary = base.with_extension("pending");
    let mut file = sandsurf_native::local::create_private_file(&temporary)?;
    file.write_all(&serde_json::to_vec(boundary)?)?;
    file.sync_all()?;
    drop(file);
    sandsurf_native::storage::replace_journal_file(&temporary, &base.with_extension("json"))?;
    Ok(())
}
fn capture(mut input: Box<dyn Read + Send>, mut data: File, base: PathBuf, mut boundary: Boundary) {
    let mut buffer = [0; 16 * 1024];
    let mut published = Instant::now();
    let result = (|| -> Result<()> {
        loop {
            let count = match input.read(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                boundary.open = false;
                break;
            }
            boundary.available = boundary
                .available
                .checked_add(count as u64)
                .filter(|value| *value <= Counter::MAX)
                .ok_or(Error::Protocol("console cursor overflow"))?;
            let retained = count.min((RETAINED_BYTES - boundary.retained) as usize);
            if retained != 0 {
                data.write_all(&buffer[..retained])?;
                sandsurf_native::storage::sync_file(&data)?;
                boundary.retained += retained as u64;
            }
            // A full prefix admits only one durable loss update per second.
            if retained != 0 || published.elapsed() >= Duration::from_secs(1) {
                publish(&base, &boundary)?;
                published = Instant::now();
            }
        }
        publish(&base, &boundary)
    })();
    if result.is_err() {
        boundary.capture_failed = true;
        boundary.open = false;
        let _ = fs::remove_file(base.with_extension("pending"));
        let _ = publish(&base, &boundary);
        // Archive failure never blocks native control behind serial output.
        let _ = std::io::copy(&mut input, &mut std::io::sink());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flood_retains_bounded_prefix_and_reports_durable_loss() {
        let root = std::env::temp_dir().join(format!(
            "sandsurf-console-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        sandsurf_native::local::create_private_directory(&root).unwrap();
        let base = root.join("1");
        let data =
            sandsurf_native::local::create_private_file(&base.with_extension("bytes")).unwrap();
        capture(
            Box::new(std::io::Cursor::new(vec![
                0xff;
                RETAINED_BYTES as usize + 17
            ])),
            data,
            base.clone(),
            Boundary {
                retained: 0,
                available: 0,
                open: true,
                capture_failed: false,
            },
        );
        let mut store = ConsoleStore::new(root.parent().unwrap());
        store.root = root.clone();
        let page = store
            .read(Counter::ONE, RETAINED_BYTES.try_into().unwrap(), 4096)
            .unwrap();
        assert_eq!(page.loss.unwrap().to.get(), RETAINED_BYTES + 17);
        assert!(!page.open);
        assert!(!page.capture_failed);
        assert_eq!(
            fs::metadata(base.with_extension("bytes")).unwrap().len(),
            RETAINED_BYTES
        );
        fs::remove_dir_all(root).unwrap();
    }
}
