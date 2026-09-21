use sandsurf_protocol::{Counter, Digest, ProcessId, bytes_digest};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_CONTROL_FILE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupLimits {
    pub memory_max: Option<u64>,
    pub pids_max: Option<u64>,
    /// Quota and period in microseconds.
    pub cpu_max: Option<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupUsage {
    pub cpu_usage_micros: Counter,
    pub memory_current: Counter,
    pub memory_peak: Counter,
    pub pids_current: Counter,
    pub io_read_bytes: Counter,
    pub io_write_bytes: Counter,
    pub complete: bool,
}

impl CgroupUsage {
    pub fn digest(&self) -> Digest {
        let mut bytes = b"sandsurf-cgroup-v2-usage-v1".to_vec();
        for value in [
            self.cpu_usage_micros,
            self.memory_current,
            self.memory_peak,
            self.pids_current,
            self.io_read_bytes,
            self.io_write_bytes,
        ] {
            bytes.extend_from_slice(&value.get().to_be_bytes());
        }
        bytes.push(u8::from(self.complete));
        bytes_digest(&bytes)
    }
}

#[derive(Debug, Clone)]
pub struct CgroupManager {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProcessCgroup {
    path: PathBuf,
}

impl CgroupManager {
    /// Open an already delegated cgroup-v2 subtree. Provisioning delegation is
    /// a trusted bootstrap responsibility, never an SDK path parameter.
    pub fn open(root: &Path) -> io::Result<Self> {
        if !root.is_absolute() || !fs::metadata(root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cgroup root must be an absolute delegated directory",
            ));
        }
        let controllers = read_bounded(&root.join("cgroup.subtree_control"))?;
        let enabled: std::collections::BTreeSet<_> = controllers.split_ascii_whitespace().collect();
        if ["cpu", "memory", "pids", "io"]
            .iter()
            .any(|controller| !enabled.contains(controller))
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "required cgroup v2 controllers are not delegated",
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn create_process(
        &self,
        process_id: &ProcessId,
        limits: CgroupLimits,
    ) -> io::Result<ProcessCgroup> {
        validate_limits(limits)?;
        let path = self.root.join(process_id.as_str());
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if populated(&path)? {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "process cgroup is already populated",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        let handle = ProcessCgroup { path };
        let configured = (|| {
            if let Some(memory) = limits.memory_max {
                write_control(&handle.path.join("memory.max"), &memory.to_string())?;
            }
            if let Some(pids) = limits.pids_max {
                write_control(&handle.path.join("pids.max"), &pids.to_string())?;
            }
            if let Some((quota, period)) = limits.cpu_max {
                write_control(&handle.path.join("cpu.max"), &format!("{quota} {period}"))?;
            }
            Ok(())
        })();
        if let Err(error) = configured {
            let _ = fs::remove_dir(&handle.path);
            return Err(error);
        }
        Ok(handle)
    }

    /// Apply aggregate workload limits at the delegated root. The protected
    /// supervisor is in a sibling cgroup and therefore retains control/evidence
    /// capacity when the workload reaches these ceilings.
    pub fn apply_aggregate(&self, limits: CgroupLimits) -> io::Result<()> {
        validate_limits(limits)?;
        write_control(
            &self.root.join("memory.max"),
            &limits
                .memory_max
                .map_or_else(|| "max".into(), |value| value.to_string()),
        )?;
        write_control(
            &self.root.join("pids.max"),
            &limits
                .pids_max
                .map_or_else(|| "max".into(), |value| value.to_string()),
        )?;
        write_control(
            &self.root.join("cpu.max"),
            &limits.cpu_max.map_or_else(
                || "max 100000".into(),
                |(quota, period)| format!("{quota} {period}"),
            ),
        )
    }

    pub fn aggregate_usage(&self) -> io::Result<CgroupUsage> {
        usage_at(&self.root, false)
    }
}

impl ProcessCgroup {
    pub fn attachment(&self) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.procs"))
    }

    pub fn kill(&self) -> io::Result<()> {
        write_control(&self.path.join("cgroup.kill"), "1")
    }

    pub fn populated(&self) -> io::Result<bool> {
        populated(&self.path)
    }

    pub fn wait_empty(&self, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.populated()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn usage(&self, complete: bool) -> io::Result<CgroupUsage> {
        usage_at(&self.path, complete)
    }

    pub fn cleanup(&self) -> io::Result<()> {
        if self.populated()? {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "process cgroup remains populated",
            ));
        }
        fs::remove_dir(&self.path)
    }
}

fn usage_at(path: &Path, complete: bool) -> io::Result<CgroupUsage> {
    let cpu = key_values(&read_bounded(&path.join("cpu.stat"))?)?;
    let io = nested_key_values(&read_bounded(&path.join("io.stat"))?)?;
    Ok(CgroupUsage {
        cpu_usage_micros: counter(*cpu.get("usage_usec").unwrap_or(&0))?,
        memory_current: counter(read_number(&path.join("memory.current"))?)?,
        memory_peak: counter(read_optional_number(&path.join("memory.peak"))?.unwrap_or(0))?,
        pids_current: counter(read_number(&path.join("pids.current"))?)?,
        io_read_bytes: counter(*io.get("rbytes").unwrap_or(&0))?,
        io_write_bytes: counter(*io.get("wbytes").unwrap_or(&0))?,
        complete,
    })
}

fn validate_limits(limits: CgroupLimits) -> io::Result<()> {
    if limits.memory_max == Some(0)
        || limits.pids_max == Some(0)
        || limits
            .cpu_max
            .is_some_and(|(quota, period)| quota == 0 || !(1_000..=1_000_000).contains(&period))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid cgroup process limits",
        ));
    }
    Ok(())
}

fn populated(path: &Path) -> io::Result<bool> {
    let values = key_values(&read_bounded(&path.join("cgroup.events"))?)?;
    match values.get("populated") {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cgroup.events has no valid populated field",
        )),
    }
}

fn read_number(path: &Path) -> io::Result<u64> {
    read_bounded(path)?
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup counter"))
}

fn read_optional_number(path: &Path) -> io::Result<Option<u64>> {
    match read_number(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn key_values(value: &str) -> io::Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for line in value.lines() {
        let mut fields = line.split_ascii_whitespace();
        let key = fields.next().ok_or_else(invalid_control)?;
        let number = fields
            .next()
            .ok_or_else(invalid_control)?
            .parse()
            .map_err(|_| invalid_control())?;
        if fields.next().is_some() || result.insert(key.to_owned(), number).is_some() {
            return Err(invalid_control());
        }
    }
    Ok(result)
}

fn nested_key_values(value: &str) -> io::Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::<String, u64>::new();
    for line in value.lines() {
        for field in line.split_ascii_whitespace().skip(1) {
            let (key, number) = field.split_once('=').ok_or_else(invalid_control)?;
            let number: u64 = number.parse().map_err(|_| invalid_control())?;
            let entry = result.entry(key.to_owned()).or_default();
            *entry = entry.checked_add(number).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "cgroup counter overflow")
            })?;
        }
    }
    Ok(result)
}

fn read_bounded(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_CONTROL_FILE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTROL_FILE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cgroup control file exceeds bound",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cgroup control is not UTF-8"))
}

fn write_control(path: &Path, value: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(value.as_bytes())?;
    file.flush()
}

fn counter(value: u64) -> io::Result<Counter> {
    value
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cgroup counter overflow"))
}

fn invalid_control() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid cgroup control contents",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-cgroup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn usage_is_aggregate_bounded_and_content_bound() {
        let root = Temp::new();
        fs::write(root.0.join("cpu.stat"), "usage_usec 42\nuser_usec 30\n").unwrap();
        fs::write(root.0.join("memory.current"), "100\n").unwrap();
        fs::write(root.0.join("memory.peak"), "200\n").unwrap();
        fs::write(root.0.join("pids.current"), "3\n").unwrap();
        fs::write(
            root.0.join("io.stat"),
            "8:0 rbytes=4 wbytes=5 rios=1\n8:1 rbytes=6 wbytes=7\n",
        )
        .unwrap();
        let usage = ProcessCgroup {
            path: root.0.clone(),
        }
        .usage(true)
        .unwrap();
        assert_eq!(usage.cpu_usage_micros.get(), 42);
        assert_eq!(usage.io_read_bytes.get(), 10);
        assert_eq!(usage.io_write_bytes.get(), 12);
        assert!(usage.complete);
        assert_ne!(usage.digest(), bytes_digest(b"leader-only"));
    }

    #[test]
    fn malformed_or_overflowing_controls_fail_closed() {
        assert!(key_values("populated 1 extra").is_err());
        assert!(nested_key_values("8:0 rbytes=nope").is_err());
        assert!(
            validate_limits(CgroupLimits {
                memory_max: Some(0),
                ..Default::default()
            })
            .is_err()
        );
    }
}
