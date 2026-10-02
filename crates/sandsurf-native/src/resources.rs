//! Limits outside the guest. Only the owning systemd user unit is configured;
//! this module never enables controllers, changes host policy, or adopts PIDs.
use sandsurf_protocol::{Counter, Resources};
use std::io;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const CPU_PERIOD_MICROS: u64 = 100_000;

pub fn unit_name(machine_root: &Path) -> io::Result<String> {
    let canonical = crate::local::canonical_private_directory(machine_root)?;
    let identity = canonical
        .to_str()
        .ok_or_else(|| invalid("machine root is not UTF-8"))?;
    Ok(format!(
        "sandsurf-machine-{}.service",
        crate::storage::object_name(identity)
    ))
}

pub fn systemd_properties(resources: &Resources) -> io::Result<Vec<String>> {
    resources
        .validate()
        .map_err(|error| io::Error::other(error.to_string()))?;
    // systemd's transient-unit parser accepts hundredths of one CPU percent.
    // With the fixed 100ms period that is exactly 10µs; admission rejects finer
    // values rather than rounding authority into a different native limit.
    let quota = resources.cpu_quota_micros.get();
    Ok(vec![
        format!("CPUQuota={}.{:02}%", quota / 1000, (quota % 1000) / 10),
        "CPUQuotaPeriodSec=100ms".into(),
        format!(
            "MemoryMax={}",
            resources
                .host_memory_bytes()
                .map_err(io::Error::other)?
                .get()
        ),
        "MemorySwapMax=0".into(),
        // OOMPolicy=kill installs memory.oom.group=1. Verify the kernel value
        // below; there is no systemd property named MemoryOOMGroup.
        "OOMPolicy=kill".into(),
        "KillMode=control-group".into(),
        "Delegate=no".into(),
        "Restart=no".into(),
        // Native threads and channel/session workers are covered. This is a
        // host-task cap, never a promise about root-controlled guest PIDs.
        format!("TasksMax={}", task_budget(resources)?),
    ])
}

fn task_budget(resources: &Resources) -> io::Result<u64> {
    resources
        .channels
        .get()
        .checked_mul(8)
        .and_then(|channels| {
            resources
                .vcpus
                .get()
                .checked_mul(8)
                .and_then(|cpus| channels.checked_add(cpus))
        })
        .and_then(|tasks| tasks.checked_add(128))
        .ok_or_else(|| invalid("native task budget overflow"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
pub struct HostProcessUsage {
    pub cpu_micros: Counter,
    pub memory_current: Counter,
    pub memory_peak: Option<Counter>,
    pub io_read_bytes: Option<Counter>,
    pub io_write_bytes: Option<Counter>,
}

/// Retains the exact host cgroup of this guardian. Its children inherit this
/// unit; guest cgroup deletion has no access to this host mount or hierarchy.
#[cfg(target_os = "linux")]
pub struct ProcessEnvelope {
    root: PathBuf,
    unit: String,
}

#[cfg(target_os = "linux")]
impl ProcessEnvelope {
    pub fn current(machine_root: &Path, resources: &Resources) -> io::Result<Self> {
        let unit = unit_name(machine_root)?;
        let membership = std::fs::read_to_string("/proc/self/cgroup")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| invalid("cgroup v2 is required for host enforcement"))?;
        let path = Path::new(relative);
        if !path.is_absolute()
            || path.file_name().and_then(|name| name.to_str()) != Some(unit.as_str())
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(invalid(
                "guardian is outside its owned systemd resource unit",
            ));
        }
        let root =
            Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").map_err(io::Error::other)?);
        let value = Self { root, unit };
        value.verify(resources)?;
        Ok(value)
    }

    pub fn verify(&self, resources: &Resources) -> io::Result<()> {
        resources.validate().map_err(io::Error::other)?;
        let cpu = self.read("cpu.max")?;
        let fields: Vec<_> = cpu.split_whitespace().collect();
        if fields.len() != 2
            || fields[0].parse::<u64>().ok() != Some(resources.cpu_quota_micros.get())
            || fields[1].parse::<u64>().ok() != Some(CPU_PERIOD_MICROS)
            || self.number("memory.max")?
                != resources
                    .host_memory_bytes()
                    .map_err(io::Error::other)?
                    .get()
            || self.number("memory.swap.max")? != 0
            || self.number("memory.oom.group")? != 1
        {
            return Err(invalid(
                "external CPU/memory enforcement differs from host authority",
            ));
        }
        if self.number("pids.max")? != task_budget(resources)? {
            return Err(invalid("external task cap differs from host authority"));
        }
        Ok(())
    }

    /// All changes apply to the same owned unit. Failure is never reported as
    /// applied; callers contain the VM if a partial tightening is ambiguous.
    pub fn apply(&self, resources: &Resources) -> io::Result<()> {
        let mut command = Command::new("systemctl");
        command.args(["--user", "--runtime", "set-property", &self.unit]);
        // Service execution properties are immutable; only controller limits
        // can be updated on an already running unit.
        for property in systemd_properties(resources)? {
            if property.starts_with("CPUQuota")
                || property.starts_with("MemoryMax=")
                || property.starts_with("MemorySwapMax=")
                || property.starts_with("TasksMax=")
            {
                command.arg(property);
            }
        }
        run_bounded(command)?;
        self.verify(resources)
    }

    pub fn usage(&self) -> io::Result<HostProcessUsage> {
        let cpu = self.read("cpu.stat")?;
        let cpu = cpu
            .lines()
            .find_map(|line| line.strip_prefix("usage_usec "))
            .ok_or_else(|| invalid("native CPU measurement unavailable"))?;
        let io = match self.read("io.stat") {
            Ok(value) => Some(value),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let mut read = 0_u64;
        let mut write = 0_u64;
        for field in io.as_deref().unwrap_or("").split_whitespace() {
            if let Some(value) = field.strip_prefix("rbytes=") {
                read = read
                    .checked_add(parse(value)?)
                    .ok_or_else(|| invalid("native I/O overflow"))?;
            }
            if let Some(value) = field.strip_prefix("wbytes=") {
                write = write
                    .checked_add(parse(value)?)
                    .ok_or_else(|| invalid("native I/O overflow"))?;
            }
        }
        Ok(HostProcessUsage {
            cpu_micros: Counter::try_from(parse(cpu)?).map_err(io::Error::other)?,
            memory_current: Counter::try_from(self.number("memory.current")?)
                .map_err(io::Error::other)?,
            memory_peak: match self.number("memory.peak") {
                Ok(value) => Some(Counter::try_from(value).map_err(io::Error::other)?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            },
            io_read_bytes: io
                .as_ref()
                .map(|_| Counter::try_from(read).map_err(io::Error::other))
                .transpose()?,
            io_write_bytes: io
                .as_ref()
                .map(|_| Counter::try_from(write).map_err(io::Error::other))
                .transpose()?,
        })
    }

    fn number(&self, name: &str) -> io::Result<u64> {
        parse(self.read(name)?.trim())
    }
    fn read(&self, name: &str) -> io::Result<String> {
        use std::io::Read;
        let mut value = String::new();
        std::fs::File::open(self.root.join(name))?
            .take(65537)
            .read_to_string(&mut value)?;
        if value.len() > 65536 {
            return Err(invalid("native accounting exceeds bound"));
        }
        Ok(value)
    }
}

#[cfg(target_os = "linux")]
fn parse(value: &str) -> io::Result<u64> {
    value
        .parse()
        .map_err(|_| invalid("invalid native resource counter"))
}

/// Host policy commands have no stdin and a fixed deadline. Inherits neither
/// guest input nor shell expansion. Only a child launched here may be killed.
pub fn run_bounded(mut command: Command) -> io::Result<()> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other("owned resource policy command failed"))
            };
        }
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned resource policy command timed out",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn topology_and_scheduling_are_distinct_and_memory_includes_overhead() {
        let mut limits = Resources::from_geometry(
            Counter::try_from(2).unwrap(),
            Counter::try_from(256).unwrap(),
            Counter::ONE,
            Counter::ONE,
            Counter::ONE,
        )
        .unwrap();
        limits.cpu_quota_micros = Counter::try_from(25_010).unwrap();
        let properties = systemd_properties(&limits).unwrap();
        assert!(properties.contains(&"CPUQuota=25.01%".to_owned()));
        assert!(properties.contains(&format!(
            "MemoryMax={}",
            256 * 1024 * 1024 + limits.host_overhead_bytes.get()
        )));
        assert!(properties.contains(&"Delegate=no".to_owned()));
        assert!(properties.contains(&"MemorySwapMax=0".to_owned()));
        assert!(properties.contains(&"OOMPolicy=kill".to_owned()));
        assert!(
            !properties
                .iter()
                .any(|value| value.starts_with("MemoryOOMGroup="))
        );
    }
    #[test]
    fn scheduling_and_retention_cannot_exceed_their_external_reservations() {
        let mut limits = Resources::from_geometry(
            Counter::ONE,
            Counter::try_from(128).unwrap(),
            Counter::try_from(1024 * 1024).unwrap(),
            Counter::ONE,
            Counter::ONE,
        )
        .unwrap();
        assert!(limits.validate().is_ok());
        limits.cpu_quota_micros = Counter::try_from(999).unwrap();
        assert!(systemd_properties(&limits).is_err());
        limits.cpu_quota_micros = Counter::try_from(25_001).unwrap();
        assert!(systemd_properties(&limits).is_err());
        limits.cpu_quota_micros = Counter::try_from(100_000).unwrap();
        limits.physical_storage_bytes = limits.disk_bytes;
        assert!(systemd_properties(&limits).is_err());
    }
}
