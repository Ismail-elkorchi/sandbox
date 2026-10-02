//! Shared host-service budgets are separate from per-machine budgets. A pool
//! address names supervision, not another machine or authorization authority.
use std::io;
use std::path::Path;

#[derive(Clone, Copy)]
pub enum ServicePool {
    Api,
    Supervisor,
    Images,
}

impl ServicePool {
    pub fn worker_kind(self) -> crate::resource_broker::WorkerKind {
        match self {
            Self::Api => crate::resource_broker::WorkerKind::Api,
            Self::Supervisor => crate::resource_broker::WorkerKind::Supervisor,
            Self::Images => crate::resource_broker::WorkerKind::Images,
        }
    }

    pub fn process_budget(self) -> crate::process_budget::ProcessBudget {
        crate::process_budget::ProcessBudget {
            cpu_quota_micros: if matches!(self, Self::Images) && !cfg!(target_os = "linux") {
                25000
            } else {
                100000
            },
            memory_bytes: if matches!(self, Self::Images) && !cfg!(target_os = "linux") {
                256 * 1024 * 1024
            } else {
                self.memory_bytes()
            },
            processes: if cfg!(target_os = "macos") { 2 } else { 1 },
        }
    }
    pub fn unit(self, root: &Path) -> io::Result<String> {
        let root = crate::local::canonical_private_directory(root)?;
        let root = root
            .to_str()
            .ok_or_else(|| io::Error::other("pool directory is not UTF-8"))?;
        Ok(format!(
            "sandsurf-{}-{}.service",
            match self {
                Self::Api => "api",
                Self::Supervisor => "supervisor",
                Self::Images => "images",
            },
            crate::storage::object_name(root)
        ))
    }

    pub fn memory_bytes(self) -> u64 {
        match self {
            Self::Api => 512 * 1024 * 1024,
            Self::Supervisor => 128 * 1024 * 1024,
            Self::Images => 1024 * 1024 * 1024,
        }
    }
    pub fn tasks(self) -> u64 {
        match self {
            Self::Api => 256,
            Self::Supervisor => 64,
            Self::Images => 64,
        }
    }

    pub fn properties(self) -> Vec<String> {
        let mut result = vec![
            "CPUQuota=100%".into(),
            "CPUQuotaPeriodSec=100ms".into(),
            format!("MemoryMax={}", self.memory_bytes()),
            "MemorySwapMax=0".into(),
            "OOMPolicy=kill".into(),
            format!("TasksMax={}", self.tasks()),
            "KillMode=control-group".into(),
            "Delegate=no".into(),
            "Restart=no".into(),
            "TimeoutStopSec=5".into(),
        ];
        if matches!(self, Self::Images) {
            result.push("RuntimeMaxSec=300".into());
        }
        result
    }

    /// False means this process is not the pool, never that an owned but
    /// incorrectly configured pool can be accepted. Every controller is read
    /// back before processing an admitted request.
    #[cfg(target_os = "linux")]
    pub fn current(self, root: &Path) -> io::Result<bool> {
        let unit = self.unit(root)?;
        let membership = std::fs::read_to_string("/proc/self/cgroup")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| io::Error::other("shared service pools require cgroup v2"))?;
        let path = Path::new(relative);
        if !path.is_absolute()
            || path
                .components()
                .any(|v| matches!(v, std::path::Component::ParentDir))
        {
            return Err(io::Error::other("invalid pool cgroup address"));
        }
        if path.file_name().and_then(|v| v.to_str()) != Some(unit.as_str()) {
            return Ok(false);
        }
        let cgroup =
            Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").map_err(io::Error::other)?);
        for (name, expected) in [
            ("cpu.max", "100000 100000".to_owned()),
            ("memory.max", self.memory_bytes().to_string()),
            ("memory.swap.max", "0".to_owned()),
            ("memory.oom.group", "1".to_owned()),
            ("pids.max", self.tasks().to_string()),
        ] {
            if std::fs::read_to_string(cgroup.join(name))?.trim() != expected {
                return Err(io::Error::other(
                    "shared pool enforcement differs from host budget",
                ));
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn api_and_image_budgets_are_separate_and_only_builds_have_a_deadline() {
        for pool in [
            ServicePool::Api,
            ServicePool::Supervisor,
            ServicePool::Images,
        ] {
            let properties = pool.properties();
            assert!(properties.contains(&format!("MemoryMax={}", pool.memory_bytes())));
            assert!(properties.contains(&"KillMode=control-group".to_owned()));
            assert!(properties.contains(&"MemorySwapMax=0".to_owned()));
        }
        assert!(
            !ServicePool::Api
                .properties()
                .iter()
                .any(|v| v.starts_with("RuntimeMaxSec="))
        );
        assert!(
            !ServicePool::Supervisor
                .properties()
                .iter()
                .any(|v| v.starts_with("RuntimeMaxSec="))
        );
        assert!(
            ServicePool::Images
                .properties()
                .contains(&"RuntimeMaxSec=300".to_owned())
        );
    }
}
