//! Closed device roles shared by the native owners. An offline executor is a
//! hardware-isolated filesystem worker, not a computer with an empty grant.
use sandsurf_protocol::MachineId;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum Devices {
    Computer {
        machine_id: MachineId,
        system_disk: PathBuf,
        authentication_disk: PathBuf,
    },
    OfflineDisk {
        trusted_root: PathBuf,
        target: PathBuf,
        writable: bool,
    },
}

impl Devices {
    pub fn disks(&self) -> [(&Path, bool); 2] {
        match self {
            Self::Computer {
                system_disk,
                authentication_disk,
                ..
            } => [(system_disk, false), (authentication_disk, true)],
            Self::OfflineDisk {
                trusted_root,
                target,
                writable,
            } => [(trusted_root, true), (target, !writable)],
        }
    }

    pub fn machine_id(&self) -> Option<&MachineId> {
        match self {
            Self::Computer { machine_id, .. } => Some(machine_id),
            Self::OfflineDisk { .. } => None,
        }
    }

    pub fn boot_arguments(&self, console: &str) -> String {
        match self {
            Self::Computer { .. } => crate::linux_boot_arguments(console, "/dev/vda"),
            // The reviewed root and helper are runtime TCB, never the target
            // machine's installed kernel, init or administration software.
            Self::OfflineDisk { .. } => format!(
                "console={console} reboot=k panic=0 root=/dev/vda ro init=/usr/sbin/sandsurf-guest"
            ),
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        let [(root, _), (secondary, _)] = self.disks();
        if root == secondary {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VM device roles overlap",
            ));
        }
        for path in [root, secondary] {
            if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid VM device address",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_roles_never_become_computers_or_boot_the_target() {
        let root = std::env::temp_dir().join("reviewed-root");
        let target = std::env::temp_dir().join("owned-disk");
        let devices = Devices::OfflineDisk {
            trusted_root: root.clone(),
            target: target.clone(),
            writable: false,
        };
        devices.validate().unwrap();
        assert!(devices.machine_id().is_none());
        assert_eq!(
            devices.disks(),
            [(root.as_path(), true), (target.as_path(), true)]
        );
        let args = devices.boot_arguments("ttyS0");
        assert!(args.contains("root=/dev/vda ro"));
        assert!(!args.contains("init=/sbin/init"));
        assert!(!args.contains("/owned/disk"));
    }
}
