//! One explicit hardware-only device model for owned QEMU workers. No user
//! QEMU options, host mounts, monitor shell, SLIRP, TAP bridge or TCG fallback.
use crate::GuestArchitecture;
use crate::qemu_endpoints::{CONSOLE, NIC, QMP};
use sandsurf_network::LinkIdentity;
use sandsurf_protocol::{GUEST_SERIAL_CONNECTIONS, GUEST_SERIAL_PREFIX, VmEngine};
use serde_json::json;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accelerator {
    Hvf,
    Whpx,
}

impl Accelerator {
    pub fn engine(self) -> VmEngine {
        match self {
            Self::Hvf => VmEngine::QemuHvf,
            Self::Whpx => VmEngine::QemuWhpx,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Hvf => "hvf",
            Self::Whpx => "whpx",
        }
    }
}

pub struct LaunchConfig {
    pub accelerator: Accelerator,
    pub architecture: GuestArchitecture,
    pub devices: crate::devices::Devices,
    pub kernel: PathBuf,
    pub initramfs: Option<PathBuf>,
    /// Verified, bundled firmware only; never QEMU's host-wide search path.
    pub firmware_directory: PathBuf,
    pub memory_mib: u32,
    pub vcpus: u32,
}

impl LaunchConfig {
    pub fn validate(&self) -> io::Result<()> {
        for path in [&self.kernel, &self.firmware_directory] {
            path_text(path)?;
        }
        self.devices.validate()?;
        for (path, _) in self.devices.disks() {
            path_text(path)?;
        }
        if let Some(path) = &self.initramfs {
            path_text(path)?;
        }
        crate::validate_hardware(
            &self.accelerator.engine(),
            self.vcpus.into(),
            self.memory_mib.into(),
        )?;
        Ok(())
    }

    /// Arguments only. The native owner must verify executable identity,
    /// storage custody and applied process/partition limits before spawning.
    pub fn arguments(&self, endpoints: &Path) -> io::Result<Vec<OsString>> {
        self.validate()?;
        path_text(endpoints)?;
        crate::qemu_endpoints::validate(endpoints)?;
        let mut args: Vec<OsString> = [
            "-no-user-config",
            "-nodefaults",
            "-display",
            "none",
            "-monitor",
            "none",
            "-no-reboot",
            "-S",
            "-accel",
            self.accelerator.name(),
            "-machine",
            match self.architecture {
                GuestArchitecture::Amd64 => "q35",
                GuestArchitecture::Arm64 => "virt,gic-version=3",
            },
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let mut pair = |name: &str, value: String| {
            args.push(name.into());
            args.push(value.into());
        };
        pair(
            "-smp",
            format!("cpus={},maxcpus={}", self.vcpus, self.vcpus),
        );
        pair("-m", self.memory_mib.to_string());
        pair("-L", path_text(&self.firmware_directory)?.to_owned());
        pair(
            "-cpu",
            if self.architecture == GuestArchitecture::Arm64 {
                "host".into()
            } else if self.accelerator == Accelerator::Hvf {
                // Upstream HVF cannot migrate invariant TSC. Do not advertise
                // that CPU feature in this explicitly migratable device model.
                "host,-invtsc".into()
            } else {
                // WHPX's x86 CPU model is supplied by its native accelerator; do
                // not select TCG-only 'max' or an unsupported host-model fallback.
                "qemu64".into()
            },
        );
        pair("-kernel", path_text(&self.kernel)?.to_owned());
        if let Some(path) = &self.initramfs {
            pair("-initrd", path_text(path)?.to_owned());
        }
        pair(
            "-append",
            self.devices
                .boot_arguments(if self.architecture == GuestArchitecture::Amd64 {
                    "ttyS0"
                } else {
                    "ttyAMA0"
                }),
        );
        for (slot, (node, (path, read_only))) in ["root", "secondary"]
            .into_iter()
            .zip(self.devices.disks())
            .enumerate()
        {
            // Explicit raw format disables guest-selected backing files and
            // image-format probes. JSON preserves commas and other path bytes.
            pair(
                "-blockdev",
                json!({
                    "driver": "raw", "node-name": node, "read-only": read_only,
                    "file": { "driver": "file", "filename": if self.accelerator == Accelerator::Whpx {
                        format!("sandsurf-disk:{slot}")
                    } else { path_text(path)?.to_owned() },
                        "aio": "threads",
                        "cache": { "direct": true, "no-flush": false } },
                })
                .to_string(),
            );
            pair(
                "-device",
                format!("virtio-blk-pci,drive={node},serial={node}"),
            );
        }
        pair(
            "-qmp",
            format!(
                "unix:{},server=on,wait=off",
                escaped_path(&endpoints.join(QMP))?
            ),
        );
        pair("-chardev", socket("console", &endpoints.join(CONSOLE))?);
        pair("-serial", "chardev:console".into());
        pair(
            "-device",
            "virtio-serial-pci,id=control-bus,max_ports=9".into(),
        );
        for slot in 0..GUEST_SERIAL_CONNECTIONS {
            pair(
                "-chardev",
                socket(
                    &format!("control{slot}"),
                    &endpoints.join(sandsurf_native::serial_channel::socket_name(slot)?),
                )?,
            );
            pair(
                "-device",
                format!(
                    "virtserialport,bus=control-bus.0,nr={},chardev=control{slot},name={GUEST_SERIAL_PREFIX}{slot}",
                    slot + 1,
                ),
            );
        }
        if let Some(machine_id) = self.devices.machine_id() {
            pair(
                "-netdev",
                format!(
                    "stream,id=external,server=on,addr.type=unix,addr.path={}",
                    escaped_path(&endpoints.join(NIC))?
                ),
            );
            pair(
                "-device",
                format!(
                    "virtio-net-pci,netdev=external,mac={},host_mtu=1500,romfile=,csum=off,gso=off,guest_csum=off,guest_tso4=off,guest_tso6=off,guest_ecn=off,guest_ufo=off,guest_uso4=off,guest_uso6=off,guest_tunnel=off,guest_tunnel_csum=off,host_tso4=off,host_tso6=off,host_ecn=off,host_ufo=off,host_uso=off,host_tunnel=off,host_tunnel_csum=off,guest_rsc_ext=off,ctrl_guest_offloads=off",
                    LinkIdentity::for_machine(machine_id).mac_address(),
                ),
            );
        }
        Ok(args)
    }
}

fn socket(id: &str, path: &Path) -> io::Result<String> {
    Ok(format!(
        "socket,id={id},path={},server=on,wait=off",
        escaped_path(path)?
    ))
}
fn escaped_path(path: &Path) -> io::Result<String> {
    Ok(path_text(path)?.replace(',', ",,"))
}
fn path_text(path: &Path) -> io::Result<&str> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("QEMU path is not UTF-8"))?;
    if !path.is_absolute() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(invalid("QEMU path must be bounded and absolute"));
    }
    Ok(value)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(accelerator: Accelerator, architecture: GuestArchitecture) -> LaunchConfig {
        // A platform-native absolute path, including on Windows CI.
        let root = std::env::temp_dir();
        LaunchConfig {
            accelerator,
            architecture,
            devices: crate::devices::Devices::Computer {
                machine_id: "qemu-machine".try_into().unwrap(),
                system_disk: root.join("system,disk.raw"),
                authentication_disk: root.join("auth.raw"),
            },
            kernel: root.join("boot,kernel"),
            initramfs: Some(root.join("initramfs")),
            firmware_directory: root.join("firmware"),
            memory_mib: 512,
            vcpus: 2,
        }
    }
    #[test]
    fn both_native_accelerators_have_one_enforced_packet_path_and_no_fallback() {
        for accelerator in [Accelerator::Hvf, Accelerator::Whpx] {
            for architecture in [GuestArchitecture::Amd64, GuestArchitecture::Arm64] {
                let endpoints = crate::qemu_endpoints::Endpoints::create().unwrap();
                let args = config(accelerator, architecture)
                    .arguments(endpoints.path())
                    .unwrap();
                let args: Vec<_> = args.iter().map(|arg| arg.to_str().unwrap()).collect();
                assert_eq!(args.iter().filter(|arg| **arg == "-accel").count(), 1);
                assert!(
                    args.windows(2)
                        .any(|pair| pair == ["-accel", accelerator.name()])
                );
                assert!(args.contains(&"-S"));
                assert!(args.contains(&"-no-reboot"));
                assert!(args.contains(&"-no-user-config"));
                assert!(args.windows(2).any(|pair| {
                    pair[0] == "-L"
                        && pair[1]
                            == config(accelerator, architecture)
                                .firmware_directory
                                .to_str()
                                .unwrap()
                }));
                assert_eq!(args.iter().filter(|arg| **arg == "-netdev").count(), 1);
                assert!(!args.iter().any(|arg| arg.contains("tcg")
                    || arg.contains("slirp")
                    || arg.contains("hostfwd")
                    || arg.contains("netdev=user")));
                assert_eq!(
                    args.iter()
                        .filter(|arg| arg.starts_with("virtserialport,"))
                        .count(),
                    GUEST_SERIAL_CONNECTIONS
                );
                assert!(args.iter().any(|arg| arg.contains("csum=off,gso=off")));
                let disks: Vec<_> = args
                    .windows(2)
                    .filter(|pair| pair[0] == "-blockdev")
                    .map(|pair| serde_json::from_str::<serde_json::Value>(pair[1]).unwrap())
                    .collect();
                assert_eq!(disks.len(), 2);
                assert_eq!(disks[0]["driver"], "raw");
                assert_eq!(disks[0]["read-only"], false);
                assert_eq!(disks[1]["read-only"], true);
                for disk in &disks {
                    assert_eq!(disk["file"]["cache"]["direct"], true);
                    assert_eq!(disk["file"]["cache"]["no-flush"], false);
                }
                if accelerator == Accelerator::Whpx {
                    assert_eq!(disks[0]["file"]["filename"], "sandsurf-disk:0");
                    assert_eq!(disks[1]["file"]["filename"], "sandsurf-disk:1");
                } else {
                    assert!(
                        disks[0]["file"]["filename"]
                            .as_str()
                            .unwrap()
                            .contains("system,disk.raw")
                    );
                }
            }
        }
    }
    #[test]
    fn launch_rejects_alias_disks_unbounded_sockets_and_control_injection() {
        let mut config = config(Accelerator::Hvf, GuestArchitecture::Arm64);
        let endpoints = crate::qemu_endpoints::Endpoints::create().unwrap();
        let original = config.devices.clone();
        if let crate::devices::Devices::Computer {
            system_disk,
            authentication_disk,
            ..
        } = &mut config.devices
        {
            *authentication_disk = system_disk.clone();
        }
        assert!(config.arguments(endpoints.path()).is_err());
        config.devices = original;
        assert!(
            config
                .arguments(&std::env::temp_dir().join("x".repeat(104)))
                .is_err()
        );
        config.kernel = std::env::temp_dir().join("kernel\n-accel tcg");
        assert!(config.arguments(endpoints.path()).is_err());
    }
}
