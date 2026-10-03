//! A disposable hardware VM executing one offline disk session. It reuses the
//! native owners, not the machine lifecycle/authority model. No NIC, host mount
//! or root-controlled boot program is attached. Every original lease reaches
//! the actual VMM before its first instruction.
use crate::devices::Devices;
#[cfg(target_os = "linux")]
use sandsurf_native::GuestChannel;
use sandsurf_native::GuestConnection;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Runtime {
    #[cfg(target_os = "linux")]
    Firecracker {
        launcher: PathBuf,
        executable: PathBuf,
        sha256: String,
    },
    #[cfg(any(target_os = "macos", windows))]
    Qemu {
        manifest: PathBuf,
        digest: sandsurf_protocol::Digest,
    },
}

pub struct Config {
    pub runtime: Runtime,
    pub kernel: PathBuf,
    pub initramfs: Option<PathBuf>,
    pub trusted_root: PathBuf,
    pub target: PathBuf,
    pub writable: bool,
    pub state: PathBuf,
    pub custody: Vec<Arc<File>>,
}

pub struct OfflineVm {
    #[cfg(target_os = "linux")]
    owner: crate::firecracker::FirecrackerProcess,
    #[cfg(any(target_os = "macos", windows))]
    owner: crate::qemu_worker::QemuWorker,
}

impl OfflineVm {
    pub fn launch(config: Config) -> io::Result<Self> {
        let devices = Devices::OfflineDisk {
            trusted_root: config.trusted_root,
            target: config.target,
            writable: config.writable,
        };
        devices.validate()?;
        if config.custody.is_empty() || config.custody.len() > sandsurf_native::MAX_WORKER_CUSTODY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid offline native custody",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let Runtime::Firecracker {
                launcher,
                executable,
                sha256,
            } = config.runtime;
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
            let owner = crate::firecracker::FirecrackerProcess::spawn_offline(
                &crate::firecracker::FirecrackerConfig {
                    devices,
                    launcher_executable: launcher,
                    firecracker_executable: executable,
                    firecracker_sha256: sha256,
                    state_directory: config.state,
                    kernel_image: config.kernel,
                    initial_ramdisk: config.initramfs,
                    storage_custody: config.custody,
                    owner_token: nonce.iter().map(|byte| format!("{byte:02x}")).collect(),
                    guest_cid: 3,
                    guest_port: sandsurf_protocol::disk::DISK_EXECUTOR_PORT,
                    vcpu_count: 1,
                    memory_mib: 512,
                },
            )
            .map_err(io::Error::other)?;
            Ok(Self { owner })
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            let Runtime::Qemu { manifest, digest } = config.runtime;
            let architecture = if cfg!(target_arch = "aarch64") {
                crate::GuestArchitecture::Arm64
            } else {
                crate::GuestArchitecture::Amd64
            };
            let runtime = crate::qemu_runtime::verify(&manifest, &digest, architecture)?;
            sandsurf_native::local::create_private_directory(&config.state)?;
            let accelerator = if cfg!(target_os = "macos") {
                crate::qemu::Accelerator::Hvf
            } else {
                crate::qemu::Accelerator::Whpx
            };
            let machine = crate::qemu_driver::QemuConfig {
                launch: crate::qemu::LaunchConfig {
                    accelerator,
                    architecture,
                    devices,
                    kernel: config.kernel,
                    initramfs: config.initramfs,
                    firmware_directory: runtime.firmware_directory,
                    memory_mib: 512,
                    vcpus: 1,
                },
                runtime_manifest: manifest,
                runtime_digest: digest,
                capture_directory: None,
            };
            // Controller has 25% CPU / 256MiB. The actual native worker and its
            // retained owner fit the remaining pool allowance on each platform.
            let budget = sandsurf_native::process_budget::ProcessBudget {
                cpu_quota_micros: if cfg!(windows) { 25000 } else { 75000 },
                memory_bytes: 768 * 1024 * 1024,
                processes: if cfg!(windows) { 1 } else { 2 },
            };
            let guest_cpu = if cfg!(windows) { 50000 } else { 0 };
            let mut owner = crate::qemu_worker::QemuWorker::launch(
                &machine,
                budget,
                guest_cpu,
                config.custody,
                None,
            )?;
            owner.control()?.resume()?;
            Ok(Self { owner })
        }
    }

    pub fn connect(&mut self) -> io::Result<Box<dyn GuestConnection>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            #[cfg(target_os = "linux")]
            let attempt = {
                if self.owner.has_exited().map_err(io::Error::other)? {
                    return Err(io::Error::other(
                        "offline VM exited before device readiness",
                    ));
                }
                sandsurf_native::UnixVsockChannel {
                    socket_path: self.owner.vsock_path.clone(),
                    guest_port: sandsurf_protocol::disk::DISK_EXECUTOR_PORT,
                    timeout: Duration::from_secs(1),
                }
                .connect()
                .map_err(|error| match error {
                    sandsurf_native::GuestChannelError::Io(error) => error,
                    error => io::Error::other(error),
                })
            };
            #[cfg(any(target_os = "macos", windows))]
            let attempt = self
                .owner
                .attach_control(0)
                .map(|connection| Box::new(connection) as Box<dyn GuestConnection>);
            match attempt {
                Ok(connection) => {
                    connection.set_io_timeout(Some(Duration::from_secs(300)))?;
                    return Ok(connection);
                }
                Err(error)
                    if Instant::now() < deadline
                        && matches!(
                            error.kind(),
                            io::ErrorKind::NotFound
                                | io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::WouldBlock
                                | io::ErrorKind::UnexpectedEof
                        ) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Success requires the original native worker to be contained. A guest
    /// completion or a closed management stream cannot authorize byte reuse.
    pub fn finish(mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.owner.terminate().map_err(io::Error::other)?;
            self.owner.wait().map_err(io::Error::other)?;
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            self.owner.child.terminate()?;
        }
        Ok(())
    }
}
