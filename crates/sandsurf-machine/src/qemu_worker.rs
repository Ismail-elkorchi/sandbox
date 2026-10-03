//! Original native QEMU custody, independent of computer attachments.
//! No guest management, network policy, lifecycle intent, or catalog ownership.
use crate::GuestArchitecture;
use crate::qemu::{Accelerator, QemuControl};
use crate::qemu_driver::QemuConfig;
use crate::qemu_endpoints::{CONSOLE, Endpoints, NIC, QMP};
use sandsurf_native::process_budget::ProcessBudget;
use sandsurf_native::socket_io::SocketConnection;
use sandsurf_protocol::{Digest, bytes_digest};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(target_os = "macos")]
type NativeWorker = sandsurf_native::resource_broker::macos::OwnedWorker;
#[cfg(windows)]
type NativeWorker = sandsurf_native::owned_windows::OwnedWorker;
pub(crate) struct QemuWorker {
    pub(crate) child: NativeWorker,
    pub(crate) control: Option<QemuControl>,
    pub(crate) control_identity: [u8; 32],
    endpoints: Endpoints,
    startup_deadline: Instant,
    _custody: Vec<Arc<File>>,
    _runtime: crate::qemu_runtime::Runtime,
}
impl QemuWorker {
    pub(crate) fn launch(
        machine: &QemuConfig,
        budget: ProcessBudget,
        guest_cpu_quota: u64,
        custody: Vec<Arc<File>>,
        restore: Option<&Path>,
    ) -> io::Result<Self> {
        let config = &machine.launch;
        let captures = &machine.capture_directory;
        config.validate()?;
        budget.validate()?;
        let expected = if cfg!(target_os = "macos") {
            Accelerator::Hvf
        } else {
            Accelerator::Whpx
        };
        let architecture = if cfg!(target_arch = "aarch64") {
            GuestArchitecture::Arm64
        } else {
            GuestArchitecture::Amd64
        };
        if config.accelerator != expected || config.architecture != architecture {
            return Err(invalid(
                "hardware accelerator and guest architecture must match this native host",
            ));
        }
        let runtime = crate::qemu_runtime::verify(
            &machine.runtime_manifest,
            &machine.runtime_digest,
            architecture,
        )?;
        if config.firmware_directory != runtime.firmware_directory {
            return Err(invalid("native firmware differs from verified runtime"));
        }
        #[cfg(target_os = "macos")]
        let executable = runtime.executable.as_path();
        #[cfg(windows)]
        let [(root, root_read_only), (secondary, secondary_read_only)] = config.devices.disks();
        #[cfg(windows)]
        let disks = [
            sandsurf_native::owned_windows::disk_input(root, root_read_only)?,
            sandsurf_native::owned_windows::disk_input(secondary, secondary_read_only)?,
        ];
        #[cfg(windows)]
        let isolation = {
            if restore.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "WHPX full-state restore is unavailable",
                ));
            }
            let parent = sandsurf_native::windows_vmm::disk_volume(&disks[0])?;
            let kernel = sandsurf_native::windows_vmm::boot_input(&config.kernel)?;
            let initramfs = config
                .initramfs
                .as_deref()
                .map(sandsurf_native::windows_vmm::boot_input)
                .transpose()?;
            let original_inputs: Vec<_> = runtime.original_inputs().collect();
            sandsurf_native::windows_vmm::Isolation::create(
                &parent,
                runtime
                    .executable
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| invalid("native executable name is invalid"))?,
                &original_inputs,
                &kernel,
                initramfs.as_ref(),
            )?
        };
        #[cfg(windows)]
        let sealed = {
            let mut sealed = config.clone();
            sealed.kernel = isolation.kernel().to_owned();
            sealed.initramfs = isolation.initramfs().map(Path::to_owned);
            sealed.firmware_directory = isolation.firmware().to_owned();
            sealed
        };
        #[cfg(windows)]
        let config = &sealed;
        #[cfg(target_os = "macos")]
        let mut endpoints = Endpoints::create()?;
        #[cfg(windows)]
        let mut endpoints = Endpoints::for_vmm(isolation.namespace())?;
        let mut arguments = config.arguments(endpoints.path())?;
        // The namespace exists before the kernel policy is installed. Future
        // capture files have one fixed shape, not access to the guardian tree.
        if config.devices.machine_id().is_some() != captures.is_some() {
            return Err(invalid(
                "native capture footprint differs from the device role",
            ));
        }
        if let Some(captures) = captures {
            sandsurf_native::local::canonical_private_directory(captures)?;
        }
        if restore.is_some() {
            arguments.extend(["-incoming".into(), "defer".into()]);
        }
        #[cfg(target_os = "macos")]
        let child = {
            if guest_cpu_quota != 0
                || sandsurf_native::resource_broker::macos::virtual_machine_executable()?
                    != executable
            {
                return Err(invalid(
                    "HVF requires the installed resource-owned VMM and one aggregate task CPU cap",
                ));
            }
            let mut read_only = runtime.read_paths.clone();
            read_only.push(config.kernel.clone());
            let mut writable = Vec::new();
            for (path, read_only_disk) in config.devices.disks() {
                if read_only_disk {
                    read_only.push(path.to_owned());
                } else {
                    writable.push(path.to_owned());
                }
            }
            read_only.extend(config.initramfs.iter().cloned());
            read_only.extend(restore.map(Path::to_owned));
            let profile = sandsurf_native::darwin_vmm::Files {
                read_only,
                writable,
                endpoints: endpoints.path().to_owned(),
                captures: captures.clone(),
            }
            .profile()?;
            let mut admitted = vec!["--sandsurf-seatbelt".into(), profile.into()];
            admitted.extend(arguments);
            sandsurf_native::resource_broker::macos::launch_vm(
                budget,
                &admitted,
                custody.clone(),
                std::process::Stdio::null(),
            )?
        };
        #[cfg(windows)]
        let child = {
            let cap = sandsurf_native::process_budget::windows::guest_cpu_cap(
                guest_cpu_quota,
                config.vcpus,
            )?;
            let mut admitted = vec!["--sandsurf-cpu-cap".into(), cap.to_string().into()];
            admitted.extend(arguments);
            sandsurf_native::owned_windows::OwnedWorker::launch_vm(
                isolation.executable(),
                &admitted,
                budget,
                custody.clone(),
                disks,
                isolation.clone(),
            )?
        };
        let mut child = child;
        let mut control_identity = [0; 32];
        getrandom::getrandom(&mut control_identity).map_err(io::Error::other)?;
        let timeout = Duration::from_secs(15);
        let deadline = Instant::now() + timeout;
        // Resource-gate acknowledgement is not device readiness. Wait for
        // this retained child's sockets without treating an absent endpoint
        // as permission to create a replacement native computer.
        let control = (|| {
            let qmp = connect_device(
                &endpoints.namespace(),
                &endpoints.path().join(QMP),
                &mut child,
                deadline,
            )?;
            QemuControl::open(
                qmp,
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "native control startup deadline exceeded",
                        )
                    })?,
            )
        })();
        let control = match control {
            Ok(control) => control,
            Err(error) => {
                // Failed attachment is not native exit. Only this retained
                // child's confirmed containment permits socket reclamation.
                if child.terminate().is_ok()
                    && let Err(cleanup) = endpoints.remove_after_exit()
                {
                    eprintln!("sandsurf native endpoint cleanup unavailable: {cleanup}");
                }
                return Err(error);
            }
        };
        Ok(Self {
            child,
            control: Some(control),
            control_identity,
            endpoints,
            startup_deadline: deadline,
            _custody: custody,
            _runtime: runtime,
        })
    }
    pub(crate) fn process_id(&self) -> u32 {
        self.child.process_id()
    }
    pub(crate) fn control(&mut self) -> io::Result<&mut QemuControl> {
        self.control.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "native save owns the original control channel",
            )
        })
    }
    pub(crate) fn namespace(&self) -> sandsurf_native::socket_io::SocketNamespace {
        self.endpoints.namespace()
    }
    pub(crate) fn attach(&mut self, name: &str) -> io::Result<SocketConnection> {
        if !matches!(name, CONSOLE | NIC) {
            return Err(invalid("unknown native device attachment"));
        }
        connect_device(
            &self.endpoints.namespace(),
            &self.endpoints.path().join(name),
            &mut self.child,
            self.startup_deadline,
        )
    }
    pub(crate) fn attach_control(&mut self, slot: usize) -> io::Result<SocketConnection> {
        let name = sandsurf_native::serial_channel::socket_name(slot)?;
        connect_device(
            &self.endpoints.namespace(),
            &self.endpoints.path().join(name),
            &mut self.child,
            Instant::now() + Duration::from_secs(1),
        )
    }
    pub(crate) fn native_exit(&mut self) -> io::Result<Option<(bool, Digest)>> {
        #[cfg(target_os = "macos")]
        {
            self.child.try_wait().map(|value| {
                value.map(|exit| {
                    (
                        exit == sandsurf_native::resource_broker::WorkerExit::Exited(0),
                        bytes_digest(format!("qemu-native-exit:{exit:?}").as_bytes()),
                    )
                })
            })
        }
        #[cfg(windows)]
        {
            self.child.try_wait().map(|value| {
                value.map(|exit| {
                    (
                        exit == 0,
                        bytes_digest(format!("qemu-native-exit:{exit}").as_bytes()),
                    )
                })
            })
        }
    }
}
impl Drop for QemuWorker {
    fn drop(&mut self) {
        // A failed native receipt leaves the namespace intact. Destructor
        // cleanup is not a journal claim of power or operation completion.
        if self.child.terminate().is_ok()
            && let Err(error) = self.endpoints.remove_after_exit()
        {
            eprintln!("sandsurf native endpoint cleanup unavailable: {error}");
        }
    }
}
fn connect_device(
    namespace: &sandsurf_native::socket_io::SocketNamespace,
    path: &Path,
    child: &mut NativeWorker,
    deadline: Instant,
) -> io::Result<SocketConnection> {
    loop {
        if child.try_wait()?.is_some() {
            return Err(invalid("native VMM exited before device attachment"));
        }
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native device startup deadline exceeded",
                )
            })?;
        match SocketConnection::connect_in(namespace, path, child.process_id(), timeout) {
            Ok(socket) => return Ok(socket),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
