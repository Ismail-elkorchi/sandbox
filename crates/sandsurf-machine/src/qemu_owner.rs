//! One retained QEMU child, a private native control channel and one externally
//! enforced NIC. Guest management is a separate optional serial attachment.
//! This owner observes native state; it owns no grants or lifecycle intention.
use crate::qemu_driver::QemuConfig;
use crate::qemu_endpoints::{CONSOLE, NIC};
use crate::qemu_worker::QemuWorker;
use crate::{NativeConsole, NativePowerObservation};
use sandsurf_native::GuestConnection;
use sandsurf_native::process_budget::ProcessBudget;
use sandsurf_native::serial_channel::{SerialChannel, SerialOwner};
use sandsurf_network::{LinkIdentity, NativeNetworkGateway, PacketStream, PacketTransport};
use sandsurf_protocol::{Digest, Exposure, MachineState, NetworkPolicy, bytes_digest};
use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

pub struct QemuOwner {
    worker: QemuWorker,
    serial: SerialOwner,
    network: Arc<NativeNetworkGateway>,
    console: Option<NativeConsole>,
    exit: Option<NativePowerObservation>,
    reset: Option<Digest>,
}

pub(crate) struct CaptureControl {
    identity: [u8; 32],
    channel: crate::qemu::QemuControl,
}
pub struct QemuCapture {
    control: CaptureControl,
    destination: PathBuf,
}
impl QemuCapture {
    pub(crate) fn execute(mut self) -> crate::capture::CaptureCompletion {
        let files = self
            .control
            .channel
            .save_state(&self.destination)
            .and_then(|()| {
                let file = sandsurf_native::local::open_private_file(
                    &self.destination,
                    sandsurf_native::PrivateFileAccess::ReadOnly,
                )?;
                let state_bytes = file.metadata()?.len();
                file.sync_all()?;
                Ok(crate::capture::SnapshotFiles {
                    state: self.destination,
                    state_bytes,
                    memory: None,
                })
            });
        crate::capture::CaptureCompletion {
            files,
            control: self.control,
        }
    }
}

impl QemuOwner {
    /// Starts paused. Before resuming, the guardian must apply its current
    /// admitted policy, including after restore. No guest readiness handshake
    /// is needed to construct, observe, stop or capture this native computer.
    pub fn launch(
        config: &QemuConfig,
        budget: ProcessBudget,
        guest_cpu_quota: u64,
        custody: Vec<Arc<File>>,
        restore: Option<&Path>,
    ) -> io::Result<Self> {
        let machine_id = config
            .launch
            .devices
            .machine_id()
            .ok_or_else(|| invalid("computer owner requires a native NIC"))?;
        let mut worker = QemuWorker::launch(config, budget, guest_cpu_quota, custody, restore)?;
        let process = worker.process_id();
        let timeout = std::time::Duration::from_secs(15);
        let serial = SerialOwner::new(worker.endpoints(), process, timeout)?;
        let output = worker.attach(CONSOLE)?;
        let input = output.try_clone()?;
        output.set_io_timeout(None)?;
        input.set_io_timeout(Some(std::time::Duration::from_secs(1)))?;
        let socket = worker.attach(NIC)?;
        let network = Arc::new(NativeNetworkGateway::start(
            PacketTransport::Stream(Box::new(PacketStream::new(socket.into_socket())?)),
            LinkIdentity::for_machine(machine_id),
        )?);
        Ok(Self {
            worker,
            serial,
            network,
            console: Some(NativeConsole {
                input: Box::new(input),
                output: Box::new(output),
            }),
            exit: None,
            reset: None,
        })
    }

    pub fn management_channel(&self) -> SerialChannel {
        self.serial.channel()
    }
    pub fn network(&self) -> Arc<NativeNetworkGateway> {
        Arc::clone(&self.network)
    }
    pub fn take_console(&mut self) -> Option<NativeConsole> {
        self.console.take()
    }

    #[cfg(target_os = "macos")]
    pub fn resource_usage(&mut self) -> io::Result<sandsurf_native::resource_broker::WorkerUsage> {
        self.worker.child.usage()
    }
    #[cfg(windows)]
    pub fn resource_usage(
        &mut self,
    ) -> io::Result<sandsurf_native::process_budget::windows::JobUsage> {
        self.worker.child.usage()
    }

    #[cfg(windows)]
    pub fn partition_usage(&mut self) -> io::Result<crate::qemu::PartitionUsage> {
        self.worker.control()?.partition_usage()
    }

    pub fn configure_network(
        &self,
        policy: &NetworkPolicy,
        exposures: &[Exposure],
    ) -> io::Result<()> {
        self.network.configure(policy, exposures)
    }
    pub fn pause(&mut self) -> io::Result<()> {
        self.worker.control()?.pause()
    }
    pub fn resume(&mut self) -> io::Result<()> {
        if !self.network.is_alive() {
            return Err(invalid("external NIC enforcement is unavailable"));
        }
        self.worker.control()?.resume()
    }

    pub fn observe_power(&mut self) -> io::Result<NativePowerObservation> {
        if let Some(exit) = &self.exit {
            return Ok(exit.clone());
        }
        if let Some((clean, native)) = self.worker.native_exit()? {
            self.serial.close();
            let complete = self
                .worker
                .control
                .as_mut()
                .is_some_and(|control| control.drain_exit_events().is_ok());
            let events = self
                .worker
                .control
                .as_mut()
                .map(|control| control.take_power_events())
                .unwrap_or_default();
            if clean && complete && events.failed.is_none() {
                self.reset = events.guest_reset;
            }
            let exit = NativePowerObservation {
                state: if clean && complete && events.failed.is_none() {
                    MachineState::Stopped
                } else {
                    MachineState::Failed
                },
                evidence_digest: native,
            };
            self.exit = Some(exit.clone());
            return Ok(exit);
        }
        let status = self.worker.control()?.status()?;
        let state = match status.as_str() {
            "running" => MachineState::Running,
            "paused" | "prelaunch" | "postmigrate" | "inmigrate" => MachineState::Paused,
            "shutdown" => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native shutdown event is awaiting confirmed child exit",
                ));
            }
            "guest-panicked" | "internal-error" | "io-error" => MachineState::Failed,
            _ => return Err(invalid("native QEMU power observation is indeterminate")),
        };
        Ok(NativePowerObservation {
            state,
            evidence_digest: bytes_digest(status.as_bytes()),
        })
    }

    pub fn take_guest_reset(&mut self) -> Option<Digest> {
        self.reset.take()
    }

    pub fn prepare_save(&mut self, destination: &Path) -> io::Result<crate::capture::CaptureTask> {
        let channel = self
            .worker
            .control
            .take()
            .ok_or_else(|| invalid("native save is already in flight"))?;
        Ok(crate::capture::CaptureTask::Qemu(QemuCapture {
            control: CaptureControl {
                identity: self.worker.control_identity,
                channel,
            },
            destination: destination.to_owned(),
        }))
    }

    pub fn complete_save(
        &mut self,
        completion: crate::capture::CaptureCompletion,
    ) -> io::Result<crate::capture::SnapshotFiles> {
        if self.worker.control.is_some()
            || completion.control.identity != self.worker.control_identity
        {
            return Err(invalid("native save belongs to a different original owner"));
        }
        self.worker.control = Some(completion.control.channel);
        completion.files
    }

    pub fn load_state(&mut self, source: &Path) -> io::Result<()> {
        self.worker.control()?.load_state(source)
    }

    pub fn terminate(&mut self) -> io::Result<()> {
        self.worker.child.terminate()?;
        self.serial.close();
        // The native exit result, not QMP delivery or management reachability,
        // confirms containment. A missing broker receipt remains unavailable.
        self.observe_power()?;
        Ok(())
    }
}

impl Drop for QemuOwner {
    fn drop(&mut self) {
        self.serial.close();
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
