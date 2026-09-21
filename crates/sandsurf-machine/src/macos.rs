//! Guardian-owned Apple Virtualization.framework machine controller.
//!
//! The signed helper owns the native `VZVirtualMachine`. Rust owns admission,
//! qualification, request bounds, lifecycle evidence, and helper containment.

use crate::{
    DriverQualification, GuestArchitecture, MachineDriver, MachineOutcome, MachineTransition,
};
use sandsurf_protocol::{
    Counter, Digest, LifecycleCommand, MachineObservation, MachineState, Qualification, SandboxId,
    VmEngine, bytes_digest,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const MAX_HELPER_MESSAGE: usize = 1024 * 1024;
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleQualification {
    pub lifecycle: Option<Digest>,
    pub full_state: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppleDisk {
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleConfig {
    pub sandbox_id: SandboxId,
    pub helper: PathBuf,
    pub helper_digest: Digest,
    pub guest_architecture: GuestArchitecture,
    pub kernel: PathBuf,
    pub initial_ramdisk: Option<PathBuf>,
    pub command_line: String,
    pub disks: Vec<AppleDisk>,
    pub memory_bytes: u64,
    pub vcpus: u32,
    pub operation_timeout: Duration,
    pub qualification: AppleQualification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppleConfigError {
    RelativeHelper,
    RelativeKernel,
    RelativeInitialRamdisk,
    MissingDisk,
    RelativeDisk,
    DuplicateDisk,
    InvalidMemory,
    InvalidCpuCount,
    InvalidCommandLine,
    TimeoutOutOfRange,
}

pub struct AppleDriver {
    config: AppleConfig,
    owner: Option<HelperOwner>,
    applied_revision: Option<Counter>,
}

impl AppleConfig {
    pub fn validate(&self) -> Result<(), AppleConfigError> {
        if !self.helper.is_absolute() {
            return Err(AppleConfigError::RelativeHelper);
        }
        if !self.kernel.is_absolute() {
            return Err(AppleConfigError::RelativeKernel);
        }
        if self
            .initial_ramdisk
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(AppleConfigError::RelativeInitialRamdisk);
        }
        if self.disks.is_empty() {
            return Err(AppleConfigError::MissingDisk);
        }
        let mut seen = std::collections::BTreeSet::new();
        for disk in &self.disks {
            if !disk.path.is_absolute() {
                return Err(AppleConfigError::RelativeDisk);
            }
            if !seen.insert(disk.path.clone()) {
                return Err(AppleConfigError::DuplicateDisk);
            }
        }
        if self.memory_bytes < 256 * 1024 * 1024 || !self.memory_bytes.is_multiple_of(1024 * 1024) {
            return Err(AppleConfigError::InvalidMemory);
        }
        if self.vcpus == 0 || self.vcpus > 1024 {
            return Err(AppleConfigError::InvalidCpuCount);
        }
        if self.command_line.len() > 16 * 1024 || self.command_line.contains('\0') {
            return Err(AppleConfigError::InvalidCommandLine);
        }
        if self.operation_timeout.is_zero()
            || self.operation_timeout.as_millis() > u128::from(u32::MAX)
        {
            return Err(AppleConfigError::TimeoutOutOfRange);
        }
        Ok(())
    }
}

impl AppleDriver {
    pub fn new(config: AppleConfig) -> Result<Self, AppleConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            owner: None,
            applied_revision: None,
        })
    }

    pub fn default_timeout() -> Duration {
        DEFAULT_OPERATION_TIMEOUT
    }

    fn unavailable(reason: &'static [u8]) -> MachineOutcome {
        MachineOutcome::NotApplied(bytes_digest(reason))
    }

    fn lifecycle_qualified(&self) -> bool {
        self.config.qualification.lifecycle.is_some()
    }

    fn create_and_start(&mut self, command: &LifecycleCommand, epoch: Counter) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return Self::unavailable(b"apple-sandbox-identity-mismatch");
        }
        if !self.lifecycle_qualified() {
            return Self::unavailable(b"apple-configuration-not-qualified");
        }
        if self.owner.is_some() {
            return MachineOutcome::Unknown;
        }
        if !file_digest_matches(&self.config.helper, &self.config.helper_digest) {
            return Self::unavailable(b"apple-helper-integrity-mismatch");
        }
        let mut owner = match HelperOwner::spawn(&self.config.helper, self.config.operation_timeout)
        {
            Ok(value) => value,
            Err(_) => return Self::unavailable(b"apple-helper-not-started"),
        };
        let response = owner.request(&HelperRequest::Create {
            sandbox_id: command.sandbox_id.clone(),
            kernel: self.config.kernel.clone(),
            initial_ramdisk: self.config.initial_ramdisk.clone(),
            command_line: self.config.command_line.clone(),
            disks: self.config.disks.clone(),
            memory_bytes: self.config.memory_bytes,
            vcpus: self.config.vcpus,
        });
        match response {
            Ok(value)
                if value.kind == ResponseKind::Observed && value.state == MachineState::Running =>
            {
                self.owner = Some(owner);
                self.applied_revision = Some(command.revision);
                MachineOutcome::Observed(vec![
                    transition(
                        command,
                        epoch,
                        MachineState::Creating,
                        b"vz-create-complete",
                    ),
                    transition(command, epoch, MachineState::Running, b"vz-start-complete"),
                ])
            }
            Ok(value) if value.kind == ResponseKind::NotApplied => {
                Self::unavailable(b"apple-create-not-applied")
            }
            Ok(_) | Err(_) => {
                owner.contain();
                MachineOutcome::Unknown
            }
        }
    }

    fn transition_owner(
        &mut self,
        command: &LifecycleCommand,
        epoch: Counter,
        request: HelperRequest,
        expected: MachineState,
        evidence: &'static [u8],
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return Self::unavailable(b"apple-sandbox-identity-mismatch");
        }
        let Some(owner) = self.owner.as_mut() else {
            return Self::unavailable(b"apple-machine-owner-unavailable");
        };
        match owner.request(&request) {
            Ok(value) if value.kind == ResponseKind::Observed && value.state == expected => {
                MachineOutcome::Observed(vec![transition(command, epoch, expected, evidence)])
            }
            Ok(value) if value.kind == ResponseKind::NotApplied => {
                Self::unavailable(b"apple-transition-not-applied")
            }
            Ok(_) | Err(_) => MachineOutcome::Unknown,
        }
    }

    fn stop_owner(
        &mut self,
        command: &LifecycleCommand,
        epoch: Counter,
        already_stopped: bool,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return Self::unavailable(b"apple-sandbox-identity-mismatch");
        }
        let Some(mut owner) = self.owner.take() else {
            return if already_stopped {
                MachineOutcome::Observed(vec![transition(
                    command,
                    epoch,
                    MachineState::Stopped,
                    b"vz-already-stopped",
                )])
            } else {
                MachineOutcome::Unknown
            };
        };
        let result = owner.request(&HelperRequest::Stop);
        let exited = owner.finish();
        match (result, exited) {
            (Ok(value), true)
                if value.kind == ResponseKind::Observed && value.state == MachineState::Stopped =>
            {
                MachineOutcome::Observed(vec![transition(
                    command,
                    epoch,
                    MachineState::Stopped,
                    b"vz-stop-complete",
                )])
            }
            _ => MachineOutcome::Unknown,
        }
    }
}

impl MachineDriver for AppleDriver {
    fn qualification(&self) -> DriverQualification {
        DriverQualification {
            engine: VmEngine::AppleVirtualization,
            guest_architecture: self.config.guest_architecture,
            lifecycle: qualification(
                self.config.qualification.lifecycle.clone(),
                "Apple lifecycle contract has not passed on this host/configuration",
            ),
            full_state: qualification(
                self.config.qualification.full_state.clone(),
                "Apple full-state contract has not passed on this host/configuration",
            ),
        }
    }

    fn create(&mut self, command: &LifecycleCommand) -> MachineOutcome {
        self.create_and_start(command, Counter::ONE)
    }

    fn reconfigure(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        if command.sandbox_id != self.config.sandbox_id {
            return Self::unavailable(b"apple-sandbox-identity-mismatch");
        }
        if self.owner.is_none()
            || self.applied_revision != Some(current.applied_revision)
            || command.revision <= current.applied_revision
        {
            return Self::unavailable(b"apple-live-reconfiguration-not-supported");
        }
        self.applied_revision = Some(command.revision);
        MachineOutcome::Observed(vec![transition(
            command,
            current.epoch,
            MachineState::Running,
            b"vz-already-running",
        )])
    }

    fn start(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        let Ok(epoch) = current.epoch.next() else {
            return MachineOutcome::Unknown;
        };
        self.create_and_start(command, epoch)
    }

    fn pause(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        self.transition_owner(
            command,
            current.epoch,
            HelperRequest::Pause,
            MachineState::Paused,
            b"vz-pause-complete",
        )
    }

    fn resume(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        self.transition_owner(
            command,
            current.epoch,
            HelperRequest::Resume,
            MachineState::Running,
            b"vz-resume-complete",
        )
    }

    fn suspend(
        &mut self,
        _command: &LifecycleCommand,
        _current: &MachineObservation,
    ) -> MachineOutcome {
        Self::unavailable(b"apple-full-state-capture-not-implemented")
    }

    fn restore(
        &mut self,
        _command: &LifecycleCommand,
        _current: &MachineObservation,
    ) -> MachineOutcome {
        Self::unavailable(b"apple-full-state-restore-not-implemented")
    }

    fn stop(&mut self, command: &LifecycleCommand, current: &MachineObservation) -> MachineOutcome {
        self.stop_owner(
            command,
            current.epoch,
            current.state == MachineState::Stopped,
        )
    }

    fn destroy(
        &mut self,
        command: &LifecycleCommand,
        current: &MachineObservation,
    ) -> MachineOutcome {
        let stopped = self.stop_owner(
            command,
            current.epoch,
            current.state == MachineState::Stopped,
        );
        if !matches!(stopped, MachineOutcome::Observed(_)) {
            return stopped;
        }
        MachineOutcome::Observed(vec![
            transition(
                command,
                current.epoch,
                MachineState::Destroying,
                b"vz-destroying",
            ),
            transition(
                command,
                current.epoch,
                MachineState::Destroyed,
                b"vz-owner-exited",
            ),
        ])
    }
}

impl Drop for AppleDriver {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.as_mut() {
            owner.contain();
        }
    }
}

struct HelperOwner {
    child: Child,
    input: Option<ChildStdin>,
    output: Arc<Mutex<ChildStdout>>,
    timeout: Duration,
    poisoned: bool,
}

impl HelperOwner {
    fn spawn(path: &Path, timeout: Duration) -> io::Result<Self> {
        let mut child = Command::new(path)
            .arg("--sandsurf-owner-v1")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("helper stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("helper stdout unavailable"))?;
        Ok(Self {
            child,
            input: Some(input),
            output: Arc::new(Mutex::new(output)),
            timeout,
            poisoned: false,
        })
    }

    fn request(&mut self, request: &HelperRequest) -> io::Result<HelperResponse> {
        if self.poisoned {
            return Err(io::Error::other("Apple owner channel is poisoned"));
        }
        let encoded = serde_json::to_vec(request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if encoded.len() > MAX_HELPER_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Apple owner request exceeds bound",
            ));
        }
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "helper input is closed"))?;
        input.write_all(&(encoded.len() as u32).to_be_bytes())?;
        input.write_all(&encoded)?;
        input.flush()?;

        let output = Arc::clone(&self.output);
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = output
                .lock()
                .map_err(|_| io::Error::other("helper output lock poisoned"))
                .and_then(|mut stream| read_response(&mut *stream));
            let _ = sender.send(result);
        });
        match receiver.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(_) => {
                self.poisoned = true;
                self.contain();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Apple owner response timed out",
                ))
            }
        }
    }

    fn contain(&mut self) {
        self.input.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn finish(&mut self) -> bool {
        self.input.take();
        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return false;
                }
            }
        }
    }
}

impl Drop for HelperOwner {
    fn drop(&mut self) {
        self.contain();
    }
}

fn read_response(stream: &mut impl Read) -> io::Result<HelperResponse> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_HELPER_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Apple owner response length is invalid",
        ));
    }
    let mut value = vec![0u8; length];
    stream.read_exact(&mut value)?;
    serde_json::from_slice(&value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum HelperRequest {
    Create {
        sandbox_id: SandboxId,
        kernel: PathBuf,
        initial_ramdisk: Option<PathBuf>,
        command_line: String,
        disks: Vec<AppleDisk>,
        memory_bytes: u64,
        vcpus: u32,
    },
    Pause,
    Resume,
    Stop,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ResponseKind {
    Observed,
    NotApplied,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperResponse {
    kind: ResponseKind,
    state: MachineState,
}

fn file_digest_matches(path: &Path, expected: &Digest) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    bytes_digest(&bytes) == *expected
}

fn qualification(evidence: Option<Digest>, reason: &str) -> Qualification {
    match evidence {
        Some(evidence) => Qualification::Qualified { evidence },
        None => Qualification::Unqualified {
            reasons: vec![reason.to_owned()],
        },
    }
}

fn transition(
    command: &LifecycleCommand,
    epoch: Counter,
    state: MachineState,
    native_evidence: &[u8],
) -> MachineTransition {
    let mut evidence = Vec::with_capacity(native_evidence.len() + 64);
    evidence.extend_from_slice(native_evidence);
    evidence.extend_from_slice(command.request_digest.as_str().as_bytes());
    MachineTransition {
        epoch,
        state,
        evidence_digest: bytes_digest(&evidence),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_owner_and_disk_paths() {
        let value = AppleConfig {
            sandbox_id: "box".try_into().unwrap(),
            helper: PathBuf::from("helper"),
            helper_digest: bytes_digest(b"helper"),
            guest_architecture: GuestArchitecture::Arm64,
            kernel: PathBuf::from("/kernel"),
            initial_ramdisk: None,
            command_line: "console=hvc0".to_owned(),
            disks: vec![AppleDisk {
                path: PathBuf::from("/disk.raw"),
                read_only: false,
            }],
            memory_bytes: 1024 * 1024 * 1024,
            vcpus: 2,
            operation_timeout: Duration::from_secs(30),
            qualification: AppleQualification {
                lifecycle: None,
                full_state: None,
            },
        };
        assert_eq!(value.validate(), Err(AppleConfigError::RelativeHelper));
    }

    #[test]
    fn helper_response_is_bounded_and_strict() {
        let payload = br#"{"kind":"observed","state":"running"}"#;
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        let response = read_response(&mut framed.as_slice()).unwrap();
        assert_eq!(response.kind, ResponseKind::Observed);
        assert_eq!(response.state, MachineState::Running);

        let mut oversized = ((MAX_HELPER_MESSAGE + 1) as u32).to_be_bytes().to_vec();
        oversized.extend_from_slice(b"{}");
        assert!(read_response(&mut oversized.as_slice()).is_err());
    }

    #[test]
    fn unqualified_configuration_is_reported_not_assumed() {
        let value = qualification(None, "not tested");
        assert!(matches!(value, Qualification::Unqualified { .. }));
    }
}
