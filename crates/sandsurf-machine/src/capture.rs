//! A closed native save operation, separated from the original VM kill handle.
//! Workers can save already-paused state, never start, resume, or adopt a VM.
use std::io;
use std::path::PathBuf;

pub struct SnapshotFiles {
    pub state: PathBuf,
    pub state_bytes: u64,
    pub memory: Option<(PathBuf, u64)>,
}

pub enum CaptureTask {
    #[cfg(target_os = "linux")]
    Firecracker(crate::firecracker::FirecrackerCapture),
    #[cfg(any(target_os = "macos", windows))]
    Qemu(crate::qemu_owner::QemuCapture),
}

pub struct CaptureCompletion {
    pub files: io::Result<SnapshotFiles>,
    #[cfg(any(target_os = "macos", windows))]
    pub(crate) control: crate::qemu_owner::CaptureControl,
}

impl CaptureTask {
    pub fn execute(self) -> CaptureCompletion {
        match self {
            #[cfg(target_os = "linux")]
            Self::Firecracker(task) => CaptureCompletion {
                files: task
                    .execute()
                    .map(|snapshot| SnapshotFiles {
                        state: snapshot.snapshot_state,
                        state_bytes: snapshot.state_bytes,
                        memory: Some((snapshot.snapshot_memory, snapshot.memory_bytes)),
                    })
                    .map_err(io::Error::other),
            },
            #[cfg(any(target_os = "macos", windows))]
            Self::Qemu(task) => task.execute(),
        }
    }
}
