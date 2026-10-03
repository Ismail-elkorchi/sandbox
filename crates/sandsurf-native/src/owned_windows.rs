//! A native worker starts suspended and enters its private, verified Job before
//! its first instruction. Handles, not discovered PIDs, establish ownership.
use crate::process_budget::{ProcessBudget, windows::JobEnvelope};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_NO_BUFFERING, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW,
    STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

struct Handle(HANDLE);
// SAFETY: this wrapper uniquely owns a kernel handle, which can be used on any
// thread. Drop remains unique when the owning worker moves between threads.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: only successful CreateProcess output constructs this handle.
        unsafe { CloseHandle(self.0) };
    }
}

/// The caller retains this object in the guardian, not in an SDK connection.
/// Closing the Job contains all its children, including on guardian failure.
pub struct OwnedWorker {
    process: Handle,
    process_id: u32,
    job: JobEnvelope,
    _executable: File,
    _isolation: Option<Arc<crate::windows_vmm::Isolation>>,
    exit: Option<u32>,
}

enum LaunchRole {
    Standalone,
    Factory,
    VirtualMachine([Arc<File>; 2], Arc<crate::windows_vmm::Isolation>),
}

/// Open an explicit disk role through the already validated original file,
/// not another pathname lookup. QEMU's threaded raw I/O uses unbuffered handles.
pub fn disk_input(path: &Path, read_only: bool) -> io::Result<Arc<File>> {
    let access = if read_only {
        crate::PrivateFileAccess::ReadOnly
    } else {
        crate::PrivateFileAccess::ReadWrite
    };
    let original = crate::local::open_private_file(path, access)?;
    let bytes = original.metadata()?.len();
    if bytes == 0 || bytes > 128 * 1024 * 1024 * 1024 || bytes % 512 != 0 {
        return Err(invalid("native disk input geometry exceeds bound"));
    }
    // SAFETY: original is retained and validated. ReOpenFile opens that kernel
    // file identity with only the admitted access; it cannot resolve a new path.
    let handle = unsafe {
        ReOpenFile(
            original.as_raw_handle().cast(),
            windows_sys::Win32::Foundation::GENERIC_READ
                | if read_only {
                    0
                } else {
                    windows_sys::Win32::Foundation::GENERIC_WRITE
                },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_NO_BUFFERING,
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful ReOpenFile returned one newly owned file handle.
    Ok(Arc::new(unsafe { File::from_raw_handle(handle.cast()) }))
}

impl OwnedWorker {
    /// `executable` must already have been verified against the installed
    /// native manifest by the host. A no-write/no-delete lease prevents path
    /// substitution until the child has exited. No stdio or guest handles are
    /// inherited, and no arbitrary process can be adopted by this API.
    pub fn launch(
        executable: &Path,
        arguments: &[OsString],
        budget: ProcessBudget,
    ) -> io::Result<Self> {
        Self::launch_inner(
            executable,
            arguments,
            budget,
            Vec::new(),
            LaunchRole::Standalone,
        )
    }

    /// The only factory entry is this installed host executable with a closed
    /// host role. No request supplies another executable or raw command line.
    pub fn launch_host(
        kind: crate::resource_broker::WorkerKind,
        executable: &Path,
        arguments: &[OsString],
        budget: ProcessBudget,
    ) -> io::Result<Self> {
        if kind == crate::resource_broker::WorkerKind::Images {
            return Err(invalid("image workers require transferred pool custody"));
        }
        let mode = kind
            .host_mode()
            .ok_or_else(|| invalid("invalid host worker role"))?;
        if executable != std::env::current_exe()? || budget.processes != 1 {
            return Err(invalid(
                "host workers require this executable and one native process",
            ));
        }
        let mut admitted = vec![mode.into()];
        admitted.extend_from_slice(arguments);
        Self::launch_inner(
            executable,
            &admitted,
            budget,
            Vec::new(),
            LaunchRole::Factory,
        )
    }

    /// Closed image-worker launch, retaining the pool lease before the child
    /// can execute. No native path or caller-selected executable is accepted.
    pub fn launch_images(
        executable: &Path,
        arguments: &[OsString],
        custody: Arc<File>,
    ) -> io::Result<Self> {
        if executable != std::env::current_exe()? {
            return Err(invalid("image worker differs from installed host"));
        }
        let mut admitted = vec!["image-worker".into()];
        admitted.extend_from_slice(arguments);
        Self::launch_inner(
            executable,
            &admitted,
            crate::service_pool::ServicePool::Images.process_budget(),
            vec![custody],
            LaunchRole::Factory,
        )
    }

    /// Adopt the explicit inherited reference only inside the verified image
    /// factory. A read-only identity check does not reacquire its writer lease.
    pub fn receive_image_lease(handle: usize, path: &Path) -> io::Result<File> {
        JobEnvelope::verify_current_factory(
            crate::service_pool::ServicePool::Images.process_budget(),
        )?;
        if handle == 0 || handle == usize::MAX {
            return Err(invalid("invalid inherited image custody handle"));
        }
        let mut flags = 0;
        // SAFETY: scalar handle query validates existence without adoption.
        if unsafe {
            windows_sys::Win32::Foundation::GetHandleInformation(handle as HANDLE, &mut flags)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT == 0 {
            return Err(invalid("image custody was not explicitly inherited"));
        }
        // SAFETY: this single entrypoint consumes the sole explicit inherited
        // file reference after verifying its factory role and live handle.
        let file = unsafe { File::from_raw_handle(handle as _) };
        crate::storage::verify_transferred_lease(&file, path)?;
        // SAFETY: the owned live file must not leak into other worker launches.
        if unsafe {
            windows_sys::Win32::Foundation::SetHandleInformation(
                file.as_raw_handle().cast(),
                windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    /// Transfer the kernel file object's share-denial lease into the VMM. The
    /// child inherits this bounded closure only, not stdio/grants/host endpoints.
    /// Inputs are original storage/input leases, never guest-selected handles.
    pub fn launch_vm(
        executable: &Path,
        arguments: &[OsString],
        budget: ProcessBudget,
        custody: Vec<Arc<File>>,
        disks: [Arc<File>; 2],
        isolation: Arc<crate::windows_vmm::Isolation>,
    ) -> io::Result<Self> {
        if budget.processes != 1 {
            return Err(invalid("a VMM cannot launch native descendants"));
        }
        crate::resource_broker::validate_custody_count(
            crate::resource_broker::WorkerKind::VirtualMachine,
            custody.len(),
        )?;
        Self::launch_inner(
            executable,
            arguments,
            budget,
            custody,
            LaunchRole::VirtualMachine(disks, isolation),
        )
    }

    fn launch_inner(
        executable: &Path,
        arguments: &[OsString],
        budget: ProcessBudget,
        custody: Vec<Arc<File>>,
        role: LaunchRole,
    ) -> io::Result<Self> {
        if !executable.is_absolute() {
            return Err(invalid("native worker path must be absolute"));
        }
        let executable_file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(executable)?;
        let metadata = executable_file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
            return Err(invalid("invalid native worker executable"));
        }
        let application = wide(executable.as_os_str())?;
        let directory = wide(
            executable
                .parent()
                .ok_or_else(|| invalid("worker has no directory"))?
                .as_os_str(),
        )?;
        let factory = matches!(&role, LaunchRole::Factory);
        let break_away = !matches!(&role, LaunchRole::Standalone);
        let job = if factory {
            JobEnvelope::create_factory(budget)?
        } else {
            JobEnvelope::create_owned(budget)?
        };
        let mut files = custody.clone();
        let isolation = if let LaunchRole::VirtualMachine(disks, isolation) = &role {
            if executable.as_os_str() != isolation.executable().as_os_str() {
                return Err(invalid("VMM executable is outside the sealed native scope"));
            }
            crate::resource_broker::validate_custody_count(
                crate::resource_broker::WorkerKind::VirtualMachine,
                custody.len() + 1,
            )?;
            files.push(isolation.custody());
            files.extend(disks.iter().cloned());
            Some(isolation.clone())
        } else {
            None
        };
        // The OS needs LOCALAPPDATA for a registered AppContainer identity.
        // All scratch paths refer to its original bounded device scope; no
        // caller profile, loader variables, PATH or credentials are inherited.
        let environment = environment(isolation.as_ref().map(|value| value.namespace()))?;
        let mut inherited = if files.is_empty() {
            None
        } else {
            Some(InheritedCustody::new(&files, isolation.clone())?)
        };
        let mut admitted = arguments.to_vec();
        if factory && let Some(value) = &inherited {
            admitted.push("--owned-lease".into());
            if value.handles.len() != 1 {
                return Err(invalid("an image factory owns exactly one pool lease"));
            }
            admitted.push((value.handles[0].0 as usize).to_string().into());
        }
        if matches!(&role, LaunchRole::VirtualMachine(_, _)) {
            let value = inherited
                .as_ref()
                .ok_or_else(|| invalid("native disk handles are missing"))?;
            admitted.push("--sandsurf-disk-handles".into());
            for handle in &value.handles[value.handles.len() - 2..] {
                admitted.push((handle.0 as usize).to_string().into());
            }
        }
        let mut command_line =
            crate::windows_arguments::command_line(executable.as_os_str(), &admitted)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = if inherited.is_some() {
            size_of::<STARTUPINFOEXW>()
        } else {
            size_of::<STARTUPINFOW>()
        } as u32;
        if let Some(value) = &mut inherited {
            startup.lpAttributeList = value.list.as_mut_ptr().cast();
        }
        let mut native = PROCESS_INFORMATION::default();
        if let Some(isolation) = &isolation {
            isolation.claim_launch()?;
        }
        // SAFETY: all UTF-16 input buffers are bounded, NUL-terminated and live;
        // command_line is writable. Only the explicit custody handle list is
        // inherited; no stdio, IPC, Job or credential handles leak. The
        // initial thread cannot run until the verified Job is assigned below.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                i32::from(inherited.is_some()),
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | if break_away {
                        CREATE_BREAKAWAY_FROM_JOB
                    } else {
                        0
                    }
                    | if inherited.is_some() {
                        EXTENDED_STARTUPINFO_PRESENT
                    } else {
                        0
                    },
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut native,
            )
        } == 0
        {
            if let Some(isolation) = &isolation {
                isolation.native_exited();
            }
            return Err(io::Error::last_os_error());
        }
        let thread = Handle(native.hThread);
        let mut worker = Self {
            process: Handle(native.hProcess),
            process_id: native.dwProcessId,
            job,
            _executable: executable_file,
            _isolation: isolation,
            exit: None,
        };
        if break_away && crate::process_budget::windows::process_in_job(worker.process.0)? {
            worker.terminate()?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "an ambient ancestor Job prevented independent native ownership",
            ));
        }
        worker.job.assign_suspended(&worker.process)?;
        worker.job.verify()?;
        if let Some(isolation) = &worker._isolation {
            // Token and namespace proofs precede the first VMM instruction.
            isolation.verify_process(worker.process.0)?;
            isolation.check()?;
        }
        // SAFETY: the retained initial thread belongs to this newly created
        // suspended worker; its process already has the verified envelope.
        let resumed = unsafe { ResumeThread(thread.0) };
        if resumed != 1 {
            let error = if resumed == u32::MAX {
                io::Error::last_os_error()
            } else {
                io::Error::other("owned worker initial thread was not suspended")
            };
            worker.terminate()?;
            return Err(error);
        }
        Ok(worker)
    }

    pub fn process_id(&self) -> u32 {
        self.process_id
    }

    pub fn usage(&self) -> io::Result<crate::process_budget::windows::JobUsage> {
        let mut usage = self.job.usage()?;
        // Cumulative associations can include denied native creation attempts.
        // Current memory belongs to the original live leader, not that counter.
        // SAFETY: zero-time observation of this retained original process.
        if usage.active_processes == 1
            && unsafe { WaitForSingleObject(self.process.0, 0) } == WAIT_TIMEOUT
        {
            let (memory, creation) =
                crate::process_budget::windows::original_process_usage(self.process.0)?;
            usage.current_private_commit = Some(memory);
            usage.process_creation_time = Some(creation);
        }
        Ok(usage)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<u32>> {
        self.wait_for(Duration::ZERO)
    }

    /// Querying an exit code before the handle is signaled is incorrect:
    /// STILL_ACTIVE (259) can itself be a legitimate program exit code.
    pub fn wait_for(&mut self, deadline: Duration) -> io::Result<Option<u32>> {
        if let Some(exit) = self.exit {
            return Ok(Some(exit));
        }
        let milliseconds = u32::try_from(deadline.as_millis())
            .ok()
            .filter(|value| *value < u32::MAX)
            .ok_or_else(|| invalid("native wait exceeds bound"))?;
        // SAFETY: this retained process handle cannot alias a recycled PID.
        match unsafe { WaitForSingleObject(self.process.0, milliseconds) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut exit = 0;
                // SAFETY: the signaled owned process and writable scalar output
                // establish its actual native exit code, including 259.
                if unsafe { GetExitCodeProcess(self.process.0, &mut exit) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                self.exit = Some(exit);
                if let Some(isolation) = &self._isolation {
                    isolation.native_exited();
                }
                Ok(Some(exit))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub fn terminate(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // SAFETY: the handle came from our CreateProcess, never OpenProcess or
        // a PID supplied by another owner. Zero is not a guest shutdown claim.
        if unsafe { TerminateProcess(self.process.0, 70) } == 0 {
            let error = io::Error::last_os_error();
            if self.try_wait()?.is_none() {
                return Err(error);
            }
        }
        if self.wait_for(Duration::from_secs(5))?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned worker containment unconfirmed",
            ));
        }
        Ok(())
    }
}

impl Drop for OwnedWorker {
    fn drop(&mut self) {
        let _ = self.terminate();
        // JobEnvelope's final close also contains descendants if the leader
        // exited first. The guardian never interprets Drop as committed state.
    }
}

impl JobEnvelope {
    fn assign_suspended(&self, process: &Handle) -> io::Result<()> {
        self.assign_owned_handle(process.0)
    }
}

struct InheritedCustody {
    list: Vec<usize>,
    handles: Vec<Handle>,
    raw_handles: Vec<HANDLE>,
    initialized: bool,
    _isolation: Option<Arc<crate::windows_vmm::Isolation>>,
    capabilities: Option<Box<windows_sys::Win32::Security::SECURITY_CAPABILITIES>>,
    _capability: Option<Box<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>>,
    lpac_policy: Box<u32>,
}

impl InheritedCustody {
    fn new(
        files: &[Arc<File>],
        isolation: Option<Arc<crate::windows_vmm::Isolation>>,
    ) -> io::Result<Self> {
        if files.is_empty() || files.len() > crate::MAX_WORKER_CUSTODY + 2 {
            return Err(invalid("invalid native custody closure"));
        }
        let mut handles = Vec::with_capacity(files.len());
        for (index, file) in files.iter().enumerate() {
            let mut handle = std::ptr::null_mut();
            // Custody is lifetime evidence, not a writable host file. Reduced
            // access preserves the original share-denial kernel file object.
            let disk = isolation.is_some() && index >= files.len() - 2;
            // SAFETY: retained source and self process; each successful call
            // returns one inheritable reference to the original kernel object.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    file.as_raw_handle().cast(),
                    GetCurrentProcess(),
                    &mut handle,
                    if disk {
                        0
                    } else {
                        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
                    },
                    1,
                    if disk { DUPLICATE_SAME_ACCESS } else { 0 },
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            handles.push(Handle(handle));
        }
        // This separate contiguous array never resizes while the attribute
        // list exists; moving the owner does not move its heap allocation.
        let raw_handles = handles.iter().map(|value| value.0).collect();
        let count = if isolation.is_some() { 3 } else { 1 };
        let mut bytes = 0;
        // SAFETY: null sizing query with one attribute and writable byte count.
        let result = unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut bytes)
        };
        if result != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes == 0
            || bytes > 65536
        {
            return Err(io::Error::other("invalid native handle-list allocation"));
        }
        let mut capability = isolation.as_ref().map(|scope| Box::new(scope.capability()));
        let capabilities = isolation
            .as_ref()
            .zip(capability.as_mut())
            .map(|(scope, capability)| Box::new(scope.capabilities(capability)));
        let mut value = Self {
            list: vec![0; bytes.div_ceil(size_of::<usize>())],
            handles,
            raw_handles,
            initialized: false,
            capabilities,
            _capability: capability,
            _isolation: isolation,
            lpac_policy: Box::new(1), // PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
        };
        // SAFETY: usize storage supplies HANDLE alignment and the queried full
        // capacity; the vector never resizes while the native list exists.
        if unsafe {
            InitializeProcThreadAttributeList(value.list.as_mut_ptr().cast(), count, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        value.initialized = true;
        // SAFETY: the initialized list has one slot; its attribute is one live
        // bounded inheritable file handles. No ambient inheritance/arbitrary PID.
        if unsafe {
            UpdateProcThreadAttribute(
                value.list.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                value.raw_handles.as_ptr().cast(),
                value.raw_handles.len() * size_of::<HANDLE>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(capabilities) = &value.capabilities {
            // SAFETY: heap-stable capability/SID buffers and initialized list;
            // both are retained until DeleteProcThreadAttributeList.
            if unsafe {
                UpdateProcThreadAttribute(
                    value.list.as_mut_ptr().cast(),
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (&**capabilities as *const windows_sys::Win32::Security::SECURITY_CAPABILITIES)
                        .cast(),
                    size_of::<windows_sys::Win32::Security::SECURITY_CAPABILITIES>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: heap-stable scalar opt-out policy retained with the list.
            if unsafe {
                UpdateProcThreadAttribute(
                    value.list.as_mut_ptr().cast(),
                    0,
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                    (&*value.lpac_policy as *const u32).cast(),
                    size_of::<u32>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(value)
    }
}

impl Drop for InheritedCustody {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: initialized native list in its original retained storage.
            unsafe { DeleteProcThreadAttributeList(self.list.as_mut_ptr().cast()) };
        }
    }
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut bytes: Vec<_> = value.encode_wide().take(4097).collect();
    if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
        return Err(invalid("native path exceeds UTF-16 bound"));
    }
    bytes.push(0);
    Ok(bytes)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn environment(namespace: Option<crate::socket_io::SocketNamespace>) -> io::Result<Vec<u16>> {
    let mut root = [0u16; 4096];
    // SAFETY: exact initialized UTF-16 output capacity; no caller path input.
    let bytes = unsafe { GetWindowsDirectoryW(root.as_mut_ptr(), root.len() as u32) };
    if bytes == 0 || bytes as usize >= root.len() {
        return Err(io::Error::last_os_error());
    }
    let mut environment: Vec<u16> = "SystemRoot=".encode_utf16().collect();
    environment.extend_from_slice(&root[..bytes as usize]);
    environment.push(0);
    if let Some(namespace) = namespace {
        namespace.check()?;
        let scratch = wide(namespace.path().as_os_str())?;
        for name in ["LOCALAPPDATA=", "TEMP=", "TMP="] {
            environment.extend(name.encode_utf16());
            environment.extend_from_slice(&scratch);
        }
    }
    environment.push(0);
    Ok(environment)
}
