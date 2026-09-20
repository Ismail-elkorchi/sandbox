//! Private local guardian transport for Windows.
//!
//! The endpoint is an owner-only, local named pipe tied to a protected state
//! directory and an exclusive crash-released file lease. Both peers verify the
//! other process token. This establishes an OS-account boundary; signed Sandsurf
//! operations still establish service authority and retry safety.

use sandsurf_protocol::Frame;
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetExplicitEntriesFromAclW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT, SetNamedPipeHandleState, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};
use windows_sys::core::PWSTR;

const LEASE: &str = "control.lock";
const MAX_DEADLINE: Duration = Duration::from_secs(60);
const PIPE_BUFFER_BYTES: u32 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pub process_id: u32,
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct Handle(HANDLE);
impl Handle {
    fn new(value: HANDLE) -> io::Result<Self> {
        if value.is_null() || value == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: this value uniquely owns the live Win32 handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this allocation came from a Win32 LocalAlloc-returning API.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct UserToken {
    _token: Handle,
    buffer: Vec<usize>,
}
impl UserToken {
    fn current() -> io::Result<Self> {
        // SAFETY: GetCurrentProcess returns a valid pseudo handle.
        Self::for_process(unsafe { GetCurrentProcess() }, false)
    }

    fn for_process(process: HANDLE, close_process: bool) -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: process is a live process handle and token is a writable output.
        let result = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        if close_process {
            // SAFETY: callers pass a newly owned OpenProcess handle in this case.
            unsafe { CloseHandle(process) };
        }
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle::new(token)?;
        let mut bytes = 0_u32;
        // SAFETY: a null zero-length query obtains the required token buffer size.
        let first = unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut bytes) };
        if first != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes < size_of::<TOKEN_USER>() as u32
        {
            return Err(io::Error::other(
                "Windows did not report a valid token user size",
            ));
        }
        let words = (bytes as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        // SAFETY: the aligned buffer has the exact capacity reported by Windows.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _token: token,
            buffer,
        })
    }

    fn for_pid(process_id: u32) -> io::Result<Self> {
        // SAFETY: scalar access flags and PID have no pointer preconditions.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        Self::for_process(process, true)
    }

    fn sid(&self) -> PSID {
        // SAFETY: TokenUser retrieval initialized this aligned buffer.
        unsafe { (&*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn sid_string(&self) -> io::Result<String> {
        let mut value: PWSTR = null_mut();
        // SAFETY: the token SID and output pointer are valid.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allocation = LocalAllocation(value.cast());
        let mut length = 0_usize;
        // SAFETY: the API returns a NUL-terminated LocalAlloc UTF-16 string.
        while unsafe { *value.add(length) } != 0 {
            length += 1;
            if length > 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "current user SID exceeds its bound",
                ));
            }
        }
        // SAFETY: the loop established the initialized string length.
        let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "current SID is invalid"));
        drop(allocation);
        result
    }
}

fn require_current_user(process_id: u32) -> io::Result<()> {
    let current = UserToken::current()?;
    let peer = UserToken::for_pid(process_id)?;
    // SAFETY: both SIDs remain valid in their token buffers for this comparison.
    if unsafe { EqualSid(current.sid(), peer.sid()) } == 0 {
        return Err(denied("local pipe peer belongs to another account"));
    }
    Ok(())
}

struct SecurityDescriptor {
    allocation: LocalAllocation,
}
impl SecurityDescriptor {
    fn current_user(inheritable: bool) -> io::Result<Self> {
        let user = UserToken::current()?;
        let inheritance = if inheritable { "OICI" } else { "" };
        let sddl = wide(&format!(
            "O:{0}D:P(A;{inheritance};GA;;;{0})",
            user.sid_string()?
        ));
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: SDDL is terminated and descriptor is a writable output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            allocation: LocalAllocation(descriptor),
        })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.allocation.0,
            bInheritHandle: 0,
        }
    }
}

/// Atomically provision a protected current-user directory suitable for a local
/// endpoint. Existing paths are never adopted or chmodded.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid("local endpoint root must be absolute"));
    }
    let descriptor = SecurityDescriptor::current_user(true)?;
    let attributes = descriptor.attributes();
    let path_wide = wide_os(path)?;
    // SAFETY: path and security attributes remain initialized for this call.
    if unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = Directory::open(path) {
        let _ = fs::remove_dir(path);
        return Err(error);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume: u32,
    file: u64,
}

struct Directory {
    path: PathBuf,
    held: File,
    identity: FileIdentity,
}
impl Directory {
    fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("local endpoint root must be absolute"));
        }
        let original = open_directory(path)?;
        let identity = validate_private(&original, true, true)?;
        let canonical = fs::canonicalize(path)?;
        let resolved = open_directory(&canonical)?;
        if validate_private(&resolved, true, true)? != identity {
            return Err(denied("local endpoint root changed during resolution"));
        }
        Ok(Self {
            path: canonical,
            held: original,
            identity,
        })
    }

    fn check(&self) -> io::Result<()> {
        let current = open_directory(&self.path)?;
        if validate_private(&current, true, true)? != self.identity
            || validate_private(&self.held, true, true)? != self.identity
        {
            return Err(denied("local endpoint root identity changed"));
        }
        Ok(())
    }

    fn pipe_name(&self) -> Vec<u16> {
        wide(&format!(
            r"\\.\pipe\sandsurf-{:08x}-{:016x}",
            self.identity.volume, self.identity.file
        ))
    }
}

struct Lease(File);
impl Lease {
    fn acquire(root: &Directory) -> io::Result<Self> {
        let path = root.path.join(LEASE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        validate_private(&file, false, false)?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => {
                io::Error::new(io::ErrorKind::WouldBlock, "endpoint already has an owner")
            }
            std::fs::TryLockError::Error(error) => error,
        })?;
        root.check()?;
        let lease = Self(file);
        lease.check(root)?;
        Ok(lease)
    }

    fn check(&self, root: &Directory) -> io::Result<()> {
        if validate_private(&self.0, false, false)?
            != validate_private_path(&root.path.join(LEASE), false, false)?
        {
            return Err(denied("endpoint lease identity changed"));
        }
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

struct ListenerState {
    pending: Option<Handle>,
    first_instance: bool,
}

/// One private endpoint owner. A pending pipe instance exists from bind until
/// close, so a same-thread client can connect before the first accept call.
pub struct LocalListener {
    root: Directory,
    lease: Lease,
    pipe_name: Vec<u16>,
    state: Mutex<ListenerState>,
}
impl LocalListener {
    pub fn bind(directory: &Path) -> io::Result<Self> {
        let root = Directory::open(directory)?;
        let lease = Lease::acquire(&root)?;
        let pipe_name = root.pipe_name();
        let pending = create_pipe(&pipe_name, true)?;
        root.check()?;
        lease.check(&root)?;
        Ok(Self {
            root,
            lease,
            pipe_name,
            state: Mutex::new(ListenerState {
                pending: Some(pending),
                first_instance: false,
            }),
        })
    }

    pub fn accept(&self, timeout: Duration) -> io::Result<LocalConnection> {
        let deadline = Deadline::new(timeout)?;
        self.root.check()?;
        self.lease.check(&self.root)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("local listener state is poisoned"))?;
        let pipe = state
            .pending
            .take()
            .ok_or_else(|| io::Error::other("local listener has no pending pipe"))?;
        if let Err(error) = connect_pipe(&pipe, &deadline) {
            state.pending = Some(pipe);
            return Err(error);
        }
        let replacement = create_pipe(&self.pipe_name, state.first_instance)?;
        state.first_instance = false;
        state.pending = Some(replacement);
        drop(state);
        self.root.check()?;
        let process_id = pipe_client_pid(&pipe)?;
        require_current_user(process_id)?;
        Ok(LocalConnection {
            pipe,
            peer: PeerIdentity { process_id },
            usable: true,
        })
    }

    pub fn close(self) -> io::Result<()> {
        self.root.check()?;
        self.lease.check(&self.root)?;
        Ok(())
    }
}

pub struct LocalConnection {
    pipe: Handle,
    peer: PeerIdentity,
    usable: bool,
}
impl LocalConnection {
    pub fn connect(directory: &Path, timeout: Duration) -> io::Result<Self> {
        let deadline = Deadline::new(timeout)?;
        let root = Directory::open(directory)?;
        let pipe_name = root.pipe_name();
        let pipe = loop {
            deadline.remaining()?;
            // SAFETY: pipe name is terminated and all pointer/scalar arguments are valid.
            let raw = unsafe {
                CreateFileW(
                    pipe_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                break Handle::new(raw)?;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|value| value as u32) {
                Some(ERROR_PIPE_BUSY) => {
                    let millis = deadline.millis()?;
                    // SAFETY: the pipe name is terminated and timeout is bounded.
                    if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), millis) } == 0 {
                        let wait_error = io::Error::last_os_error();
                        if wait_error.kind() != io::ErrorKind::TimedOut {
                            return Err(wait_error);
                        }
                    }
                }
                Some(ERROR_FILE_NOT_FOUND) => {
                    std::thread::sleep(deadline.remaining()?.min(Duration::from_millis(10)));
                }
                _ => return Err(error),
            }
        };
        root.check()?;
        let mode = PIPE_READMODE_BYTE;
        // SAFETY: pipe is connected and mode points to one initialized scalar.
        if unsafe { SetNamedPipeHandleState(pipe.0, &mode, null(), null()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let process_id = pipe_server_pid(&pipe)?;
        require_current_user(process_id)?;
        Ok(Self {
            pipe,
            peer: PeerIdentity { process_id },
            usable: true,
        })
    }

    pub fn peer(&self) -> PeerIdentity {
        self.peer
    }

    pub fn read_frame(&mut self, timeout: Duration) -> io::Result<Option<Frame>> {
        let deadline = Deadline::new(timeout)?;
        self.check()?;
        let result = Frame::read(&mut DeadlineIo {
            pipe: &self.pipe,
            deadline,
        });
        if !matches!(&result, Ok(Some(_))) {
            self.usable = false;
        }
        result
    }

    pub fn write_frame(&mut self, frame: &Frame, timeout: Duration) -> io::Result<()> {
        let deadline = Deadline::new(timeout)?;
        self.check()?;
        let result = frame.write(&mut DeadlineIo {
            pipe: &self.pipe,
            deadline,
        });
        if result.is_err() {
            self.usable = false;
        }
        result
    }

    fn check(&self) -> io::Result<()> {
        if self.usable {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "local connection is closed",
            ))
        }
    }
}

struct Deadline(Instant);
impl Deadline {
    fn new(timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() || timeout > MAX_DEADLINE {
            return Err(invalid("local transport deadline must be in (0, 60s]"));
        }
        Ok(Self(Instant::now() + timeout))
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.0.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local transport deadline elapsed",
            ))
        } else {
            Ok(remaining)
        }
    }

    fn millis(&self) -> io::Result<u32> {
        Ok(self
            .remaining()?
            .as_millis()
            .max(1)
            .min(u128::from(u32::MAX - 1)) as u32)
    }
}

struct DeadlineIo<'a> {
    pipe: &'a Handle,
    deadline: Deadline,
}
impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        overlapped_io(
            self.pipe,
            bytes.len(),
            &self.deadline,
            |count, overlapped| {
                // SAFETY: bytes is writable for count bytes and overlapped remains live.
                unsafe {
                    ReadFile(
                        self.pipe.0,
                        bytes.as_mut_ptr(),
                        count,
                        null_mut(),
                        overlapped,
                    )
                }
            },
        )
    }
}
impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        overlapped_io(
            self.pipe,
            bytes.len(),
            &self.deadline,
            |count, overlapped| {
                // SAFETY: bytes is readable for count bytes and overlapped remains live.
                unsafe { WriteFile(self.pipe.0, bytes.as_ptr(), count, null_mut(), overlapped) }
            },
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn create_pipe(name: &[u16], first: bool) -> io::Result<Handle> {
    let descriptor = SecurityDescriptor::current_user(false)?;
    let attributes = descriptor.attributes();
    let first_flag = if first {
        FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        0
    };
    // SAFETY: name and security attributes are initialized for this call.
    Handle::new(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first_flag,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &attributes,
        )
    })
}

fn connect_pipe(pipe: &Handle, deadline: &Deadline) -> io::Result<()> {
    let event = create_event()?;
    // SAFETY: OVERLAPPED accepts zero initialization and a live event handle.
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    overlapped.hEvent = event.0;
    // SAFETY: pipe and overlapped are live until completion is collected.
    if unsafe { ConnectNamedPipe(pipe.0, &mut overlapped) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error().map(|value| value as u32) {
        Some(ERROR_PIPE_CONNECTED) => Ok(()),
        Some(ERROR_IO_PENDING) => {
            wait_overlapped(pipe, &mut overlapped, &event, deadline).map(|_| ())
        }
        _ => Err(error),
    }
}

fn overlapped_io<F>(
    pipe: &Handle,
    requested: usize,
    deadline: &Deadline,
    operation: F,
) -> io::Result<usize>
where
    F: FnOnce(u32, *mut OVERLAPPED) -> i32,
{
    if requested == 0 {
        return Ok(0);
    }
    let count = u32::try_from(requested).map_err(|_| invalid("local I/O request is too large"))?;
    let event = create_event()?;
    // SAFETY: OVERLAPPED accepts zero initialization and a live event handle.
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    overlapped.hEvent = event.0;
    if operation(count, &mut overlapped) != 0 {
        let mut transferred = 0_u32;
        // SAFETY: an immediately completed operation has a valid result record.
        if unsafe { GetOverlappedResult(pipe.0, &overlapped, &mut transferred, 0) } == 0 {
            return pipe_error();
        }
        return Ok(transferred as usize);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error().map(|value| value as u32) != Some(ERROR_IO_PENDING) {
        return map_pipe_error(error);
    }
    wait_overlapped(pipe, &mut overlapped, &event, deadline).map(|count| count as usize)
}

fn create_event() -> io::Result<Handle> {
    // SAFETY: unnamed, non-inheritable event creation has no borrowed pointers.
    Handle::new(unsafe { CreateEventW(null(), 1, 0, null()) })
}

fn wait_overlapped(
    pipe: &Handle,
    overlapped: &mut OVERLAPPED,
    event: &Handle,
    deadline: &Deadline,
) -> io::Result<u32> {
    // SAFETY: event is a live event handle and timeout is bounded.
    let wait = unsafe { WaitForSingleObject(event.0, deadline.millis()?) };
    if wait == WAIT_TIMEOUT {
        // SAFETY: the operation belongs to this handle/OVERLAPPED. Completion is
        // collected below before either stack object is released.
        unsafe { CancelIoEx(pipe.0, overlapped) };
        let mut ignored = 0_u32;
        // SAFETY: waiting here only drains the cancelled operation.
        unsafe { GetOverlappedResult(pipe.0, overlapped, &mut ignored, 1) };
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "local transport deadline elapsed",
        ));
    }
    if wait == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    if wait != WAIT_OBJECT_0 {
        return Err(io::Error::other("unexpected local transport wait result"));
    }
    let mut transferred = 0_u32;
    // SAFETY: the event signalled completion of this exact operation.
    if unsafe { GetOverlappedResult(pipe.0, overlapped, &mut transferred, 0) } == 0 {
        return pipe_error().map(|count| count as u32);
    }
    Ok(transferred)
}

fn pipe_error() -> io::Result<usize> {
    map_pipe_error(io::Error::last_os_error())
}

fn map_pipe_error(error: io::Error) -> io::Result<usize> {
    let code = error.raw_os_error().map(|value| value as u32);
    match code {
        Some(value)
            if value == ERROR_BROKEN_PIPE
                || value == ERROR_NO_DATA
                || value == ERROR_PIPE_NOT_CONNECTED =>
        {
            Ok(0)
        }
        Some(ERROR_OPERATION_ABORTED) => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "local pipe operation was cancelled",
        )),
        _ => Err(error),
    }
}

fn pipe_client_pid(pipe: &Handle) -> io::Result<u32> {
    let mut process_id = 0_u32;
    // SAFETY: pipe is connected and process_id is writable.
    if unsafe { GetNamedPipeClientProcessId(pipe.0, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process_id)
}

fn pipe_server_pid(pipe: &Handle) -> io::Result<u32> {
    let mut process_id = 0_u32;
    // SAFETY: pipe is connected and process_id is writable.
    if unsafe { GetNamedPipeServerProcessId(pipe.0, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process_id)
}

fn open_directory(path: &Path) -> io::Result<File> {
    let path = wide_os(path)?;
    // Omit FILE_SHARE_DELETE so this held handle fences rename/replacement.
    // SAFETY: path is terminated and all flags are valid.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned one newly owned file-compatible handle.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn validate_private_path(
    path: &Path,
    directory: bool,
    protected: bool,
) -> io::Result<FileIdentity> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = if directory {
        open_directory(path)?
    } else {
        options.open(path)?
    };
    validate_private(&file, directory, protected)
}

fn validate_private(file: &File, directory: bool, protected: bool) -> io::Result<FileIdentity> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain output storage initialized by
    // GetFileInformationByHandle before any field is observed.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: information is writable and file owns a live handle.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && information.nNumberOfLinks != 1)
    {
        return Err(denied(
            "local endpoint object has an unsafe type, link, or reparse identity",
        ));
    }
    validate_acl(file, protected)?;
    Ok(FileIdentity {
        volume: information.dwVolumeSerialNumber,
        file: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}

fn validate_acl(file: &File, protected: bool) -> io::Result<()> {
    let user = UserToken::current()?;
    let mut owner: PSID = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: all outputs are writable and descriptor is released below.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor_allocation = LocalAllocation(descriptor);
    // SAFETY: owner belongs to the live descriptor and user SID is valid.
    if owner.is_null() || acl.is_null() || unsafe { EqualSid(owner, user.sid()) } == 0 {
        return Err(denied("local endpoint owner or DACL is unavailable"));
    }
    if protected {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: descriptor is live and scalar outputs are writable.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(denied("local endpoint root inherits replaceable access"));
        }
    }
    let mut count = 0_u32;
    let mut entries: *mut EXPLICIT_ACCESS_W = null_mut();
    // SAFETY: ACL is live and outputs are writable.
    let status = unsafe { GetExplicitEntriesFromAclW(acl, &mut count, &mut entries) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let entries_allocation = LocalAllocation(entries.cast());
    if count > 64 || (count != 0 && entries.is_null()) {
        return Err(denied("local endpoint DACL exceeds its trusted bound"));
    }
    if count != 0 {
        // SAFETY: enumeration returned exactly count initialized entries.
        for entry in unsafe { std::slice::from_raw_parts(entries, count as usize) } {
            if (entry.grfAccessMode == GRANT_ACCESS || entry.grfAccessMode == SET_ACCESS)
                && (entry.Trustee.TrusteeForm != TRUSTEE_IS_SID
                    // SAFETY: SID-form trustee remains live with the descriptor.
                    || unsafe { EqualSid(entry.Trustee.ptstrName.cast(), user.sid()) } == 0)
            {
                return Err(denied("local endpoint grants another principal access"));
            }
            if entry.grfAccessMode != GRANT_ACCESS
                && entry.grfAccessMode != SET_ACCESS
                && entry.grfAccessMode != DENY_ACCESS
            {
                return Err(denied("local endpoint DACL contains an audit entry"));
            }
        }
    }
    drop(entries_allocation);
    drop(descriptor_allocation);
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn wide_os(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(invalid("Windows endpoint path contains NUL"));
    }
    value.push(0);
    Ok(value)
}
