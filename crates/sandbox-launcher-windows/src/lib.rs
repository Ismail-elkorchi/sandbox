#![deny(unsafe_op_in_unsafe_fn)]

//! Windows AppContainer launcher primitives.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::io;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;

pub const BACKEND_ID: &str = "windows-appcontainer-v1";

/// Encode an executable and argument vector using the quoting rules consumed by
/// `CommandLineToArgvW` and the Microsoft C runtime.
#[must_use]
pub fn encode_windows_command_line(executable: &str, args: &[String]) -> String {
    std::iter::once(executable.to_owned())
        .chain(args.iter().cloned())
        .map(|argument| quote_windows_argument(&argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Construct the sorted, double-NUL-terminated UTF-16 environment block used
/// by `CreateProcessW`.
pub fn encode_windows_environment(values: &[(String, String)]) -> Result<Vec<u16>, &'static str> {
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|left| left.0.to_uppercase());
    let mut block = Vec::new();
    for (name, value) in sorted {
        let drive_current_directory = name.len() == 3
            && name.starts_with('=')
            && name.ends_with(':')
            && name.as_bytes()[1].is_ascii_alphabetic();
        if name.contains('\0')
            || (name.contains('=') && !drive_current_directory)
            || value.contains('\0')
        {
            return Err("invalid environment entry");
        }
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[must_use]
pub fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|character| character == ' ' || character == '\t' || character == '"')
    {
        return value.to_owned();
    }
    let mut output = String::from("\"");
    let mut backslashes = 0_usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            output.push('"');
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n('\\', backslashes));
            backslashes = 0;
            output.push(character);
        }
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2));
    output.push('"');
    output
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AclJournalEntry {
    pub path: PathBuf,
    pub access: GrantAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg(target_os = "windows")]
struct AclRecoveryJournal {
    format_version: u32,
    moniker: String,
    entries: Vec<AclJournalEntry>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GrantAccess {
    Read,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupReport {
    pub attempted: Vec<String>,
    pub failures: Vec<String>,
}

impl CleanupReport {
    #[must_use]
    pub fn completed(&self) -> bool {
        self.failures.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JobLimits {
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u32>,
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::ffi::OsStr;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, REVOKE_ACCESS, SE_FILE_OBJECT,
        SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
        DeriveAppContainerSidFromAppContainerName,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, PSID, SECURITY_CAPABILITIES,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        MoveFileExW,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

    static NONCE: AtomicU64 = AtomicU64::new(1);
    const MAX_ACL_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_ACL_JOURNAL_ENTRIES: usize = 4096;

    #[derive(Debug)]
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this type has unique ownership of the live Win32 handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    #[derive(Debug)]
    struct OwnedSid(PSID);

    impl Drop for OwnedSid {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: AppContainer profile APIs allocate this SID with LocalAlloc.
                unsafe { LocalFree(self.0.cast()) };
            }
        }
    }

    pub struct AppContainerSession {
        moniker: Vec<u16>,
        sid: OwnedSid,
        state_root: PathBuf,
        profile_root: PathBuf,
        journal_path: PathBuf,
        journal: Vec<AclJournalEntry>,
        lease: Option<File>,
        profile_deleted: bool,
    }

    // Profile and SID ownership can be moved to the runtime cleanup thread; the Win32 objects are
    // process-wide and all access remains serialized by the owning value.
    unsafe impl Send for AppContainerSession {}

    impl AppContainerSession {
        pub fn create(state_parent: &Path) -> io::Result<Self> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let sequence = NONCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                "sandbox-appcontainer-{}-{now:x}-{sequence:x}",
                std::process::id()
            );
            let moniker = wide(&name);
            let display = wide("Sandbox ephemeral profile");
            let description = wide("Per-session sandbox AppContainer profile");
            let mut sid: PSID = null_mut();
            // SAFETY: all strings are NUL-terminated; capability count is zero and the output
            // SID pointer is valid for the duration of the call.
            let result = unsafe {
                CreateAppContainerProfile(
                    moniker.as_ptr(),
                    display.as_ptr(),
                    description.as_ptr(),
                    null(),
                    0,
                    &mut sid,
                )
            };
            if result < 0 {
                return Err(hresult_error("CreateAppContainerProfile", result));
            }
            let state_root = state_parent.join(&name);
            if let Err(error) = fs::create_dir(&state_root) {
                // SAFETY: moniker remains live and identifies the profile just created.
                unsafe { DeleteAppContainerProfile(moniker.as_ptr()) };
                // SAFETY: SID ownership has not yet been transferred to OwnedSid.
                unsafe { LocalFree(sid.cast()) };
                return Err(error);
            }
            let lease = match exclusive_file(&state_root.join("owner.lock"), true) {
                Ok(file) => file,
                Err(error) => {
                    // SAFETY: moniker identifies the profile created in this function.
                    unsafe { DeleteAppContainerProfile(moniker.as_ptr()) };
                    // SAFETY: SID ownership has not been transferred to OwnedSid.
                    unsafe { LocalFree(sid.cast()) };
                    let _ = fs::remove_dir_all(&state_root);
                    return Err(error);
                }
            };
            let profile_root = state_root.join("profile");
            if let Err(error) = fs::create_dir(&profile_root) {
                // SAFETY: moniker identifies the profile created in this function.
                unsafe { DeleteAppContainerProfile(moniker.as_ptr()) };
                // SAFETY: SID ownership has not been transferred to OwnedSid.
                unsafe { LocalFree(sid.cast()) };
                drop(lease);
                let _ = fs::remove_dir_all(&state_root);
                return Err(error);
            }
            let journal_path = state_root.join("acl-journal.json");
            let mut session = Self {
                moniker,
                sid: OwnedSid(sid),
                state_root,
                profile_root,
                journal_path,
                journal: Vec::new(),
                lease: Some(lease),
                profile_deleted: false,
            };
            session.persist_journal()?;
            // Profile-local state is explicit and inaccessible until its exact ACE is installed.
            session.grant(&session.profile_root.clone(), GrantAccess::ReadWrite)?;
            Ok(session)
        }

        #[must_use]
        pub fn moniker(&self) -> String {
            String::from_utf16_lossy(&self.moniker[..self.moniker.len().saturating_sub(1)])
        }

        pub fn grant(&mut self, path: &Path, access: GrantAccess) -> io::Result<()> {
            self.journal.push(AclJournalEntry {
                path: path.to_path_buf(),
                access,
            });
            if let Err(error) = self.persist_journal() {
                self.journal.pop();
                return Err(error);
            }
            if let Err(error) = apply_appcontainer_ace(path, self.sid.0, access) {
                self.journal.pop();
                let _ = self.persist_journal();
                return Err(error);
            }
            Ok(())
        }

        pub fn launch_suspended(&self, spec: &LaunchSpec<'_>) -> io::Result<WindowsProcess> {
            if spec.inherited_handles.len() != 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exactly stdin, stdout, and stderr handles are required",
                ));
            }
            let mut attribute_size = 0_usize;
            // SAFETY: documented sizing call; null list intentionally obtains required bytes.
            unsafe {
                InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut attribute_size);
            }
            if attribute_size == 0 {
                return Err(last_error("InitializeProcThreadAttributeList(size)"));
            }
            let mut attribute_storage = vec![0_u8; attribute_size];
            let attributes = attribute_storage.as_mut_ptr().cast();
            // SAFETY: storage is suitably sized and remains pinned until CreateProcessW returns.
            if unsafe { InitializeProcThreadAttributeList(attributes, 2, 0, &mut attribute_size) }
                == 0
            {
                return Err(last_error("InitializeProcThreadAttributeList"));
            }
            let attribute_guard = AttributeList(attributes);
            let capabilities = SECURITY_CAPABILITIES {
                AppContainerSid: self.sid.0,
                Capabilities: null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };
            // SAFETY: values and attribute list remain valid through CreateProcessW.
            if unsafe {
                UpdateProcThreadAttribute(
                    attribute_guard.0,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                    (&capabilities as *const SECURITY_CAPABILITIES).cast(),
                    size_of::<SECURITY_CAPABILITIES>(),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err(last_error(
                    "UpdateProcThreadAttribute(security capabilities)",
                ));
            }
            // SAFETY: the handle slice remains valid through process creation and is exact.
            if unsafe {
                UpdateProcThreadAttribute(
                    attribute_guard.0,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    spec.inherited_handles.as_ptr().cast(),
                    std::mem::size_of_val(spec.inherited_handles),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err(last_error("UpdateProcThreadAttribute(handle list)"));
            }
            // SAFETY: STARTUPINFOEXW is plain Win32 data and zero initialization is valid.
            let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = spec.inherited_handles[0];
            startup.StartupInfo.hStdOutput = spec.inherited_handles[1];
            startup.StartupInfo.hStdError = spec.inherited_handles[2];
            startup.lpAttributeList = attribute_guard.0;
            let executable = wide_os(spec.executable.as_os_str());
            let cwd = wide_os(spec.cwd.as_os_str());
            let mut command_line = wide(&windows_command_line(spec.executable, spec.args));
            let environment = environment_block(spec.environment, spec.cwd)?;
            // SAFETY: PROCESS_INFORMATION is an output-only plain Win32 structure.
            let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
            // SAFETY: all pointers reference initialized, live buffers; inherited handles are
            // constrained by PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
            let created = unsafe {
                CreateProcessW(
                    executable.as_ptr(),
                    command_line.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    CREATE_SUSPENDED
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_NEW_PROCESS_GROUP,
                    environment.as_ptr().cast(),
                    cwd.as_ptr(),
                    (&startup as *const STARTUPINFOEXW).cast(),
                    &mut info,
                )
            };
            if created == 0 {
                return Err(last_error("CreateProcessW"));
            }
            let process = OwnedHandle(info.hProcess);
            let thread = OwnedHandle(info.hThread);
            // SAFETY: null security/name pointers request an unnamed job; ownership is wrapped.
            let job = OwnedHandle(unsafe { CreateJobObjectW(null(), null()) });
            if job.0.is_null() {
                let error = last_error("CreateJobObjectW");
                terminate_process_and_wait(process.0, 125, "CreateJobObjectW cleanup")?;
                return Err(error);
            }
            if let Err(error) = configure_job(job.0, spec.limits) {
                terminate_process_and_wait(process.0, 125, "job configuration cleanup")?;
                return Err(error);
            }
            // SAFETY: both handles are live; process is still suspended.
            if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
                let error = last_error("AssignProcessToJobObject");
                terminate_process_and_wait(process.0, 125, "job assignment cleanup")?;
                return Err(error);
            }
            // SAFETY: primary thread is live and has never been resumed.
            if unsafe { ResumeThread(thread.0) } == u32::MAX {
                let error = last_error("ResumeThread");
                // SAFETY: kill-on-close is set, but an explicit termination makes failure atomic.
                if unsafe { TerminateJobObject(job.0, 125) } == 0 {
                    return Err(last_error("ResumeThread cleanup TerminateJobObject"));
                }
                wait_for_process_exit(process.0, "ResumeThread cleanup wait")?;
                wait_for_job_empty(job.0, "ResumeThread cleanup job")?;
                return Err(error);
            }
            drop(attribute_guard);
            Ok(WindowsProcess {
                process,
                _thread: thread,
                job,
                process_id: info.dwProcessId,
                finished: false,
            })
        }

        pub fn cleanup(mut self) -> CleanupReport {
            let mut report = CleanupReport::default();
            for entry in self.journal.iter().rev() {
                report
                    .attempted
                    .push(format!("revoke-appcontainer-ace:{}", entry.path.display()));
                match remove_appcontainer_ace(&entry.path, self.sid.0) {
                    Ok(()) => {}
                    Err(error) => report
                        .failures
                        .push(format!("restore ACL {}: {error}", entry.path.display())),
                }
            }
            report.attempted.push("delete-appcontainer-profile".into());
            // SAFETY: moniker is NUL-terminated and profile deletion is idempotent for this owner.
            let result = unsafe { DeleteAppContainerProfile(self.moniker.as_ptr()) };
            if !profile_delete_succeeded(result) {
                report
                    .failures
                    .push(format!("DeleteAppContainerProfile failed: 0x{result:08x}"));
            } else {
                self.profile_deleted = true;
            }
            if report.failures.is_empty() {
                report
                    .attempted
                    .push("remove-private-profile-storage".into());
                drop(self.lease.take());
                if let Err(error) = fs::remove_dir_all(&self.state_root)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    report
                        .failures
                        .push(format!("remove state directory: {error}"));
                }
            }
            report
        }

        fn persist_journal(&self) -> io::Result<()> {
            validate_journal_entries(&self.journal)?;
            let bytes = serde_json::to_vec(&AclRecoveryJournal {
                format_version: 2,
                moniker: self.moniker(),
                entries: self.journal.clone(),
            })
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if bytes.len() as u64 > MAX_ACL_JOURNAL_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ACL recovery journal exceeds its byte limit",
                ));
            }
            let temporary = self.journal_path.with_extension(format!(
                "json.new-{}",
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            let result = (|| {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                drop(file);
                replace_file(&temporary, &self.journal_path)
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        }
    }

    impl Drop for AppContainerSession {
        fn drop(&mut self) {
            if !self.profile_deleted {
                // Fail closed for authority lifetime. Durable ACL recovery remains in the journal.
                // SAFETY: the moniker is live for the lifetime of self.
                unsafe { DeleteAppContainerProfile(self.moniker.as_ptr()) };
            }
        }
    }

    pub struct LaunchSpec<'a> {
        pub executable: &'a Path,
        pub args: &'a [String],
        pub cwd: &'a Path,
        pub environment: &'a [(String, String)],
        pub inherited_handles: &'a [HANDLE],
        pub limits: JobLimits,
    }

    pub struct WindowsProcess {
        process: OwnedHandle,
        _thread: OwnedHandle,
        job: OwnedHandle,
        pub process_id: u32,
        finished: bool,
    }

    // Win32 kernel handles are process-wide values and may be transferred to an owning thread.
    unsafe impl Send for WindowsProcess {}

    impl WindowsProcess {
        pub fn try_wait(&mut self) -> io::Result<Option<u32>> {
            // SAFETY: process handle remains live for the duration of the nonblocking query.
            let result = unsafe { WaitForSingleObject(self.process.0, 0) };
            match result {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => return Ok(None),
                WAIT_FAILED => return Err(last_error("WaitForSingleObject")),
                other => {
                    return Err(io::Error::other(format!(
                        "WaitForSingleObject returned unexpected status {other}"
                    )));
                }
            }
            let mut code = 0_u32;
            // SAFETY: output pointer and process handle are valid.
            if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
                return Err(last_error("GetExitCodeProcess"));
            }
            self.finished = true;
            Ok(Some(code))
        }

        pub fn wait(&mut self) -> io::Result<u32> {
            // SAFETY: process handle remains owned by self for the whole wait.
            if unsafe { WaitForSingleObject(self.process.0, INFINITE) } != WAIT_OBJECT_0 {
                return Err(last_error("WaitForSingleObject"));
            }
            let mut code = 0_u32;
            // SAFETY: output pointer and live process handle are valid.
            if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
                return Err(last_error("GetExitCodeProcess"));
            }
            self.finished = true;
            Ok(code)
        }

        pub fn terminate(&mut self, code: u32) -> io::Result<()> {
            // SAFETY: job handle is live and owns the complete process tree.
            if unsafe { TerminateJobObject(self.job.0, code) } == 0 {
                return Err(last_error("TerminateJobObject"));
            }
            wait_for_process_exit(self.process.0, "TerminateJobObject wait")?;
            wait_for_job_empty(self.job.0, "TerminateJobObject accounting")?;
            self.finished = true;
            Ok(())
        }

        pub fn terminate_descendants(&mut self) -> io::Result<()> {
            self.terminate(125)
        }
    }

    impl Drop for WindowsProcess {
        fn drop(&mut self) {
            if !self.finished {
                // SAFETY: kill-on-close is a fallback, this explicitly requests immediate teardown.
                unsafe { TerminateJobObject(self.job.0, 125) };
            }
        }
    }

    struct AttributeList(LPPROC_THREAD_ATTRIBUTE_LIST);

    impl Drop for AttributeList {
        fn drop(&mut self) {
            // SAFETY: this list was initialized once and is deleted once.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }

    fn configure_job(job: HANDLE, limits: JobLimits) -> io::Result<()> {
        // SAFETY: this Job Object information structure is valid when zero-initialized.
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        information.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if let Some(max_processes) = limits.max_processes {
            information.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            information.BasicLimitInformation.ActiveProcessLimit = max_processes;
        }
        if let Some(memory) = limits.memory_bytes {
            information.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            information.JobMemoryLimit = usize::try_from(memory).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "memory limit exceeds pointer width",
                )
            })?;
        }
        // SAFETY: information points to the exact structure selected by the information class.
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(last_error("SetInformationJobObject"));
        }
        Ok(())
    }

    fn terminate_process_and_wait(process: HANDLE, code: u32, operation: &str) -> io::Result<()> {
        // SAFETY: the caller owns a live process handle and has not handed it to user code.
        if unsafe { TerminateProcess(process, code) } == 0 {
            return Err(last_error(operation));
        }
        wait_for_process_exit(process, operation)
    }

    fn wait_for_process_exit(process: HANDLE, operation: &str) -> io::Result<()> {
        // SAFETY: the process handle remains owned by the caller for the duration of the wait.
        match unsafe { WaitForSingleObject(process, 5_000) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_FAILED => Err(last_error(operation)),
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{operation} did not confirm process termination"),
            )),
            other => Err(io::Error::other(format!(
                "{operation} returned unexpected wait status {other}"
            ))),
        }
    }

    fn wait_for_job_empty(job: HANDLE, operation: &str) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: the accounting structure is valid when zero initialized.
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            // SAFETY: job is live and the output buffer exactly matches the selected class.
            if unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                )
            } == 0
            {
                return Err(last_error(operation));
            }
            if accounting.ActiveProcesses == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{operation} did not confirm complete Job Object termination"),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn apply_appcontainer_ace(path: &Path, sid: PSID, access: GrantAccess) -> io::Result<()> {
        let mut rights = FILE_GENERIC_READ;
        if matches!(
            access,
            GrantAccess::ReadWrite | GrantAccess::ReadWriteExecute
        ) {
            rights |= FILE_GENERIC_WRITE;
        }
        if matches!(
            access,
            GrantAccess::ReadExecute | GrantAccess::ReadWriteExecute
        ) {
            rights |= FILE_GENERIC_EXECUTE;
        }
        update_appcontainer_ace(
            path,
            sid,
            rights,
            GRANT_ACCESS,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        )
    }

    fn remove_appcontainer_ace(path: &Path, sid: PSID) -> io::Result<()> {
        update_appcontainer_ace(path, sid, 0, REVOKE_ACCESS, 0)
    }

    fn update_appcontainer_ace(
        path: &Path,
        sid: PSID,
        rights: u32,
        access_mode: i32,
        inheritance: u32,
    ) -> io::Result<()> {
        let path = wide_os(path.as_os_str());
        let mut current_acl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: output pointers are valid and released below with LocalFree.
        let status = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut current_acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(win32_error("GetNamedSecurityInfoW", status));
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: rights,
            grfAccessMode: access_mode,
            grfInheritance: inheritance,
            Trustee: windows_sys::Win32::Security::Authorization::TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.cast(),
            },
        };
        let mut updated_acl: *mut ACL = null_mut();
        // SAFETY: entry and source ACL stay live throughout construction.
        let update = unsafe { SetEntriesInAclW(1, &entry, current_acl, &mut updated_acl) };
        if update != 0 {
            // SAFETY: descriptor was allocated by GetNamedSecurityInfoW.
            unsafe { LocalFree(descriptor) };
            return Err(win32_error("SetEntriesInAclW", update));
        }
        // SAFETY: updated DACL remains live for the call and other security fields are unchanged.
        let applied = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr() as *mut u16,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                updated_acl,
                null_mut(),
            )
        };
        // SAFETY: both buffers are LocalAlloc-owned.
        unsafe {
            LocalFree(updated_acl.cast());
            LocalFree(descriptor);
        }
        if applied != 0 {
            return Err(win32_error("SetNamedSecurityInfoW", applied));
        }
        Ok(())
    }

    pub fn recover_acl_journal(journal_path: &Path) -> io::Result<CleanupReport> {
        let state_root = journal_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "ACL journal has no state root")
        })?;
        let root_metadata = fs::symlink_metadata(state_root)?;
        if !root_metadata.is_dir()
            || root_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACL recovery state root is not a plain directory",
            ));
        }
        let _lease = exclusive_file(&state_root.join("owner.lock"), false)?;
        let journal_file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(journal_path)?;
        let metadata = journal_file.metadata()?;
        if !metadata.is_file()
            || metadata.len() > MAX_ACL_JOURNAL_BYTES
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACL recovery journal is not a bounded regular file",
            ));
        }
        let mut journal_bytes = Vec::with_capacity(metadata.len() as usize);
        journal_file
            .take(MAX_ACL_JOURNAL_BYTES + 1)
            .read_to_end(&mut journal_bytes)?;
        if journal_bytes.len() as u64 > MAX_ACL_JOURNAL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACL recovery journal exceeds its byte limit",
            ));
        }
        let journal: AclRecoveryJournal = serde_json::from_slice(&journal_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let expected_name = state_root.file_name().and_then(|name| name.to_str());
        if journal.format_version != 2
            || expected_name != Some(journal.moniker.as_str())
            || !journal.moniker.starts_with("sandbox-appcontainer-")
            || !journal
                .moniker
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ACL recovery journal identity",
            ));
        }
        validate_journal_entries(&journal.entries)?;
        let moniker = wide(&journal.moniker);
        let mut sid: PSID = null_mut();
        // SAFETY: moniker is validated, NUL-terminated, and the SID output pointer is live.
        let derived =
            unsafe { DeriveAppContainerSidFromAppContainerName(moniker.as_ptr(), &mut sid) };
        if derived < 0 {
            return Err(hresult_error(
                "DeriveAppContainerSidFromAppContainerName",
                derived,
            ));
        }
        let sid = OwnedSid(sid);
        let mut report = CleanupReport::default();
        for entry in journal.entries.iter().rev() {
            report
                .attempted
                .push(format!("revoke-appcontainer-ace:{}", entry.path.display()));
            match remove_appcontainer_ace(&entry.path, sid.0) {
                Ok(()) => {}
                Err(error) => report
                    .failures
                    .push(format!("{}: {error}", entry.path.display())),
            }
        }
        report.attempted.push("delete-appcontainer-profile".into());
        // SAFETY: moniker is a live NUL-terminated profile name from the validated journal.
        let result = unsafe { DeleteAppContainerProfile(moniker.as_ptr()) };
        if !profile_delete_succeeded(result) {
            report
                .failures
                .push(format!("DeleteAppContainerProfile failed: 0x{result:08x}"));
        }
        if report.failures.is_empty() {
            report
                .attempted
                .push("remove-private-profile-storage".into());
            drop(_lease);
            if let Err(error) = fs::remove_dir_all(state_root)
                && error.kind() != io::ErrorKind::NotFound
            {
                report
                    .failures
                    .push(format!("remove state directory: {error}"));
            }
        }
        Ok(report)
    }

    fn validate_journal_entries(entries: &[AclJournalEntry]) -> io::Result<()> {
        if entries.len() > MAX_ACL_JOURNAL_ENTRIES
            || entries.iter().any(|entry| !entry.path.is_absolute())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACL recovery journal contains invalid entries",
            ));
        }
        Ok(())
    }

    fn exclusive_file(path: &Path, create: bool) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).share_mode(0);
        if create {
            options.create_new(true);
        }
        options.open(path).map_err(|error| {
            if !create && error.raw_os_error() == Some(32) {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "ACL recovery owner is still active",
                )
            } else {
                error
            }
        })
    }

    fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
        let source = wide_os(source.as_os_str());
        let destination = wide_os(destination.as_os_str());
        // SAFETY: both paths are live NUL-terminated buffers. The source is a private,
        // newly-created journal temporary owned by this session.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(last_error("MoveFileExW(ACL journal)"));
        }
        Ok(())
    }

    fn profile_delete_succeeded(result: i32) -> bool {
        result >= 0 || matches!(result as u32, 0x8007_0002 | 0x8007_0490)
    }

    pub(super) fn environment_block(
        values: &[(String, String)],
        cwd: &Path,
    ) -> io::Result<Vec<u16>> {
        use std::path::{Component, Prefix};

        let mut values = values.to_vec();
        if let Some(Component::Prefix(prefix)) = cwd.components().next()
            && let Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) = prefix.kind()
        {
            // CreateProcessW does not add the hidden per-drive current-directory entry when a
            // custom environment block is supplied. Keep it launch-internal: Windows consumes
            // this `=C:`-style entry for drive-relative path resolution, while policy-visible
            // environment names remain exactly those requested by the caller.
            values.push((
                format!("={}:", char::from(drive).to_ascii_uppercase()),
                cwd.to_string_lossy().into_owned(),
            ));
        }
        encode_windows_environment(&values)
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))
    }

    fn windows_command_line(executable: &Path, args: &[String]) -> String {
        encode_windows_command_line(&executable.as_os_str().to_string_lossy(), args)
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    fn wide_os(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn hresult_error(operation: &str, result: i32) -> io::Error {
        io::Error::other(format!("{operation} failed with HRESULT 0x{result:08x}"))
    }

    fn win32_error(operation: &str, result: u32) -> io::Error {
        io::Error::other(format!("{operation} failed with Win32 status {result}"))
    }

    fn last_error(operation: &str) -> io::Error {
        // SAFETY: GetLastError has no preconditions and is read immediately after failure.
        let code = unsafe { GetLastError() };
        io::Error::other(format!("{operation} failed with Win32 status {code}"))
    }

    pub use AppContainerSession as Session;
    pub use LaunchSpec as ProcessLaunchSpec;
    pub use WindowsProcess as Process;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn appcontainer_process_smoke() {
            if std::env::var_os("SANDBOX_APPCONTAINER_TEST_CHILD").is_some() {
                return;
            }

            let (parent, workspace) = test_directories("process-smoke");
            let executable = std::env::current_exe().expect("current test executable");
            let executable_parent = executable.parent().expect("test executable parent");
            let mut session = AppContainerSession::create(&parent).expect("create AppContainer");
            session
                .grant(executable_parent, GrantAccess::ReadExecute)
                .expect("grant test executable tree");
            session
                .grant(&workspace, GrantAccess::ReadWrite)
                .expect("grant working directory");

            let (stdin_read, stdin_write) = pipe().expect("stdin pipe");
            let (stdout_read, stdout_write) = pipe().expect("stdout pipe");
            let (stderr_read, stderr_write) = pipe().expect("stderr pipe");
            let args = vec![
                "--exact".to_owned(),
                "windows::tests::appcontainer_process_smoke".to_owned(),
            ];
            let mut environment = std::env::vars()
                .filter(|(name, _)| !name.contains('='))
                .collect::<Vec<_>>();
            environment.push(("SANDBOX_APPCONTAINER_TEST_CHILD".to_owned(), "1".to_owned()));
            let launch = session.launch_suspended(&LaunchSpec {
                executable: &executable,
                args: &args,
                cwd: &workspace,
                environment: &environment,
                inherited_handles: &[stdin_read.0, stdout_write.0, stderr_write.0],
                limits: JobLimits {
                    memory_bytes: None,
                    max_processes: Some(1),
                },
            });
            drop(stdin_read);
            drop(stdout_write);
            drop(stderr_write);
            drop(stdin_write);
            let mut process = match launch {
                Ok(process) => process,
                Err(error) => {
                    let report = session.cleanup();
                    let _ = fs::remove_dir_all(&parent);
                    let _ = fs::remove_dir_all(&workspace);
                    panic!(
                        "launch AppContainer test child: {error}; cleanup failures: {:?}",
                        report.failures
                    );
                }
            };
            assert_eq!(process.wait().expect("wait for test child"), 0);
            drop(stdout_read);
            drop(stderr_read);

            let report = session.cleanup();
            assert!(
                report.completed(),
                "cleanup failures: {:?}",
                report.failures
            );
            let _ = fs::remove_dir_all(&parent);
            let _ = fs::remove_dir_all(&workspace);
        }

        #[test]
        fn cleanup_revokes_only_the_ephemeral_appcontainer_sid() {
            let (parent, workspace) = test_directories("exact-ace");
            let mut session = AppContainerSession::create(&parent).expect("create AppContainer");
            session
                .grant(&workspace, GrantAccess::ReadWrite)
                .expect("grant workspace");
            let sid = derive_sid(&session.moniker()).expect("derive session SID");
            assert!(sid_ace_count(&workspace, sid.0).expect("inspect granted ACL") > 0);
            let report = session.cleanup();
            assert!(
                report.completed(),
                "cleanup failures: {:?}",
                report.failures
            );
            assert_eq!(
                sid_ace_count(&workspace, sid.0).expect("inspect revoked ACL"),
                0
            );
            let _ = fs::remove_dir_all(&parent);
            let _ = fs::remove_dir_all(&workspace);
        }

        #[test]
        fn recovery_journal_revokes_aces_after_abandoned_ownership() {
            let (parent, workspace) = test_directories("recovery");
            let mut session = AppContainerSession::create(&parent).expect("create AppContainer");
            session
                .grant(&workspace, GrantAccess::ReadWrite)
                .expect("grant workspace");
            let sid = derive_sid(&session.moniker()).expect("derive session SID");
            let journal = session.journal_path.clone();
            let state_root = session.state_root.clone();
            assert!(sid_ace_count(&workspace, sid.0).expect("inspect granted ACL") > 0);

            // Model abrupt process death: handles close, but profile, journal and ACL survive.
            session.profile_deleted = true;
            drop(session.lease.take());
            drop(session);

            let report = recover_acl_journal(&journal).expect("recover abandoned ACL journal");
            assert!(
                report.completed(),
                "recovery failures: {:?}",
                report.failures
            );
            assert_eq!(
                sid_ace_count(&workspace, sid.0).expect("inspect recovered ACL"),
                0
            );
            assert!(!state_root.exists());
            let _ = fs::remove_dir_all(&parent);
            let _ = fs::remove_dir_all(&workspace);
        }

        fn test_directories(label: &str) -> (PathBuf, PathBuf) {
            let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir();
            let parent = base.join(format!(
                "sandbox-appcontainer-test-{label}-{}-{nonce}",
                std::process::id()
            ));
            let workspace = base.join(format!(
                "sandbox-appcontainer-workspace-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&parent).expect("create state parent");
            fs::create_dir(&workspace).expect("create workspace");
            (parent, workspace)
        }

        struct TestHandle(HANDLE);

        impl Drop for TestHandle {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: this test helper uniquely owns the pipe endpoint.
                    unsafe { CloseHandle(self.0) };
                }
            }
        }

        fn pipe() -> io::Result<(TestHandle, TestHandle)> {
            let mut read = null_mut();
            let mut write = null_mut();
            let security = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: null_mut(),
                bInheritHandle: 1,
            };
            // SAFETY: both output slots and the initialized security attributes remain live.
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(&mut read, &mut write, &security, 0)
            } == 0
            {
                return Err(last_error("CreatePipe(test)"));
            }
            Ok((TestHandle(read), TestHandle(write)))
        }

        fn derive_sid(moniker: &str) -> io::Result<OwnedSid> {
            let moniker = wide(moniker);
            let mut sid: PSID = null_mut();
            // SAFETY: moniker is NUL-terminated and sid is a writable output pointer.
            let result =
                unsafe { DeriveAppContainerSidFromAppContainerName(moniker.as_ptr(), &mut sid) };
            if result < 0 {
                return Err(hresult_error(
                    "DeriveAppContainerSidFromAppContainerName",
                    result,
                ));
            }
            Ok(OwnedSid(sid))
        }

        fn sid_ace_count(path: &Path, sid: PSID) -> io::Result<usize> {
            let path = wide_os(path.as_os_str());
            let mut acl: *mut ACL = null_mut();
            let mut descriptor = null_mut();
            // SAFETY: all output pointers are live and descriptor is released below.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut acl,
                    null_mut(),
                    &mut descriptor,
                )
            };
            if status != 0 {
                return Err(win32_error("GetNamedSecurityInfoW(test)", status));
            }
            let mut count = 0_u32;
            let mut entries: *mut EXPLICIT_ACCESS_W = null_mut();
            // SAFETY: acl came from the descriptor above and both output pointers are valid.
            let status = unsafe {
                windows_sys::Win32::Security::Authorization::GetExplicitEntriesFromAclW(
                    acl,
                    &mut count,
                    &mut entries,
                )
            };
            if status != 0 {
                // SAFETY: descriptor is LocalAlloc-owned.
                unsafe { LocalFree(descriptor) };
                return Err(win32_error("GetExplicitEntriesFromAclW(test)", status));
            }
            let matches = if count == 0 {
                0
            } else {
                if entries.is_null() {
                    // SAFETY: descriptor is LocalAlloc-owned and entries has no allocation.
                    unsafe { LocalFree(descriptor) };
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ACL enumeration returned a positive count without entries",
                    ));
                }
                // SAFETY: a positive count and successful API result establish a non-null buffer
                // containing exactly `count` initialized entries.
                let entries_slice = unsafe {
                    std::slice::from_raw_parts(entries, usize::try_from(count).expect("u32 fits"))
                };
                entries_slice
                    .iter()
                    .filter(|entry| {
                        entry.Trustee.TrusteeForm == TRUSTEE_IS_SID
                            // SAFETY: SID-form trustees expose a valid SID pointer for this buffer.
                            && unsafe {
                                windows_sys::Win32::Security::EqualSid(
                                    entry.Trustee.ptstrName.cast(),
                                    sid,
                                )
                            } != 0
                    })
                    .count()
            };
            // SAFETY: both allocations were produced by Windows ACL APIs and are no longer used.
            unsafe {
                LocalFree(entries.cast());
                LocalFree(descriptor);
            }
            Ok(matches)
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows::{Process, ProcessLaunchSpec, Session, recover_acl_journal};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_completion_reflects_failures() {
        let mut report = CleanupReport::default();
        assert!(report.completed());
        report.failures.push("failure".into());
        assert!(!report.completed());
    }

    #[test]
    fn argument_quoting_preserves_windows_edges() {
        assert_eq!(quote_windows_argument("plain"), "plain");
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(quote_windows_argument("a b"), "\"a b\"");
        assert_eq!(quote_windows_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote_windows_argument("a b\\"), "\"a b\\\\\"");
    }

    #[test]
    fn environment_is_sorted_and_double_terminated() {
        let block =
            encode_windows_environment(&[("z".into(), "2".into()), ("A".into(), "1".into())])
                .expect("valid environment");
        let expected: Vec<u16> = "A=1\0z=2\0\0".encode_utf16().collect();
        assert_eq!(block, expected);
        assert!(encode_windows_environment(&[("BAD=NAME".into(), "x".into())]).is_err());
        let drive = encode_windows_environment(&[("=c:".into(), r"C:\workspace".into())])
            .expect("drive current-directory entry");
        assert_eq!(
            drive,
            "=c:=C:\\workspace\0\0".encode_utf16().collect::<Vec<_>>()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn launch_environment_adds_the_working_drive_without_exposing_parent_state() {
        let block = windows::environment_block(
            &[("HOME".into(), r"C:\private".into())],
            std::path::Path::new(r"d:\work"),
        )
        .expect("environment block");
        assert_eq!(
            block,
            "=D:=d:\\work\0HOME=C:\\private\0\0"
                .encode_utf16()
                .collect::<Vec<_>>()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_abi_layouts_match_x64_contract() {
        use std::mem::{offset_of, size_of};
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
        use windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO;
        use windows_sys::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
        use windows_sys::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOEXW};

        assert_eq!(size_of::<FILE_ID_INFO>(), 24);
        assert_eq!(offset_of!(FILE_ID_INFO, FileId), 8);
        assert_eq!(offset_of!(PROCESS_INFORMATION, hProcess), 0);
        assert_eq!(
            offset_of!(PROCESS_INFORMATION, hThread),
            size_of::<HANDLE>()
        );
        assert_eq!(
            offset_of!(PROCESS_INFORMATION, dwProcessId),
            size_of::<HANDLE>() * 2
        );
        assert_eq!(offset_of!(SECURITY_CAPABILITIES, AppContainerSid), 0);
        assert_eq!(offset_of!(STARTUPINFOEXW, StartupInfo), 0);
        assert!(
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()
                >= size_of::<
                    windows_sys::Win32::System::JobObjects::JOBOBJECT_BASIC_LIMIT_INFORMATION,
                >()
        );
    }
}
