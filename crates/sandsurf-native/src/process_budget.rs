//! Kernel process budgets for owned native workers. These are applied limits,
//! not machine authority, persistence, VM-power observations, or qualification.
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessBudget {
    /// CPU-time rate expressed in microseconds per reference 100ms.
    pub cpu_quota_micros: u64,
    /// Darwin: fatal physical-footprint limit installed by the privileged
    /// owner after exec. Windows: aggregate private commit in the owned Job.
    /// Neither measurement is a claim about every host-kernel page.
    pub memory_bytes: u64,
    pub processes: u32,
}

/// Hyper-V's per-virtual-processor cap uses 16 fractional bits (TLFS 14.2.2).
/// Splitting an aggregate guest CPU allowance always rounds toward a stricter
/// native limit; the independent native-process allowance is not included.
#[cfg(any(windows, test))]
fn partition_cpu_cap(quota: u64, vcpus: u32) -> io::Result<u32> {
    if vcpus == 0 || vcpus > 32 || quota == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid native guest CPU budget",
        ));
    }
    let denominator = u128::from(vcpus) * 100000;
    let cap = u128::from(quota) * 65536 / denominator;
    if !(1..=65536).contains(&cap) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "guest CPU budget exceeds partition cap resolution or topology",
        ));
    }
    Ok(cap as u32)
}

impl ProcessBudget {
    pub fn validate(self) -> io::Result<()> {
        if self.cpu_quota_micros < 1000
            || self.memory_bytes < 64 * 1024 * 1024
            || self.processes == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native process budget",
            ));
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn windows_cpu_rate(quota: u64, logical_processors: u32) -> io::Result<u32> {
    let divisor = u64::from(logical_processors)
        .checked_mul(10)
        .filter(|value| *value != 0)
        .ok_or_else(|| io::Error::other("native processor inventory unavailable"))?;
    // Job CPU rate is a hundredth of a percent of the host's logical CPUs.
    // A stricter representable cap is valid; never round upward into authority.
    let rate = quota / divisor;
    if !(1..=10000).contains(&rate) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "CPU budget is outside native Job rate resolution",
        ));
    }
    Ok(rate as u32)
}

#[cfg(any(target_os = "macos", test))]
fn darwin_cpu_percentage(quota: u64) -> io::Result<u32> {
    if !quota.is_multiple_of(1000) || !(1000..=255000).contains(&quota) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Darwin task CPU ledger requires whole percentages in 1..255",
        ));
    }
    Ok((quota / 1000) as u32)
}

#[cfg(windows)]
pub mod windows {
    use super::*;
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::Threading::{
        ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, GetCurrentProcess,
    };

    /// Derive the strict scalar for the owned QEMU worker. Only QEMU owns the
    /// WHP partition and installs/reads it back before WHvSetupPartition.
    pub fn guest_cpu_cap(quota: u64, vcpus: u32) -> io::Result<u32> {
        partition_cpu_cap(quota, vcpus)
    }

    /// One private unnamed Job. Child membership is inherited and breakaway is
    /// disabled. Guardian death closes this handle and contains its VM workers.
    pub struct JobEnvelope {
        job: HANDLE,
        budget: ProcessBudget,
        cpu_rate: u32,
        factory: bool,
    }

    #[derive(Debug)]
    pub struct JobUsage {
        pub cpu_micros: u64,
        pub peak_private_commit: u64,
        /// Available only with the original sole-member process handle.
        pub current_private_commit: Option<u64>,
        pub process_creation_time: Option<u64>,
        pub io_read_bytes: u64,
        pub io_write_bytes: u64,
        pub active_processes: u32,
        pub total_processes: u32,
        /// Raw kernel count of processes terminated for Job-limit violations.
        /// TotalProcesses includes historical associations, not live authority.
        pub limit_terminated_processes: u32,
    }
    // SAFETY: this wrapper uniquely owns a real Job handle; Windows permits
    // concurrent native queries. Ownership transfers without duplicating Drop.
    unsafe impl Send for JobEnvelope {}
    // SAFETY: immutable queries share a live handle; mutation requires &mut self.
    unsafe impl Sync for JobEnvelope {}

    impl JobEnvelope {
        /// Only fixed host workers may create separately bounded native owners.
        /// Their children explicitly break away, are proved outside all parent
        /// Jobs while suspended, and enter their own Job before execution.
        pub fn install_factory_current(
            role: crate::resource_broker::WorkerKind,
            budget: ProcessBudget,
        ) -> io::Result<()> {
            if role.host_mode().is_none() || budget.processes != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid native factory role",
                ));
            }
            // SAFETY: this native pseudo handle denotes only the calling process.
            let process = unsafe { GetCurrentProcess() };
            if process_in_job(process)? {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "service factory must start outside ambient Jobs; install it as an independent service",
                ));
            }
            let value = Self::create_factory(budget)?;
            // SAFETY: the original owned Job and this process's pseudo handle.
            if unsafe { AssignProcessToJobObject(value.job, GetCurrentProcess()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // This Job contains its own handle owner, unlike an externally
            // owned child Job. Closing it during Rust unwinding terminates the
            // process before its actual failure status can be established.
            // Retain exactly this one noninheritable handle until ExitProcess;
            // the kernel closes it on normal exit, panic or forced death.
            std::mem::forget(value);
            Self::verify_current_factory(budget)
        }

        pub fn verify_current_factory(budget: ProcessBudget) -> io::Result<()> {
            budget.validate()?;
            // SAFETY: scalar inventory query, no foreign process adoption.
            let processors = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
            Self::verify_limits(
                std::ptr::null_mut(),
                budget,
                windows_cpu_rate(budget.cpu_quota_micros, processors)?,
                true,
            )
        }

        fn create(budget: ProcessBudget) -> io::Result<Self> {
            Self::create_role(budget, false)
        }

        pub(crate) fn create_factory(budget: ProcessBudget) -> io::Result<Self> {
            Self::create_role(budget, true)
        }

        fn create_role(budget: ProcessBudget, factory: bool) -> io::Result<Self> {
            budget.validate()?;
            // SAFETY: this native inventory query takes only a scalar group selector.
            let processors = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
            let cpu_rate = windows_cpu_rate(budget.cpu_quota_micros, processors)?;
            // SAFETY: null attributes create a non-inheritable, unnamed Job.
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let value = Self {
                job,
                budget,
                cpu_rate,
                factory,
            };
            value.install()?;
            value.verify()?;
            Ok(value)
        }

        pub(crate) fn create_owned(budget: ProcessBudget) -> io::Result<Self> {
            Self::create(budget)
        }

        pub(crate) fn assign_owned_handle(&self, process: HANDLE) -> io::Result<()> {
            // SAFETY: the only caller retains CreateProcess's original process
            // handle and suspended initial thread; no PID lookup/adoption exists.
            if unsafe { AssignProcessToJobObject(self.job, process) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut member = 0;
            // SAFETY: the same retained process and Job plus scalar output.
            if unsafe { IsProcessInJob(process, self.job, &mut member) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if member == 0 {
                return Err(io::Error::other("owned worker is outside its verified Job"));
            }
            Ok(())
        }

        fn install(&self) -> io::Result<()> {
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            if self.factory {
                limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
            }
            limits.BasicLimitInformation.ActiveProcessLimit = self.budget.processes;
            limits.JobMemoryLimit =
                usize::try_from(self.budget.memory_bytes).map_err(io::Error::other)?;
            let cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                    | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
                    CpuRate: self.cpu_rate,
                },
            };
            // SAFETY: live owned Job and fully initialized fixed-size ABI inputs.
            if unsafe {
                SetInformationJobObject(
                    self.job,
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: cpu is the exact Job CPU-rate information layout and size.
            if unsafe {
                SetInformationJobObject(
                    self.job,
                    JobObjectCpuRateControlInformation,
                    (&raw const cpu).cast(),
                    size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn verify(&self) -> io::Result<()> {
            Self::verify_limits(self.job, self.budget, self.cpu_rate, self.factory)
        }

        fn verify_limits(
            job: HANDLE,
            budget: ProcessBudget,
            cpu_rate: u32,
            factory: bool,
        ) -> io::Result<()> {
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
            // SAFETY: live owned handle and fixed-size writable Job-limit output.
            if unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&raw mut limits).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: live owned handle and exact writable CPU-rate output layout.
            if unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectCpuRateControlInformation,
                    (&raw mut cpu).cast(),
                    size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let flags = limits.BasicLimitInformation.LimitFlags;
            if flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
                != if factory {
                    JOB_OBJECT_LIMIT_BREAKAWAY_OK
                } else {
                    0
                }
                || flags
                    & (JOB_OBJECT_LIMIT_JOB_MEMORY
                        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
                    != JOB_OBJECT_LIMIT_JOB_MEMORY
                        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                || limits.JobMemoryLimit as u64 != budget.memory_bytes
                || limits.BasicLimitInformation.ActiveProcessLimit != budget.processes
                || cpu.ControlFlags
                    != JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
            {
                return Err(io::Error::other(
                    "native Job limits differ from the admitted budget",
                ));
            }
            // SAFETY: ControlFlags above establish CpuRate as the active union field.
            if unsafe { cpu.Anonymous.CpuRate } != cpu_rate {
                return Err(io::Error::other(
                    "native Job CPU rate differs from the admitted budget",
                ));
            }
            Ok(())
        }

        pub fn usage(&self) -> io::Result<JobUsage> {
            Self::query_usage(self.job)
        }

        pub fn current_factory_usage(budget: ProcessBudget) -> io::Result<JobUsage> {
            Self::verify_current_factory(budget)?;
            let mut usage = Self::query_usage(std::ptr::null_mut())?;
            if usage.active_processes != 1 {
                return Err(io::Error::other("native factory no longer has one member"));
            }
            // SAFETY: pseudo handle names only the calling factory process.
            let (memory, creation) = original_process_usage(unsafe { GetCurrentProcess() })?;
            usage.current_private_commit = Some(memory);
            usage.process_creation_time = Some(creation);
            Ok(usage)
        }

        fn query_usage(job: HANDLE) -> io::Result<JobUsage> {
            let mut accounting = JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION::default();
            let mut memory = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // SAFETY: retained owned Job and exact initialized native outputs.
            if unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicAndIoAccountingInformation,
                    (&raw mut accounting).cast(),
                    size_of::<JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: same retained Job and exact writable memory-limit layout.
            if unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&raw mut memory).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let user =
                u64::try_from(accounting.BasicInfo.TotalUserTime).map_err(io::Error::other)?;
            let kernel =
                u64::try_from(accounting.BasicInfo.TotalKernelTime).map_err(io::Error::other)?;
            Ok(JobUsage {
                cpu_micros: user
                    .checked_add(kernel)
                    .ok_or_else(|| io::Error::other("native CPU measurement overflow"))?
                    / 10,
                peak_private_commit: memory.PeakJobMemoryUsed as u64,
                current_private_commit: None,
                process_creation_time: None,
                io_read_bytes: accounting.IoInfo.ReadTransferCount,
                io_write_bytes: accounting.IoInfo.WriteTransferCount,
                active_processes: accounting.BasicInfo.ActiveProcesses,
                total_processes: accounting.BasicInfo.TotalProcesses,
                limit_terminated_processes: accounting.BasicInfo.TotalTerminatedProcesses,
            })
        }
    }

    /// Called only for self or CreateProcess's retained original handle. This
    /// does not open a PID, enumerate a Job, or adopt a foreign process tree.
    pub(crate) fn original_process_usage(process: HANDLE) -> io::Result<(u64, u64)> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
        };
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        let mut memory = PROCESS_MEMORY_COUNTERS_EX {
            cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..Default::default()
        };
        // SAFETY: retained process and exact extended process-memory layout;
        // the cb argument and leading field select this complete output ABI.
        if unsafe { K32GetProcessMemoryInfo(process, (&raw mut memory).cast(), memory.cb) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: original live handle and four exact writable FILETIME outputs.
        if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let creation = u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime);
        if creation == 0 {
            return Err(io::Error::other("native process has no creation identity"));
        }
        Ok((memory.PrivateUsage as u64, creation))
    }

    pub(crate) fn process_in_job(process: HANDLE) -> io::Result<bool> {
        let mut member = 0;
        // SAFETY: a retained process handle (or this process's pseudo handle)
        // and an exact writable scalar, never PID lookup or foreign adoption.
        if unsafe { IsProcessInJob(process, std::ptr::null_mut(), &mut member) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(member != 0)
    }

    impl Drop for JobEnvelope {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns the live non-inherited Job
            // handle. KILL_ON_JOB_CLOSE is intentional owner-death containment.
            unsafe { CloseHandle(self.job) };
        }
    }
}

/// XNU's syscall converts this interval from seconds to Mach nanoseconds.
/// The misleading nanoseconds comment in process_policy.h is not the ABI's
/// behavior; pass one second, not 100 million seconds.
#[cfg(any(target_os = "macos", test))]
#[repr(C)]
struct DarwinCpuPolicy {
    action: u32,
    percentage: u32,
    interval_seconds: u64,
    deadline_nanos: u64,
}

#[cfg(any(target_os = "macos", test))]
impl DarwinCpuPolicy {
    fn for_quota(quota: u64) -> io::Result<Self> {
        Ok(Self {
            action: 1,
            percentage: darwin_cpu_percentage(quota)?,
            interval_seconds: 1,
            deadline_nanos: 0,
        })
    }
    fn matches(&self, quota: u64) -> io::Result<bool> {
        let expected = Self::for_quota(quota)?;
        Ok(self.action == expected.action
            && self.percentage == expected.percentage
            && self.interval_seconds == expected.interval_seconds
            && self.deadline_nanos == expected.deadline_nanos)
    }
}

#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    #[repr(C)]
    struct MachTimebase {
        numer: u32,
        denom: u32,
    }
    // SAFETY: Darwin's public mach_timebase_info ABI writes this exact pair of
    // u32 values; it takes no authority-bearing target or guest-selected input.
    unsafe extern "C" {
        #[link_name = "mach_timebase_info"]
        fn host_timebase_info(output: *mut MachTimebase) -> i32;
    }

    /// Raw kernel observations for self or an original, unreaped child only.
    /// CPU times in proc_pid_rusage are Mach ticks, not nanoseconds on arm64.
    pub(crate) struct TaskUsage {
        pub start_ticks: u64,
        pub cpu_micros: u64,
        pub physical_footprint: u64,
        pub io_read_bytes: u64,
        pub io_write_bytes: u64,
    }

    fn task_usage(pid: libc::pid_t) -> io::Result<TaskUsage> {
        // SAFETY: exact initialized native output layouts. Only the private
        // self/owned-child entrypoints below can select this scalar PID.
        let mut usage: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        let mut timebase = MachTimebase { numer: 0, denom: 0 };
        // SAFETY: proc_pid_rusage's unusual pointer typedef still denotes the
        // supplied rusage buffer itself, not a pointer-to-buffer allocation.
        if unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V4, (&raw mut usage).cast()) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: exact live output for the calling kernel's timebase.
        if unsafe { host_timebase_info(&mut timebase) } != 0 {
            return Err(io::Error::other("Darwin timebase unavailable"));
        }
        Ok(TaskUsage {
            start_ticks: usage.ri_proc_start_abstime,
            cpu_micros: mach_cpu_micros(
                usage.ri_user_time,
                usage.ri_system_time,
                timebase.numer,
                timebase.denom,
            )?,
            physical_footprint: usage.ri_phys_footprint,
            io_read_bytes: usage.ri_diskio_bytesread,
            io_write_bytes: usage.ri_diskio_byteswritten,
        })
    }

    pub(crate) fn owned_usage(child: &std::process::Child) -> io::Result<TaskUsage> {
        task_usage(i32::try_from(child.id()).map_err(io::Error::other)?)
    }

    pub(crate) fn current_usage() -> io::Result<TaskUsage> {
        // SAFETY: scalar query names only this process.
        task_usage(unsafe { libc::getpid() })
    }
    // SAFETY: this is Darwin's process_policy syscall-wrapper ABI. Calls below
    // target self or an unreaped owned child using the exact CPU-policy layout.
    unsafe extern "C" {
        fn __process_policy(
            scope: i32,
            action: i32,
            policy: i32,
            subtype: i32,
            attributes: *mut DarwinCpuPolicy,
            pid: libc::pid_t,
            thread: u64,
        ) -> i32;
    }
    fn install_cpu(pid: libc::pid_t, budget: ProcessBudget) -> io::Result<()> {
        budget.validate()?;
        let mut cpu = DarwinCpuPolicy::for_quota(budget.cpu_quota_micros)?;
        // SAFETY: pid is self or the privileged broker's unreaped child, never
        // an application-supplied target; the initialized ABI is exact. XNU's
        // ACTION_SET (not ACTION_APPLY) admits a privileged foreign-task setter.
        if unsafe { __process_policy(1, 10, 4, 3, &mut cpu, pid, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        verify_cpu(pid, budget)
    }
    fn verify_cpu(pid: libc::pid_t, budget: ProcessBudget) -> io::Result<()> {
        budget.validate()?;
        let mut cpu = DarwinCpuPolicy {
            action: 0,
            percentage: 0,
            interval_seconds: 0,
            deadline_nanos: 0,
        };
        // SAFETY: same self or unreaped owned child; ACTION_GET writes exactly
        // the supplied layout. No discovered PID or guest-controlled value.
        if unsafe { __process_policy(1, 11, 4, 3, &mut cpu, pid, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if !cpu.matches(budget.cpu_quota_micros)? {
            return Err(io::Error::other(
                "Darwin task CPU ledger differs from the admitted worker budget",
            ));
        }
        Ok(())
    }

    // SAFETY: this is XNU's fixed memorystatus_control syscall-wrapper ABI;
    // only the broker itself or its unreaped child is targeted below.
    unsafe extern "C" {
        fn memorystatus_control(
            command: u32,
            pid: i32,
            flags: u32,
            buffer: *mut libc::c_void,
            bytes: usize,
        ) -> i32;
    }

    /// Used only by the broker while retaining its own unreaped child. Even a
    /// child that exits during the syscall cannot have its PID reused until
    /// the broker reaps it. There is no API accepting an application PID.
    pub(crate) fn install_owned(
        child: &std::process::Child,
        budget: ProcessBudget,
    ) -> io::Result<()> {
        // SAFETY: geteuid is a scalar credential query without pointers.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let pid = i32::try_from(child.id()).map_err(io::Error::other)?;
        // Both operations target the final executable after its native gate.
        // Failure of either is followed by containment, never partial success.
        install_memory(pid, budget.memory_bytes)?;
        install_cpu(pid, budget)
    }

    pub(crate) fn install_broker_current() -> io::Result<()> {
        // SAFETY: own PID and effective UID are scalar credential queries.
        let (pid, uid) = unsafe { (libc::getpid(), libc::geteuid()) };
        if uid != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        install_memory(pid, crate::resource_broker::BROKER_MEMORY_BYTES)?;
        install_cpu(
            0,
            ProcessBudget {
                cpu_quota_micros: crate::resource_broker::BROKER_CPU_MICROS,
                memory_bytes: crate::resource_broker::BROKER_MEMORY_BYTES,
                processes: 1,
            },
        )
    }

    fn install_memory(pid: i32, memory_bytes: u64) -> io::Result<()> {
        let mut requested = DarwinMemoryProperties::for_bytes(memory_bytes)?;
        // SAFETY: self or unreaped owned child and exact initialized ABI input.
        if unsafe { memorystatus_control(7, pid, 0, (&raw mut requested).cast(), 16) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut observed = DarwinMemoryProperties::default();
        // SAFETY: same self or unreaped child and exact writable ABI output.
        if unsafe { memorystatus_control(8, pid, 0, (&raw mut observed).cast(), 16) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if observed != requested {
            return Err(io::Error::other(
                "fatal physical-memory limit readback differs",
            ));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", test))]
fn mach_cpu_micros(user: u64, system: u64, numer: u32, denom: u32) -> io::Result<u64> {
    if numer == 0 || denom == 0 {
        return Err(io::Error::other("invalid Darwin timebase"));
    }
    u64::try_from(
        (u128::from(user) + u128::from(system)) * u128::from(numer) / u128::from(denom) / 1000,
    )
    .map_err(io::Error::other)
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default, PartialEq, Eq)]
#[repr(C)]
struct DarwinMemoryProperties {
    active_mib: i32,
    active_attributes: u32,
    inactive_mib: i32,
    inactive_attributes: u32,
}

#[cfg(any(target_os = "macos", test))]
impl DarwinMemoryProperties {
    fn for_bytes(bytes: u64) -> io::Result<Self> {
        let mib = i32::try_from(bytes / (1024 * 1024)).map_err(io::Error::other)?;
        if mib < 64 || !bytes.is_multiple_of(1024 * 1024) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fatal physical-memory budget requires whole MiB, at least 64MiB",
            ));
        }
        Ok(Self {
            active_mib: mib,
            active_attributes: 1,
            inactive_mib: mib,
            inactive_attributes: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_memory_is_fatal_in_both_activity_states_not_an_address_space_limit() {
        assert_eq!(std::mem::size_of::<DarwinMemoryProperties>(), 16);
        let expected = DarwinMemoryProperties::for_bytes(128 * 1024 * 1024).unwrap();
        assert_eq!(expected.active_mib, 128);
        assert_eq!(expected.inactive_mib, 128);
        assert_eq!(expected.active_attributes, 1);
        assert_eq!(expected.inactive_attributes, 1);
        assert!(DarwinMemoryProperties::for_bytes(128 * 1024 * 1024 + 1).is_err());
        assert!(DarwinMemoryProperties::for_bytes(0).is_err());
        assert!(DarwinMemoryProperties::for_bytes(u64::MAX).is_err());
    }
    #[test]
    fn darwin_syscall_interval_is_seconds_and_readback_checks_every_field() {
        let mut policy = DarwinCpuPolicy::for_quota(25000).unwrap();
        assert_eq!(std::mem::size_of::<DarwinCpuPolicy>(), 24);
        assert_eq!(policy.interval_seconds, 1);
        assert!(policy.matches(25000).unwrap());
        policy.interval_seconds = 100_000_000;
        assert!(!policy.matches(25000).unwrap());
        policy.interval_seconds = 1;
        policy.action = 2;
        assert!(!policy.matches(25000).unwrap());
        policy.action = 1;
        policy.deadline_nanos = 1;
        assert!(!policy.matches(25000).unwrap());
        policy.deadline_nanos = 0;
        assert!(!policy.matches(26000).unwrap());
    }
    #[test]
    fn darwin_cpu_time_uses_the_kernel_timebase_without_wrap_or_float_rounding() {
        assert_eq!(mach_cpu_micros(1000, 2000, 1, 1).unwrap(), 3);
        assert_eq!(mach_cpu_micros(120000, 240000, 125, 3).unwrap(), 15000);
        assert_eq!(mach_cpu_micros(1, 1, 1, 1).unwrap(), 0);
        assert!(mach_cpu_micros(0, 0, 0, 1).is_err());
        assert!(mach_cpu_micros(0, 0, 1, 0).is_err());
        assert!(mach_cpu_micros(u64::MAX, u64::MAX, u32::MAX, 1).is_err());
    }
    #[test]
    fn native_rate_quantization_never_increases_cpu_authority() {
        for processors in 1..=256 {
            for quota in [1000, 25100, 100000, 200000, 255000] {
                if let Ok(rate) = windows_cpu_rate(quota, processors) {
                    assert!(u64::from(rate) * u64::from(processors) * 10 <= quota);
                }
            }
        }
        assert_eq!(darwin_cpu_percentage(25000).unwrap(), 25);
        for vcpus in 1..=32 {
            for quota in [1000, 25000, 100000, 195000, 3200000] {
                if let Ok(cap) = partition_cpu_cap(quota, vcpus) {
                    assert!(
                        u128::from(cap) * u128::from(vcpus) * 100000 <= u128::from(quota) * 65536
                    );
                }
            }
        }
        assert_eq!(partition_cpu_cap(150000, 2).unwrap(), 0xc000);
        assert!(partition_cpu_cap(0, 2).is_err());
        assert!(partition_cpu_cap(1, 32).is_err());
        assert!(partition_cpu_cap(400000, 2).is_err());
        for quota in [0, 999, 25010, 256000] {
            assert!(darwin_cpu_percentage(quota).is_err());
        }
    }
    #[test]
    fn zero_or_unbounded_workers_cannot_install_a_budget() {
        assert!(
            ProcessBudget {
                cpu_quota_micros: 100000,
                memory_bytes: 128 * 1024 * 1024,
                processes: 8
            }
            .validate()
            .is_ok()
        );
        assert!(
            ProcessBudget {
                cpu_quota_micros: 0,
                memory_bytes: 128 * 1024 * 1024,
                processes: 8
            }
            .validate()
            .is_err()
        );
        assert!(windows_cpu_rate(1000, 0).is_err());
        assert!(windows_cpu_rate(u64::MAX, 1).is_err());
    }
}
