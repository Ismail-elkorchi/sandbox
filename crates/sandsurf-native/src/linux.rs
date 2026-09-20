use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};

/// Retain a process identity independently of numeric PID reuse.
pub fn open_pidfd(pid: u32) -> io::Result<File> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process identity",
        ));
    }
    // SAFETY: pidfd_open takes scalar arguments and returns a new owned descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful syscall returned a descriptor transferred once to File.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn validate_live_pidfd(process: &File) -> io::Result<()> {
    // SAFETY: signal 0 validates a live process handle without delivering a signal.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            process.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Observe a process in this PID namespace or a descendant namespace. The caller
/// must have signal permission; trusted outer-namespace parent observation uses
/// `bind_to_retained_parent` instead.
pub fn process_exited(process: &File) -> io::Result<bool> {
    // Ordinary files poll as readable but are not exit evidence.
    match validate_live_pidfd(process) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(true),
        Err(error) => return Err(error),
    }
    poll_exit(process, 0)
}

fn poll_exit(process: &File, timeout: i32) -> io::Result<bool> {
    let mut event = libc::pollfd {
        fd: process.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: event is an initialized pollfd for this retained process handle.
    let result = unsafe { libc::poll(&mut event, 1, timeout) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(io::Error::other("process observation descriptor failed"));
    }
    Ok(result > 0 && event.revents & (libc::POLLIN | libc::POLLHUP) != 0)
}

/// Stop exactly the retained process; success means signal delivery, not exit.
/// VM ownership uses a confined PID-namespace init so its death contains the VM.
pub fn kill_process(process: &File) -> io::Result<()> {
    // SAFETY: pidfd_send_signal identifies the retained process, never a recycled PID.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            process.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

/// A bounded exit observation, not reaping or a complete VM cleanup receipt.
pub fn wait_process_exit(process: &File, timeout: Duration) -> io::Result<bool> {
    if timeout > Duration::from_secs(60) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exit observation timeout exceeds bound",
        ));
    }
    if process_exited(process)? {
        return Ok(true);
    }
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return process_exited(process);
        }
        let milliseconds = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
        match poll_exit(process, milliseconds) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Bind the single-threaded launcher to its immediate parent. Installation and
/// held-identity checks close the parent-exit race around PR_SET_PDEATHSIG.
pub fn bind_lifetime_to_parent() -> io::Result<()> {
    // SAFETY: getppid takes no arguments and cannot corrupt memory.
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "launcher has no live owner parent",
        ));
    }
    let held = open_pidfd(parent as u32)?;
    bind_to_retained_parent(&held)?;
    // SAFETY: getppid takes no arguments; verify the parent did not change at setup.
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "owner changed during lifeline installation",
        ));
    }
    Ok(())
}

/// For trusted bootstrap code whose parent may be outside its PID view. This
/// descriptor must identify its immediate parent in the verified launch topology,
/// not an arbitrary caller-selected process. Supervision remains necessary.
pub fn bind_to_retained_parent(parent: &File) -> io::Result<()> {
    // pidfd_send_signal cannot validate an outer-namespace parent: Linux permits
    // signals only into the sender's PID namespace or its descendants. The
    // trusted bootstrap retains this pidfd before entering the child namespace.
    if poll_exit(parent, 0)? {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "owner exited before lifeline installation",
        ));
    }
    // SAFETY: PR_SET_PDEATHSIG changes only this calling process's lifecycle rule.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if poll_exit(parent, 0)? {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "owner exited during lifeline installation",
        ));
    }
    Ok(())
}

/// Mark descriptors above stdio close-on-exec without closing setup handles still
/// needed to execute a verified held binary.
pub fn prepare_descriptors_for_exec() -> io::Result<()> {
    // SAFETY: close_range with CLOEXEC only marks descriptors and takes no pointers.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn pipe_cloexec() -> io::Result<(File, File)> {
    let mut fds = [-1; 2];
    // SAFETY: fds is writable storage for the two descriptors returned by pipe2.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned distinct owned descriptors, each transferred once.
    let read = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: this is the second distinct owned descriptor returned by pipe2.
    let write = unsafe { File::from_raw_fd(fds[1]) };
    Ok((read, write))
}
