#![deny(unsafe_op_in_unsafe_fn)]

//! macOS Seatbelt launcher primitives.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

pub const BACKEND_ID: &str = "darwin-seatbelt-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GrantAccess {
    Read,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub resolved_host_path: PathBuf,
    pub target_path: PathBuf,
    pub access: GrantAccess,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    None,
    Unrestricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SeatbeltPolicy {
    pub profile: String,
    pub profile_sha256: String,
    pub private_home: PathBuf,
    pub private_temporary: PathBuf,
    pub network: NetworkMode,
}

impl SeatbeltPolicy {
    pub fn generate(
        grants: &[Grant],
        private_home: PathBuf,
        private_temporary: PathBuf,
        network: NetworkMode,
    ) -> io::Result<Self> {
        Self::generate_with_masks(grants, &[], private_home, private_temporary, network)
    }

    pub fn generate_with_masks(
        grants: &[Grant],
        masks: &[PathBuf],
        private_home: PathBuf,
        private_temporary: PathBuf,
        network: NetworkMode,
    ) -> io::Result<Self> {
        for grant in grants {
            if grant.target_path != grant.resolved_host_path {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "darwin-seatbelt-v1 does not support path remapping",
                ));
            }
            if !grant.resolved_host_path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Seatbelt grants must be absolute",
                ));
            }
        }
        if !private_home.is_absolute() || !private_temporary.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private home and temporary paths must be absolute",
            ));
        }
        let mut profile = String::from(
            "(version 1)\n\
             (deny default)\n\
             (allow process-exec)\n\
             (allow process-fork)\n\
             (allow signal (target self))\n\
             (allow sysctl-read)\n\
             (allow file-read-metadata)\n",
        );
        for runtime_root in [
            "/System",
            "/usr/bin",
            "/usr/lib",
            "/usr/share",
            "/bin",
            "/sbin",
            "/Library/Apple",
            "/private/etc",
            "/dev/null",
            "/dev/urandom",
            "/dev/random",
        ] {
            append_path_rule(&mut profile, "file-read*", runtime_root)?;
        }
        // Dynamic linking and ordinary CLI startup require these global services. They are
        // reported as compatibility caveats instead of being described as process isolation.
        for service in [
            "com.apple.cfprefsd.agent",
            "com.apple.system.opendirectoryd.libinfo",
            "com.apple.system.logger",
            "com.apple.system.notification_center",
        ] {
            profile.push_str("(allow mach-lookup (global-name ");
            profile.push_str(&seatbelt_literal(service)?);
            profile.push_str("))\n");
        }
        for grant in grants {
            let operation = match grant.access {
                GrantAccess::Read => "file-read*",
                GrantAccess::ReadWrite => "file-read* file-write*",
            };
            append_path_rule(
                &mut profile,
                operation,
                path_text(&grant.resolved_host_path)?,
            )?;
        }
        append_path_rule(
            &mut profile,
            "file-read* file-write*",
            path_text(&private_home)?,
        )?;
        for mask in masks {
            profile.push_str("(deny file* (subpath ");
            profile.push_str(&seatbelt_literal(path_text(mask)?)?);
            profile.push_str("))\n");
        }
        append_path_rule(
            &mut profile,
            "file-read* file-write*",
            path_text(&private_temporary)?,
        )?;
        match network {
            NetworkMode::None => profile.push_str("(deny network*)\n"),
            NetworkMode::Unrestricted => profile.push_str("(allow network*)\n"),
        }
        let profile_sha256 = format!("{:x}", Sha256::digest(profile.as_bytes()));
        Ok(Self {
            profile,
            profile_sha256,
            private_home,
            private_temporary,
            network,
        })
    }
}

fn append_path_rule(profile: &mut String, operations: &str, path: &str) -> io::Result<()> {
    profile.push_str("(allow ");
    profile.push_str(operations);
    profile.push_str(" (subpath ");
    profile.push_str(&seatbelt_literal(path)?);
    profile.push_str("))\n");
    Ok(())
}

fn path_text(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not valid UTF-8"))
}

fn seatbelt_literal(value: &str) -> io::Result<String> {
    if value.contains('\0') || value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Seatbelt literal contains a control character",
        ));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceLimits {
    pub cpu_time_ms: Option<u64>,
    pub max_file_bytes: Option<u64>,
    pub max_processes: Option<u64>,
    pub max_open_files: Option<u64>,
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ffi::{CString, c_char};
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::time::{Duration, Instant};

    // SAFETY: these declarations use the stable macOS C ABI and are called only with
    // owned NUL-terminated buffers or scalar descriptors as documented below.
    unsafe extern "C" {
        fn sandbox_init(
            profile: *const c_char,
            flags: u64,
            error_buffer: *mut *mut c_char,
        ) -> libc::c_int;
        fn sandbox_free_error(error_buffer: *mut c_char);
        fn closefrom(low_fd: libc::c_int) -> libc::c_int;
    }

    pub struct LaunchSpec<'a> {
        pub launcher_executable: &'a Path,
        pub executable: &'a Path,
        pub args: &'a [String],
        pub cwd: &'a Path,
        pub environment: &'a [(String, String)],
        pub stdin_fd: RawFd,
        pub stdout_fd: RawFd,
        pub stderr_fd: RawFd,
        pub policy: &'a SeatbeltPolicy,
        pub resources: ResourceLimits,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct OwnedLaunchSpec {
        executable: PathBuf,
        args: Vec<String>,
        cwd: PathBuf,
        environment: Vec<(String, String)>,
        policy: SeatbeltPolicy,
        resources: ResourceLimits,
    }

    pub struct MacProcess {
        guardian_pid: libc::pid_t,
        target_pid: libc::pid_t,
        setup_status_fd: RawFd,
        lifeline_fd: RawFd,
        lifecycle_fd: RawFd,
        reaped: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExitStatus {
        pub exit_code: Option<i32>,
        pub signal: Option<i32>,
        pub core_dumped: bool,
    }

    impl MacProcess {
        pub fn spawn(spec: &LaunchSpec<'_>) -> io::Result<Self> {
            validate_spec(spec)?;
            let mut status_pipe = [-1; 2];
            let mut specification_pipe = [-1; 2];
            let mut lifeline_pipe = [-1; 2];
            let mut lifecycle_pipe = [-1; 2];
            // SAFETY: every array contains two writable integers. Partially created pipes are
            // closed together on failure.
            if unsafe { libc::pipe(status_pipe.as_mut_ptr()) } != 0
                // SAFETY: `specification_pipe` is another two-integer writable array.
                || unsafe { libc::pipe(specification_pipe.as_mut_ptr()) } != 0
                // SAFETY: `lifeline_pipe` is another two-integer writable array.
                || unsafe { libc::pipe(lifeline_pipe.as_mut_ptr()) } != 0
                // SAFETY: `lifecycle_pipe` is another two-integer writable array.
                || unsafe { libc::pipe(lifecycle_pipe.as_mut_ptr()) } != 0
            {
                close_fds(&[
                    status_pipe[0],
                    status_pipe[1],
                    specification_pipe[0],
                    specification_pipe[1],
                    lifeline_pipe[0],
                    lifeline_pipe[1],
                    lifecycle_pipe[0],
                    lifecycle_pipe[1],
                ]);
                return Err(io::Error::last_os_error());
            }
            let child_descriptors = match duplicate_control_fds([
                status_pipe[1],
                specification_pipe[0],
                lifeline_pipe[0],
                lifecycle_pipe[1],
            ]) {
                Ok(descriptors) => descriptors,
                Err(error) => {
                    close_fds(&[
                        status_pipe[0],
                        status_pipe[1],
                        specification_pipe[0],
                        specification_pipe[1],
                        lifeline_pipe[0],
                        lifeline_pipe[1],
                        lifecycle_pipe[0],
                        lifecycle_pipe[1],
                    ]);
                    return Err(error);
                }
            };
            let [
                child_status,
                child_specification,
                child_lifeline,
                child_lifecycle,
            ] = child_descriptors;
            let close_before_spawn_return = || {
                close_fds(&[
                    status_pipe[0],
                    status_pipe[1],
                    specification_pipe[0],
                    specification_pipe[1],
                    lifeline_pipe[0],
                    lifeline_pipe[1],
                    lifecycle_pipe[0],
                    lifecycle_pipe[1],
                    child_status,
                    child_specification,
                    child_lifeline,
                    child_lifecycle,
                ]);
            };
            let owned = OwnedLaunchSpec {
                executable: spec.executable.to_path_buf(),
                args: spec.args.to_vec(),
                cwd: spec.cwd.to_path_buf(),
                environment: spec.environment.to_vec(),
                policy: spec.policy.clone(),
                resources: spec.resources,
            };
            let encoded = match serde_json::to_vec(&owned)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
            {
                Ok(encoded) => encoded,
                Err(error) => {
                    close_before_spawn_return();
                    return Err(error);
                }
            };
            if encoded.len() > 4 * 1024 * 1024 {
                close_before_spawn_return();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "macOS launcher specification exceeds 4 MiB",
                ));
            }
            let launcher = match CString::new(spec.launcher_executable.as_os_str().as_bytes()) {
                Ok(launcher) => launcher,
                Err(_) => {
                    close_before_spawn_return();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "launcher path contains NUL",
                    ));
                }
            };
            let launcher_mode = CString::new("--macos-launcher").expect("static");
            let argv = [
                launcher.as_ptr().cast_mut(),
                launcher_mode.as_ptr().cast_mut(),
                null_mut(),
            ];
            let environment_value = CString::new("PATH=/usr/bin:/bin").expect("static");
            let environment = [environment_value.as_ptr().cast_mut(), null_mut()];
            // SAFETY: both opaque POSIX spawn values are initialized immediately by their
            // corresponding init functions before any other API observes them.
            let mut actions: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
            // SAFETY: see the initialization invariant above; this value is not read first.
            let mut attributes: libc::posix_spawnattr_t = unsafe { std::mem::zeroed() };
            let mut initialized_actions = false;
            let mut initialized_attributes = false;
            let mut pid = 0;
            let spawn_result = (|| -> io::Result<()> {
                // SAFETY: actions points to writable storage and is not already initialized.
                posix_result(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
                initialized_actions = true;
                for (source, target) in [
                    (spec.stdin_fd, libc::STDIN_FILENO),
                    (spec.stdout_fd, libc::STDOUT_FILENO),
                    (spec.stderr_fd, libc::STDERR_FILENO),
                    (child_status, 3),
                    (child_specification, 4),
                    (child_lifeline, 5),
                    (child_lifecycle, 6),
                ] {
                    // SAFETY: actions is initialized and source/target are live integer FDs.
                    posix_result(unsafe {
                        libc::posix_spawn_file_actions_adddup2(&mut actions, source, target)
                    })?;
                }
                // SAFETY: attributes points to writable storage and is not initialized yet.
                posix_result(unsafe { libc::posix_spawnattr_init(&mut attributes) })?;
                initialized_attributes = true;
                // SAFETY: attributes is initialized; process group zero requests a new group.
                posix_result(unsafe { libc::posix_spawnattr_setpgroup(&mut attributes, 0) })?;
                // SAFETY: attributes is initialized and the supplied flag is supported.
                posix_result(unsafe {
                    libc::posix_spawnattr_setflags(
                        &mut attributes,
                        libc::POSIX_SPAWN_SETPGROUP as libc::c_short,
                    )
                })?;
                // SAFETY: all C strings, vectors and initialized spawn objects remain live
                // for the entire call; pid is a writable output slot.
                posix_result(unsafe {
                    libc::posix_spawn(
                        &mut pid,
                        launcher.as_ptr(),
                        &actions,
                        &attributes,
                        argv.as_ptr(),
                        environment.as_ptr(),
                    )
                })
            })();
            if initialized_attributes {
                // SAFETY: this value was initialized once and is destroyed exactly once.
                unsafe { libc::posix_spawnattr_destroy(&mut attributes) };
            }
            if initialized_actions {
                // SAFETY: this value was initialized once and is destroyed exactly once.
                unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
            }
            close_fd(status_pipe[1]);
            close_fd(specification_pipe[0]);
            close_fd(lifeline_pipe[0]);
            close_fd(lifecycle_pipe[1]);
            close_fds(&child_descriptors);
            if let Err(error) = spawn_result {
                close_fd(status_pipe[0]);
                close_fd(specification_pipe[1]);
                close_fd(lifeline_pipe[1]);
                close_fd(lifecycle_pipe[0]);
                return Err(error);
            }
            let write_result = (|| -> io::Result<()> {
                write_all_fd(specification_pipe[1], &(encoded.len() as u32).to_be_bytes())?;
                write_all_fd(specification_pipe[1], &encoded)
            })();
            close_fd(specification_pipe[1]);
            if let Err(error) = write_result {
                // SAFETY: pid is the positive process-group leader returned by posix_spawn.
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                let mut status = 0;
                // SAFETY: pid is the direct child and status is writable.
                unsafe { libc::waitpid(pid, &mut status, 0) };
                close_fd(status_pipe[0]);
                close_fd(lifeline_pipe[1]);
                close_fd(lifecycle_pipe[0]);
                return Err(error);
            }
            let mut process = Self {
                guardian_pid: pid,
                target_pid: -1,
                setup_status_fd: status_pipe[0],
                lifeline_fd: lifeline_pipe[1],
                lifecycle_fd: lifecycle_pipe[0],
                reaped: false,
            };
            process.await_setup()?;
            process.target_pid = process.await_target_pid()?;
            Ok(process)
        }

        #[must_use]
        pub fn process_id(&self) -> u32 {
            self.target_pid as u32
        }

        pub fn wait(&mut self) -> io::Result<ExitStatus> {
            let mut status = 0;
            loop {
                // SAFETY: waits for the exact child owned by self.
                let result = unsafe { libc::waitpid(self.guardian_pid, &mut status, 0) };
                if result == self.guardian_pid {
                    self.reaped = true;
                    return self.read_target_status(status);
                }
                if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io::Error::last_os_error());
            }
        }

        pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            let mut status = 0;
            // SAFETY: nonblocking wait for the exact child owned by self.
            let result = unsafe { libc::waitpid(self.guardian_pid, &mut status, libc::WNOHANG) };
            if result == 0 {
                return Ok(None);
            }
            if result == self.guardian_pid {
                self.reaped = true;
                return self.read_target_status(status).map(Some);
            }
            Err(io::Error::last_os_error())
        }

        pub fn terminate(&mut self, grace: Duration) -> io::Result<ExitStatus> {
            // SAFETY: the negative PID targets only the target-owned process group reported by
            // the fresh guardian before exec.
            if unsafe { libc::kill(-self.target_pid, libc::SIGTERM) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(error);
                }
            }
            let deadline = Instant::now() + grace;
            loop {
                if let Some(status) = self.try_wait()? {
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    // SAFETY: hard-kill is still restricted to the owned target process group.
                    unsafe { libc::kill(-self.target_pid, libc::SIGKILL) };
                    let hard_deadline = Instant::now() + Duration::from_secs(2);
                    loop {
                        if let Some(status) = self.try_wait()? {
                            return Ok(status);
                        }
                        if Instant::now() >= hard_deadline {
                            // SAFETY: this is the exact trusted guardian child owned by self.
                            unsafe { libc::kill(self.guardian_pid, libc::SIGKILL) };
                            let _ = self.wait();
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "macOS guardian did not finish target cleanup",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        pub fn terminate_descendants(&self) -> io::Result<()> {
            // The direct target may already be reaped while descendants retain its process group.
            // SAFETY: negative PID addresses only the group created by the target child.
            if unsafe { libc::kill(-self.target_pid, libc::SIGKILL) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(());
                }
                return Err(error);
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                // SAFETY: signal zero probes the exact target-owned process group.
                if unsafe { libc::kill(-self.target_pid, 0) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::NotFound {
                        return Ok(());
                    }
                    return Err(error);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "target process group remained visible after SIGKILL",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn await_target_pid(&self) -> io::Result<libc::pid_t> {
            let mut bytes = [0_u8; 4];
            read_exact_with_deadline(
                self.lifecycle_fd,
                &mut bytes,
                Instant::now() + Duration::from_secs(10),
                "macOS launcher target PID deadline exceeded",
            )?;
            let pid = i32::from_ne_bytes(bytes);
            if pid <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "macOS launcher returned an invalid target PID",
                ));
            }
            Ok(pid)
        }

        fn await_setup(&mut self) -> io::Result<()> {
            let mut bytes = [0_u8; 4];
            let result = read_setup_status(
                self.setup_status_fd,
                &mut bytes,
                Instant::now() + Duration::from_secs(10),
            );
            close_fd(self.setup_status_fd);
            self.setup_status_fd = -1;
            match result? {
                None => Ok(()),
                Some(()) => Err(io::Error::from_raw_os_error(i32::from_ne_bytes(bytes))),
            }
        }

        fn read_target_status(&mut self, guardian_status: libc::c_int) -> io::Result<ExitStatus> {
            close_fd(self.lifeline_fd);
            self.lifeline_fd = -1;
            let mut bytes = [0_u8; 4];
            match read_exact_fd(self.lifecycle_fd, &mut bytes) {
                Ok(()) => Ok(decode_status(i32::from_ne_bytes(bytes))),
                Err(error) => {
                    let guardian = decode_status(guardian_status);
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!(
                            "macOS guardian exited without target status ({guardian:?}): {error}"
                        ),
                    ))
                }
            }
        }
    }

    impl Drop for MacProcess {
        fn drop(&mut self) {
            close_fd(self.setup_status_fd);
            close_fd(self.lifeline_fd);
            if !self.reaped {
                if self.target_pid > 0 {
                    // SAFETY: target_pid was reported by our fresh guardian.
                    unsafe { libc::kill(-self.target_pid, libc::SIGKILL) };
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let mut status = 0;
                    // SAFETY: nonblocking reap of the exact guardian child.
                    let result =
                        unsafe { libc::waitpid(self.guardian_pid, &mut status, libc::WNOHANG) };
                    if result == self.guardian_pid {
                        break;
                    }
                    if result < 0 || Instant::now() >= deadline {
                        // SAFETY: exact trusted guardian child; any target group was killed above.
                        unsafe { libc::kill(self.guardian_pid, libc::SIGKILL) };
                        // SAFETY: bounded fallback now waits only for a SIGKILLed direct child.
                        unsafe { libc::waitpid(self.guardian_pid, &mut status, 0) };
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            close_fd(self.lifecycle_fd);
        }
    }

    fn validate_spec(spec: &LaunchSpec<'_>) -> io::Result<()> {
        if !spec.executable.is_absolute() || !spec.cwd.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executable and cwd must be absolute",
            ));
        }
        for value in spec.args {
            if value.contains('\0') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "argument contains NUL",
                ));
            }
        }
        Ok(())
    }

    // SAFETY: caller must invoke this only in the freshly forked target child, with descriptors
    // 0-3 installed according to the private launcher protocol and no other threads present.
    unsafe fn child_exec(spec: &OwnedLaunchSpec, status_fd: RawFd) -> ! {
        // SAFETY: the setup channel must close atomically on successful exec.
        if unsafe { libc::fcntl(status_fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            fail_child(status_fd, errno());
        }
        // SAFETY: target gets only descriptors 0-2. Descriptor 3 reports setup and closes on exec;
        // guardian lifeline and lifecycle descriptors start at 5 and are not inherited.
        unsafe { closefrom(4) };
        if unsafe { libc::setpgid(0, 0) } != 0 {
            fail_child(status_fd, errno());
        }
        if let Err(error) = apply_limits(spec.resources) {
            fail_child(status_fd, error.raw_os_error().unwrap_or(libc::EINVAL));
        }
        let profile = match CString::new(spec.policy.profile.as_bytes()) {
            Ok(value) => value,
            Err(_) => fail_child(status_fd, libc::EINVAL),
        };
        let mut sandbox_error: *mut c_char = null_mut();
        // SAFETY: direct profile string is NUL-terminated, flags zero selects a literal profile,
        // and error_buffer is a valid output pointer.
        if unsafe { sandbox_init(profile.as_ptr(), 0, &mut sandbox_error) } != 0 {
            if !sandbox_error.is_null() {
                // SAFETY: buffer came from sandbox_init and is released once.
                unsafe { sandbox_free_error(sandbox_error) };
            }
            fail_child(status_fd, libc::EPERM);
        }
        let cwd = match CString::new(spec.cwd.as_os_str().as_bytes()) {
            Ok(value) => value,
            Err(_) => fail_child(status_fd, libc::EINVAL),
        };
        // SAFETY: cwd is a live NUL-terminated path.
        if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
            fail_child(status_fd, errno());
        }
        let executable = match CString::new(spec.executable.as_os_str().as_bytes()) {
            Ok(value) => value,
            Err(_) => fail_child(status_fd, libc::EINVAL),
        };
        let mut argument_storage = Vec::with_capacity(spec.args.len() + 1);
        argument_storage.push(executable.clone());
        for argument in &spec.args {
            match CString::new(argument.as_bytes()) {
                Ok(value) => argument_storage.push(value),
                Err(_) => fail_child(status_fd, libc::EINVAL),
            }
        }
        let mut arguments = argument_storage
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        arguments.push(null());
        let mut environment_storage = Vec::with_capacity(spec.environment.len());
        for (name, value) in &spec.environment {
            if name.contains(['\0', '=']) || value.contains('\0') {
                fail_child(status_fd, libc::EINVAL);
            }
            match CString::new(format!("{name}={value}")) {
                Ok(value) => environment_storage.push(value),
                Err(_) => fail_child(status_fd, libc::EINVAL),
            }
        }
        let mut environment = environment_storage
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        environment.push(null());
        // SAFETY: executable, argument vector and environment vector remain live until exec.
        unsafe {
            libc::execve(
                executable.as_ptr(),
                arguments.as_ptr(),
                environment.as_ptr(),
            )
        };
        fail_child(status_fd, errno());
    }

    // SAFETY: this runs only in the dedicated single-threaded helper produced by posix_spawn.
    // Descriptors 3-6 are respectively setup status, specification, parent lifeline, and
    // lifecycle status. The fresh child is the only process that applies Seatbelt and execs.
    unsafe fn guardian_main(spec: &OwnedLaunchSpec) -> ! {
        // SAFETY: the helper is single-threaded, so fork does not duplicate any foreign locks.
        let target_pid = unsafe { libc::fork() };
        if target_pid < 0 {
            fail_child(3, errno());
        }
        if target_pid == 0 {
            // SAFETY: this is the fresh child described by child_exec's preconditions.
            unsafe { child_exec(spec, 3) };
        }

        close_fds(&[
            libc::STDIN_FILENO,
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            3,
            4,
        ]);
        if write_all_fd(6, &target_pid.to_ne_bytes()).is_err() {
            kill_target_group(target_pid);
            let _ = waitpid_exact(target_pid);
            // SAFETY: terminates only the dedicated guardian without Rust destructors.
            unsafe { libc::_exit(125) }
        }

        let mut lifeline = libc::pollfd {
            fd: 5,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        loop {
            let mut status = 0;
            // SAFETY: target_pid is the exact direct child created above.
            let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::WNOHANG) };
            if waited == target_pid {
                finish_guardian(target_pid, status);
            }
            if waited < 0 {
                // A missing final status is intentionally surfaced as a runtime failure outside.
                // SAFETY: terminates only this dedicated guardian.
                unsafe { libc::_exit(125) }
            }
            lifeline.revents = 0;
            // SAFETY: one initialized pollfd is writable and the bounded timeout keeps target
            // reaping responsive even without parent activity.
            let polled = unsafe { libc::poll(&mut lifeline, 1, 50) };
            if polled < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                kill_target_group(target_pid);
                let status = waitpid_exact(target_pid).unwrap_or(0);
                finish_guardian(target_pid, status);
            }
            if polled > 0 {
                let mut byte = [0_u8; 1];
                // Parent never writes to the lifeline. Data, EOF, HUP, or an error all revoke
                // ownership and require immediate target-group teardown.
                // SAFETY: one-byte buffer is writable and fd 5 belongs to this guardian.
                let read = unsafe { libc::read(5, byte.as_mut_ptr().cast(), 1) };
                if read <= 0 || lifeline.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                    kill_target_group(target_pid);
                    let status = waitpid_exact(target_pid).unwrap_or(0);
                    finish_guardian(target_pid, status);
                }
                kill_target_group(target_pid);
                let status = waitpid_exact(target_pid).unwrap_or(0);
                finish_guardian(target_pid, status);
            }
        }
    }

    fn finish_guardian(target_pid: libc::pid_t, status: libc::c_int) -> ! {
        // Kill any ordinary descendants that retained the original target process group after
        // its leader exited. macOS offers no unescapable job primitive, which remains reported.
        // SAFETY: target_pid names only the fresh group created in child_exec.
        unsafe { libc::kill(-target_pid, libc::SIGKILL) };
        let _ = write_all_fd(6, &status.to_ne_bytes());
        close_fds(&[5, 6]);
        // SAFETY: this is the dedicated guardian and all owned descriptors have been released.
        unsafe { libc::_exit(0) }
    }

    fn kill_target_group(target_pid: libc::pid_t) {
        if target_pid <= 0 {
            return;
        }
        // The direct kill covers the short fork-to-setpgid race; the group kill covers ordinary
        // descendants once child_exec has established the private process group.
        // SAFETY: both identifiers originate from this guardian's exact child.
        unsafe {
            libc::kill(-target_pid, libc::SIGKILL);
            libc::kill(target_pid, libc::SIGKILL);
        }
    }

    fn waitpid_exact(pid: libc::pid_t) -> io::Result<libc::c_int> {
        let mut status = 0;
        loop {
            // SAFETY: waits for the exact direct child owned by the caller.
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                return Ok(status);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    pub fn launcher_main() -> i32 {
        let result = (|| -> io::Result<OwnedLaunchSpec> {
            let mut length = [0_u8; 4];
            read_exact_fd(4, &mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > 4 * 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid macOS launcher specification length",
                ));
            }
            let mut encoded = vec![0_u8; length];
            read_exact_fd(4, &mut encoded)?;
            serde_json::from_slice(&encoded)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })();
        match result {
            // SAFETY: launcher_main is the dedicated single-threaded helper with the private
            // descriptors installed by posix_spawn.
            Ok(spec) => unsafe { guardian_main(&spec) },
            Err(error) => fail_child(3, error.raw_os_error().unwrap_or(libc::EINVAL)),
        }
    }

    fn duplicate_control_fds(sources: [RawFd; 4]) -> io::Result<[RawFd; 4]> {
        let mut descriptors = [-1; 4];
        for (index, source) in sources.into_iter().enumerate() {
            match duplicate_above_standard(source) {
                Ok(descriptor) => descriptors[index] = descriptor,
                Err(error) => {
                    close_fds(&descriptors);
                    return Err(error);
                }
            }
        }
        Ok(descriptors)
    }

    fn duplicate_above_standard(fd: RawFd) -> io::Result<RawFd> {
        // SAFETY: fd is live and F_DUPFD_CLOEXEC returns an independently owned descriptor.
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 20) };
        if duplicated < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(duplicated)
    }

    fn posix_result(result: libc::c_int) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(result))
        }
    }

    fn read_exact_fd(fd: RawFd, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            // SAFETY: bytes exposes a writable region of the supplied length and fd is borrowed.
            let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if count > 0 {
                bytes = &mut bytes[count as usize..];
            } else if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "launcher input closed",
                ));
            } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn read_exact_with_deadline(
        fd: RawFd,
        mut bytes: &mut [u8],
        deadline: Instant,
        timeout_message: &str,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            poll_readable(fd, deadline, timeout_message)?;
            // SAFETY: bytes is a live writable region and fd is borrowed for this read.
            let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if count > 0 {
                bytes = &mut bytes[count as usize..];
            } else if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "macOS launcher lifecycle channel closed",
                ));
            } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn read_setup_status(
        fd: RawFd,
        bytes: &mut [u8; 4],
        deadline: Instant,
    ) -> io::Result<Option<()>> {
        let mut offset = 0;
        loop {
            poll_readable(fd, deadline, "macOS target setup deadline exceeded")?;
            // SAFETY: the remaining region is writable and fd is the owned setup pipe.
            let count = unsafe {
                libc::read(
                    fd,
                    bytes[offset..].as_mut_ptr().cast(),
                    bytes.len() - offset,
                )
            };
            if count > 0 {
                offset += count as usize;
                if offset == bytes.len() {
                    return Ok(Some(()));
                }
            } else if count == 0 {
                return if offset == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "partial macOS launcher setup status",
                    ))
                };
            } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    }

    fn poll_readable(fd: RawFd, deadline: Instant, timeout_message: &str) -> io::Result<()> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, timeout_message));
            }
            let timeout = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            // SAFETY: one initialized pollfd is writable for the duration of this bounded call.
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, timeout_message));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            // SAFETY: bytes exposes a readable region of the supplied length and fd is borrowed.
            let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if count > 0 {
                bytes = &bytes[count as usize..];
            } else if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            } else {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn fail_child(status_fd: RawFd, error: i32) -> ! {
        let bytes = error.to_ne_bytes();
        // SAFETY: status descriptor belongs to this child and buffer is valid.
        unsafe { libc::write(status_fd, bytes.as_ptr().cast(), bytes.len()) };
        // SAFETY: direct child termination avoids running inherited Rust destructors.
        unsafe { libc::_exit(125) }
    }

    fn apply_limits(limits: ResourceLimits) -> io::Result<()> {
        if let Some(milliseconds) = limits.cpu_time_ms {
            let seconds = milliseconds.saturating_add(999) / 1000;
            set_limit(libc::RLIMIT_CPU, seconds, seconds.saturating_add(1))?;
        }
        if let Some(bytes) = limits.max_file_bytes {
            set_limit(libc::RLIMIT_FSIZE, bytes, bytes)?;
        }
        if let Some(processes) = limits.max_processes {
            set_limit(libc::RLIMIT_NPROC, processes, processes)?;
        }
        if let Some(files) = limits.max_open_files {
            set_limit(libc::RLIMIT_NOFILE, files, files)?;
        }
        Ok(())
    }

    fn set_limit(resource: libc::c_int, current: u64, maximum: u64) -> io::Result<()> {
        let limit = libc::rlimit {
            rlim_cur: current,
            rlim_max: maximum,
        };
        // SAFETY: resource is a supported RLIMIT selector and limit is fully initialized.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn decode_status(status: libc::c_int) -> ExitStatus {
        if libc::WIFEXITED(status) {
            ExitStatus {
                exit_code: Some(libc::WEXITSTATUS(status)),
                signal: None,
                core_dumped: false,
            }
        } else if libc::WIFSIGNALED(status) {
            ExitStatus {
                exit_code: None,
                signal: Some(libc::WTERMSIG(status)),
                core_dumped: libc::WCOREDUMP(status),
            }
        } else {
            ExitStatus {
                exit_code: None,
                signal: None,
                core_dumped: false,
            }
        }
    }

    fn errno() -> i32 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL)
    }

    fn close_fd(fd: RawFd) {
        if fd >= 0 {
            // SAFETY: close is idempotent at the ownership sites used in this module.
            unsafe { libc::close(fd) };
        }
    }

    fn close_fds(fds: &[RawFd]) {
        for fd in fds {
            close_fd(*fd);
        }
    }

    pub use LaunchSpec as ProcessLaunchSpec;
    pub use MacProcess as Process;
}

#[cfg(target_os = "macos")]
pub use macos::{ExitStatus, Process, ProcessLaunchSpec, launcher_main};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_deny_by_default_and_escapes_paths() {
        let policy = SeatbeltPolicy::generate(
            &[Grant {
                resolved_host_path: PathBuf::from("/tmp/a quote \" here"),
                target_path: PathBuf::from("/tmp/a quote \" here"),
                access: GrantAccess::Read,
            }],
            PathBuf::from("/private/tmp/home"),
            PathBuf::from("/private/tmp/tmp"),
            NetworkMode::None,
        )
        .expect("policy");
        assert!(policy.profile.contains("(deny default)"));
        assert!(policy.profile.contains("(deny network*)"));
        assert!(policy.profile.contains("a quote \\\" here"));
    }

    #[test]
    fn path_remapping_is_rejected() {
        let error = SeatbeltPolicy::generate(
            &[Grant {
                resolved_host_path: PathBuf::from("/tmp/a"),
                target_path: PathBuf::from("/workspace"),
                access: GrantAccess::ReadWrite,
            }],
            PathBuf::from("/tmp/home"),
            PathBuf::from("/tmp/tmp"),
            NetworkMode::None,
        )
        .expect_err("remap must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
