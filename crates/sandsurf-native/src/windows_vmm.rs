//! Mandatory per-owner LPAC confinement. A native Job bounds compute; it does
//! not authorize reading host state or connecting to host IP networks.
use crate::local::{Directory, ScopeAccess, ScopedDirectory};
use crate::socket_io::SocketNamespace;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{
    CopySid, EqualSid, FreeSid, GetLengthSid, GetTokenInformation, PSID, SECURITY_CAPABILITIES,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TokenAppContainerSid,
    TokenCapabilities, TokenIsAppContainer, TokenIsLessPrivilegedAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
use windows_sys::Win32::System::Threading::OpenProcessToken;

pub(crate) struct AppSid(Vec<usize>);
impl AppSid {
    fn derive(name: &str) -> io::Result<Self> {
        let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut original = std::ptr::null_mut();
        // SAFETY: terminated name and writable SID output. No profile is created:
        // a default writable AppContainer home is outside the owned volume.
        let result =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut original) };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if original.is_null() {
            return Err(invalid("native AppContainer SID is absent"));
        }
        // SAFETY: successful derivation returned a valid newly allocated SID.
        let bytes = unsafe { GetLengthSid(original) };
        if !(8..=68).contains(&bytes) {
            // SAFETY: the derivation returned this newly allocated SID.
            unsafe { FreeSid(original) };
            return Err(invalid("native AppContainer SID exceeds bound"));
        }
        let mut value = Self(vec![0; (bytes as usize).div_ceil(size_of::<usize>())]);
        // SAFETY: bounded aligned destination and the retained original SID.
        let copied = unsafe { CopySid(bytes, value.raw(), original) } != 0;
        // SAFETY: the original allocation came from AppContainer SID derivation.
        unsafe { FreeSid(original) };
        if !copied {
            return Err(invalid("native AppContainer SID exceeds bound"));
        }
        // Vec's allocation, not its owner, is used by launch attributes.
        value.0.shrink_to_fit();
        Ok(value)
    }
    pub(crate) fn raw(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }
    pub(crate) fn text(&self) -> io::Result<String> {
        crate::local::sid_text(self.raw())
    }
}

/// This original scope is created before the process and can launch exactly
/// once. Inputs are immutable independent copies, never ACL changes to stores.
pub struct Isolation {
    sid: Arc<AppSid>,
    root: Option<Directory>,
    directories: Vec<ScopedDirectory>,
    inputs: Vec<File>,
    namespace: SocketNamespace,
    lease: Option<Arc<File>>,
    executable: PathBuf,
    kernel: PathBuf,
    initramfs: Option<PathBuf>,
    firmware: PathBuf,
    launched: AtomicBool,
    exited: AtomicBool,
}

impl Isolation {
    /// `parent` is the original bounded volume in production. Kernel fixtures
    /// may use a private test directory; this function never provisions quotas.
    pub fn create(
        parent: &Path,
        executable_name: &str,
        runtime: &[(&Path, &File)],
        kernel: &File,
        initramfs: Option<&File>,
    ) -> io::Result<Arc<Self>> {
        let parent = Directory::open(parent)?;
        reclaim(parent.path())?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
        let name = format!(
            "svm-{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let path = parent.path().join(&name);
        crate::local::create_private_directory(&path)?;
        let root = Directory::open(&path)?;
        let lease = Arc::new(crate::storage::disk_lease(&root.path().join(".owner"))?);
        let sid = Arc::new(AppSid::derive(&name)?);
        let input_directory = ScopedDirectory::create(
            &root.path().join("r"),
            sid.clone(),
            ScopeAccess::ReadExecute,
        )?;
        let endpoint_directory =
            ScopedDirectory::create(&root.path().join("e"), sid.clone(), ScopeAccess::Devices)?;
        let namespace = SocketNamespace::virtual_machine(endpoint_directory);
        if namespace
            .path()
            .join("control-7.sock")
            .as_os_str()
            .as_encoded_bytes()
            .len()
            > 103
        {
            return Err(invalid(
                "bounded volume native endpoint exceeds socket path bound",
            ));
        }
        let executable = input_directory.path().join(executable_name);
        let kernel_path = input_directory.path().join("kernel");
        let firmware_directory = ScopedDirectory::create(
            &input_directory.path().join("firmware"),
            sid.clone(),
            ScopeAccess::ReadExecute,
        )?;
        let firmware = firmware_directory.path().to_owned();
        let mut value = Self {
            sid,
            root: Some(root),
            directories: vec![input_directory, firmware_directory],
            inputs: Vec::new(),
            namespace,
            lease: Some(lease),
            executable,
            kernel: kernel_path,
            initramfs: None,
            firmware,
            launched: AtomicBool::new(false),
            exited: AtomicBool::new(false),
        };
        if runtime.is_empty()
            || runtime.len() > 128
            || !["sandsurf-qemu-x64.exe", "sandsurf-qemu-arm64.exe"].contains(&executable_name)
        {
            return Err(invalid("invalid native runtime closure"));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut total = 0u64;
        for (relative, file) in runtime {
            let relative = relative
                .components()
                .map(|part| {
                    if !matches!(part, std::path::Component::Normal(_)) {
                        return Err(invalid("runtime role is not relative"));
                    }
                    part.as_os_str()
                        .to_str()
                        .ok_or_else(|| invalid("runtime role is not UTF-8"))
                })
                .collect::<io::Result<Vec<_>>>()?
                .join("/");
            let (directory, name) = if let Some(name) =
                relative.strip_prefix("qemu-runtime/firmware/")
            {
                if ![
                    "bios-256k.bin",
                    "linuxboot_dma.bin",
                    "kvmvapic.bin",
                    "pvh.bin",
                ]
                .contains(&name)
                {
                    return Err(invalid("unknown native firmware role"));
                }
                (1, name)
            } else if relative == executable_name || relative.to_ascii_lowercase().ends_with(".dll")
            {
                (0, relative.as_str())
            } else {
                return Err(invalid("unknown sealed native runtime role"));
            };
            if !names.insert(relative.to_lowercase()) {
                return Err(invalid("native runtime role is duplicated"));
            }
            let bytes = file.metadata()?.len();
            total = total
                .checked_add(bytes)
                .ok_or_else(|| invalid("native runtime size overflow"))?;
            if total > 1024 * 1024 * 1024 {
                return Err(invalid("native runtime closure exceeds bound"));
            }
            value.copy_input(directory, name, file, 512 * 1024 * 1024)?;
        }
        if !names.contains(&executable_name.to_lowercase()) {
            return Err(invalid("native executable is not in its closure"));
        }
        value.copy_input(0, "kernel", kernel, 128 * 1024 * 1024)?;
        if let Some(initramfs) = initramfs {
            value.copy_input(0, "initramfs", initramfs, 256 * 1024 * 1024)?;
            value.initramfs = Some(value.directories[0].path().join("initramfs"));
        }
        value.check()?;
        Ok(Arc::new(value))
    }

    fn copy_input(
        &mut self,
        directory: usize,
        name: &str,
        original: &File,
        limit: u64,
    ) -> io::Result<()> {
        let before = original.metadata()?;
        if !before.is_file() || before.len() == 0 || before.len() > limit {
            return Err(invalid("sealed native input exceeds bound"));
        }
        let target = &self.directories[directory];
        let mut output = target.create_input(name)?;
        let mut source = original.try_clone()?;
        // Clones share position on Windows. ReadFile's synchronous file pointer
        // is explicitly positioned and never used after this sealing operation.
        use std::io::{Seek, SeekFrom};
        source.seek(SeekFrom::Start(0))?;
        let copied = io::copy(
            &mut Read::by_ref(&mut source).take(before.len() + 1),
            &mut output,
        )?;
        if copied != before.len() {
            return Err(invalid("sealed native input changed length"));
        }
        output.flush()?;
        output.sync_all()?;
        drop(output);
        let held = target.input_lease(name)?;
        self.inputs.push(held);
        Ok(())
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn kernel(&self) -> &Path {
        &self.kernel
    }
    pub fn initramfs(&self) -> Option<&Path> {
        self.initramfs.as_deref()
    }
    pub fn firmware(&self) -> &Path {
        &self.firmware
    }
    pub fn namespace(&self) -> SocketNamespace {
        self.namespace.clone()
    }
    pub fn custody(&self) -> Arc<File> {
        self.lease.as_ref().expect("live native scope").clone()
    }
    pub(crate) fn capabilities(&self) -> SECURITY_CAPABILITIES {
        SECURITY_CAPABILITIES {
            AppContainerSid: self.sid.raw(),
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        }
    }
    pub(crate) fn check(&self) -> io::Result<()> {
        self.root
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .check()?;
        for directory in &self.directories {
            directory.check()?;
        }
        self.namespace.check()
    }
    pub(crate) fn claim_launch(&self) -> io::Result<()> {
        self.check()?;
        self.launched
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| invalid("native scope already launched"))?;
        Ok(())
    }
    pub(crate) fn native_exited(&self) {
        self.exited.store(true, Ordering::Release);
    }
    pub(crate) fn verify_process(&self, process: HANDLE) -> io::Result<()> {
        let mut token = std::ptr::null_mut();
        // SAFETY: retained original process handle and writable token output.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            for class in [TokenIsAppContainer, TokenIsLessPrivilegedAppContainer] {
                let bytes = token_info(token, class)?;
                if bytes.len() * size_of::<usize>() < 4 || (bytes[0] as u32) != 1 {
                    return Err(invalid("native process lacks mandatory LPAC token"));
                }
            }
            let identity = token_info(token, TokenAppContainerSid)?;
            if identity.len() * size_of::<usize>() < size_of::<TOKEN_APPCONTAINER_INFORMATION>() {
                return Err(invalid("native AppContainer token is truncated"));
            }
            // SAFETY: aligned initialized token output remains retained here.
            let actual = unsafe {
                (&*identity.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer
            };
            // SAFETY: both SID buffers remain retained; null is rejected first.
            if actual.is_null() || unsafe { EqualSid(actual, self.sid.raw()) } == 0 {
                return Err(invalid("native process belongs to a different scope"));
            }
            let groups = token_info(token, TokenCapabilities)?;
            if groups.len() * size_of::<usize>() < size_of::<u32>() {
                return Err(invalid("native capabilities are truncated"));
            }
            // TokenCapabilities can contain only its count and no group array.
            // Do not create a reference to an absent TOKEN_GROUPS tail.
            if groups[0] as u32 != 0 {
                return Err(invalid("native process acquired ambient capabilities"));
            }
            Ok(())
        })();
        // SAFETY: successful token query returned one newly owned token handle.
        unsafe { CloseHandle(token) };
        result
    }
}

fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut bytes = 0;
    // SAFETY: zero-capacity sizing query on a retained token handle.
    if unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut bytes) } != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || bytes == 0
        || bytes > 16384
    {
        return Err(invalid("native token query exceeds bound"));
    }
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned storage holds the entire queried output capacity.
    if unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), bytes, &mut bytes) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

/// Obtain the physical GUID root from the original disk handle, not an
/// ancestor search or a host temp directory outside its physical cap.
pub fn disk_volume(file: &File) -> io::Result<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_GUID};
    let mut buffer = [0u16; 32768];
    // SAFETY: retained original disk handle and bounded initialized output.
    let bytes = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            VOLUME_NAME_GUID,
        )
    };
    if bytes == 0 || bytes as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let path = String::from_utf16(&buffer[..bytes as usize])
        .map_err(|_| invalid("native volume address is not UTF-16"))?;
    let guid = path
        .get(..49)
        .filter(|root| root.starts_with(r"\\?\Volume{") && root.ends_with("}\\"))
        .ok_or_else(|| invalid("original disk is not on a GUID volume"))?;
    Ok(Directory::open(Path::new(guid))?.path().to_owned())
}

/// Retain a boot input without write/delete sharing until its sealed copy is
/// complete. The original host preparation owns its content authorization.
pub fn boot_input(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    use std::os::windows::fs::MetadataExt;
    if file.metadata()?.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err(invalid("native boot input is a reparse alias"));
    }
    Ok(file)
}

impl Drop for Isolation {
    fn drop(&mut self) {
        if self.launched.load(Ordering::Acquire) && !self.exited.load(Ordering::Acquire) {
            return;
        }
        let result = (|| -> io::Result<()> {
            let root = self.root.take().ok_or(io::ErrorKind::NotConnected)?;
            root.check()?;
            let lease = self.lease.take().ok_or(io::ErrorKind::NotConnected)?;
            let lease = Arc::try_unwrap(lease)
                .map_err(|_| invalid("native scope still has original custody"))?;
            self.namespace.close()?;
            self.inputs.clear();
            self.directories.clear();
            reclaim_scope(root, lease)
        })();
        match result {
            Ok(()) => {}
            Err(error) => eprintln!("sandsurf native scope cleanup unavailable: {error}"),
        }
    }
}

/// Crash recovery uses the original inherited scope lease, not a PID, a
/// missing management channel or a cached host lifecycle observation.
pub fn reclaim(parent: &Path) -> io::Result<()> {
    let parent = Directory::open(parent)?;
    let candidates = fs::read_dir(parent.path())?
        .take(4097)
        .collect::<io::Result<Vec<_>>>()?;
    if candidates.len() > 4096 {
        return Err(invalid("native scope inventory exceeds bound"));
    }
    for entry in candidates {
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| scope_name(name)) else {
            continue;
        };
        parent.check()?;
        let root = Directory::open(&entry.path())?;
        if root.path().file_name().and_then(|name| name.to_str()) != Some(name) {
            return Err(invalid("native scope path changed"));
        }
        // Never create a missing ownership marker during recovery.
        match fs::symlink_metadata(root.path().join(".owner")) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && entries(root.path(), 1)?.is_empty() =>
            {
                // Interrupted exclusive creation before its marker exists. A
                // live creator's original directory handle denies deletion.
                let path = root.path().to_owned();
                drop(root);
                match fs::remove_dir(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
                    Err(error) => return Err(error),
                }
                continue;
            }
            _ => return Err(invalid("native scope has no original custody marker")),
        }
        let lease = match crate::storage::disk_lease(&root.path().join(".owner")) {
            Ok(lease) => lease,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        };
        reclaim_scope(root, lease)?;
    }
    Ok(())
}

fn scope_name(name: &str) -> bool {
    name.strip_prefix("svm-").is_some_and(|tail| {
        tail.len() == 32
            && tail
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn entries(directory: &Path, maximum: usize) -> io::Result<Vec<fs::DirEntry>> {
    let entries = fs::read_dir(directory)?
        .take(maximum + 1)
        .collect::<io::Result<Vec<_>>>()?;
    if entries.len() > maximum {
        return Err(invalid("native scope closure exceeds bound"));
    }
    Ok(entries)
}

fn reclaim_scope(root: Directory, lease: File) -> io::Result<()> {
    root.check()?;
    let name = root
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| scope_name(name))
        .ok_or_else(|| invalid("native scope name is not canonical"))?;
    let sid = Arc::new(AppSid::derive(name)?);
    let root_entries = entries(root.path(), 3)?;
    if root_entries
        .iter()
        .any(|entry| !matches!(entry.file_name().to_str(), Some(".owner" | "r" | "e")))
    {
        return Err(invalid("native scope contains an unowned role"));
    }
    let mut files = Vec::new();
    let mut sockets = Vec::new();
    let mut directories = Vec::new();
    let mut total = 0u64;
    for entry in root_entries {
        let kind = entry.file_name();
        if kind == ".owner" {
            continue;
        }
        let access = if kind == "e" {
            ScopeAccess::Devices
        } else {
            ScopeAccess::ReadExecute
        };
        let directory = ScopedDirectory::open(&entry.path(), sid.clone(), access)?;
        if kind == "e" {
            for socket in entries(
                directory.path(),
                sandsurf_protocol::GUEST_SERIAL_CONNECTIONS + 3,
            )? {
                let name = socket.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("native endpoint name is invalid"))?;
                if !matches!(name, "qmp.sock" | "console.sock" | "nic.sock")
                    && !(0..sandsurf_protocol::GUEST_SERIAL_CONNECTIONS)
                        .any(|slot| format!("control-{slot}.sock") == name)
                {
                    return Err(invalid("native scope contains an unowned endpoint"));
                }
                crate::socket_io::verify_windows_socket_name(&socket.path())?;
                sockets.push(socket.path());
            }
        } else {
            for input in entries(directory.path(), 132)? {
                let name = input.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid("native input name is invalid"))?;
                if name == "firmware" {
                    let firmware = ScopedDirectory::open(
                        &input.path(),
                        sid.clone(),
                        ScopeAccess::ReadExecute,
                    )?;
                    for input in entries(firmware.path(), 4)? {
                        let name = input.file_name();
                        let name = name
                            .to_str()
                            .ok_or_else(|| invalid("native firmware name is invalid"))?;
                        if ![
                            "bios-256k.bin",
                            "linuxboot_dma.bin",
                            "kvmvapic.bin",
                            "pvh.bin",
                        ]
                        .contains(&name)
                        {
                            return Err(invalid("native firmware contains an unowned input"));
                        }
                        let held = firmware.input_lease(name)?;
                        if held.metadata()?.len() > 1024 * 1024 {
                            return Err(invalid("native firmware exceeds bound"));
                        }
                        files.push((input.path(), held));
                    }
                    directories.push(firmware);
                } else {
                    if !(matches!(
                        name,
                        "sandsurf-qemu-x64.exe"
                            | "sandsurf-qemu-arm64.exe"
                            | "kernel"
                            | "initramfs"
                    ) || (name.len() <= 128
                        && name.to_ascii_lowercase().ends_with(".dll")
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))))
                    {
                        return Err(invalid("native scope contains an unowned input"));
                    }
                    let held = directory.input_lease(name)?;
                    let bytes = held.metadata()?.len();
                    let cap = match name {
                        "kernel" => 128 * 1024 * 1024,
                        "initramfs" => 256 * 1024 * 1024,
                        _ => 512 * 1024 * 1024,
                    };
                    total = total
                        .checked_add(bytes)
                        .ok_or_else(|| invalid("native scope byte count overflow"))?;
                    if bytes > cap || total > 1408 * 1024 * 1024 {
                        return Err(invalid("native scope bytes exceed bound"));
                    }
                    files.push((input.path(), held));
                }
            }
        }
        directories.insert(0, directory);
    }
    // Validate the entire closure before unlinking any bytes. File leases fence
    // substitutions; unknown roles, aliases and foreign ACLs remain untouched.
    root.check()?;
    let paths: Vec<_> = files.iter().map(|(path, _)| path.clone()).collect();
    drop(files);
    for path in paths.into_iter().chain(sockets) {
        fs::remove_file(path)?;
    }
    let paths: Vec<_> = directories
        .iter()
        .map(|directory| directory.path().to_owned())
        .collect();
    drop(directories);
    // Children before parents, independent of filesystem enumeration order.
    let mut paths = paths;
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in paths {
        fs::remove_dir(path)?;
    }
    root.check()?;
    drop(lease);
    fs::remove_file(root.path().join(".owner"))?;
    let path = root.path().to_owned();
    drop(root);
    fs::remove_dir(path)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
