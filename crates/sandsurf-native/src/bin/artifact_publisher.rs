//! Build-time publication, not a host-service role. The process doing the
//! copying and renames itself retains the OS lease; no lock-helper lifetime,
//! PID adoption, stale lock directory, or application-held authority cache.
use sandsurf_native::storage::{sync_directory, sync_file};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_FILE: u64 = 512 * 1024 * 1024;
const PLATFORMS: [&str; 5] = [
    "linux-x64",
    "linux-arm64",
    "macos-x64",
    "macos-arm64",
    "windows-x64",
];

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Platform {
        root: PathBuf,
        platform: String,
        payload: PathBuf,
        corresponding: Option<PathBuf>,
        corresponding_files: Vec<String>,
    },
    Tree {
        root: PathBuf,
        staged: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    format_version: u16,
    build_id: String,
    files: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Publication {
    version: u16,
    staged: PathBuf,
    backup: Option<PathBuf>,
    manifest_digest: String,
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn clear_publication(parent: &Path) -> io::Result<()> {
    fs::remove_file(parent.join(".native-publication.json"))?;
    sync_directory(parent)
}

/// The same publisher recovers its interrupted two-directory rename under the
/// same OS lease, before reading the platform set. Never adopt a missing root
/// as an empty generation when its original bytes are in the recorded backup.
fn recover(root: &Path) -> io::Result<()> {
    let parent = root
        .parent()
        .ok_or_else(|| invalid("native root has no parent"))?;
    let path = parent.join(".native-publication.json");
    if !exists(&path)? {
        return Ok(());
    }
    let mut bytes = Vec::new();
    regular(&path)?.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(invalid("publication record exceeds bound"));
    }
    let record: Publication = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if record.version != 1
        || record.manifest_digest.len() != 64
        || !record
            .manifest_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || record.staged.parent() != Some(parent)
        || record.staged == root
        || record.backup.as_ref().is_some_and(|backup| {
            backup.file_name().and_then(|name| name.to_str()) != Some("native")
                || backup.parent().and_then(Path::parent) != Some(parent)
                || !backup
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.strip_prefix(".native-previous-")
                            .is_some_and(|suffix| {
                                suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                    })
        })
    {
        return Err(invalid("publication recovery record has an invalid owner"));
    }
    if exists(root)? {
        directory(root)?;
        if !exists(&record.staged)? {
            // The new complete tree has been installed. Keep the prior tree
            // recoverable if its caller never received the returned reference.
            verify_manifest(root)?;
            if hash(&root.join("manifest.json"))? != record.manifest_digest {
                return Err(invalid(
                    "installed publication differs from interrupted operation",
                ));
            }
        } else if record
            .backup
            .as_ref()
            .is_some_and(|backup| exists(backup).unwrap_or(true))
        {
            return Err(invalid("publication has conflicting original names"));
        }
    } else if let Some(backup) = &record.backup {
        directory(backup)?;
        fs::rename(backup, root)?;
        sync_directory(parent)?;
    } else if !exists(&record.staged)? {
        return Err(invalid("publication lost its staged name"));
    }
    clear_publication(parent)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Build outputs belong to a trusted source checkout, not the private machine
// service namespace. Its lock still has one native owner doing all mutations.
fn build_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}

fn new_file(path: &Path) -> io::Result<File> {
    build_options().create_new(true).open(path)
}

fn build_lease(path: &Path) -> io::Result<File> {
    let file = build_options()
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| {
            if cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33)) {
                io::Error::new(io::ErrorKind::WouldBlock, "native publication has an owner")
            } else {
                error
            }
        })?;
    regular(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        // SAFETY: getuid is a scalar account identity query.
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::getuid() } {
            return Err(invalid("native publication lease has a foreign owner"));
        }
    }
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            io::Error::new(io::ErrorKind::WouldBlock, "native publication has an owner")
        }
        std::fs::TryLockError::Error(error) => error,
    })?;
    Ok(file)
}

fn canonical(path: &Path) -> io::Result<bool> {
    let real = fs::canonicalize(path)?;
    #[cfg(not(windows))]
    {
        Ok(real == path)
    }
    #[cfg(windows)]
    {
        let real = real
            .to_str()
            .ok_or_else(|| invalid("invalid canonical path"))?;
        let path = path
            .to_str()
            .ok_or_else(|| invalid("invalid native path"))?;
        Ok(real
            .strip_prefix("\\\\?\\")
            .unwrap_or(real)
            .eq_ignore_ascii_case(path.strip_prefix("\\\\?\\").unwrap_or(path)))
    }
}

fn directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.to_str().is_none() {
        return Err(invalid("native directory must be absolute UTF-8"));
    }
    if !canonical(path)? || !fs::symlink_metadata(path)?.is_dir() {
        return Err(invalid("native artifact directory is an alias"));
    }
    Ok(())
}

fn regular(path: &Path) -> io::Result<File> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.len() > MAX_FILE {
        return Err(invalid(
            "native artifact is not a bounded exclusive regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err(invalid(
                "native artifact is not a bounded exclusive regular file",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 {
            return Err(invalid("native artifact is a reparse alias"));
        }
    }
    let file = File::open(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = Default::default();
        // SAFETY: this file retains the live handle and info is writable output.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.nNumberOfLinks != 1 || info.dwFileAttributes & 0x400 != 0 {
            return Err(invalid(
                "native artifact is not a bounded exclusive regular file",
            ));
        }
    }
    if file.metadata()?.len() != before.len() || !canonical(path)? {
        return Err(invalid("native artifact identity changed"));
    }
    Ok(file)
}

fn files(root: &Path) -> io::Result<Vec<String>> {
    fn walk(root: &Path, relative: &str, depth: usize, result: &mut Vec<String>) -> io::Result<()> {
        if depth > 6 {
            return Err(invalid("native payload nesting exceeds its bound"));
        }
        let path = root.join(relative);
        directory(&path)?;
        for (count, entry) in fs::read_dir(&path)?.enumerate() {
            if count >= 256 {
                return Err(invalid("native payload directory exceeds its bound"));
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("invalid native artifact name"))?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
            {
                return Err(invalid("invalid native artifact name"));
            }
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            if fs::symlink_metadata(root.join(&child))?.is_dir() {
                walk(root, &child, depth + 1, result)?;
            } else {
                regular(&root.join(&child))?;
                result.push(child);
            }
            if result.len() > 512 {
                return Err(invalid("native payload file count exceeds its bound"));
            }
        }
        Ok(())
    }
    let mut result = Vec::new();
    walk(root, "", 0, &mut result)?;
    result.sort();
    Ok(result)
}

fn hash(path: &Path) -> io::Result<String> {
    let mut input = regular(path)?;
    let length = input.metadata()?.len();
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut count = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > length {
            return Err(invalid("native input changed during hashing"));
        }
        hash.update(&buffer[..read]);
    }
    if count != length {
        return Err(invalid("native input changed during hashing"));
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    for name in files(source)? {
        let from = source.join(&name);
        let to = destination.join(&name);
        fs::create_dir_all(
            to.parent()
                .ok_or_else(|| invalid("artifact has no parent"))?,
        )?;
        let expected = hash(&from)?;
        let mut input = regular(&from)?;
        let length = input.metadata()?.len();
        let mut output = new_file(&to)?;
        if io::copy(&mut Read::by_ref(&mut input).take(length + 1), &mut output)? != length {
            return Err(invalid("native build input changed during staging"));
        }
        // Retain the writable descriptor for durable flushing. Preserve Unix
        // executable modes, not Windows' non-authoritative readonly attribute.
        // Loaded-runtime protection is established by the runtime verifier and
        // native owner, not inferred from build-directory file attributes.
        #[cfg(unix)]
        fs::set_permissions(&to, input.metadata()?.permissions())?;
        sync_file(&output)?;
        drop(output);
        if hash(&from)? != expected || hash(&to)? != expected {
            return Err(invalid("native build input changed during staging"));
        }
    }
    Ok(())
}

fn verify_manifest(root: &Path) -> io::Result<()> {
    let mut bytes = Vec::new();
    regular(&root.join("manifest.json"))?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(invalid("invalid staged native manifest"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if manifest.format_version != 1 || manifest.build_id != "sandsurf-native-1.0.0" {
        return Err(invalid("invalid staged native manifest envelope"));
    }
    let actual: Vec<_> = files(root)?
        .into_iter()
        .filter(|name| name != "manifest.json")
        .collect();
    if actual != manifest.files.keys().cloned().collect::<Vec<_>>() {
        return Err(invalid(
            "staged native manifest does not cover its complete payload",
        ));
    }
    for (name, digest) in manifest.files {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || hash(&root.join(name))? != digest
        {
            return Err(invalid("staged native artifact failed its digest"));
        }
    }
    Ok(())
}

fn temporary(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
    let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let path = parent.join(format!(".{prefix}-{nonce}"));
    fs::create_dir(&path)?;
    Ok(path)
}

fn publish(staged: &Path, root: &Path) -> io::Result<Option<PathBuf>> {
    if staged.parent() != root.parent() || staged == root {
        return Err(invalid(
            "native publication requires an adjacent staged tree",
        ));
    }
    directory(staged)?;
    verify_manifest(staged)?;
    let parent = root
        .parent()
        .ok_or_else(|| invalid("native root has no parent"))?;
    let backup = if exists(root)? {
        directory(root)?;
        Some(temporary(parent, "native-previous")?.join("native"))
    } else {
        None
    };
    // Flush nested directory entries as well as their payloads before the
    // manifest-bound tree can acquire the public name.
    let mut directories = std::collections::BTreeSet::new();
    directories.insert(staged.to_path_buf());
    for name in files(staged)? {
        let mut path = staged.join(name);
        while let Some(parent) = path.parent() {
            if !parent.starts_with(staged) {
                break;
            }
            directories.insert(parent.to_path_buf());
            path = parent.to_path_buf();
        }
    }
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    let publication = Publication {
        version: 1,
        staged: staged.to_path_buf(),
        backup: backup.clone(),
        manifest_digest: hash(&staged.join("manifest.json"))?,
    };
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
    let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let pending = parent.join(format!(".native-publication-{nonce}.pending"));
    let mut record = new_file(&pending)?;
    record.write_all(&serde_json::to_vec(&publication).map_err(io::Error::other)?)?;
    sync_file(&record)?;
    drop(record);
    // Same-directory no-replace publication on the build filesystem, not an
    // account-private IPC endpoint or a privileged host-state transaction.
    fs::hard_link(&pending, parent.join(".native-publication.json"))?;
    fs::remove_file(&pending)?;
    sync_directory(parent)?;
    if let Some(backup) = &backup {
        if let Err(error) = fs::rename(root, backup) {
            clear_publication(parent)?;
            return Err(error);
        }
        sync_directory(backup.parent().expect("owned backup holder"))?;
        sync_directory(parent)?;
    }
    if let Err(error) = fs::rename(staged, root) {
        if let Some(backup) = &backup {
            fs::rename(backup, root)?;
        }
        sync_directory(parent)?;
        clear_publication(parent)?;
        return Err(error);
    }
    sync_directory(parent)?;
    clear_publication(parent)?;
    Ok(backup)
}

fn platform(
    root: &Path,
    platform: &str,
    payload: &Path,
    corresponding: Option<&Path>,
    expected: &[String],
) -> io::Result<()> {
    if !PLATFORMS.contains(&platform) {
        return Err(invalid("invalid native build publication target"));
    }
    files(payload)?;
    let parent = root
        .parent()
        .ok_or_else(|| invalid("native root has no parent"))?;
    let staged = temporary(parent, "native-build")?;
    let result = (|| {
        let existing: Vec<String> = match fs::symlink_metadata(root) {
            Ok(_) => {
                directory(root)?;
                let mut names = Vec::new();
                for entry in fs::read_dir(root)? {
                    if names.len() >= PLATFORMS.len() + 2 {
                        return Err(invalid("native output contains non-artifact paths"));
                    }
                    names.push(
                        entry?
                            .file_name()
                            .into_string()
                            .map_err(|_| invalid("invalid native output name"))?,
                    );
                }
                names
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        if existing.iter().any(|name| {
            name != "manifest.json" && name != "qemu-source" && !PLATFORMS.contains(&name.as_str())
        }) {
            return Err(invalid("native output contains non-artifact paths"));
        }
        let others: Vec<_> = existing
            .iter()
            .filter(|name| PLATFORMS.contains(&name.as_str()) && *name != platform)
            .collect();
        if let Some(source) = corresponding {
            let inputs = files(source)?;
            if inputs != expected {
                return Err(invalid("incomplete corresponding QEMU source"));
            }
            if existing.iter().any(|name| name == "qemu-source")
                && others.iter().any(|name| !name.starts_with("linux-"))
            {
                let previous = root.join("qemu-source");
                if files(&previous)? != inputs {
                    return Err(invalid(
                        "remaining QEMU platforms have different corresponding source",
                    ));
                }
                for name in &inputs {
                    if hash(&previous.join(name))? != hash(&source.join(name))? {
                        return Err(invalid(
                            "rebuild all QEMU platforms together when corresponding source changes",
                        ));
                    }
                }
            }
            fs::create_dir(staged.join("qemu-source"))?;
            copy_tree(source, &staged.join("qemu-source"))?;
        } else if existing.iter().any(|name| name == "qemu-source") {
            fs::create_dir(staged.join("qemu-source"))?;
            copy_tree(&root.join("qemu-source"), &staged.join("qemu-source"))?;
        }
        for other in others {
            fs::create_dir(staged.join(other))?;
            copy_tree(&root.join(other), &staged.join(other))?;
        }
        fs::create_dir(staged.join(platform))?;
        copy_tree(payload, &staged.join(platform))?;
        let mut contents = BTreeMap::new();
        for name in files(&staged)? {
            contents.insert(name.clone(), hash(&staged.join(name))?);
        }
        let manifest = Manifest {
            format_version: 1,
            build_id: "sandsurf-native-1.0.0".into(),
            files: contents,
        };
        let mut record = File::create_new(staged.join("manifest.json"))?;
        record.write_all(&serde_json::to_vec(&manifest).map_err(io::Error::other)?)?;
        sync_file(&record)?;
        drop(record);
        sync_directory(&staged)?;
        if let Some(backup) = publish(&staged, root)? {
            // Only this invocation's displaced generated tree, never machines.
            fs::remove_dir_all(backup.parent().expect("owned backup holder"))?;
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if staged.exists() {
        fs::remove_dir_all(&staged)?;
    }
    result
}

fn run() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(invalid("publisher accepts one bounded stdin request"));
    }
    let mut bytes = Vec::new();
    io::stdin().take(32769).read_to_end(&mut bytes)?;
    if bytes.len() > 32768 {
        return Err(invalid("publication request exceeds bound"));
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let root = match &request {
        Request::Platform { root, .. } | Request::Tree { root, .. } => root,
    };
    if !root.is_absolute() || root.file_name().and_then(|name| name.to_str()) != Some("native") {
        return Err(invalid("invalid native publication target"));
    }
    let parent = root
        .parent()
        .ok_or_else(|| invalid("native root has no parent"))?;
    directory(parent)?;
    let deadline = Instant::now() + Duration::from_secs(300);
    let _custody = loop {
        match build_lease(&parent.join(".native-publication.lock")) {
            Ok(file) => break file,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(error) => return Err(error),
        }
    };
    recover(root)?;
    let backup = match request {
        Request::Tree { root, staged } => publish(&staged, &root)?,
        Request::Platform {
            root,
            platform: name,
            payload,
            corresponding,
            mut corresponding_files,
        } => {
            corresponding_files.sort();
            if corresponding_files.len() > 512 {
                return Err(invalid("corresponding source count exceeds bound"));
            }
            platform(
                &root,
                &name,
                &payload,
                corresponding.as_deref(),
                &corresponding_files,
            )?;
            None
        }
    };
    serde_json::to_writer(io::stdout(), &backup).map_err(io::Error::other)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("sandsurf-artifact-publisher: {error}");
        std::process::exit(1);
    }
}
