//! The complete loaded QEMU runtime is one digest-bound artifact. Native file
//! leases protect its executable, dependency closure and firmware, not only the
//! main executable. Corresponding source is distribution data, not loaded TCB.
use crate::GuestArchitecture;
use sandsurf_protocol::Digest;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    format_version: u16,
    architecture: GuestArchitecture,
    qemu_version: String,
    files: BTreeMap<String, Digest>,
}

pub struct Runtime {
    pub executable: PathBuf,
    pub firmware_directory: PathBuf,
    /// Individually verified inputs for the native filesystem boundary. A
    /// runtime directory is not permission to read newly added host files.
    pub read_paths: Vec<PathBuf>,
    _inputs: Vec<File>,
}

pub fn verify(
    path: &Path,
    expected: &Digest,
    architecture: GuestArchitecture,
) -> io::Result<Runtime> {
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some("qemu-runtime.json")
    {
        return Err(invalid("invalid native runtime manifest address"));
    }
    let root = path
        .parent()
        .ok_or_else(|| invalid("runtime manifest has no owner"))?;
    let mut file = open(path)?;
    let mut bytes = Vec::new();
    file.by_ref().take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 || sandsurf_protocol::bytes_digest(&bytes) != *expected {
        return Err(invalid("native runtime manifest identity changed"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if manifest.format_version != 1
        || manifest.qemu_version != "11.1.2"
        || manifest.architecture != architecture
        || manifest.files.len() > 128
    {
        return Err(invalid(
            "native runtime format, architecture or dependency bound differs",
        ));
    }
    let executable = format!(
        "sandsurf-qemu-{}{}",
        if architecture == GuestArchitecture::Arm64 {
            "arm64"
        } else {
            "x64"
        },
        if cfg!(windows) { ".exe" } else { "" }
    );
    let mut required = BTreeSet::from([executable.clone()]);
    if architecture == GuestArchitecture::Amd64 {
        for name in [
            "bios-256k.bin",
            "linuxboot_dma.bin",
            "kvmvapic.bin",
            "pvh.bin",
        ] {
            required.insert(format!("qemu-runtime/firmware/{name}"));
        }
    }
    if !required
        .iter()
        .all(|name| manifest.files.contains_key(name))
    {
        return Err(invalid(
            "native executable or firmware closure is incomplete",
        ));
    }
    let library = |name: &str| {
        let basename = if cfg!(windows) {
            Some(name)
        } else {
            name.strip_prefix("lib/")
        };
        basename.is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
                && if cfg!(windows) {
                    name.to_ascii_lowercase().ends_with(".dll")
                } else {
                    name.ends_with(".dylib")
                }
        })
    };
    if manifest
        .files
        .keys()
        .any(|name| !required.contains(name) && !library(name))
    {
        return Err(invalid("unknown native runtime input role"));
    }
    // OS loaders search directories, not our manifest. Reject undeclared
    // libraries and firmware before launch, including case aliases on Windows.
    let declared: BTreeSet<_> = manifest.files.keys().cloned().collect();
    if architecture == GuestArchitecture::Amd64 {
        directory_inputs(root, "qemu-runtime/firmware", &declared, false)?;
    }
    if cfg!(windows) {
        directory_inputs(root, "", &declared, true)?;
    } else {
        directory_inputs(root, "lib", &declared, false)?;
    }
    let mut inputs = vec![file];
    let mut read_paths = Vec::new();
    let mut total = 0_u64;
    for (relative, digest) in manifest.files {
        let path = root.join(relative);
        let mut input = open(&path)?;
        let length = input.metadata()?.len();
        total = total
            .checked_add(length)
            .ok_or_else(|| invalid("runtime size overflow"))?;
        if length == 0 || length > 512 * 1024 * 1024 || total > 1024 * 1024 * 1024 {
            return Err(invalid("native runtime exceeds its byte envelope"));
        }
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 65536];
        let mut read = 0_u64;
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read += count as u64;
            if read > length {
                return Err(invalid("native runtime input grew"));
            }
            hash.update(&buffer[..count]);
        }
        if read != length || format!("{:x}", hash.finalize()) != digest.as_str() {
            return Err(invalid("native runtime input changed"));
        }
        inputs.push(input);
        read_paths.push(path);
    }
    Ok(Runtime {
        executable: root.join(executable),
        firmware_directory: if architecture == GuestArchitecture::Amd64 {
            root.join("qemu-runtime/firmware")
        } else {
            // ARM virt direct kernel boot has no ROM inputs. Disable host-wide
            // firmware search with the existing, sealed runtime directory.
            root.to_owned()
        },
        _inputs: inputs,
        read_paths,
    })
}

fn directory_inputs(
    root: &Path,
    relative: &str,
    declared: &BTreeSet<String>,
    only_libraries: bool,
) -> io::Result<()> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("runtime load directory is an alias"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(invalid("runtime load directory is a reparse alias"));
        }
    }
    let mut names = BTreeSet::new();
    let mut count = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        count += 1;
        if count > 256 {
            return Err(invalid("runtime load directory exceeds its entry bound"));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("runtime input name is not UTF-8"))?;
        if only_libraries && !name.to_ascii_lowercase().ends_with(".dll") {
            continue;
        }
        let key = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        if !declared.contains(&key) || !names.insert(name.to_ascii_lowercase()) {
            return Err(invalid("unverified or case-aliased runtime load input"));
        }
        // Checking the entry itself also rejects links to otherwise declared
        // inputs. The opened input leases below provide the file identities.
        let kind = entry.file_type()?;
        if !kind.is_file() || kind.is_symlink() {
            return Err(invalid("runtime load input is not an independent file"));
        }
    }
    Ok(())
}

fn open(path: &Path) -> io::Result<File> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(invalid("native input is not a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
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
    let file = options.open(path)?;
    let after = file.metadata()?;
    if !after.is_file() {
        return Err(invalid("native input type changed"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() || after.nlink() != 1 {
            return Err(invalid("native input file identity is aliased"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            if metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || metadata.file_type().is_symlink()
            {
                return Err(invalid(
                    "installed native runtime is not root-owned and immutable",
                ));
            }
            sandsurf_native::macos::require_protected_ancestor_acl(ancestor)?;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if after.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(invalid("native input is a reparse alias"));
        }
    }
    Ok(file)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "sandsurf-runtime-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::create_dir_all(root.join("qemu-runtime/firmware")).unwrap();
            fs::create_dir(root.join("lib")).unwrap();
            Self(root)
        }
        fn manifest(&self, extra: &[&str]) -> (PathBuf, Digest) {
            let executable = if cfg!(windows) {
                "sandsurf-qemu-x64.exe"
            } else {
                "sandsurf-qemu-x64"
            };
            let mut files = BTreeMap::new();
            for name in [
                executable,
                "qemu-runtime/firmware/bios-256k.bin",
                "qemu-runtime/firmware/linuxboot_dma.bin",
                "qemu-runtime/firmware/kvmvapic.bin",
                "qemu-runtime/firmware/pvh.bin",
            ]
            .into_iter()
            .chain(extra.iter().copied())
            {
                fs::write(self.0.join(name), name.as_bytes()).unwrap();
                files.insert(name, sandsurf_protocol::bytes_digest(name.as_bytes()));
            }
            let bytes = serde_json::to_vec(&json!({"formatVersion":1,"architecture":"amd64",
                "qemuVersion":"11.1.2","files":files}))
            .unwrap();
            let path = self.0.join("qemu-runtime.json");
            fs::write(&path, &bytes).unwrap();
            (path, sandsurf_protocol::bytes_digest(&bytes))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn complete_runtime_is_bound_to_its_manifest_and_every_input() {
        let fixture = Fixture::new();
        let library = if cfg!(windows) {
            "glib-2.0.dll"
        } else {
            "lib/libglib-2.0.dylib"
        };
        let (path, digest) = fixture.manifest(&[library]);
        assert!(verify(&path, &digest, GuestArchitecture::Amd64).is_ok());
        assert!(verify(&path, &digest, GuestArchitecture::Arm64).is_err());
        fs::write(fixture.0.join(library), b"changed library").unwrap();
        assert!(verify(&path, &digest, GuestArchitecture::Amd64).is_err());
    }
    #[test]
    fn loader_search_cannot_add_unverified_inputs() {
        let fixture = Fixture::new();
        let (path, digest) = fixture.manifest(&[]);
        let unknown = if cfg!(windows) {
            "KERNEL32.dll"
        } else {
            "lib/libunknown.dylib"
        };
        fs::write(fixture.0.join(unknown), b"not part of runtime").unwrap();
        assert!(verify(&path, &digest, GuestArchitecture::Amd64).is_err());
    }
    #[test]
    fn firmware_closure_cannot_be_missing_or_expanded() {
        let fixture = Fixture::new();
        let (path, digest) = fixture.manifest(&[]);
        fs::write(
            fixture.0.join("qemu-runtime/firmware/option.rom"),
            b"unverified",
        )
        .unwrap();
        assert!(verify(&path, &digest, GuestArchitecture::Amd64).is_err());
        fs::remove_file(fixture.0.join("qemu-runtime/firmware/option.rom")).unwrap();
        fs::remove_file(fixture.0.join("qemu-runtime/firmware/bios-256k.bin")).unwrap();
        assert!(verify(&path, &digest, GuestArchitecture::Amd64).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn runtime_files_cannot_be_shared_aliases() {
        let fixture = Fixture::new();
        let (path, digest) = fixture.manifest(&[]);
        fs::hard_link(fixture.0.join("sandsurf-qemu-x64"), fixture.0.join("alias")).unwrap();
        assert!(verify(&path, &digest, GuestArchitecture::Amd64).is_err());
    }
}
