use crate::appliance::{self, Operation};
use crate::{Architecture, ImageArtifact};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const MAX_KERNEL: u64 = 128 * 1024 * 1024;
pub const MAX_INITRAMFS: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BootProfile {
    /// Custom image contract: updates do not change its explicitly pinned boot.
    Pinned,
    /// Alpine package commit hook atomically selects /boot/sandsurf.json.
    Alpine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootSelection {
    pub architecture: Architecture,
    pub kernel: String,
    pub initramfs: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenBoot {
    pub architecture: Architecture,
    pub kernel: ImageArtifact,
    pub initramfs: Option<ImageArtifact>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn validate_selection(value: &BootSelection, architecture: Architecture) -> io::Result<()> {
    if value.architecture != architecture {
        return Err(invalid("boot architecture mismatch"));
    }
    for path in std::iter::once(&value.kernel).chain(value.initramfs.iter()) {
        if !path.starts_with("/boot/")
            || path.len() > 256
            || path[6..].is_empty()
            || path[6..].split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return Err(invalid(
                "boot selection must name canonical files under /boot",
            ));
        }
    }
    Ok(())
}

/// Caller holds disk custody or uses an immutable captured copy. No guest
/// programs execute during extraction; no pristine fallback on any error.
pub fn extract(
    disk: &Path,
    directory: &Path,
    architecture: Architecture,
) -> io::Result<FrozenBoot> {
    let selection_path = directory.join("selection.json");
    appliance::download(disk, "/boot/sandsurf.json", &selection_path, 4096)?;
    let selection: BootSelection = serde_json::from_slice(&fs::read(&selection_path)?)
        .map_err(|_| invalid("corrupt /boot/sandsurf.json"))?;
    validate_selection(&selection, architecture)?;
    // realpath is interpreted only inside the appliance. Reject symlink escapes
    // from /boot even though those could never reach the host filesystem.
    for path in std::iter::once(&selection.kernel).chain(selection.initramfs.iter()) {
        let resolved = appliance::run(
            disk,
            false,
            &[
                Operation::Mount { writable: false },
                Operation::Realpath { path: path.clone() },
            ],
        )?
        .text()?;
        let resolved = resolved.trim();
        let check = BootSelection {
            architecture,
            kernel: resolved.into(),
            initramfs: None,
        };
        validate_selection(&check, architecture)?;
    }
    let kernel = directory.join("kernel");
    appliance::download(disk, &selection.kernel, &kernel, MAX_KERNEL)?;
    validate_kernel(&kernel, architecture)?;
    let initramfs = if let Some(path) = &selection.initramfs {
        let output = directory.join("initramfs");
        appliance::download(disk, path, &output, MAX_INITRAMFS)?;
        validate_initramfs(&output)?;
        Some(artifact(&output, "initramfs", MAX_INITRAMFS)?)
    } else {
        None
    };
    let frozen = FrozenBoot {
        architecture,
        kernel: artifact(&kernel, "kernel", MAX_KERNEL)?,
        initramfs,
    };
    for path in [
        Some(kernel),
        frozen
            .initramfs
            .as_ref()
            .map(|_| directory.join("initramfs")),
    ]
    .into_iter()
    .flatten()
    {
        fs::File::open(&path)?.sync_all()?;
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_readonly(true);
            fs::set_permissions(path, permissions)?;
        }
    }
    Ok(frozen)
}

pub fn artifact(path: &Path, name: &str, bound: u64) -> io::Result<ImageArtifact> {
    let file = sandsurf_native::local::open_private_file(
        path,
        sandsurf_native::PrivateFileAccess::ReadOnly,
    )?;
    if file.metadata()?.len() == 0 || file.metadata()?.len() > bound {
        return Err(invalid("boot artifact bound"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut input = file.take(bound + 1);
    let mut total = 0;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hash.update(&buffer[..n]);
    }
    if total > bound {
        return Err(invalid("boot artifact grew"));
    }
    Ok(ImageArtifact {
        path: name.into(),
        sha256: format!("{:x}", hash.finalize()),
    })
}

pub fn verify(directory: &Path, boot: &FrozenBoot) -> io::Result<()> {
    for (value, name, bound) in std::iter::once((&boot.kernel, "kernel", MAX_KERNEL)).chain(
        boot.initramfs
            .iter()
            .map(|value| (value, "initramfs", MAX_INITRAMFS)),
    ) {
        if value.path != name || artifact(&directory.join(name), name, bound)? != *value {
            return Err(invalid("frozen boot artifact identity changed"));
        }
    }
    if let Some(value) = &boot.initramfs {
        validate_initramfs(&directory.join(&value.path))?;
    }
    validate_kernel(&directory.join("kernel"), boot.architecture).map(|_| ())
}

pub fn validate_initramfs(path: &Path) -> io::Result<()> {
    let mut magic = [0; 6];
    fs::File::open(path)?.read_exact(&mut magic)?;
    if &magic != b"070701"
        && &magic != b"070702"
        && magic[..2] != [0x1f, 0x8b]
        && magic != [0xfd, b'7', b'z', b'X', b'Z', 0]
        && magic[..4] != [0x28, 0xb5, 0x2f, 0xfd]
    {
        return Err(invalid("unsupported initramfs format"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFormat {
    Elf { pvh_entry: Option<u32> },
    LinuxBoot,
    ArmImage,
}

impl KernelFormat {
    pub fn require_qemu(self) -> io::Result<()> {
        if matches!(self, Self::Elf { pvh_entry: None }) {
            Err(invalid(
                "QEMU x86 direct boot requires a physical PVH ELF entry",
            ))
        } else {
            Ok(())
        }
    }
}

pub fn validate_kernel(path: &Path, architecture: Architecture) -> io::Result<KernelFormat> {
    let mut file = fs::File::open(path)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_KERNEL {
        return Err(invalid("kernel byte bound"));
    }
    let mut header = [0; 4096];
    let count = file.read(&mut header)?;
    let h = &header[..count];
    let elf = architecture == Architecture::X64
        && h.len() >= 64
        && &h[..4] == b"\x7fELF"
        && h[4] == 2
        && h[5] == 1
        && h[6] == 1
        && u16::from_le_bytes([h[18], h[19]]) == 62
        && u16::from_le_bytes([h[16], h[17]]) == 2;
    let bz = architecture == Architecture::X64
        && h.len() >= 0x238
        && &h[0x202..0x206] == b"HdrS"
        && h[0x1fe..0x200] == [0x55, 0xaa]
        && h[0x236] & 1 != 0
        && u16::from_le_bytes([h[0x206], h[0x207]]) >= 0x020c;
    let arm = architecture == Architecture::Arm64
        && h.len() >= 64
        && &h[56..60] == b"ARM\x64"
        && &h[..2] == b"MZ"
        && u64::from_le_bytes(h[16..24].try_into().unwrap()) > 0
        && u64::from_le_bytes(h[16..24].try_into().unwrap()) <= length;
    if !elf && !bz && !arm {
        return Err(invalid("kernel format/architecture unsupported"));
    }
    if elf {
        let offset = u64::from_le_bytes(h[32..40].try_into().unwrap());
        let size = u16::from_le_bytes(h[54..56].try_into().unwrap());
        let segments = u16::from_le_bytes(h[56..58].try_into().unwrap());
        let entry = u64::from_le_bytes(h[24..32].try_into().unwrap());
        if size != 56
            || segments == 0
            || segments > 128
            || offset < 64
            || offset
                .checked_add(u64::from(segments) * 56)
                .is_none_or(|end| end > length)
        {
            return Err(invalid("malformed ELF program table"));
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut executable_entry = false;
        let mut physical_executable = Vec::new();
        let mut notes = Vec::new();
        let mut note_bytes = 0_u64;
        for _ in 0..segments {
            let mut segment = [0; 56];
            file.read_exact(&mut segment)?;
            let kind = u32::from_le_bytes(segment[..4].try_into().unwrap());
            if kind == 4 {
                let start = u64::from_le_bytes(segment[8..16].try_into().unwrap());
                let bytes = u64::from_le_bytes(segment[32..40].try_into().unwrap());
                let alignment = u64::from_le_bytes(segment[48..56].try_into().unwrap());
                note_bytes = note_bytes
                    .checked_add(bytes)
                    .filter(|bytes| *bytes <= 1024 * 1024)
                    .ok_or_else(|| invalid("ELF note byte envelope"))?;
                if !(alignment == 4 || alignment == 8)
                    || start.checked_add(bytes).is_none_or(|end| end > length)
                {
                    return Err(invalid("malformed ELF note segment"));
                }
                notes.push((start, bytes, alignment));
            }
            if kind != 1 {
                continue;
            }
            let file_offset = u64::from_le_bytes(segment[8..16].try_into().unwrap());
            let address = u64::from_le_bytes(segment[16..24].try_into().unwrap());
            let physical = u64::from_le_bytes(segment[24..32].try_into().unwrap());
            let bytes = u64::from_le_bytes(segment[32..40].try_into().unwrap());
            let memory = u64::from_le_bytes(segment[40..48].try_into().unwrap());
            if bytes > memory
                || memory > 1024 * 1024 * 1024
                || file_offset
                    .checked_add(bytes)
                    .is_none_or(|end| end > length)
                || physical
                    .checked_add(memory)
                    .is_none_or(|end| end > 4 * 1024 * 1024 * 1024)
                || address.checked_add(memory).is_none()
            {
                return Err(invalid("ELF load segment exceeds boot bounds"));
            }
            if u32::from_le_bytes(segment[4..8].try_into().unwrap()) & 1 != 0 {
                physical_executable.push((physical, physical + bytes));
            }
            executable_entry |= u32::from_le_bytes(segment[4..8].try_into().unwrap()) & 1 != 0
                && entry >= address
                && entry < address + memory;
        }
        if !executable_entry {
            return Err(invalid("ELF entry is outside executable load segments"));
        }
        let mut pvh_entry = None;
        for (offset, length, alignment) in notes {
            file.seek(SeekFrom::Start(offset))?;
            let mut bytes = vec![0; length as usize];
            file.read_exact(&mut bytes)?;
            let mut cursor = 0_usize;
            let aligned = |length: u32| -> io::Result<usize> {
                u64::from(length)
                    .checked_add(alignment - 1)
                    .map(|length| (length & !(alignment - 1)) as usize)
                    .ok_or_else(|| invalid("ELF note alignment overflow"))
            };
            while cursor < bytes.len() {
                let header = bytes
                    .get(cursor..cursor + 12)
                    .ok_or_else(|| invalid("truncated ELF note header"))?;
                let name_length = u32::from_le_bytes(header[..4].try_into().unwrap());
                let value_length = u32::from_le_bytes(header[4..8].try_into().unwrap());
                let kind = u32::from_le_bytes(header[8..12].try_into().unwrap());
                cursor += 12;
                let name_end = cursor
                    .checked_add(aligned(name_length)?)
                    .filter(|end| *end <= bytes.len())
                    .ok_or_else(|| invalid("ELF note name exceeds its segment"))?;
                let name = &bytes[cursor..cursor + name_length as usize];
                cursor = name_end;
                let value_end = cursor
                    .checked_add(aligned(value_length)?)
                    .filter(|end| *end <= bytes.len())
                    .ok_or_else(|| invalid("ELF note value exceeds its segment"))?;
                if name == b"Xen\0" && kind == 18 {
                    if value_length != 4 || pvh_entry.is_some() {
                        return Err(invalid("ambiguous or malformed physical PVH entry"));
                    }
                    let entry = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                    if entry == 0
                        || !physical_executable.iter().any(|(start, end)| {
                            u64::from(entry) >= *start && u64::from(entry) < *end
                        })
                    {
                        return Err(invalid("PVH entry is outside physical executable payload"));
                    }
                    pvh_entry = Some(entry);
                }
                cursor = value_end;
            }
        }
        return Ok(KernelFormat::Elf { pvh_entry });
    }
    Ok(if bz {
        KernelFormat::LinuxBoot
    } else {
        KernelFormat::ArmImage
    })
}

pub fn paths(directory: &Path, value: &FrozenBoot) -> (PathBuf, Option<PathBuf>) {
    (
        directory.join(&value.kernel.path),
        value.initramfs.as_ref().map(|v| directory.join(&v.path)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_formats_share_one_parser_but_obey_native_loader_contracts() {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "sandsurf-kernel-loader-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        sandsurf_native::local::create_private_directory(&directory).unwrap();
        let path = directory.join("kernel");
        let mut elf = [0_u8; 512];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[24..32].copy_from_slice(&0x100100u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&2u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[80..88].copy_from_slice(&0x100000u64.to_le_bytes());
        elf[88..96].copy_from_slice(&0x100000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&512u64.to_le_bytes());
        elf[104..112].copy_from_slice(&512u64.to_le_bytes());
        elf[120..124].copy_from_slice(&4u32.to_le_bytes());
        elf[128..136].copy_from_slice(&256u64.to_le_bytes());
        elf[152..160].copy_from_slice(&20u64.to_le_bytes());
        elf[168..176].copy_from_slice(&4u64.to_le_bytes());
        elf[256..260].copy_from_slice(&4u32.to_le_bytes());
        elf[260..264].copy_from_slice(&4u32.to_le_bytes());
        elf[264..268].copy_from_slice(&18u32.to_le_bytes());
        elf[268..272].copy_from_slice(b"Xen\0");
        elf[272..276].copy_from_slice(&0x100100u32.to_le_bytes());
        fs::write(&path, elf).unwrap();
        let format = validate_kernel(&path, Architecture::X64).unwrap();
        assert_eq!(
            format,
            KernelFormat::Elf {
                pvh_entry: Some(0x100100)
            }
        );
        assert!(format.require_qemu().is_ok());
        let mut no_pvh = elf;
        no_pvh[264..268].copy_from_slice(&0u32.to_le_bytes());
        fs::write(&path, no_pvh).unwrap();
        let format = validate_kernel(&path, Architecture::X64).unwrap();
        assert_eq!(format, KernelFormat::Elf { pvh_entry: None });
        assert!(format.require_qemu().is_err());
        for corruption in [0, 1, 2, 3] {
            let mut invalid = elf;
            match corruption {
                0 => invalid[272..276].copy_from_slice(&u32::MAX.to_le_bytes()),
                1 => invalid[260..264].copy_from_slice(&8u32.to_le_bytes()),
                2 => invalid[152..160].copy_from_slice(&u64::MAX.to_le_bytes()),
                _ => {
                    invalid[56..58].copy_from_slice(&3u16.to_le_bytes());
                    invalid[176..232].copy_from_slice(&elf[120..176]);
                }
            }
            fs::write(&path, invalid).unwrap();
            assert!(validate_kernel(&path, Architecture::X64).is_err());
        }
        let mut linux = [0; 4096];
        linux[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        linux[0x202..0x206].copy_from_slice(b"HdrS");
        linux[0x206..0x208].copy_from_slice(&0x020cu16.to_le_bytes());
        linux[0x236] = 1;
        fs::write(&path, linux).unwrap();
        assert_eq!(
            validate_kernel(&path, Architecture::X64).unwrap(),
            KernelFormat::LinuxBoot
        );
        linux[0x206..0x208].copy_from_slice(&0x020bu16.to_le_bytes());
        fs::write(&path, linux).unwrap();
        assert!(validate_kernel(&path, Architecture::X64).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn boot_selection_rejects_host_paths_traversal_commands_and_wrong_architecture() {
        for path in [
            "/etc/passwd",
            "/boot/../etc/passwd",
            "/boot//kernel",
            "/boot/k\n!id",
            "/boot/$(id)",
            "/boot/",
        ] {
            assert!(
                validate_selection(
                    &BootSelection {
                        architecture: Architecture::X64,
                        kernel: path.into(),
                        initramfs: None
                    },
                    Architecture::X64
                )
                .is_err()
            );
        }
        let value = BootSelection {
            architecture: Architecture::Arm64,
            kernel: "/boot/vmlinuz-lts".into(),
            initramfs: Some("/boot/initramfs-lts".into()),
        };
        assert!(validate_selection(&value, Architecture::Arm64).is_ok());
        assert!(validate_selection(&value, Architecture::X64).is_err());
        assert!(serde_json::from_slice::<BootSelection>(br#"{"updateIncomplete":true}"#).is_err());
        assert!(serde_json::from_slice::<BootSelection>(br#"{"architecture":"x64","kernel":"/boot/kernel","initramfs":null,"hostPath":"/etc/passwd"}"#).is_err());
    }

    #[test]
    fn malformed_program_tables_and_truncated_initramfs_fail_before_native_loading() {
        use std::io::Write;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "sandsurf-boot-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        sandsurf_native::local::create_private_directory(&directory).unwrap();
        let kernel = directory.join("kernel");
        let mut malformed = [0; 64];
        malformed[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        malformed[16..18].copy_from_slice(&2u16.to_le_bytes());
        malformed[18..20].copy_from_slice(&62u16.to_le_bytes());
        malformed[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        malformed[54..56].copy_from_slice(&56u16.to_le_bytes());
        malformed[56..58].copy_from_slice(&1u16.to_le_bytes());
        sandsurf_native::local::create_private_file(&kernel)
            .unwrap()
            .write_all(&malformed)
            .unwrap();
        assert!(validate_kernel(&kernel, Architecture::X64).is_err());
        assert!(validate_kernel(&kernel, Architecture::Arm64).is_err());
        let initramfs = directory.join("initramfs");
        sandsurf_native::local::create_private_file(&initramfs)
            .unwrap()
            .write_all(&[0x1f, 0x8b])
            .unwrap();
        assert!(validate_initramfs(&initramfs).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
