//! File and socket footprint of an original Darwin VMM. This is host-supplied
//! native confinement, not guest authority. No guest pathname becomes a grant.
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

pub struct Files {
    /// Individually verified executable, libraries, firmware and boot inputs.
    /// Never the runtime directory, guardian directory, or image directory.
    pub read_only: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
    pub endpoints: PathBuf,
    pub captures: Option<PathBuf>,
}

impl Files {
    pub fn profile(&self) -> io::Result<String> {
        if self.read_only.is_empty() || self.read_only.len() > 144 {
            return Err(invalid("VMM input closure exceeds its bound"));
        }
        if self.writable.len() > 1 {
            return Err(invalid("VMM mutable disk closure exceeds its bound"));
        }
        let disks = self
            .writable
            .iter()
            .map(|path| canonical_file(path))
            .collect::<io::Result<BTreeSet<_>>>()?;
        let endpoints = crate::local::canonical_private_directory(&self.endpoints)?;
        let captures = self
            .captures
            .as_ref()
            .map(|path| crate::local::canonical_private_directory(path))
            .transpose()?;
        if captures.as_ref().is_some_and(|captures| {
            endpoints.starts_with(captures) || captures.starts_with(&endpoints)
        }) || disks.iter().any(|disk| {
            disk.starts_with(&endpoints)
                || captures
                    .as_ref()
                    .is_some_and(|captures| disk.starts_with(captures))
        }) {
            return Err(invalid("VMM input and output roles overlap"));
        }
        let mut inputs = BTreeSet::new();
        for input in &self.read_only {
            let input = canonical_file(input)?;
            if disks.contains(&input)
                || input.starts_with(&endpoints)
                || captures
                    .as_ref()
                    .is_some_and(|captures| input.starts_with(captures))
            {
                return Err(invalid("VMM read input overlaps a mutable role"));
            }
            inputs.insert(input);
        }
        // OS frameworks/shared cache are the platform TCB. Non-system QEMU
        // libraries are admitted individually below, never by a search root.
        // Metadata permits path traversal, not reading host document bytes.
        let mut profile = String::from(
            "(version 1)\n(allow default)\n\
             (deny process-fork)\n(deny process-exec)\n\
             (deny file-read*)\n(deny file-write*)\n(deny file-ioctl)\n\
             (allow file-read-metadata)\n\
             (allow file-read* (subpath \"/System/Library\") (subpath \"/usr/lib\")\n\
               (subpath \"/System/Volumes/Preboot/Cryptexes/OS/System/Library\")\n\
               (subpath \"/System/Volumes/Preboot/Cryptexes/OS/usr/lib\")\n\
               (subpath \"/usr/share/zoneinfo\")\n\
               (literal \"/dev/null\") (literal \"/dev/random\") (literal \"/dev/urandom\"))\n\
             (allow file-write-data (literal \"/dev/null\"))\n\
             (deny system-fcntl (fcntl-command 80 110))\n\
             (deny system-socket)\n(allow system-socket (socket-domain AF_UNIX))\n\
             (deny network*)\n",
        );
        for input in inputs {
            writeln!(profile, "(allow file-read* (literal {}))", quoted(&input)?).unwrap();
        }
        for disk in disks {
            writeln!(profile, "(allow file-read* (literal {}))", quoted(&disk)?).unwrap();
            writeln!(
                profile,
                "(allow file-write-data (literal {}))",
                quoted(&disk)?
            )
            .unwrap();
        }
        writeln!(
            profile,
            "(allow file-read* file-write* (subpath {}))",
            quoted(&endpoints)?
        )
        .unwrap();
        for operation in ["network-bind", "network-inbound"] {
            writeln!(
                profile,
                "(allow {operation} (local unix-socket (subpath {})))",
                quoted(&endpoints)?
            )
            .unwrap();
        }
        // QEMU serves device sockets. It has no reason to connect to host
        // services, even Unix ones. The already-open root-owner gate survives.
        writeln!(
            profile,
            "(deny file-write-unlink (literal {}))",
            quoted(&endpoints)?
        )
        .unwrap();
        // Only native state bytes may be written in future capture directories.
        // In particular capture.json, reconnect.json and boot/auth are NOT
        // writable by the VMM. The host creates each operation directory.
        // Keep caller path bytes in a literal filter, not the kernel regex
        // language. Express the bounded address explicitly rather than relying
        // on counted repetition or pathname regexp escaping in Seatbelt.
        if let Some(captures) = &captures {
            let pattern = format!("/id-{}/snapshot[.]vmstate$", "[0-9a-f]".repeat(64));
            writeln!(
                profile,
                "(allow file-read* file-write* (require-all (subpath {}) (regex {})))",
                quoted(captures)?,
                string_literal(&pattern)
            )
            .unwrap();
        }
        if profile.len() > crate::resource_broker::VMM_PROFILE_BYTES {
            return Err(invalid("VMM confinement profile exceeds its byte bound"));
        }
        Ok(profile)
    }
}

fn canonical_file(path: &Path) -> io::Result<PathBuf> {
    text(path)?;
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(invalid("VMM input is not an independent file"));
    }
    let canonical = std::fs::canonicalize(path)?;
    text(&canonical)?;
    Ok(canonical)
}
fn text(path: &Path) -> io::Result<&str> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("VMM path is not UTF-8"))?;
    if !path.is_absolute() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(invalid("VMM path must be bounded and absolute"));
    }
    Ok(value)
}
fn quoted(path: &Path) -> io::Result<String> {
    Ok(string_literal(text(path)?))
}
fn string_literal(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closure_is_explicit_and_paths_cannot_inject_policy_or_capture_patterns() {
        let root =
            std::env::temp_dir().join(format!("sandsurf-footprint-{}-\"(x)\\", std::process::id()));
        crate::local::create_private_directory(&root).unwrap();
        // macOS's temporary root commonly traverses /var -> /private/var.
        // The policy deliberately binds the canonical input, not that alias.
        let root = std::fs::canonicalize(root).unwrap();
        let disk = root.join("disk");
        let kernel = root.join("kernel");
        for path in [&disk, &kernel] {
            drop(crate::local::create_private_file(path).unwrap());
        }
        let endpoints = root.join("endpoints");
        let captures = root.join("captures");
        crate::local::create_private_directory(&endpoints).unwrap();
        crate::local::create_private_directory(&captures).unwrap();
        let mut files = Files {
            read_only: vec![kernel.clone()],
            writable: vec![disk.clone()],
            endpoints: endpoints.clone(),
            captures: Some(captures.clone()),
        };
        let profile = files.profile().unwrap();
        assert!(profile.contains("(deny network*)"));
        assert!(!profile.contains("allow network-outbound"));
        assert!(profile.contains(&format!(
            "/id-{}/snapshot[.]vmstate$",
            "[0-9a-f]".repeat(64)
        )));
        assert!(profile.contains(&quoted(&kernel).unwrap()));
        assert!(profile.contains(&format!(
            "(require-all (subpath {})",
            quoted(&captures).unwrap()
        )));
        assert!(!profile.contains("capture.json"));
        files.captures = None;
        assert!(!files.profile().unwrap().contains("snapshot[.]vmstate"));
        files.captures = Some(captures.clone());
        assert_eq!(string_literal("\"\\"), "\"\\\"\\\\\"");
        files.read_only.push(disk.clone());
        assert!(files.profile().is_err());
        files.read_only = vec![kernel.clone()];
        files.endpoints = captures.clone();
        assert!(files.profile().is_err());
        files.endpoints = endpoints.clone();
        files.read_only = vec![kernel.clone(); 145];
        assert!(files.profile().is_err());
        for path in [disk, kernel] {
            std::fs::remove_file(path).unwrap();
        }
        for path in [endpoints, captures, root] {
            std::fs::remove_dir(path).unwrap();
        }
    }
}
