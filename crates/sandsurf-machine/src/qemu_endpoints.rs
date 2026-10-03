//! Transient native attachment names belong to one original QEMU owner, not
//! durable machine configuration. No later boot may adopt this namespace.
#[cfg(any(target_os = "macos", windows, test))]
use std::fs;
use std::io;
use std::path::Path;

const MAX_PATH: usize = 103;
pub(crate) const QMP: &str = "qmp.sock";
pub(crate) const NIC: &str = "nic.sock";
pub(crate) const CONSOLE: &str = "console.sock";
fn names() -> impl Iterator<Item = String> {
    [QMP, NIC, CONSOLE].into_iter().map(str::to_owned).chain(
        (0..sandsurf_protocol::GUEST_SERIAL_CONNECTIONS).map(|slot| {
            sandsurf_native::serial_channel::socket_name(slot).expect("fixed serial slot")
        }),
    )
}

pub(crate) fn validate(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || names().any(|name| path.join(name).as_os_str().as_encoded_bytes().len() > MAX_PATH)
    {
        return Err(invalid(
            "private QEMU endpoints exceed native socket path bounds",
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", windows, test))]
pub(crate) struct Endpoints {
    directory: Option<sandsurf_native::socket_io::SocketNamespace>,
}

#[cfg(any(target_os = "macos", windows, test))]
impl Endpoints {
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn create() -> io::Result<Self> {
        // macOS's per-user TMPDIR is normally too long for native device names.
        // The sticky system directory is an ancestry, never an adopted owner.
        #[cfg(target_os = "macos")]
        let parent = Path::new("/private/tmp").to_owned();
        #[cfg(not(target_os = "macos"))]
        let parent = std::env::temp_dir();
        Self::under(&parent)
    }

    #[cfg(any(target_os = "macos", test))]
    fn under(parent: &Path) -> io::Result<Self> {
        let parent = fs::canonicalize(parent)?;
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
        let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = parent.join(format!("ssq-{name}"));
        validate(&path)?;
        // Exclusive creation, not ensure/adoption, even on a nonce collision.
        sandsurf_native::local::create_private_directory(&path)?;
        Ok(Self {
            directory: Some(sandsurf_native::socket_io::SocketNamespace::private(
                &sandsurf_native::local::canonical_private_directory(&path)?,
            )?),
        })
    }

    #[cfg(windows)]
    pub(crate) fn for_vmm(
        namespace: sandsurf_native::socket_io::SocketNamespace,
    ) -> io::Result<Self> {
        validate(namespace.path())?;
        namespace.check()?;
        Ok(Self {
            directory: Some(namespace),
        })
    }

    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn namespace(&self) -> sandsurf_native::socket_io::SocketNamespace {
        self.directory
            .as_ref()
            .expect("live native namespace")
            .clone()
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory
            .as_ref()
            .expect("live endpoint namespace")
            .path()
    }

    /// Only after the original native child has confirmed exit. Unknown files
    /// or changed namespaces are retained; this never scans another boot.
    pub(crate) fn remove_after_exit(&mut self) -> io::Result<()> {
        self.check()?;
        let names: Vec<_> = names().collect();
        let entries: Vec<_> = fs::read_dir(self.path())?
            .take(names.len() + 1)
            .collect::<io::Result<_>>()?;
        if entries.len() > names.len()
            || entries.iter().any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_none_or(|name| !names.iter().any(|expected| expected == name))
            })
        {
            return Err(invalid(
                "native endpoint namespace contains an unowned name",
            ));
        }
        for entry in &entries {
            let kind = entry.file_type()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if !kind.is_socket() {
                    return Err(invalid("native endpoint is not a socket"));
                }
            }
            // Windows AF_UNIX names are kernel reparse files, not directories.
            #[cfg(windows)]
            {
                if kind.is_dir() {
                    return Err(invalid("native endpoint is a directory"));
                }
                sandsurf_native::socket_io::verify_windows_socket_name(&entry.path())?;
            }
        }
        for entry in entries {
            self.check()?;
            fs::remove_file(entry.path())?;
        }
        self.check()?;
        let path = self.path().to_owned();
        // Windows's retained private handle deliberately denies replacement.
        // Release it only after native exit and all admitted socket removals.
        self.directory.as_ref().expect("live namespace").close()?;
        self.directory.take();
        fs::remove_dir(path)
    }

    fn check(&self) -> io::Result<()> {
        self.directory
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .check()
    }
}

#[cfg(any(target_os = "macos", windows, test))]
impl Drop for Endpoints {
    fn drop(&mut self) {
        // Covers pre-launch failure only. Nonempty names need explicit native
        // exit evidence; an unavailable broker receipt cannot authorize loss.
        if let Some(directory) = self.directory.take()
            && directory.check().is_ok()
        {
            let path = directory.path().to_owned();
            let _ = directory.close();
            let _ = fs::remove_dir(path);
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_names_are_fresh_private_and_never_persisted_or_adopted() {
        let first = Endpoints::create().unwrap();
        let second = Endpoints::create().unwrap();
        assert_ne!(first.path(), second.path());
        assert_eq!(
            sandsurf_native::local::canonical_private_directory(first.path()).unwrap(),
            first.path()
        );
        validate(first.path()).unwrap();
        let path = first.path().to_owned();
        drop(first);
        assert!(!path.exists(), "unused namespace was retained");
    }
    #[test]
    fn unowned_files_and_replacements_are_preserved() {
        let mut original = Endpoints::create().unwrap();
        let path = original.path().to_owned();
        fs::write(path.join("unexpected"), b"keep").unwrap();
        assert!(original.remove_after_exit().is_err());
        drop(original);
        assert_eq!(fs::read(path.join("unexpected")).unwrap(), b"keep");
        fs::remove_file(path.join("unexpected")).unwrap();
        fs::remove_dir(&path).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn replacement_namespace_never_becomes_the_original_owner() {
        let mut original = Endpoints::create().unwrap();
        let path = original.path().to_owned();
        let held = path.with_extension("held");
        fs::rename(&path, &held).unwrap();
        sandsurf_native::local::create_private_directory(&path).unwrap();
        assert!(original.remove_after_exit().is_err());
        drop(original);
        assert!(path.exists());
        fs::remove_dir(path).unwrap();
        fs::remove_dir(held).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn held_private_namespace_fences_windows_replacement() {
        let mut original = Endpoints::create().unwrap();
        let path = original.path().to_owned();
        assert!(fs::rename(&path, path.with_extension("replacement")).is_err());
        original.remove_after_exit().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn long_ancestry_fails_before_creating_an_endpoint() {
        let root = Endpoints::create().unwrap();
        let long = root.path().join("x".repeat(104));
        fs::create_dir(&long).unwrap();
        assert!(Endpoints::under(&long).is_err());
        assert_eq!(fs::read_dir(&long).unwrap().count(), 0);
        fs::remove_dir(long).unwrap();
    }
    #[test]
    fn confirmed_native_exit_reclaims_only_socket_names() {
        let mut root = Endpoints::create().unwrap();
        let path = root.path().to_owned();
        for name in names() {
            let socket =
                socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
            socket
                .bind(&socket2::SockAddr::unix(path.join(name)).unwrap())
                .unwrap();
            drop(socket);
        }
        root.remove_after_exit().unwrap();
        assert!(!path.exists());
        let mut root = Endpoints::create().unwrap();
        let path = root.path().to_owned();
        fs::write(path.join("qmp.sock"), b"not a socket").unwrap();
        assert!(root.remove_after_exit().is_err());
        drop(root);
        assert!(path.join("qmp.sock").exists());
        fs::remove_file(path.join("qmp.sock")).unwrap();
        fs::remove_dir(path).unwrap();
    }
}
