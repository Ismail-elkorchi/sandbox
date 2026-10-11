//! Transient native attachment names belong to one original QEMU owner, not
//! durable machine configuration. No later boot may adopt this namespace.
#[cfg(any(target_os = "macos", windows, test))]
use std::fs;
use std::io;
use std::path::Path;
#[cfg(all(unix, any(target_os = "macos", test)))]
use {sandsurf_native::socket_io::NAMESPACE_LEASE, std::fs::File, std::sync::Arc};

#[cfg(all(unix, any(target_os = "macos", test)))]
const POOL_LOCK: &str = ".creation.lock";
#[cfg(all(unix, any(target_os = "macos", test)))]
const MAX_NAMESPACES: usize = 256;

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
    #[cfg(unix)]
    pool: Arc<sandsurf_native::local::Directory>,
    #[cfg(unix)]
    lease: Arc<File>,
    #[cfg(unix)]
    handed_off: bool,
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
        #[cfg(unix)]
        // SAFETY: scalar identity query; no pointers or credential changes.
        let parent = parent.join(format!("ssq-{}", unsafe { libc::geteuid() }));
        Self::under(&parent)
    }

    #[cfg(any(target_os = "macos", test))]
    fn under(parent: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            // Check the complete socket length before publishing pool metadata.
            validate(&parent.join(format!("ssq-{}", "0".repeat(32))))?;
            sandsurf_native::local::ensure_private_directory(parent)?;
        }
        let parent = fs::canonicalize(parent)?;
        #[cfg(unix)]
        let pool = Arc::new(sandsurf_native::local::Directory::open(&parent)?);
        #[cfg(unix)]
        let _writer = pool_writer(&pool)?;
        #[cfg(unix)]
        Self::reclaim(&pool)?;
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
        let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = parent.join(format!("ssq-{name}"));
        validate(&path)?;
        // Exclusive creation, not ensure/adoption, even on a nonce collision.
        sandsurf_native::local::create_private_directory(&path)?;
        #[cfg(unix)]
        let lease = Arc::new(sandsurf_native::storage::disk_lease(
            &path.join(NAMESPACE_LEASE),
        )?);
        Ok(Self {
            directory: Some(sandsurf_native::socket_io::SocketNamespace::private(
                &sandsurf_native::local::canonical_private_directory(&path)?,
            )?),
            #[cfg(unix)]
            pool,
            #[cfg(unix)]
            lease,
            #[cfg(unix)]
            handed_off: false,
        })
    }

    #[cfg(all(unix, any(target_os = "macos", test)))]
    fn reclaim(pool: &Arc<sandsurf_native::local::Directory>) -> io::Result<()> {
        pool.check()?;
        let entries = fs::read_dir(pool.path())?
            .take(MAX_NAMESPACES + 2)
            .collect::<io::Result<Vec<_>>>()?;
        if entries.len() > MAX_NAMESPACES + 1 {
            return Err(invalid("native endpoint pool exceeds its namespace bound"));
        }
        let mut live = 0;
        for entry in entries {
            if entry.file_name() == POOL_LOCK {
                continue;
            }
            let name = entry.file_name();
            let nonce = name.to_str().and_then(|name| name.strip_prefix("ssq-"));
            if nonce.is_none_or(|nonce| {
                nonce.len() != 32
                    || !nonce
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                return Err(invalid("native endpoint pool contains an unowned name"));
            }
            let directory = sandsurf_native::socket_io::SocketNamespace::private(&entry.path())?;
            let lease = match sandsurf_native::local::open_private_file(
                &entry.path().join(NAMESPACE_LEASE),
                sandsurf_native::PrivateFileAccess::ReadWrite,
            ) {
                Ok(lease) => lease,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // Creation/removal holds the same pool writer. A missing
                    // marker authorizes only removal of a still-empty directory.
                    directory.check()?;
                    directory.close()?;
                    fs::remove_dir(entry.path())?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match lease.try_lock() {
                Ok(()) => {}
                Err(fs::TryLockError::WouldBlock) => {
                    live += 1;
                    continue;
                }
                Err(fs::TryLockError::Error(error)) => return Err(error),
            }
            // All original custody descriptions are gone. No PID, socket
            // response or guest report can substitute for this exclusion.
            let mut orphan = Self {
                directory: Some(directory),
                pool: pool.clone(),
                lease: Arc::new(lease),
                handed_off: true,
            };
            orphan.remove_locked()?;
        }
        if live == MAX_NAMESPACES {
            return Err(invalid("native endpoint pool is full"));
        }
        pool.check()
    }

    #[cfg(all(unix, any(target_os = "macos", test)))]
    pub(crate) fn custody(&mut self) -> Arc<File> {
        self.handed_off = true;
        self.lease.clone()
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
    /// or changed namespaces are retained; this never adopts another boot.
    pub(crate) fn remove_after_exit(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        let _writer = pool_writer(&self.pool)?;
        self.remove_locked()
    }

    fn remove_locked(&mut self) -> io::Result<()> {
        self.check()?;
        #[cfg(unix)]
        {
            sandsurf_native::storage::verify_transferred_lease(
                &self.lease,
                &self.path().join(NAMESPACE_LEASE),
            )?;
            if self.lease.metadata()?.len() != 0 {
                return Err(invalid("native endpoint custody contains unowned bytes"));
            }
        }
        let names: Vec<_> = names()
            .chain({
                #[cfg(unix)]
                {
                    Some(NAMESPACE_LEASE.to_owned())
                }
                #[cfg(windows)]
                {
                    None
                }
            })
            .collect();
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
                if entry.file_name() == NAMESPACE_LEASE {
                    continue;
                }
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
            #[cfg(unix)]
            if entry.file_name() == NAMESPACE_LEASE {
                continue;
            }
            self.check()?;
            fs::remove_file(entry.path())?;
        }
        self.check()?;
        #[cfg(unix)]
        {
            let path = self.path().join(NAMESPACE_LEASE);
            sandsurf_native::storage::verify_transferred_lease(&self.lease, &path)?;
            fs::remove_file(path)?;
        }
        let path = self.path().to_owned();
        // Windows's retained private handle deliberately denies replacement.
        // Release it only after native exit and all admitted socket removals.
        self.directory.as_ref().expect("live namespace").close()?;
        self.directory.take();
        fs::remove_dir(path)
    }

    fn check(&self) -> io::Result<()> {
        #[cfg(unix)]
        self.pool.check()?;
        self.directory
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .check()
    }
}

#[cfg(all(unix, any(target_os = "macos", test)))]
fn pool_writer(pool: &sandsurf_native::local::Directory) -> io::Result<File> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        pool.check()?;
        match sandsurf_native::storage::disk_lease(&pool.path().join(POOL_LOCK)) {
            Ok(lease) => {
                if lease.metadata()?.len() != 0 {
                    return Err(invalid("native endpoint pool lock contains unowned bytes"));
                }
                return Ok(lease);
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(any(target_os = "macos", windows, test))]
impl Drop for Endpoints {
    fn drop(&mut self) {
        #[cfg(unix)]
        if !self.handed_off && self.directory.is_some() {
            let _ = self.remove_after_exit();
        }
        // Covers pre-launch failure only. Nonempty names need explicit native
        // exit evidence; an unavailable broker receipt cannot authorize loss.
        #[cfg(windows)]
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
    struct Pool(std::path::PathBuf);
    impl Pool {
        #[cfg(windows)]
        fn new() -> Self {
            // Windows uses the original native scope, not a Unix custody
            // pool. Do not add ancestry to already-bounded AF_UNIX names.
            Self(fs::canonicalize(std::env::temp_dir()).unwrap())
        }
        #[cfg(unix)]
        fn new() -> Self {
            let mut nonce = [0_u8; 4];
            getrandom::getrandom(&mut nonce).unwrap();
            let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            #[cfg(target_os = "macos")]
            let parent = Path::new("/private/tmp").to_owned();
            #[cfg(not(target_os = "macos"))]
            let parent = std::env::temp_dir();
            let path = fs::canonicalize(parent).unwrap().join(format!("q-{name}"));
            sandsurf_native::local::create_private_directory(&path).unwrap();
            Self(path)
        }
        fn create(&self) -> Endpoints {
            Endpoints::under(&self.0).unwrap()
        }
    }
    impl Drop for Pool {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                let _ = fs::remove_file(self.0.join(POOL_LOCK));
                // Never recursively remove unexpected test bytes on failure.
                let _ = fs::remove_dir(&self.0);
            }
        }
    }
    fn remove_marker(path: &Path) {
        #[cfg(unix)]
        fs::remove_file(path.join(NAMESPACE_LEASE)).unwrap();
        #[cfg(windows)]
        let _ = path;
    }
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
        let pool = Pool::new();
        let mut original = pool.create();
        let path = original.path().to_owned();
        fs::write(path.join("unexpected"), b"keep").unwrap();
        assert!(original.remove_after_exit().is_err());
        drop(original);
        assert_eq!(fs::read(path.join("unexpected")).unwrap(), b"keep");
        fs::remove_file(path.join("unexpected")).unwrap();
        remove_marker(&path);
        fs::remove_dir(&path).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn replacement_namespace_never_becomes_the_original_owner() {
        let pool = Pool::new();
        let mut original = pool.create();
        let path = original.path().to_owned();
        let held = path.with_extension("held");
        fs::rename(&path, &held).unwrap();
        sandsurf_native::local::create_private_directory(&path).unwrap();
        assert!(original.remove_after_exit().is_err());
        drop(original);
        assert!(path.exists());
        fs::remove_dir(path).unwrap();
        remove_marker(&held);
        fs::remove_dir(held).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn held_private_namespace_fences_windows_replacement() {
        let pool = Pool::new();
        let mut original = pool.create();
        let path = original.path().to_owned();
        assert!(fs::rename(&path, path.with_extension("replacement")).is_err());
        original.remove_after_exit().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn long_ancestry_fails_before_creating_an_endpoint() {
        let pool = Pool::new();
        let root = pool.create();
        let long = root.path().join("x".repeat(104));
        fs::create_dir(&long).unwrap();
        assert!(Endpoints::under(&long).is_err());
        assert_eq!(fs::read_dir(&long).unwrap().count(), 0);
        fs::remove_dir(long).unwrap();
    }
    #[test]
    fn confirmed_native_exit_reclaims_only_socket_names() {
        let pool = Pool::new();
        let mut root = pool.create();
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
        let mut root = pool.create();
        let path = root.path().to_owned();
        fs::write(path.join("qmp.sock"), b"not a socket").unwrap();
        assert!(root.remove_after_exit().is_err());
        drop(root);
        assert!(path.join("qmp.sock").exists());
        fs::remove_file(path.join("qmp.sock")).unwrap();
        remove_marker(&path);
        fs::remove_dir(path).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn crash_cleanup_waits_for_last_original_native_custody() {
        let pool = Pool::new();
        let mut original = pool.create();
        let path = original.path().to_owned();
        let custody = original.custody();
        let native = custody.try_clone().unwrap();
        let socket = std::os::unix::net::UnixListener::bind(path.join(QMP)).unwrap();
        drop(socket);
        drop(original);
        drop(custody);
        drop(pool.create());
        assert!(
            path.join(QMP).exists(),
            "live native namespace was reclaimed"
        );
        drop(native);
        drop(pool.create());
        assert!(!path.exists(), "orphan was not reclaimed after native exit");
    }

    #[test]
    #[cfg(unix)]
    fn orphan_inventory_is_complete_before_deleting_any_socket() {
        let pool = Pool::new();
        let mut original = pool.create();
        let path = original.path().to_owned();
        let socket = std::os::unix::net::UnixListener::bind(path.join(QMP)).unwrap();
        drop(socket);
        drop(original.custody());
        fs::write(path.join("keep"), b"unknown").unwrap();
        drop(original);
        assert!(Endpoints::under(&pool.0).is_err());
        assert!(path.join(QMP).exists());
        assert_eq!(fs::read(path.join("keep")).unwrap(), b"unknown");
        fs::remove_file(path.join("keep")).unwrap();
        fs::write(path.join(NAMESPACE_LEASE), b"not a lease").unwrap();
        assert!(Endpoints::under(&pool.0).is_err());
        assert!(path.join(QMP).exists());
        fs::remove_file(path.join(NAMESPACE_LEASE)).unwrap();
        assert!(
            Endpoints::under(&pool.0).is_err(),
            "missing lease authorized nonempty cleanup"
        );
        assert!(path.join(QMP).exists());
        fs::remove_file(path.join(QMP)).unwrap();
        drop(pool.create());
        assert!(
            !path.exists(),
            "interrupted empty publication was not reclaimed"
        );
    }
}
