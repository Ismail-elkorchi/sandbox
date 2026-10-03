//! Lazy reviewed offline execution TCB for an admitted image-worker job.
//! This has no image catalog, grants, lifecycle or independent publication.
use sandsurf_image::appliance::{Appliance, Executor as DiskExecutor};
use sandsurf_image::{ImageTrust, VerifiedImage};
use sandsurf_machine::offline::{Config, Runtime};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) struct Executor {
    root: PathBuf,
    executable: PathBuf,
    custody: Vec<Arc<File>>,
    loaded: Option<Loaded>,
}

struct Loaded {
    image: VerifiedImage,
    runtime: Runtime,
    custody: Arc<File>,
}

impl Executor {
    pub(crate) fn new(root: &Path, custody: Vec<Arc<File>>, executable: PathBuf) -> Self {
        Self {
            root: root.into(),
            executable,
            custody,
            loaded: None,
        }
    }

    pub(crate) fn retain(&mut self, original: Arc<File>) {
        self.custody.push(original);
    }

    fn load(&mut self) -> io::Result<&Loaded> {
        if self.loaded.is_none() {
            let digest = crate::images::bundled_image_digest().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native build has no reviewed offline image identity",
                )
            })?;
            let executable = self.executable.clone();
            let directory = executable
                .parent()
                .ok_or_else(|| invalid("native executable has no owner"))?;
            let package = directory
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| invalid("native executable is not packaged"))?;
            let architecture = if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "x64"
            };
            let manifest = package
                .join("images")
                .join(format!("development-{architecture}"))
                .join("manifest.json");
            let store = self.root.join("offline-runtime");
            let image = sandsurf_image::distribution::install(
                &store,
                &manifest,
                ImageTrust::Pinned {
                    manifest_digest: digest.as_str(),
                },
            )
            .map_err(io::Error::other)?;
            let custody = Arc::new(sandsurf_native::storage::disk_lease(
                &store.join(format!(".image-owner-{}", digest.as_str())),
            )?);
            // Revalidate after acquiring the original cache owner. Installed
            // bytes are immutable; this lease fences replacement/reclamation.
            let image = sandsurf_image::verify_image(
                &image.manifest_path,
                ImageTrust::Pinned {
                    manifest_digest: digest.as_str(),
                },
            )
            .map_err(io::Error::other)?;
            if image.initramfs_path.is_none()
                || image.manifest.architecture
                    != if cfg!(target_arch = "aarch64") {
                        sandsurf_image::Architecture::Arm64
                    } else {
                        sandsurf_image::Architecture::X64
                    }
            {
                return Err(invalid(
                    "reviewed offline boot image does not match this native host",
                ));
            }
            #[cfg(target_os = "linux")]
            let runtime = {
                let firecracker = directory.join(if cfg!(target_arch = "aarch64") {
                    "firecracker-v1.17.0-aarch64"
                } else {
                    "firecracker-v1.17.0-x86_64"
                });
                Runtime::Firecracker {
                    launcher: executable,
                    sha256: file_digest(&firecracker, 256 * 1024 * 1024)?,
                    executable: firecracker,
                }
            };
            #[cfg(any(target_os = "macos", windows))]
            let runtime = {
                let manifest = directory.join("qemu-runtime.json");
                let digest = file_digest(&manifest, 65536)?
                    .try_into()
                    .map_err(io::Error::other)?;
                sandsurf_machine::qemu_runtime::verify(
                    &manifest,
                    &digest,
                    crate::service::native_guest_architecture(),
                )?;
                Runtime::Qemu { manifest, digest }
            };
            self.loaded = Some(Loaded {
                image,
                runtime,
                custody,
            });
        }
        Ok(self.loaded.as_ref().expect("initialized reviewed runtime"))
    }
}

impl DiskExecutor for Executor {
    fn identity(&mut self) -> io::Result<String> {
        Ok(self.load()?.image.manifest_digest.clone())
    }

    fn open(
        &mut self,
        disk: &Path,
        writable: bool,
        mut custody: Vec<Arc<File>>,
    ) -> io::Result<Appliance> {
        custody.extend(self.custody.iter().cloned());
        let loaded = self.load()?;
        custody.push(loaded.custody.clone());
        let parent = disk
            .parent()
            .ok_or_else(|| invalid("offline disk has no storage owner"))?;
        sandsurf_native::volume::inspect(parent)?;
        let state = parent.join(".offline");
        // Entry is allowed only under the admitted pool's original exclusive
        // lease. Every earlier VMM inherited that same open description; an
        // interrupted controller cannot release it while its VMM is alive.
        match std::fs::symlink_metadata(&state) {
            Ok(_) => {
                sandsurf_native::local::canonical_private_directory(&state)?;
                std::fs::remove_dir_all(&state)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Appliance::launch(Config {
            runtime: loaded.runtime.clone(),
            kernel: loaded.image.kernel_path.clone(),
            initramfs: loaded.image.initramfs_path.clone(),
            trusted_root: loaded.image.system_path.clone(),
            target: disk.into(),
            writable,
            state,
            custody,
        })
    }
}

fn file_digest(path: &Path, maximum: u64) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("native runtime is not a regular file"));
    }
    let file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut input = file.take(maximum + 1);
    let mut buffer = [0; 65536];
    let mut total = 0;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hash.update(&buffer[..n]);
    }
    if total == 0 || total > maximum {
        return Err(invalid("native runtime digest bound"));
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
