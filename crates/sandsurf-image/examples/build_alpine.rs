//! Offline Alpine package lifecycle scripts execute only inside the appliance.
#[cfg(target_os = "linux")]
mod producer;
#[cfg(target_os = "linux")]
use producer::{Producer, invoke};
#[cfg(target_os = "linux")]
use sandsurf_image::appliance::Filesystem;
use std::io;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
fn main() -> io::Result<()> {
    let arguments: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [root, packages, overlay, output, artifacts] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected root archive, package archive, recipe archive, raw output, boot output",
        ));
    };
    let disk = sandsurf_native::local::create_private_file(output)?;
    disk.set_len(2 * 1024 * 1024 * 1024)?;
    disk.sync_all()?;
    let host = |path: &std::path::Path| -> io::Result<String> {
        let value = path
            .to_str()
            .ok_or_else(|| io::Error::other("producer path encoding"))?;
        if !path.is_absolute() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(io::Error::other("producer path bound"));
        }
        Ok(value.into())
    };
    let tar_in = |path: &std::path::Path, gzip: bool| -> io::Result<Vec<String>> {
        let mut args = vec![
            "tar-in".into(),
            host(path)?,
            "/".into(),
            "xattrs:true".into(),
            "selinux:true".into(),
            "acls:true".into(),
        ];
        if gzip {
            args.push("compress:gzip".into());
        }
        Ok(args)
    };
    invoke(
        output,
        true,
        &[
            vec!["mkfs".into(), "ext4".into(), "/dev/sda".into()],
            vec![
                "mount-options".into(),
                "rw".into(),
                "/dev/sda".into(),
                "/".into(),
            ],
            tar_in(root, true)?,
            tar_in(packages, true)?,
            tar_in(overlay, false)?,
            vec!["command".into(), "'/bin/sh' '/sandsurf-build.sh'".into()],
            vec!["zero-free-space".into(), "/".into()],
            vec!["sync".into()],
            vec!["umount-all".into()],
            vec!["e2fsck".into(), "/dev/sda".into(), "forceno:true".into()],
        ],
    )?;
    let mut filesystem = Producer { disk: output };
    // The package-produced selection is copied and checked before publishing.
    sandsurf_native::local::create_private_directory(artifacts)?;
    let architecture = if cfg!(target_arch = "aarch64") {
        sandsurf_image::Architecture::Arm64
    } else {
        sandsurf_image::Architecture::X64
    };
    sandsurf_image::boot::extract(&mut filesystem, artifacts, architecture)?;
    filesystem.download(
        "/lib/apk/db/installed",
        &artifacts.join("package-database"),
        4 * 1024 * 1024,
    )?;
    let inventory = sandsurf_image::packages::alpine_inventory(
        &std::fs::read(artifacts.join("package-database"))?,
        architecture,
    )
    .map_err(io::Error::other)?;
    let mut file =
        sandsurf_native::local::create_private_file(&artifacts.join("distribution.json"))?;
    use std::io::Write;
    file.write_all(&serde_json::to_vec(&inventory).map_err(io::Error::other)?)?;
    file.sync_all()?;
    std::fs::File::open(output)?.sync_all()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "reviewed image bootstrap requires the Linux KVM producer",
    ))
}
