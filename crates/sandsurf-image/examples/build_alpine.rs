//! Offline Alpine package lifecycle scripts execute only inside the appliance.
use sandsurf_image::appliance::{command, host_path, mount, run};
use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let arguments: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [root, packages, overlay, output, artifacts] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected root archive, package archive, recipe archive, raw output, boot output",
        ));
    };
    let root = host_path(root)?;
    let packages = host_path(packages)?;
    let overlay = host_path(overlay)?;
    let disk = sandsurf_native::local::create_private_file(output)?;
    disk.set_len(2 * 1024 * 1024 * 1024)?;
    disk.sync_all()?;
    run(
        output,
        true,
        &[
            command("mkfs", &["ext4", "/dev/sda"]),
            mount(true),
            command(
                "tar-in",
                &[&root, "/", "compress:gzip", "xattrs:true", "acls:true"],
            ),
            command(
                "tar-in",
                &[&packages, "/", "compress:gzip", "xattrs:true", "acls:true"],
            ),
            command("tar-in", &[&overlay, "/", "xattrs:true", "acls:true"]),
            command("command", &["/bin/sh /sandsurf-build.sh"]),
            command("zero-free-space", &["/"]),
            command("sync", &[]),
            command("umount-all", &[]),
            command("e2fsck", &["/dev/sda", "forceno:true"]),
        ],
    )?;
    // The package-produced selection is copied and checked before publishing.
    sandsurf_native::local::create_private_directory(artifacts)?;
    let architecture = if cfg!(target_arch = "aarch64") {
        sandsurf_image::Architecture::Arm64
    } else {
        sandsurf_image::Architecture::X64
    };
    sandsurf_image::boot::extract(output, artifacts, architecture)?;
    std::fs::File::open(output)?.sync_all()?;
    Ok(())
}
