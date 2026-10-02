//! Offline Alpine package lifecycle scripts execute only inside the appliance.
use sandsurf_image::appliance::{Compression, Operation, run};
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
    let disk = sandsurf_native::local::create_private_file(output)?;
    disk.set_len(2 * 1024 * 1024 * 1024)?;
    disk.sync_all()?;
    run(
        output,
        true,
        &[
            Operation::MakeExt4,
            Operation::Mount { writable: true },
            Operation::ImportTar {
                source: root.clone(),
                compression: Compression::Gzip,
            },
            Operation::ImportTar {
                source: packages.clone(),
                compression: Compression::Gzip,
            },
            Operation::ImportTar {
                source: overlay.clone(),
                compression: Compression::None,
            },
            Operation::Execute {
                argv: vec!["/bin/sh".into(), "/sandsurf-build.sh".into()],
            },
            Operation::ZeroFreeSpace,
            Operation::Sync,
            Operation::Unmount,
            Operation::CheckExt4,
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
