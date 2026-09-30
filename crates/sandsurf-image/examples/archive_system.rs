//! Archive the reviewed distribution staging tree without confusing temporary
//! host read permissions with the Linux image's declared inode metadata.
#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("source missing"))?,
    );
    let output = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("archive missing"))?,
    );
    if args.next().is_some() || !root.is_absolute() || !output.is_absolute() {
        return Err(io::Error::other(
            "expected absolute source and archive paths",
        ));
    }
    archive(&root, &output)
}

#[cfg(not(unix))]
fn main() -> io::Result<()> {
    Err(io::Error::other(
        "distribution staging requires Unix inode metadata",
    ))
}

#[cfg(unix)]
fn archive(root: &Path, output: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut paths = Vec::new();
    collect(root, Path::new(""), 0, &mut paths)?;
    paths.sort();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut builder = tar::Builder::new(file);
    let mut hardlinks = BTreeMap::new();
    for relative in paths {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path)?;
        let mut header = tar::Header::new_gnu();
        header.set_metadata(&metadata);
        header.set_mode(metadata.mode() & 0o7777);
        header.set_mtime(1_700_000_000);
        let administrator_owned =
            relative.starts_with("home/agent") || relative.starts_with("workspace");
        header.set_uid(if administrator_owned { 1000 } else { 0 });
        header.set_gid(if administrator_owned { 1000 } else { 0 });
        if metadata.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            builder.append_data(&mut header, relative, io::empty())?;
        } else if metadata.file_type().is_symlink() {
            header.set_size(0);
            builder.append_link(&mut header, relative, fs::read_link(&path)?)?;
        } else if metadata.is_file() {
            let identity = (metadata.dev(), metadata.ino());
            if let Some(first) = hardlinks.get(&identity) {
                header.set_entry_type(tar::EntryType::Link);
                header.set_size(0);
                builder.append_link(&mut header, &relative, first)?;
            } else {
                // This is a private, host-owned build tree, never a mounted
                // guest disk. Restore its mode immediately after opening; the
                // archive header always retains the original declared mode.
                let needs_read = metadata.mode() & 0o400 == 0;
                if needs_read {
                    fs::set_permissions(
                        &path,
                        fs::Permissions::from_mode(metadata.mode() | 0o400),
                    )?;
                }
                let opened = File::open(&path);
                if needs_read {
                    fs::set_permissions(&path, metadata.permissions())?;
                }
                let mut source = opened?;
                let actual = source.metadata()?;
                if (actual.dev(), actual.ino(), actual.len())
                    != (metadata.dev(), metadata.ino(), metadata.len())
                {
                    return Err(io::Error::other(
                        "distribution entry changed during archive creation",
                    ));
                }
                builder.append_data(&mut header, &relative, &mut source)?;
                if metadata.nlink() > 1 {
                    hardlinks.insert(identity, relative);
                }
            }
        } else {
            return Err(io::Error::other(
                "distribution archive cannot encode special devices or IPC nodes",
            ));
        }
    }
    builder.finish()?;
    builder.into_inner()?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn collect(root: &Path, relative: &Path, depth: usize, paths: &mut Vec<PathBuf>) -> io::Result<()> {
    if depth > 256 || paths.len() >= 100_000 {
        return Err(io::Error::other("distribution tree exceeds bounds"));
    }
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let path = relative.join(entry.file_name());
        if paths.len() >= 100_000 {
            return Err(io::Error::other("distribution tree exceeds bounds"));
        }
        paths.push(path.clone());
        if entry.file_type()?.is_dir() {
            collect(root, &path, depth + 1, paths)?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn image_metadata_is_independent_of_host_read_access() {
        let root =
            std::env::temp_dir().join(format!("sandsurf-system-archive-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let source = root.join("tree");
        fs::create_dir_all(source.join("home/agent")).unwrap();
        fs::write(source.join("execute-only"), b"program").unwrap();
        fs::set_permissions(
            source.join("execute-only"),
            fs::Permissions::from_mode(0o4111),
        )
        .unwrap();
        fs::hard_link(source.join("execute-only"), source.join("second-link")).unwrap();
        symlink("/execute-only", source.join("symlink")).unwrap();
        let output = root.join("system.tar");
        archive(&source, &output).unwrap();
        let mut reader = tar::Archive::new(File::open(output).unwrap());
        let mut modes = BTreeMap::new();
        for entry in reader.entries().unwrap() {
            let entry = entry.unwrap();
            modes.insert(
                entry.path().unwrap().into_owned(),
                (
                    entry.header().mode().unwrap(),
                    entry.header().uid().unwrap(),
                    entry.header().entry_type(),
                ),
            );
        }
        assert_eq!(modes[Path::new("execute-only")].0, 0o4111);
        assert_eq!(modes[Path::new("home/agent")].1, 1000);
        assert!(modes[Path::new("second-link")].2.is_hard_link());
        assert!(modes[Path::new("symlink")].2.is_symlink());
        assert_eq!(
            fs::metadata(source.join("execute-only"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o4111
        );
        fs::remove_dir_all(root).unwrap();
    }
}
