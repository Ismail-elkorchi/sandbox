//! The disk executor's closed contract. Host transfer names are not guest RPC
//! arguments. A backend may serialize guest paths and values, never host paths.
#[cfg(any(target_os = "linux", test))]
use super::host_path;
use super::invalid;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
}

#[derive(Debug)]
pub enum Operation {
    Mount {
        writable: bool,
    },
    MakeExt4,
    ImportTar {
        source: PathBuf,
        compression: Compression,
    },
    Execute {
        argv: Vec<String>,
    },
    Sync,
    Unmount,
    CheckExt4,
    Remove {
        path: String,
    },
    Write {
        path: String,
        bytes: String,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    Mkdir {
        path: String,
    },
    ZeroFreeSpace,
    Realpath {
        path: String,
    },
    FileSize {
        path: String,
    },
    Download {
        path: String,
        destination: PathBuf,
        offset: u64,
        bytes: u64,
    },
    Cat {
        path: String,
    },
    Stat {
        path: String,
    },
    Readlink {
        path: String,
    },
    Exists {
        path: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Stat {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Complete,
    Text(String),
    Size(u64),
    Exists(bool),
    Stat(Stat),
}

impl Reply {
    pub fn text(self) -> io::Result<String> {
        match self {
            Self::Text(value) => Ok(value),
            _ => Err(invalid("disk executor returned the wrong result type")),
        }
    }
    pub fn size(self) -> io::Result<u64> {
        match self {
            Self::Size(value) => Ok(value),
            _ => Err(invalid("disk executor returned the wrong result type")),
        }
    }
}

impl Operation {
    pub(super) fn query(&self) -> bool {
        matches!(
            self,
            Self::Realpath { .. }
                | Self::FileSize { .. }
                | Self::Cat { .. }
                | Self::Stat { .. }
                | Self::Readlink { .. }
                | Self::Exists { .. }
        )
    }

    pub(super) fn mutation(&self) -> bool {
        matches!(
            self,
            Self::Mount { writable: true }
                | Self::MakeExt4
                | Self::ImportTar { .. }
                | Self::Execute { .. }
                | Self::Remove { .. }
                | Self::Write { .. }
                | Self::Chmod { .. }
                | Self::Mkdir { .. }
                | Self::ZeroFreeSpace
        )
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn arguments(&self) -> io::Result<Vec<String>> {
        let guest = |path: &str| -> io::Result<String> {
            if !path.starts_with('/')
                || path.len() > 4096
                || path.chars().any(char::is_control)
                || path.split('/').any(|part| part == "..")
            {
                return Err(invalid(
                    "disk operation requires a bounded absolute guest path",
                ));
            }
            Ok(path.to_owned())
        };
        let values: Vec<String> = match self {
            Self::Mount { writable } => vec![
                "mount-options".into(),
                if *writable { "rw" } else { "ro,noload" }.into(),
                "/dev/sda".into(),
                "/".into(),
            ],
            Self::MakeExt4 => vec!["mkfs".into(), "ext4".into(), "/dev/sda".into()],
            Self::ImportTar {
                source,
                compression,
            } => {
                let mut args = vec![
                    "tar-in".into(),
                    host_path(source)?,
                    "/".into(),
                    "xattrs:true".into(),
                    "selinux:true".into(),
                    "acls:true".into(),
                ];
                if *compression == Compression::Gzip {
                    args.push("compress:gzip".into());
                }
                args
            }
            Self::Execute { argv } => {
                if argv.is_empty() || argv.len() > 64 || argv[0].is_empty() {
                    return Err(invalid("invalid appliance program argv"));
                }
                // guestfish's argv-list parser is not a shell. Quote each exact
                // token using its single-quote grammar, including terminal
                // backslashes outside the final quote. No shell interpolation.
                let mut encoded = Vec::new();
                for token in argv {
                    if token.len() > 4096 || token.contains('\0') {
                        return Err(invalid("appliance program token exceeds bound"));
                    }
                    let prefix = token.trim_end_matches('\\');
                    encoded.push(format!(
                        "'{}'{}",
                        prefix.replace('\'', "\\'"),
                        &token[prefix.len()..]
                    ));
                }
                vec!["command".into(), encoded.join(" ")]
            }
            Self::Sync => vec!["sync".into()],
            Self::Unmount => vec!["umount-all".into()],
            Self::CheckExt4 => vec!["e2fsck".into(), "/dev/sda".into(), "forceno:true".into()],
            Self::Remove { path } => vec!["rm-f".into(), guest(path)?],
            Self::Write { path, bytes } => vec!["write".into(), guest(path)?, bytes.clone()],
            Self::Chmod { path, mode } => {
                if *mode > 0o7777 {
                    return Err(invalid("invalid guest file mode"));
                }
                // guestfish parses this argument as an integer, not shell octal.
                vec!["chmod".into(), mode.to_string(), guest(path)?]
            }
            Self::Mkdir { path } => vec!["mkdir-p".into(), guest(path)?],
            Self::ZeroFreeSpace => vec!["zero-free-space".into(), "/".into()],
            Self::Realpath { path } => vec!["realpath".into(), guest(path)?],
            Self::FileSize { path } => vec!["filesize".into(), guest(path)?],
            Self::Download {
                path,
                destination,
                offset,
                bytes,
            } => {
                if *bytes == 0 || offset.checked_add(*bytes).is_none() {
                    return Err(invalid("invalid disk download range"));
                }
                vec![
                    "download-offset".into(),
                    guest(path)?,
                    host_path(destination)?,
                    offset.to_string(),
                    bytes.to_string(),
                ]
            }
            Self::Cat { path } => vec!["cat".into(), guest(path)?],
            Self::Stat { path } => vec!["statns".into(), guest(path)?],
            Self::Readlink { path } => vec!["readlink".into(), guest(path)?],
            Self::Exists { path } => vec!["exists".into(), guest(path)?],
        };
        if values
            .iter()
            .any(|value| value.len() > 8192 || value.contains('\0') || value == ":")
        {
            return Err(invalid("disk operation argument exceeds bound"));
        }
        Ok(values)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn reply(&self, bytes: Vec<u8>) -> io::Result<Reply> {
        let text = || {
            std::str::from_utf8(&bytes).map_err(|_| invalid("invalid disk observation encoding"))
        };
        Ok(match self {
            Self::Realpath { .. } | Self::Readlink { .. } => {
                Reply::Text(text()?.trim_end_matches('\n').into())
            }
            Self::Cat { .. } => Reply::Text(text()?.into()),
            Self::FileSize { .. } => Reply::Size(
                text()?
                    .trim()
                    .parse()
                    .map_err(|_| invalid("invalid disk file size"))?,
            ),
            Self::Exists { .. } => Reply::Exists(match text()?.trim() {
                "true" => true,
                "false" => false,
                _ => return Err(invalid("invalid disk existence observation")),
            }),
            Self::Stat { .. } => {
                let mut fields = std::collections::BTreeMap::new();
                for line in text()?.lines() {
                    let (name, value) = line
                        .split_once(": ")
                        .ok_or_else(|| invalid("invalid disk stat field"))?;
                    if fields.insert(name, value).is_some() {
                        return Err(invalid("duplicate disk stat field"));
                    }
                }
                let number = |name| {
                    fields
                        .get(name)
                        .ok_or_else(|| invalid("missing disk stat field"))?
                        .parse::<u64>()
                        .map_err(|_| invalid("invalid disk stat value"))
                };
                Reply::Stat(Stat {
                    uid: number("st_uid")?
                        .try_into()
                        .map_err(|_| invalid("guest uid exceeds bound"))?,
                    gid: number("st_gid")?
                        .try_into()
                        .map_err(|_| invalid("guest gid exceeds bound"))?,
                    mode: number("st_mode")?
                        .try_into()
                        .map_err(|_| invalid("guest mode exceeds bound"))?,
                    bytes: number("st_size")?,
                })
            }
            _ => Reply::Complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_operations_reject_escapes_ranges_modes_and_argument_delimiters() {
        for op in [
            Operation::Cat {
                path: "../host".into(),
            },
            Operation::Cat {
                path: "/etc/../host".into(),
            },
            Operation::Chmod {
                path: "/file".into(),
                mode: 0o10000,
            },
            Operation::Write {
                path: "/file".into(),
                bytes: ":".into(),
            },
            Operation::Download {
                path: "/file".into(),
                destination: std::env::temp_dir().join("output"),
                offset: u64::MAX,
                bytes: 2,
            },
            Operation::Execute { argv: vec![] },
        ] {
            assert!(op.arguments().is_err(), "{op:?}");
        }
    }
    #[test]
    fn observations_have_one_type_and_never_accept_missing_or_duplicate_fields() {
        let size = Operation::FileSize {
            path: "/file".into(),
        };
        assert_eq!(size.reply(b"123\n".to_vec()).unwrap(), Reply::Size(123));
        for value in [b"-1".as_slice(), b"1\n2", b"18446744073709551616"] {
            assert!(size.reply(value.to_vec()).is_err());
        }
        let stat = Operation::Stat {
            path: "/file".into(),
        };
        assert_eq!(
            stat.reply(b"st_uid: 1000\nst_gid: 1000\nst_mode: 35309\nst_size: 8\n".to_vec())
                .unwrap(),
            Reply::Stat(Stat {
                uid: 1000,
                gid: 1000,
                mode: 35309,
                bytes: 8
            })
        );
        assert!(stat.reply(b"st_uid: 1\nst_uid: 2\n".to_vec()).is_err());
        assert!(stat.reply(b"st_uid: 1\n".to_vec()).is_err());
        assert!(size.reply(b"3".to_vec()).unwrap().text().is_err());
    }
}
