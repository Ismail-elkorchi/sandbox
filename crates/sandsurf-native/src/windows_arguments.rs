//! CreateProcess command lines are not shell commands. Preserve every UTF-16
//! unit using the CRT quoting grammar, including trailing backslashes.
use std::ffi::{OsStr, OsString};
use std::io;

pub(crate) fn command_line(program: &OsStr, arguments: &[OsString]) -> io::Result<Vec<u16>> {
    if arguments.len() > 128 {
        return Err(invalid());
    }
    let mut command = Vec::new();
    for value in std::iter::once(program).chain(arguments.iter().map(OsString::as_os_str)) {
        #[cfg(windows)]
        let mut units = {
            use std::os::windows::ffi::OsStrExt;
            value.encode_wide()
        };
        #[cfg(not(windows))]
        let mut units = value.to_str().ok_or_else(invalid)?.encode_utf16();
        let bytes: Vec<_> = units.by_ref().take(4097).collect();
        if bytes.len() > 4096 || bytes.contains(&0) {
            return Err(invalid());
        }
        if !command.is_empty() {
            command.push(b' ' as u16);
        }
        command.push(b'"' as u16);
        let mut slashes = 0;
        for unit in bytes {
            if unit == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            let count = if unit == b'"' as u16 {
                slashes * 2 + 1
            } else {
                slashes
            };
            command.extend(std::iter::repeat_n(b'\\' as u16, count));
            command.push(unit);
            slashes = 0;
        }
        command.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        command.push(b'"' as u16);
        if command.len() > 32766 {
            return Err(invalid());
        }
    }
    command.push(0);
    Ok(command)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "native command line exceeds its UTF-16 launch envelope",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_is_not_a_shell_and_preserves_empty_quotes_and_trailing_slashes() {
        let encoded = command_line(
            OsStr::new("C:\\program files\\worker.exe"),
            &[
                "".into(),
                "a\"b".into(),
                "C:\\directory\\".into(),
                "& | $ %PATH%".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
            "\"C:\\program files\\worker.exe\" \"\" \"a\\\"b\" \"C:\\directory\\\\\" \"& | $ %PATH%\""
        );
    }
    #[test]
    fn bounded_command_line_rejects_nul_large_tokens_and_aggregate_expansion() {
        assert!(command_line(OsStr::new("worker"), &["x\0y".into()]).is_err());
        assert!(command_line(OsStr::new("worker"), &["x".repeat(4097).into()]).is_err());
        assert!(
            command_line(
                OsStr::new("worker"),
                &vec![OsString::from("\\".repeat(4096)); 8]
            )
            .is_err()
        );
        assert!(command_line(OsStr::new("worker"), &vec![OsString::new(); 129]).is_err());
    }
    #[test]
    #[cfg(windows)]
    fn unpaired_surrogates_remain_native_path_units() {
        use std::os::windows::ffi::OsStringExt;
        let value = OsString::from_wide(&[0xd800, 0x61]);
        let bytes = command_line(OsStr::new("worker"), &[value]).unwrap();
        assert!(bytes.windows(2).any(|units| units == [0xd800, 0x61]));
    }
}
