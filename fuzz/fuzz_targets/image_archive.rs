#![no_main]

use libfuzzer_sys::fuzz_target;
use sandsurf_format::archive::{Archive, CanonicalArchive, Limits};

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    exercise(data);
    // Also enter the parser through a checksum-valid header so mutations
    // exercise extension framing and payload limits instead of stopping only
    // at the checksum gate. The production reader, not tar's iterator, parses.
    let mut header = tar::Header::new_gnu();
    header.set_path("file").unwrap();
    header.set_entry_type(match data.first().copied().unwrap_or_default() % 7 {
        0 => tar::EntryType::Regular,
        1 => tar::EntryType::XHeader,
        2 => tar::EntryType::GNULongName,
        3 => tar::EntryType::GNULongLink,
        4 => tar::EntryType::GNUSparse,
        5 => tar::EntryType::XGlobalHeader,
        _ => tar::EntryType::Symlink,
    });
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(if data.first().is_some_and(|byte| byte & 0x80 != 0) && data.len() >= 9 {
        u64::from_le_bytes(data[1..9].try_into().unwrap())
    } else {
        data.len() as u64
    });
    header.set_cksum();
    let mut framed = Vec::with_capacity(512 + data.len() + 1536);
    framed.extend_from_slice(header.as_bytes());
    framed.extend_from_slice(data);
    framed.resize(framed.len().next_multiple_of(512) + 1024, 0);
    exercise(&framed);
});

fn exercise(data: &[u8]) {
    let mut archive = Archive::new(data, Limits {
        headers: 1024,
        bytes: 1024 * 1024,
        file_bytes: 1024 * 1024,
        path_bytes: 4096,
    });
    while let Ok(Some(mut entry)) = archive.next_entry() {
        let _ = entry.path();
        let _ = entry.link_name();
        if std::io::copy(&mut entry, &mut std::io::sink()).is_err() {
            break;
        }
    }
    let mut archive = CanonicalArchive::new(data, Limits {
        headers: 1024, bytes: 1024 * 1024, file_bytes: 1024 * 1024, path_bytes: 4096,
    }, 1024 * 1024);
    while let Ok(Some(mut entry)) = archive.next_entry() {
        if std::io::copy(&mut entry, &mut std::io::sink()).is_err() { break; }
    }
}
