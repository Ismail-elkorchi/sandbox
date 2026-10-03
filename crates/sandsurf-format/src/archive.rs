//! Streaming filesystem-archive vocabulary. Validate headers and extension sizes
//! before allocation, with one interpretation of PAX framing and file lengths.
//! No filesystem extraction, guest execution, sparse decoding, or unbounded
//! extension buffering occurs in this reader.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const BLOCK: usize = 512;
const MAX_PAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub headers: usize,
    pub bytes: u64,
    pub file_bytes: u64,
    pub path_bytes: usize,
}

pub struct Archive<R> {
    reader: R,
    limits: Limits,
    bytes: u64,
    headers: usize,
    remaining: u64,
    padding: usize,
    ended: bool,
}

/// The one complete-filesystem profile consumed by the offline guest and
/// verified by the host. Framing remains owned by Archive; this validator owns
/// only member order, canonical Linux paths and representable inode metadata.
/// Paths are '/'-separated guest bytes, never host filesystem components.
pub struct CanonicalArchive<R> {
    archive: Archive<R>,
    entries: BTreeMap<String, u8>,
    payload: u64,
    capacity: u64,
    maximum_entries: usize,
    failed: bool,
}

impl<R: Read> CanonicalArchive<R> {
    pub fn new(reader: R, limits: Limits, capacity: u64) -> Self {
        Self {
            archive: Archive::new(reader, limits),
            entries: BTreeMap::new(),
            payload: 0,
            capacity,
            maximum_entries: limits.headers,
            failed: false,
        }
    }

    pub fn next_entry(&mut self) -> io::Result<Option<Entry<'_, R>>> {
        if self.failed {
            return Err(invalid("canonical archive previously failed"));
        }
        self.failed = true;
        let Some(entry) = self.archive.next_entry()? else {
            self.failed = false;
            return Ok(None);
        };
        let path = canonical_path(entry.path())?;
        let kind = entry.header().entry_type();
        if self.entries.len() >= self.maximum_entries
            || self.entries.contains_key(path)
            || !(kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link())
            || entry.header().mode()? > 0o7777
            || entry.header().uid()? > u32::MAX as u64
            || entry.header().gid()? > u32::MAX as u64
            || entry.header().mtime()? > i64::MAX as u64
        {
            return Err(invalid("unsupported canonical filesystem archive metadata"));
        }
        let mut parent = path;
        while let Some((value, _)) = parent.rsplit_once('/') {
            if self.entries.get(value) != Some(&b'5') {
                return Err(invalid("archive parent is not a preceding directory"));
            }
            parent = value;
        }
        if kind.is_hard_link() {
            let target = canonical_path(
                entry
                    .link_name()
                    .ok_or_else(|| invalid("archive link has no target"))?,
            )?;
            if !self
                .entries
                .get(target)
                .is_some_and(|kind| *kind == b'0' || *kind == b'1')
            {
                return Err(invalid("archive hardlink is not a preceding inode"));
            }
        } else if kind.is_symlink() && entry.link_name().is_none() {
            return Err(invalid("archive symlink has no target"));
        }
        if kind.is_file() {
            self.payload = self
                .payload
                .checked_add(entry.size())
                .filter(|value| *value <= self.capacity)
                .ok_or_else(|| invalid("filesystem payload exceeds disk capacity"))?;
        } else if entry.size() != 0 {
            return Err(invalid("non-file archive member carries payload"));
        }
        self.entries.insert(
            path.to_owned(),
            if kind.is_file() { b'0' } else { kind.as_byte() },
        );
        self.failed = false;
        Ok(Some(entry))
    }
}

fn canonical_path(path: &Path) -> io::Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| unsupported("non-UTF-8 canonical guest path"))?;
    if text.len() > 4096
        || text.contains('\0')
        || text
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(invalid("noncanonical filesystem archive path"));
    }
    Ok(text)
}

#[derive(Default)]
struct Extensions {
    path: Option<String>,
    link: Option<String>,
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    pax: bool,
}

pub struct Entry<'a, R> {
    archive: &'a mut Archive<R>,
    header: tar::Header,
    path: PathBuf,
    link: Option<PathBuf>,
    size: u64,
}

impl<R: Read> Archive<R> {
    pub fn new(reader: R, limits: Limits) -> Self {
        Self {
            reader,
            limits,
            bytes: 0,
            headers: 0,
            remaining: 0,
            padding: 0,
            ended: false,
        }
    }

    pub fn headers_read(&self) -> usize {
        self.headers
    }

    /// Dropping an entry does not allocate or drain. Advancing the archive
    /// drains its remaining payload under the same total-byte envelope.
    pub fn next_entry(&mut self) -> io::Result<Option<Entry<'_, R>>> {
        if self.ended {
            return Ok(None);
        }
        self.finish_entry()?;
        let mut extensions = Extensions::default();
        loop {
            let mut block = [0; BLOCK];
            self.exact(&mut block)?;
            if block.iter().all(|byte| *byte == 0) {
                if extensions.pax || extensions.path.is_some() || extensions.link.is_some() {
                    return Err(invalid("archive ends with unattached metadata"));
                }
                self.exact(&mut block)?;
                if block.iter().any(|byte| *byte != 0) {
                    return Err(invalid("archive requires two zero end blocks"));
                }
                // Refuse a hidden second archive; OCI diff IDs still cover all
                // trailing zero padding, including compression-stream trailers.
                loop {
                    let count = self.read_bounded(&mut block)?;
                    if count == 0 {
                        break;
                    }
                    if block[..count].iter().any(|byte| *byte != 0) {
                        return Err(invalid("nonzero bytes follow archive end"));
                    }
                }
                self.ended = true;
                return Ok(None);
            }
            self.headers = self
                .headers
                .checked_add(1)
                .filter(|value| *value <= self.limits.headers)
                .ok_or_else(|| invalid("archive header count exceeds bound"))?;
            let mut header = tar::Header::new_old();
            header.as_mut_bytes().copy_from_slice(&block);
            let checksum: u32 = block[..148]
                .iter()
                .chain(&block[156..])
                .map(|byte| *byte as u32)
                .sum::<u32>()
                + 8 * 32;
            if checksum != header.cksum()? {
                return Err(invalid("archive header checksum mismatch"));
            }
            let kind = header.entry_type();
            let declared = header.entry_size()?;
            let extension =
                kind.is_gnu_longname() || kind.is_gnu_longlink() || kind.is_pax_local_extensions();
            if extension {
                let maximum = if kind.is_pax_local_extensions() {
                    MAX_PAX_BYTES
                } else {
                    self.limits.path_bytes.saturating_add(1) as u64
                };
                if declared == 0 || declared > maximum {
                    return Err(invalid("archive extension length exceeds bound"));
                }
                self.begin_payload(declared)?;
                let mut data = vec![0; declared as usize];
                self.exact(&mut data)?;
                self.remaining = 0;
                self.finish_entry()?;
                if kind.is_pax_local_extensions() {
                    if extensions.pax {
                        return Err(invalid("duplicate PAX extension"));
                    }
                    extensions.pax = true;
                    parse_pax(&data, &mut extensions, self.limits.path_bytes)?;
                } else {
                    let data = data
                        .strip_suffix(&[0])
                        .ok_or_else(|| invalid("GNU long name is not terminated"))?;
                    let value = bounded_text(data, self.limits.path_bytes)?;
                    set_once(
                        if kind.is_gnu_longname() {
                            &mut extensions.path
                        } else {
                            &mut extensions.link
                        },
                        value,
                    )?;
                }
                continue;
            }
            if kind.is_pax_global_extensions() || kind.is_gnu_sparse() {
                return Err(unsupported("global PAX and sparse image archives"));
            }
            if !(kind.is_file()
                || kind.is_dir()
                || kind.is_symlink()
                || kind.is_hard_link()
                || kind.is_character_special()
                || kind.is_block_special()
                || kind.is_fifo())
            {
                return Err(unsupported("unknown image archive entry type"));
            }
            let size = extensions.size.unwrap_or(declared);
            if size > self.limits.file_bytes {
                return Err(invalid("archive member size exceeds bound"));
            }
            if !kind.is_file() && size != 0 {
                return Err(invalid("non-file archive entry carries payload"));
            }
            let path = match extensions.path {
                Some(path) => path,
                None => bounded_text(&header.path_bytes(), self.limits.path_bytes)?,
            };
            let link = match extensions.link {
                Some(link) => Some(link),
                None => header
                    .link_name_bytes()
                    .map(|value| bounded_text(&value, self.limits.path_bytes))
                    .transpose()?,
            };
            if let Some(uid) = extensions.uid {
                header.set_uid(uid);
            }
            if let Some(gid) = extensions.gid {
                header.set_gid(gid);
            }
            header.set_size(size);
            self.begin_payload(size)?;
            return Ok(Some(Entry {
                archive: self,
                header,
                path: path.into(),
                link: link.map(PathBuf::from),
                size,
            }));
        }
    }

    fn begin_payload(&mut self, size: u64) -> io::Result<()> {
        let padding = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
        self.bytes
            .checked_add(size)
            .and_then(|value| value.checked_add(padding))
            .filter(|value| *value <= self.limits.bytes)
            .ok_or_else(|| invalid("archive declared payload exceeds byte envelope"))?;
        self.remaining = size;
        self.padding = padding as usize;
        Ok(())
    }

    fn finish_entry(&mut self) -> io::Result<()> {
        let mut buffer = [0; 8192];
        while self.remaining != 0 {
            let maximum = self.remaining.min(buffer.len() as u64) as usize;
            let count = self.read_bounded(&mut buffer[..maximum])?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated archive payload",
                ));
            }
            self.remaining -= count as u64;
        }
        let padding = self.padding;
        self.exact(&mut buffer[..padding])?;
        if buffer[..padding].iter().any(|byte| *byte != 0) {
            return Err(invalid("archive padding is not zero"));
        }
        self.padding = 0;
        Ok(())
    }

    fn exact(&mut self, mut output: &mut [u8]) -> io::Result<()> {
        while !output.is_empty() {
            let count = self.read_bounded(output)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated image archive",
                ));
            }
            output = &mut output[count..];
        }
        Ok(())
    }

    fn read_bounded(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = loop {
            match self.reader.read(output) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .filter(|value| *value <= self.limits.bytes)
            .ok_or_else(|| invalid("image archive exceeds byte envelope"))?;
        Ok(count)
    }
}

impl<R> Entry<'_, R> {
    pub fn header(&self) -> &tar::Header {
        &self.header
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn link_name(&self) -> Option<&Path> {
        self.link.as_deref()
    }
}

impl<R: Read> Read for Entry<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let maximum = self.archive.remaining.min(output.len() as u64) as usize;
        if maximum == 0 {
            return Ok(0);
        }
        let count = self.archive.read_bounded(&mut output[..maximum])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated archive entry",
            ));
        }
        self.archive.remaining -= count as u64;
        Ok(count)
    }
}

fn parse_pax(data: &[u8], extensions: &mut Extensions, maximum: usize) -> io::Result<()> {
    let mut offset = 0;
    let mut keys = BTreeSet::new();
    while offset < data.len() {
        let record = &data[offset..];
        let space = record
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| invalid("PAX record has no length delimiter"))?;
        let length = decimal(&record[..space])?;
        let length = usize::try_from(length).map_err(|_| invalid("PAX length overflow"))?;
        if length <= space + 3 || length > record.len() || record[length - 1] != b'\n' {
            return Err(invalid("PAX record length is invalid"));
        }
        let body = &record[space + 1..length - 1];
        let equal = body
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| invalid("PAX record has no value delimiter"))?;
        let key = &body[..equal];
        let value = &body[equal + 1..];
        if key.is_empty() || key.len() > 256 || !key.is_ascii() || key.contains(&0) {
            return Err(invalid("PAX key is outside the metadata envelope"));
        }
        if !keys.insert(key) {
            return Err(invalid("duplicate PAX key"));
        }
        match key {
            b"path" => set_once(&mut extensions.path, bounded_text(value, maximum)?)?,
            b"linkpath" => set_once(&mut extensions.link, bounded_text(value, maximum)?)?,
            b"size" => extensions.size = Some(decimal(value)?),
            b"uid" => extensions.uid = Some(decimal(value)?),
            b"gid" => extensions.gid = Some(decimal(value)?),
            // Image construction intentionally normalizes timestamps. Names
            // are non-authoritative; numeric uid/gid are preserved instead.
            b"mtime" | b"atime" | b"ctime" | b"uname" | b"gname" => {
                let _ = bounded_text(value, maximum)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "image PAX metadata {} is not represented by the filesystem builder",
                        String::from_utf8_lossy(key),
                    ),
                ));
            }
        }
        offset += length;
    }
    Ok(())
}

fn decimal(value: &[u8]) -> io::Result<u64> {
    if value.is_empty() || value.len() > 20 || !value.iter().all(u8::is_ascii_digit) {
        return Err(invalid("archive decimal value is invalid"));
    }
    value.iter().try_fold(0_u64, |number, byte| {
        number
            .checked_mul(10)
            .and_then(|number| number.checked_add((byte - b'0') as u64))
            .ok_or_else(|| invalid("archive decimal value overflows"))
    })
}

fn bounded_text(value: &[u8], maximum: usize) -> io::Result<String> {
    if value.is_empty() || value.len() > maximum || value.contains(&0) {
        return Err(invalid(
            "archive text is empty, unterminated, or exceeds bound",
        ));
    }
    String::from_utf8(value.to_vec()).map_err(|_| unsupported("non-UTF-8 image archive metadata"))
}

fn set_once(slot: &mut Option<String>, value: String) -> io::Result<()> {
    if slot.is_some() {
        return Err(invalid("conflicting GNU/PAX path metadata"));
    }
    *slot = Some(value);
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            headers: 16,
            bytes: 1024 * 1024,
            file_bytes: 4096,
            path_bytes: 4096,
        }
    }

    fn header(kind: tar::EntryType, name: &str, size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_path(name).unwrap();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        header
    }

    fn pax(key: &str, value: &str) -> Vec<u8> {
        let body = format!(" {key}={value}\n");
        let mut length = body.len() + 1;
        loop {
            let encoded = format!("{length}{body}");
            if encoded.len() == length {
                return encoded.into_bytes();
            }
            length = encoded.len();
        }
    }

    fn member(bytes: &mut Vec<u8>, header: tar::Header, payload: &[u8]) {
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
    }

    #[test]
    fn canonical_paths_have_linux_not_host_filesystem_semantics() {
        for value in [
            "CON",
            "con",
            "C:drive\\file",
            "a:b",
            "back\\slash",
            "trailing.",
        ] {
            assert_eq!(canonical_path(Path::new(value)).unwrap(), value);
        }
        for value in ["", "/a", "a//b", "a/", "./a", "a/../b", "a/./b"] {
            assert!(canonical_path(Path::new(value)).is_err());
        }
    }

    #[test]
    fn canonical_profile_preserves_regular_variants_and_prior_links_under_one_envelope() {
        let mut data = Vec::new();
        member(&mut data, header(tar::EntryType::Directory, "dir", 0), b"");
        let mut file = header(tar::EntryType::new(0), "dir/file", 3);
        file.set_uid(123);
        file.set_gid(456);
        file.set_mode(0o4755);
        file.set_cksum();
        member(&mut data, file, b"abc");
        let mut link = header(tar::EntryType::Link, "dir/alias", 0);
        link.set_link_name("dir/file").unwrap();
        link.set_cksum();
        member(&mut data, link, b"");
        let mut link = header(tar::EntryType::Symlink, "outside", 0);
        link.set_link_name("/outside").unwrap();
        link.set_cksum();
        member(&mut data, link, b"");
        data.resize(data.len() + BLOCK * 2, 0);
        let mut archive = CanonicalArchive::new(&data[..], limits(), 3);
        assert!(
            archive
                .next_entry()
                .unwrap()
                .unwrap()
                .header()
                .entry_type()
                .is_dir()
        );
        let file = archive.next_entry().unwrap().unwrap();
        assert_eq!(
            (
                file.header().uid().unwrap(),
                file.header().gid().unwrap(),
                file.header().mode().unwrap()
            ),
            (123, 456, 0o4755)
        );
        drop(file);
        assert!(
            archive
                .next_entry()
                .unwrap()
                .unwrap()
                .header()
                .entry_type()
                .is_hard_link()
        );
        assert!(
            archive
                .next_entry()
                .unwrap()
                .unwrap()
                .header()
                .entry_type()
                .is_symlink()
        );
        assert!(archive.next_entry().unwrap().is_none());
    }

    #[test]
    fn canonical_profile_rejects_metadata_parent_alias_and_capacity_violations_permanently() {
        let regular = || header(tar::EntryType::Regular, "file", 0);
        let mut mode = regular();
        mode.set_mode(0o177777);
        mode.set_cksum();
        let mut uid = regular();
        uid.set_uid(u32::MAX as u64 + 1);
        uid.set_cksum();
        let mut time = regular();
        time.set_mtime(i64::MAX as u64 + 1);
        time.set_cksum();
        let mut forward = header(tar::EntryType::Link, "alias", 0);
        forward.set_link_name("future").unwrap();
        forward.set_cksum();
        for members in [
            vec![mode],
            vec![uid],
            vec![time],
            vec![forward],
            vec![header(tar::EntryType::Regular, "missing/file", 0)],
            vec![regular(), regular()],
            vec![header(tar::EntryType::Symlink, "no-target", 0)],
            vec![header(tar::EntryType::Directory, "payload", 1)],
            vec![header(tar::EntryType::Regular, "file", 4)],
        ] {
            let mut data = Vec::new();
            for header in members {
                let size = header.size().unwrap();
                member(&mut data, header, &vec![0; size as usize]);
            }
            data.resize(data.len() + BLOCK * 2, 0);
            let mut archive = CanonicalArchive::new(&data[..], limits(), 3);
            let mut rejected = false;
            loop {
                match archive.next_entry() {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        rejected = true;
                        break;
                    }
                }
            }
            assert!(rejected);
            assert!(
                archive.next_entry().is_err(),
                "failed canonical validation cannot resume"
            );
        }
    }

    #[test]
    fn rejects_declared_extension_allocation_without_reading_payload() {
        for kind in [
            tar::EntryType::GNULongName,
            tar::EntryType::GNULongLink,
            tar::EntryType::XHeader,
        ] {
            let data = header(kind, "extension", u64::MAX / 2);
            let mut reader = Archive::new(&data.as_bytes()[..], limits());
            let error = reader.next_entry().err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("extension length"));
        }
    }

    #[test]
    fn pax_framing_controls_payload_size_and_preserves_numeric_ownership() {
        let mut data = Vec::new();
        let metadata: Vec<_> = [
            pax("path", "etc/config"),
            pax("size", "3"),
            pax("uid", "123"),
            pax("gid", "456"),
        ]
        .concat();
        member(
            &mut data,
            header(tar::EntryType::XHeader, "extension", metadata.len() as u64),
            &metadata,
        );
        // The PAX length, not the conflicting fixed header, owns framing.
        member(
            &mut data,
            header(tar::EntryType::Regular, "ignored", 999),
            b"abc",
        );
        member(&mut data, header(tar::EntryType::Regular, "next", 1), b"z");
        data.resize(data.len() + BLOCK * 2, 0);
        let mut archive = Archive::new(&data[..], limits());
        {
            let mut entry = archive.next_entry().unwrap().unwrap();
            assert_eq!(entry.path(), Path::new("etc/config"));
            assert_eq!(entry.header().uid().unwrap(), 123);
            assert_eq!(entry.header().gid().unwrap(), 456);
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"abc");
        }
        let entry = archive.next_entry().unwrap().unwrap();
        assert_eq!(entry.path(), Path::new("next"));
        drop(entry); // Advancing drains unread bytes without buffering them.
        assert!(archive.next_entry().unwrap().is_none());
        assert_eq!(archive.headers_read(), 3);
    }

    #[test]
    fn unsupported_metadata_never_disappears_silently() {
        for key in [
            "SCHILY.xattr.security.capability",
            "GNU.sparse.map",
            "vendor.unknown",
        ] {
            let metadata = pax(key, "ignored");
            let mut data = Vec::new();
            member(
                &mut data,
                header(tar::EntryType::XHeader, "extension", metadata.len() as u64),
                &metadata,
            );
            let mut reader = Archive::new(&data[..], limits());
            assert_eq!(
                reader.next_entry().err().unwrap().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[test]
    fn extension_headers_count_against_the_same_archive_envelope() {
        let name = b"long/path\0";
        let mut data = Vec::new();
        member(
            &mut data,
            header(tar::EntryType::GNULongName, "extension", name.len() as u64),
            name,
        );
        member(
            &mut data,
            header(tar::EntryType::Regular, "ignored", 0),
            b"",
        );
        data.resize(data.len() + BLOCK * 2, 0);
        let mut reader = Archive::new(
            &data[..],
            Limits {
                headers: 1,
                ..limits()
            },
        );
        assert!(
            reader
                .next_entry()
                .err()
                .unwrap()
                .to_string()
                .contains("header count")
        );
        let mut reader = Archive::new(
            &data[..],
            Limits {
                bytes: BLOCK as u64,
                ..limits()
            },
        );
        assert!(reader.next_entry().is_err());
    }

    #[test]
    fn rejects_conflicting_malformed_and_truncated_archives() {
        for metadata in [
            b"999 path=short\n".to_vec(),
            [pax("uid", "1"), pax("uid", "2")].concat(),
            pax("size", "18446744073709551616"),
        ] {
            let mut data = Vec::new();
            member(
                &mut data,
                header(tar::EntryType::XHeader, "extension", metadata.len() as u64),
                &metadata,
            );
            assert!(Archive::new(&data[..], limits()).next_entry().is_err());
        }
        let mut data = Vec::new();
        member(
            &mut data,
            header(tar::EntryType::Regular, "file", 1024),
            b"short",
        );
        let mut archive = Archive::new(&data[..], limits());
        drop(archive.next_entry().unwrap().unwrap());
        assert!(archive.next_entry().is_err());
        let mut data = vec![0; BLOCK * 2];
        data.extend_from_slice(b"hidden content");
        assert!(Archive::new(&data[..], limits()).next_entry().is_err());
    }

    #[test]
    fn normal_long_paths_are_bounded_and_preserved() {
        let name = "path/".repeat(50);
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_data(
                &mut header(tar::EntryType::Regular, "unused", 1),
                &name,
                &b"x"[..],
            )
            .unwrap();
        let data = builder.into_inner().unwrap();
        let mut archive = Archive::new(&data[..], limits());
        let entry = archive.next_entry().unwrap().unwrap();
        assert_eq!(entry.path(), Path::new(&name));
        drop(entry);
        assert!(archive.next_entry().unwrap().is_none());
        assert!(
            Archive::new(
                &data[..],
                Limits {
                    path_bytes: 128,
                    ..limits()
                }
            )
            .next_entry()
            .is_err()
        );
    }
}
