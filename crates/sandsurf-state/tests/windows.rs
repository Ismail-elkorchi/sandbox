#![cfg(windows)]

use sandsurf_protocol::{
    AuthorityBinding, Counter, DiskId, OperationId, Resources, SandboxId, bytes_digest,
};
use sandsurf_state::{
    CatalogLimits, DiskCopy, DiskPhase, DiskPurpose, HostCatalog, RuntimeJournal, RuntimeLimits,
};
use std::fs::{self, File};
use std::os::windows::fs::FileExt;

#[test]
fn windows_private_state_is_owner_only_reopenable_and_writer_exclusive() {
    let one = Counter::ONE;
    let path =
        std::env::temp_dir().join(format!("sandsurf-unqualified-state-{}", std::process::id()));
    let catalog = HostCatalog::create(
        &path,
        "windows-test-host".try_into().unwrap(),
        CatalogLimits {
            identities: one,
            operations: one,
            grants: one,
            usage_records: one,
            resources: Resources {
                vcpus: one,
                memory_mib: one,
                disk_bytes: one,
                output_bytes: one,
                processes: one,
            },
        },
    )
    .unwrap();
    assert!(path.join("authority.sqlite").is_file());
    assert!(path.join("authority.key").is_file());
    assert!(HostCatalog::open(&path).is_err());
    drop(catalog);
    let reopened = HostCatalog::open(&path).unwrap();
    assert_eq!(reopened.host_id().as_str(), "windows-test-host");
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn windows_retained_disk_copy_is_verified_and_attachable() {
    let path = std::env::temp_dir().join(format!(
        "sandsurf-windows-disk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let bytes: Vec<u8> = (0..64 * 1024).map(|value| (value % 251) as u8).collect();
    let source_path = path.join("source.raw");
    fs::write(&source_path, &bytes).unwrap();
    let source = File::open(&source_path).unwrap();
    let sandbox = SandboxId::try_from("windows-disk-box").unwrap();
    let mut journal = RuntimeJournal::create(
        &path.join("runtime"),
        sandbox,
        RuntimeLimits {
            identities: Counter::try_from(8).unwrap(),
            operations: Counter::try_from(8).unwrap(),
            observations: Counter::try_from(8).unwrap(),
            chunks: Counter::try_from(8).unwrap(),
            pins: Counter::try_from(8).unwrap(),
            output_bytes: Counter::try_from(1024).unwrap(),
            disks: Counter::try_from(8).unwrap(),
            disk_bytes: Counter::try_from(1024 * 1024).unwrap(),
            disk_headroom_bytes: Counter::try_from(1024 * 1024).unwrap(),
        },
        AuthorityBinding {
            host_id: "windows-disk-host".try_into().unwrap(),
            key_id: bytes_digest(&[
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a,
            ]),
            public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .to_owned()
                .try_into()
                .unwrap(),
        },
    )
    .unwrap();
    let request = DiskCopy {
        id: DiskId::try_from("workload").unwrap(),
        operation_id: OperationId::try_from("copy-workload").unwrap(),
        source_digest: bytes_digest(&bytes),
        bytes: Counter::try_from(bytes.len() as u64).unwrap(),
        purpose: DiskPurpose::Workload,
    };
    let record = journal.prepare_disk_copy(request).unwrap();
    assert_eq!(
        journal
            .materialize_disk(&record.request.id, &record.request_digest, &source)
            .unwrap()
            .phase,
        DiskPhase::Ready
    );
    let attachment = journal
        .acquire_disk(&record.request.id, &record.request_digest)
        .unwrap();
    let mut actual = vec![0_u8; bytes.len()];
    let read = attachment
        .duplicate_handle()
        .unwrap()
        .seek_read(&mut actual, 0)
        .unwrap();
    assert_eq!(read, bytes.len());
    assert_eq!(actual, bytes);
    drop(attachment);
    drop(journal);
    fs::remove_dir_all(path).unwrap();
}
