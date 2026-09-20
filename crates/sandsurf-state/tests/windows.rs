#![cfg(windows)]

use sandsurf_protocol::{Counter, Resources};
use sandsurf_state::{CatalogLimits, HostCatalog};
use std::fs;

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
